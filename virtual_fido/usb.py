"""Virtual USB HID device.

Port of the Go usb/ package: USB descriptors, control transfers and the two
interrupt endpoints that carry CTAPHID packets. Sits between the USB/IP
server and the CTAPHID transport.
"""

from __future__ import annotations

import logging
import struct
import threading
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from . import usbip
from ._util import ProtocolError, RequestBuffer, set_timeout, utf16_encode

logger = logging.getLogger("virtual_fido.usb")

# usbRequestType
REQUEST_GET_STATUS = 0
REQUEST_CLEAR_FEATURE = 1
REQUEST_SET_FEATURE = 3
REQUEST_SET_ADDRESS = 5
REQUEST_GET_DESCRIPTOR = 6
REQUEST_SET_DESCRIPTOR = 7
REQUEST_GET_CONFIGURATION = 8
REQUEST_SET_CONFIGURATION = 9
REQUEST_GET_INTERFACE = 10
REQUEST_SET_INTERFACE = 11
REQUEST_SYNCH_FRAME = 12

# usbDescriptorType
DESCRIPTOR_DEVICE = 1
DESCRIPTOR_CONFIGURATION = 2
DESCRIPTOR_STRING = 3
DESCRIPTOR_INTERFACE = 4
DESCRIPTOR_ENDPOINT = 5
DESCRIPTOR_DEVICE_QUALIFIER = 6
DESCRIPTOR_OTHER_SPEED_CONFIGURATION = 7
DESCRIPTOR_INTERFACE_POWER = 8
DESCRIPTOR_HID = 33
DESCRIPTOR_HID_REPORT = 34

# usbHIDRequestType
HID_REQUEST_GET_REPORT = 1
HID_REQUEST_GET_IDLE = 2
HID_REQUEST_GET_PROTOCOL = 3
HID_REQUEST_GET_DESCRIPTOR = 6
HID_REQUEST_SET_DESCRIPTOR = 7
HID_REQUEST_SET_REPORT = 9
HID_REQUEST_SET_IDLE = 10
HID_REQUEST_SET_PROTOCOL = 11

# usbDirection
HOST_TO_DEVICE = 0
DEVICE_TO_HOST = 1

# usbRequestClass
REQUEST_CLASS_STANDARD = 0
REQUEST_CLASS_CLASS = 1
REQUEST_CLASS_VENDOR = 2
REQUEST_CLASS_RESERVED = 3

# usbRequestRecipient
RECIPIENT_DEVICE = 0
RECIPIENT_INTERFACE = 1
RECIPIENT_ENDPOINT = 2
RECIPIENT_OTHER = 3

CONFIG_ATTRIBUTE_BASE = 0b10000000
CONFIG_ATTRIBUTE_SELF_POWERED = 0b01000000
CONFIG_ATTRIBUTE_REMOTE_WAKEUP = 0b00100000

INTERFACE_CLASS_HID = 3
HID_COUNTRY_CODE_NONE = 0
LANG_ID_ENG_USA = 0x0409

# usbEndpoint — endpoint numbers as seen in the USB/IP message header
ENDPOINT_CONTROL = 0
ENDPOINT_OUTPUT = 1  # interrupt IN: device -> host
ENDPOINT_INPUT = 2  # interrupt OUT: host -> device

# USB wire structs are little-endian and packed (Go: util.ToLE/ReadLE).
_SETUP_PACKET = struct.Struct("<BBHHH")
_DEVICE_DESCRIPTOR = struct.Struct("<BBHBBBBHHHBBBB")
_CONFIGURATION_DESCRIPTOR = struct.Struct("<BBHBBBBB")
_INTERFACE_DESCRIPTOR = struct.Struct("<BBBBBBBBB")
_HID_DESCRIPTOR = struct.Struct("<BBHBBBH")
_ENDPOINT_DESCRIPTOR = struct.Struct("<BBBBHB")
_STRING_DESCRIPTOR_HEADER = struct.Struct("<BB")

# Manually calculated using the HID report calculator for a FIDO device.
HID_REPORT_DESCRIPTOR = bytes(
    [6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2,
     9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192]
)

_STRING_DESCRIPTORS = {
    1: "No Company",
    2: "Virtual FIDO",
    3: "No Serial Number",
    4: "String 4",
    5: "Default Interface",
}


@dataclass
class USBSetupPacket:
    bm_request_type: int
    b_request: int
    w_value: int
    w_index: int
    w_length: int

    @classmethod
    def unpack(cls, data: bytes) -> "USBSetupPacket":
        return cls(*_SETUP_PACKET.unpack(data[: _SETUP_PACKET.size]))

    def pack(self) -> bytes:
        return _SETUP_PACKET.pack(
            self.bm_request_type,
            self.b_request,
            self.w_value,
            self.w_index,
            self.w_length,
        )

    @property
    def direction(self) -> int:
        return (self.bm_request_type >> 7) & 1

    @property
    def request_class(self) -> int:
        return (self.bm_request_type >> 4) & 0b11

    @property
    def recipient(self) -> int:
        return self.bm_request_type & 0b1111

    @classmethod
    def make(
        cls,
        direction: int = HOST_TO_DEVICE,
        request_class: int = REQUEST_CLASS_STANDARD,
        recipient: int = RECIPIENT_DEVICE,
        b_request: int = 0,
        w_value: int = 0,
        w_index: int = 0,
        w_length: int = 0,
    ) -> "USBSetupPacket":
        bm_request_type = (direction << 7) | (request_class << 4) | recipient
        return cls(bm_request_type, b_request, w_value, w_index, w_length)


def descriptor_type_and_index(w_value: int) -> tuple[int, int]:
    return w_value >> 8, w_value & 0xFF


class USBDeviceDelegate(Protocol):
    """The transport that consumes HID reports (usb.USBDeviceDelegate)."""

    def handle_message(self, transfer_buffer: bytes) -> None: ...

    def set_response_handler(self, handler: Callable[[bytes], None]) -> None: ...


class USBDevice:
    """The virtual FIDO USB device exposed through USB/IP."""

    def __init__(self, delegate: USBDeviceDelegate) -> None:
        self._delegate = delegate
        self._request_buffer = RequestBuffer()
        delegate.set_response_handler(self._request_buffer.respond)

    # ------------------------------------------------------------------
    # usbip.USBIPDevice interface
    # ------------------------------------------------------------------

    def bus_id(self) -> str:
        return "2-2"

    def device_summary(self) -> usbip.USBIPDeviceSummary:
        from ._util import pad

        return usbip.USBIPDeviceSummary(
            header=usbip.USBIPDeviceSummaryHeader(
                path=pad(b"/device/0", 256),
                bus_id=pad(b"2-2", 32),
                busnum=2,
                devnum=2,
                speed=2,
            ),
            device_interface=usbip.USBIPDeviceInterface(
                b_interface_class=INTERFACE_CLASS_HID, b_interface_subclass=0
            ),
        )

    def remove_waiting_request(self, request_id: int) -> bool:
        return self._request_buffer.cancel_request(request_id)

    def handle_message(
        self,
        request_id: int,
        on_finish: Callable[[Optional[bytes]], None],
        endpoint: int,
        setup_bytes: bytes,
        transfer_buffer: bytes,
    ) -> None:
        if endpoint == ENDPOINT_CONTROL:
            setup = USBSetupPacket.unpack(setup_bytes)
            logger.debug("CONTROL: %s", setup)
            on_finish(self._handle_control_message(setup))
        elif endpoint == ENDPOINT_OUTPUT:
            # Host is polling for a HID report; answer when the CTAPHID
            # layer produces one, or cancel after a timeout so the URB
            # doesn't stay pending forever.
            self._request_buffer.request(request_id, on_finish)

            def cancel() -> None:
                if self._request_buffer.cancel_request(request_id):
                    on_finish(None)

            set_timeout(1.0, cancel)
        elif endpoint == ENDPOINT_INPUT:
            logger.debug("INPUT DATA: %r", transfer_buffer)

            # Handling may block on user approval; don't stall the URB loop.
            # A bad packet must only lose this report, not kill the stack.
            def process() -> None:
                try:
                    self._delegate.handle_message(transfer_buffer)
                except Exception:
                    logger.exception("Error handling HID report")

            threading.Thread(target=process, daemon=True).start()
            on_finish(None)
        else:
            raise ProtocolError(f"Invalid USB endpoint: {endpoint}")

    # ------------------------------------------------------------------
    # Control transfers
    # ------------------------------------------------------------------

    def _handle_control_message(self, setup: USBSetupPacket) -> Optional[bytes]:
        if setup.recipient == RECIPIENT_DEVICE:
            return self._handle_device_request(setup)
        if setup.recipient == RECIPIENT_INTERFACE:
            return self._handle_interface_request(setup)
        raise ProtocolError(f"Invalid CMD_SUBMIT recipient: {setup.recipient}")

    def _handle_device_request(self, setup: USBSetupPacket) -> Optional[bytes]:
        if setup.b_request == REQUEST_GET_DESCRIPTOR:
            descriptor_type, index = descriptor_type_and_index(setup.w_value)
            return self._get_descriptor(descriptor_type, index)
        if setup.b_request == REQUEST_SET_CONFIGURATION:
            # No-op: there is only one configuration.
            logger.debug("SET_CONFIGURATION: no-op")
            return None
        if setup.b_request == REQUEST_GET_STATUS:
            return b"\x01"
        raise ProtocolError(f"Invalid CMD_SUBMIT bRequest: {setup.b_request}")

    def _handle_interface_request(self, setup: USBSetupPacket) -> Optional[bytes]:
        if setup.b_request == HID_REQUEST_SET_IDLE:
            # No-op: virtual device, nothing to idle.
            return None
        if setup.b_request == HID_REQUEST_SET_PROTOCOL:
            # No-op: always report protocol, no boot protocol.
            return None
        if setup.b_request == HID_REQUEST_GET_DESCRIPTOR:
            descriptor_type, index = descriptor_type_and_index(setup.w_value)
            if descriptor_type == DESCRIPTOR_HID_REPORT:
                return HID_REPORT_DESCRIPTOR
            raise ProtocolError(
                f"Invalid USB interface descriptor: {descriptor_type} - {index}"
            )
        raise ProtocolError(f"Invalid USB interface bRequest: {setup.b_request}")

    # ------------------------------------------------------------------
    # Descriptors
    # ------------------------------------------------------------------

    def _get_descriptor(self, descriptor_type: int, index: int) -> bytes:
        logger.debug("GET_DESCRIPTOR type=%d index=%d", descriptor_type, index)
        if descriptor_type == DESCRIPTOR_DEVICE:
            return self._device_descriptor()
        if descriptor_type == DESCRIPTOR_CONFIGURATION:
            return self._configuration_response()
        if descriptor_type == DESCRIPTOR_STRING:
            message = self._string_descriptor(index)
            header = _STRING_DESCRIPTOR_HEADER.pack(
                _STRING_DESCRIPTOR_HEADER.size + len(message), DESCRIPTOR_STRING
            )
            return header + message
        raise ProtocolError(f"Invalid descriptor type: {descriptor_type}")

    def _device_descriptor(self) -> bytes:
        return _DEVICE_DESCRIPTOR.pack(
            _DEVICE_DESCRIPTOR.size,  # bLength
            DESCRIPTOR_DEVICE,  # bDescriptorType
            0x0110,  # bcdUSB
            0,  # bDeviceClass
            0,  # bDeviceSubclass
            0,  # bDeviceProtocol
            64,  # bMaxPacketSize
            0,  # idVendor
            0,  # idProduct
            0x1,  # bcdDevice
            1,  # iManufacturer
            2,  # iProduct
            3,  # iSerialNumber
            1,  # bNumConfigurations
        )

    def _configuration_response(self) -> bytes:
        # Configuration descriptor is followed by interface + HID +
        # endpoint descriptors, with wTotalLength covering all of them.
        inner = (
            self._interface_descriptor()
            + self._hid_descriptor()
            + b"".join(self._endpoint_descriptors())
        )
        config = _CONFIGURATION_DESCRIPTOR.pack(
            _CONFIGURATION_DESCRIPTOR.size,  # bLength
            DESCRIPTOR_CONFIGURATION,  # bDescriptorType
            _CONFIGURATION_DESCRIPTOR.size + len(inner),  # wTotalLength
            1,  # bNumInterfaces
            0,  # bConfigurationValue
            4,  # iConfiguration
            CONFIG_ATTRIBUTE_BASE | CONFIG_ATTRIBUTE_SELF_POWERED,  # bmAttributes
            0,  # bMaxPower
        )
        return config + inner

    def _interface_descriptor(self) -> bytes:
        return _INTERFACE_DESCRIPTOR.pack(
            _INTERFACE_DESCRIPTOR.size,  # bLength
            DESCRIPTOR_INTERFACE,  # bDescriptorType
            0,  # bInterfaceNumber
            0,  # bAlternateSetting
            2,  # bNumEndpoints
            INTERFACE_CLASS_HID,  # bInterfaceClass
            0,  # bInterfaceSubclass
            0,  # bInterfaceProtocol
            5,  # iInterface
        )

    def _hid_descriptor(self) -> bytes:
        return _HID_DESCRIPTOR.pack(
            _HID_DESCRIPTOR.size,  # bLength
            DESCRIPTOR_HID,  # bDescriptorType
            0x0101,  # bcdHID
            HID_COUNTRY_CODE_NONE,  # bCountryCode
            1,  # bNumDescriptors
            DESCRIPTOR_HID_REPORT,  # bClassDescriptorType
            len(HID_REPORT_DESCRIPTOR),  # wReportDescriptorLength
        )

    def _endpoint_descriptors(self) -> list[bytes]:
        descriptors = []
        for address in (0b10000001, 0b00000010):  # 0x81 IN, 0x02 OUT
            descriptors.append(
                _ENDPOINT_DESCRIPTOR.pack(
                    _ENDPOINT_DESCRIPTOR.size,  # bLength
                    DESCRIPTOR_ENDPOINT,  # bDescriptorType
                    address,  # bEndpointAddress
                    0b00000011,  # bmAttributes: interrupt
                    64,  # wMaxPacketSize
                    255,  # bInterval
                )
            )
        return descriptors

    def _string_descriptor(self, index: int) -> bytes:
        if index == 0:
            return struct.pack("<H", LANG_ID_ENG_USA)
        try:
            return utf16_encode(_STRING_DESCRIPTORS[index])
        except KeyError:
            raise ProtocolError(f"Invalid string descriptor index: {index}") from None
