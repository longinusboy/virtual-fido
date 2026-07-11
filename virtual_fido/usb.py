"""Virtual USB device with one or more interfaces.

Descriptors and control transfers for a composite USB device. `USBDevice`
aggregates any number of `USBInterface`s (FIDO HID, OTP keyboard, CCID
smartcard, ...), assigns their interface and endpoint numbers, builds the
configuration descriptor, and routes control/data URBs to the owning
interface. Sits between the USB/IP server and the per-interface logic.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from . import usbip
from ._util import ProtocolError, utf16_encode

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

# usbDirection (matches usbip.DIR_OUT / DIR_IN)
HOST_TO_DEVICE = 0
DEVICE_TO_HOST = 1
DIR_OUT = 0  # host -> device
DIR_IN = 1  # device -> host

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
INTERFACE_CLASS_SMARTCARD = 0x0B
HID_COUNTRY_CODE_NONE = 0
LANG_ID_ENG_USA = 0x0409

# bmAttributes transfer types for endpoint descriptors
ATTR_BULK = 0b10
ATTR_INTERRUPT = 0b11

# The control endpoint is always number 0; data endpoints are numbered from 1.
ENDPOINT_CONTROL = 0

# USB wire structs are little-endian and packed (Go: util.ToLE/ReadLE).
_SETUP_PACKET = struct.Struct("<BBHHH")
_DEVICE_DESCRIPTOR = struct.Struct("<BBHBBBBHHHBBBB")
_CONFIGURATION_DESCRIPTOR = struct.Struct("<BBHBBBBB")
_INTERFACE_DESCRIPTOR = struct.Struct("<BBBBBBBBB")
_HID_DESCRIPTOR = struct.Struct("<BBHBBBH")
_ENDPOINT_DESCRIPTOR = struct.Struct("<BBBBHB")
_STRING_DESCRIPTOR_HEADER = struct.Struct("<BB")

# FIDO HID report descriptor (kept here so tests can reference it; used by the
# FIDO interface in fido_hid.py).
HID_REPORT_DESCRIPTOR = bytes(
    [6, 208, 241, 9, 1, 161, 1, 9, 32, 20, 37, 255, 117, 8, 149, 64, 129, 2,
     9, 33, 20, 37, 255, 117, 8, 149, 64, 145, 2, 192]
)


@dataclass
class USBDeviceConfig:
    """Identity the virtual device announces to the host.

    Defaults mimic a YubiKey 5 (OTP+FIDO+CCID), as enumerated by the kernel:

        usb 3-2: New USB device found, idVendor=1050, idProduct=0407, bcdDevice= 5.74
        usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=0
        usb 3-2: Product: YubiKey OTP+FIDO+CCID
        usb 3-2: Manufacturer: Yubico

    Every field can be overridden to present a different identity. A string
    field set to None omits that string descriptor entirely (a real YubiKey
    announces no serial number: SerialNumber=0 above).
    """

    id_vendor: int = 0x1050
    id_product: int = 0x0407
    bcd_device: int = 0x0574
    manufacturer: Optional[str] = "Yubico"
    product: Optional[str] = "YubiKey OTP+FIDO+CCID"
    serial_number: Optional[str] = None
    configuration_name: Optional[str] = None


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


# ---------------------------------------------------------------------------
# Descriptor builders (shared by interface implementations)
# ---------------------------------------------------------------------------


def interface_descriptor(
    number: int,
    num_endpoints: int,
    interface_class: int,
    interface_subclass: int,
    interface_protocol: int,
    i_interface: int,
) -> bytes:
    return _INTERFACE_DESCRIPTOR.pack(
        _INTERFACE_DESCRIPTOR.size,
        DESCRIPTOR_INTERFACE,
        number,  # bInterfaceNumber
        0,  # bAlternateSetting
        num_endpoints,
        interface_class,
        interface_subclass,
        interface_protocol,
        i_interface,
    )


def endpoint_descriptor(
    address: int, attributes: int, max_packet_size: int, interval: int
) -> bytes:
    return _ENDPOINT_DESCRIPTOR.pack(
        _ENDPOINT_DESCRIPTOR.size,
        DESCRIPTOR_ENDPOINT,
        address,
        attributes,
        max_packet_size,
        interval,
    )


def hid_descriptor(report_descriptor_length: int) -> bytes:
    return _HID_DESCRIPTOR.pack(
        _HID_DESCRIPTOR.size,
        DESCRIPTOR_HID,
        0x0101,  # bcdHID
        HID_COUNTRY_CODE_NONE,
        1,  # bNumDescriptors
        DESCRIPTOR_HID_REPORT,
        report_descriptor_length,
    )


@dataclass
class EndpointSpec:
    """A data endpoint an interface needs. The endpoint *number* is assigned
    by USBDevice; the interface only declares direction and transfer type."""

    is_in: bool  # True = device -> host (IN), False = host -> device (OUT)
    attributes: int = ATTR_INTERRUPT
    max_packet_size: int = 64
    interval: int = 255  # interrupt polling interval; use 0 for bulk


class USBInterface:
    """Base class for a USB interface. Subclasses set the class triple and
    endpoint specs, and implement `handle_data`. `interface_number`,
    `i_interface` and `endpoint_numbers` are filled in by USBDevice.
    """

    interface_class: int = 0
    interface_subclass: int = 0
    interface_protocol: int = 0
    interface_string: Optional[str] = None
    endpoint_specs: list[EndpointSpec] = []

    # Assigned by USBDevice at construction.
    interface_number: int = 0
    i_interface: int = 0
    endpoint_numbers: list[int] = []

    def class_descriptors(self) -> bytes:
        """Class-specific descriptors placed between the interface and its
        endpoint descriptors (e.g. HID descriptor, CCID functional descriptor)."""
        return b""

    def report_descriptor(self) -> Optional[bytes]:
        """HID report descriptor, if this is a HID interface."""
        return None

    def handle_class_control(self, setup: USBSetupPacket) -> Optional[bytes]:
        """Interface-recipient control requests (HID SET_IDLE/SET_PROTOCOL,
        CCID class requests, ...). Default: ack with no data."""
        return None

    def handle_data(
        self,
        direction: int,
        request_id: int,
        transfer_buffer: bytes,
        on_finish: Callable[[Optional[bytes]], None],
    ) -> None:
        raise NotImplementedError

    def cancel_request(self, request_id: int) -> bool:
        """Cancel a pending IN request (USB/IP UNLINK). Default: nothing to cancel."""
        return False


class USBDeviceDelegate(Protocol):
    """A transport that produces/consumes HID reports (e.g. CTAPHIDServer)."""

    def handle_message(self, transfer_buffer: bytes) -> None: ...

    def set_response_handler(self, handler: Callable[[bytes], None]) -> None: ...


class USBDevice:
    """A composite USB device exposed through USB/IP."""

    def __init__(
        self,
        interfaces: list[USBInterface],
        config: Optional[USBDeviceConfig] = None,
    ) -> None:
        if not interfaces:
            raise ValueError("USBDevice needs at least one interface")
        self._interfaces = list(interfaces)
        self._config = config or USBDeviceConfig()

        # String descriptor indexes are assigned in order over the strings
        # that are present; absent strings get index 0 ("none"). Device-level
        # strings first (so manufacturer=1, product=2 as a real YubiKey), then
        # each interface's iInterface string.
        self._strings: dict[int, str] = {}
        self._i_manufacturer = self._add_string(self._config.manufacturer)
        self._i_product = self._add_string(self._config.product)
        self._i_serial_number = self._add_string(self._config.serial_number)
        self._i_configuration = self._add_string(self._config.configuration_name)

        # Assign interface numbers, endpoint numbers and interface strings.
        self._ep_to_interface: dict[int, USBInterface] = {}
        next_endpoint = 1
        for number, iface in enumerate(self._interfaces):
            iface.interface_number = number
            iface.i_interface = self._add_string(iface.interface_string)
            iface.endpoint_numbers = []
            for _spec in iface.endpoint_specs:
                self._ep_to_interface[next_endpoint] = iface
                iface.endpoint_numbers.append(next_endpoint)
                next_endpoint += 1

    def _add_string(self, value: Optional[str]) -> int:
        if value is None:
            return 0
        index = len(self._strings) + 1
        self._strings[index] = value
        return index

    # ------------------------------------------------------------------
    # usbip.USBIPDevice interface
    # ------------------------------------------------------------------

    def bus_id(self) -> str:
        return "2-2"

    def device_summary(self) -> usbip.USBIPDeviceSummary:
        from ._util import pad

        interfaces = [
            usbip.USBIPDeviceInterface(
                b_interface_class=iface.interface_class,
                b_interface_subclass=iface.interface_subclass,
            )
            for iface in self._interfaces
        ]
        return usbip.USBIPDeviceSummary(
            header=usbip.USBIPDeviceSummaryHeader(
                path=pad(b"/device/0", 256),
                bus_id=pad(b"2-2", 32),
                busnum=2,
                devnum=2,
                speed=2,
                id_vendor=self._config.id_vendor,
                id_product=self._config.id_product,
                bcd_device=self._config.bcd_device,
                b_num_interfaces=len(self._interfaces),
            ),
            interfaces=interfaces,
        )

    def remove_waiting_request(self, request_id: int) -> bool:
        return any(iface.cancel_request(request_id) for iface in self._interfaces)

    def handle_message(
        self,
        request_id: int,
        on_finish: Callable[[Optional[bytes]], None],
        endpoint: int,
        direction: int,
        setup_bytes: bytes,
        transfer_buffer: bytes,
    ) -> None:
        if endpoint == ENDPOINT_CONTROL:
            setup = USBSetupPacket.unpack(setup_bytes)
            logger.debug("CONTROL: %s", setup)
            on_finish(self._handle_control_message(setup))
            return
        iface = self._ep_to_interface.get(endpoint)
        if iface is None:
            raise ProtocolError(f"Invalid USB endpoint: {endpoint}")
        iface.handle_data(direction, request_id, transfer_buffer, on_finish)

    # ------------------------------------------------------------------
    # Control transfers
    # ------------------------------------------------------------------

    def _handle_control_message(self, setup: USBSetupPacket) -> Optional[bytes]:
        if setup.recipient == RECIPIENT_DEVICE:
            return self._handle_device_request(setup)
        if setup.recipient == RECIPIENT_INTERFACE:
            return self._handle_interface_request(setup)
        if setup.recipient == RECIPIENT_ENDPOINT:
            # CLEAR_FEATURE(HALT), GET_STATUS on an endpoint: ack / report OK.
            if setup.b_request == REQUEST_GET_STATUS:
                return b"\x00\x00"
            return None
        raise ProtocolError(f"Invalid control recipient: {setup.recipient}")

    def _handle_device_request(self, setup: USBSetupPacket) -> Optional[bytes]:
        if setup.b_request == REQUEST_GET_DESCRIPTOR:
            descriptor_type, index = descriptor_type_and_index(setup.w_value)
            return self._get_descriptor(descriptor_type, index)
        if setup.b_request == REQUEST_SET_CONFIGURATION:
            logger.debug("SET_CONFIGURATION: no-op")  # only one configuration
            return None
        if setup.b_request == REQUEST_GET_STATUS:
            return b"\x01"
        raise ProtocolError(f"Invalid device bRequest: {setup.b_request}")

    def _handle_interface_request(self, setup: USBSetupPacket) -> Optional[bytes]:
        number = setup.w_index & 0xFF
        if number >= len(self._interfaces):
            raise ProtocolError(f"Invalid interface number: {number}")
        iface = self._interfaces[number]
        if setup.b_request == REQUEST_GET_DESCRIPTOR:
            descriptor_type, index = descriptor_type_and_index(setup.w_value)
            if descriptor_type == DESCRIPTOR_HID_REPORT:
                report = iface.report_descriptor()
                if report is None:
                    raise ProtocolError(f"Interface {number} has no report descriptor")
                return report
            raise ProtocolError(
                f"Invalid interface descriptor: {descriptor_type} - {index}"
            )
        return iface.handle_class_control(setup)

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
            0,  # bDeviceClass (per-interface)
            0,  # bDeviceSubclass
            0,  # bDeviceProtocol
            64,  # bMaxPacketSize
            self._config.id_vendor,
            self._config.id_product,
            self._config.bcd_device,
            self._i_manufacturer,
            self._i_product,
            self._i_serial_number,
            1,  # bNumConfigurations
        )

    def _configuration_response(self) -> bytes:
        # Configuration descriptor followed by, for each interface, its
        # interface descriptor + class descriptors + endpoint descriptors.
        inner = b""
        for iface in self._interfaces:
            inner += interface_descriptor(
                iface.interface_number,
                len(iface.endpoint_numbers),
                iface.interface_class,
                iface.interface_subclass,
                iface.interface_protocol,
                iface.i_interface,
            )
            inner += iface.class_descriptors()
            for number, spec in zip(iface.endpoint_numbers, iface.endpoint_specs):
                address = number | (0x80 if spec.is_in else 0)
                inner += endpoint_descriptor(
                    address, spec.attributes, spec.max_packet_size, spec.interval
                )
        config = _CONFIGURATION_DESCRIPTOR.pack(
            _CONFIGURATION_DESCRIPTOR.size,  # bLength
            DESCRIPTOR_CONFIGURATION,  # bDescriptorType
            _CONFIGURATION_DESCRIPTOR.size + len(inner),  # wTotalLength
            len(self._interfaces),  # bNumInterfaces
            0,  # bConfigurationValue
            self._i_configuration,
            CONFIG_ATTRIBUTE_BASE | CONFIG_ATTRIBUTE_SELF_POWERED,  # bmAttributes
            0,  # bMaxPower
        )
        return config + inner

    def _string_descriptor(self, index: int) -> bytes:
        if index == 0:
            return struct.pack("<H", LANG_ID_ENG_USA)
        try:
            return utf16_encode(self._strings[index])
        except KeyError:
            raise ProtocolError(f"Invalid string descriptor index: {index}") from None
