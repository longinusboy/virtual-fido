"""USB device descriptor + routing tests (port of upstream usb/usb_device_test.go,
adapted for the multi-interface USBDevice)."""

import struct

from virtual_fido import usb
from virtual_fido._util import cstring_to_str
from virtual_fido.fido_hid import FidoHIDInterface

# FIDO is the only/first interface here, so it gets endpoints 1 (IN) and 2 (OUT).
FIDO_IN_EP = 1
FIDO_OUT_EP = 2


class DummyDelegate:
    def __init__(self):
        self.transfer_buffer = None
        self.response_handler = None

    def handle_message(self, transfer_buffer):
        self.transfer_buffer = transfer_buffer

    def set_response_handler(self, handler):
        self.response_handler = handler


def make_device(delegate=None, config=None):
    delegate = delegate or DummyDelegate()
    return usb.USBDevice([FidoHIDInterface(delegate)], config=config), delegate


def _control_response(device, setup):
    responses = []
    device.handle_message(
        0, responses.append, usb.ENDPOINT_CONTROL, usb.DIR_IN, setup.pack(), b""
    )
    assert len(responses) == 1
    return responses[0]


def test_get_device_descriptor():
    device, _ = make_device()
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_DEVICE << 8,
        w_length=64,
    )
    response = _control_response(device, setup)
    assert response is not None
    (b_length, b_descriptor_type, bcd_usb) = struct.unpack("<BBH", response[:4])
    b_num_configurations = response[-1]
    assert b_length == len(response) == 18
    assert b_descriptor_type == usb.DESCRIPTOR_DEVICE
    assert bcd_usb == 0x110
    assert b_num_configurations == 1


def test_get_configuration():
    device, _ = make_device()
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_CONFIGURATION << 8,
        w_length=255,
    )
    response = _control_response(device, setup)
    assert response is not None

    offset = 0
    b_length, b_descriptor_type, w_total_length, b_num_interfaces = struct.unpack_from(
        "<BBHB", response, offset
    )
    assert b_length == 9
    assert b_descriptor_type == usb.DESCRIPTOR_CONFIGURATION
    assert w_total_length == len(response)
    assert b_num_interfaces == 1  # FIDO only, in this test
    offset += b_length

    b_length, b_descriptor_type = struct.unpack_from("<BB", response, offset)
    assert b_length == 9
    assert b_descriptor_type == usb.DESCRIPTOR_INTERFACE
    b_num_endpoints = response[offset + 4]
    assert b_num_endpoints == 2
    offset += b_length

    b_length, b_descriptor_type, _, b_country_code = struct.unpack_from(
        "<BBHB", response, offset
    )
    assert b_length == 9
    assert b_descriptor_type == usb.DESCRIPTOR_HID
    assert b_country_code == usb.HID_COUNTRY_CODE_NONE
    offset += b_length

    addresses = []
    for _ in range(b_num_endpoints):
        b_length, b_descriptor_type, address = struct.unpack_from("<BBB", response, offset)
        assert b_descriptor_type == usb.DESCRIPTOR_ENDPOINT
        assert b_length == 7
        addresses.append(address)
        offset += b_length
    assert offset == len(response)
    assert addresses == [0x81, 0x02]  # FIDO: EP1 IN, EP2 OUT (unchanged)


def test_get_hid_report_descriptor():
    device, _ = make_device()
    setup = usb.USBSetupPacket.make(
        recipient=usb.RECIPIENT_INTERFACE,
        b_request=usb.HID_REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_HID_REPORT << 8,
        w_index=0,  # interface 0 = FIDO
        w_length=64,
    )
    response = _control_response(device, setup)
    assert response == usb.HID_REPORT_DESCRIPTOR
    assert len(response) > 0


def test_get_string_descriptors():
    device, _ = make_device()
    # Default identity: language (0), manufacturer (1), product (2).
    for index in range(3):
        setup = usb.USBSetupPacket.make(
            b_request=usb.REQUEST_GET_DESCRIPTOR,
            w_value=(usb.DESCRIPTOR_STRING << 8) | index,
            w_length=64,
        )
        response = _control_response(device, setup)
        assert cstring_to_str(response + b"\x00") != ""
        assert response[0] == len(response)
        assert response[1] == usb.DESCRIPTOR_STRING


def test_string_descriptor_contents():
    device, _ = make_device()

    def get_string(index):
        setup = usb.USBSetupPacket.make(
            b_request=usb.REQUEST_GET_DESCRIPTOR,
            w_value=(usb.DESCRIPTOR_STRING << 8) | index,
            w_length=255,
        )
        return _control_response(device, setup)[2:].decode("utf-16-le")

    assert get_string(1) == "Yubico"
    assert get_string(2) == "YubiKey OTP+FIDO+CCID"


def test_device_descriptor_yubikey_identity():
    """Default identity matches a real YubiKey 5 enumeration:
    idVendor=1050, idProduct=0407, bcdDevice=5.74, Mfr=1, Product=2, SerialNumber=0."""
    device, _ = make_device()
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_DEVICE << 8,
        w_length=64,
    )
    response = _control_response(device, setup)
    id_vendor, id_product, bcd_device = struct.unpack("<HHH", response[8:14])
    i_manufacturer, i_product, i_serial = response[14], response[15], response[16]
    assert id_vendor == 0x1050
    assert id_product == 0x0407
    assert bcd_device == 0x0574
    assert (i_manufacturer, i_product, i_serial) == (1, 2, 0)


def test_custom_device_config():
    config = usb.USBDeviceConfig(
        id_vendor=0x1234,
        id_product=0x5678,
        bcd_device=0x0100,
        manufacturer="ACME",
        product="Virtual Key",
        serial_number="12345",
    )
    device, _ = make_device(config=config)
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_DEVICE << 8,
        w_length=64,
    )
    response = _control_response(device, setup)
    assert struct.unpack("<HHH", response[8:14]) == (0x1234, 0x5678, 0x0100)
    assert response[16] == 3  # serial number string present at index 3
    serial_setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=(usb.DESCRIPTOR_STRING << 8) | 3,
        w_length=255,
    )
    assert _control_response(device, serial_setup)[2:].decode("utf-16-le") == "12345"
    summary = device.device_summary()
    assert summary.header.id_vendor == 0x1234
    assert summary.header.id_product == 0x5678
    assert summary.header.bcd_device == 0x0100


def test_bus_id():
    device, _ = make_device()
    assert device.bus_id() == "2-2"


def test_device_summary():
    device, _ = make_device()
    summary = device.device_summary()
    assert summary.header.busnum == 2
    assert summary.header.devnum == 2
    assert cstring_to_str(summary.header.bus_id) == "2-2"
    assert cstring_to_str(summary.header.path) == "/device/0"
    assert summary.header.b_num_interfaces == 1
    assert len(summary.interfaces) == 1
    assert summary.interfaces[0].b_interface_class == usb.INTERFACE_CLASS_HID


def test_input_endpoint_forwards_to_delegate():
    device, delegate = make_device()
    responses = []
    device.handle_message(
        7, responses.append, FIDO_OUT_EP, usb.DIR_OUT, b"\x00" * 8, b"hello fido"
    )
    assert responses == [None]
    import time

    deadline = time.monotonic() + 2.0
    while delegate.transfer_buffer is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert delegate.transfer_buffer == b"hello fido"


def test_output_endpoint_waits_for_response():
    device, delegate = make_device()
    responses = []
    device.handle_message(9, responses.append, FIDO_IN_EP, usb.DIR_IN, b"\x00" * 8, b"")
    assert responses == []  # no data yet
    delegate.response_handler(b"report!")
    assert responses == [b"report!"]


def test_output_endpoint_cancel():
    device, delegate = make_device()
    responses = []
    device.handle_message(11, responses.append, FIDO_IN_EP, usb.DIR_IN, b"\x00" * 8, b"")
    assert device.remove_waiting_request(11)
    assert not device.remove_waiting_request(11)
    delegate.response_handler(b"late")
    assert responses == []  # cancelled request must not fire


def test_output_endpoint_stays_pending_no_timeout_nak():
    """Regression: an interrupt-IN poll must stay pending until data arrives,
    never self-completing with an empty/zero packet."""
    import time

    device, delegate = make_device()
    responses = []
    device.handle_message(1, responses.append, FIDO_IN_EP, usb.DIR_IN, b"\x00" * 8, b"")
    time.sleep(1.2)  # well past the old 1-second timeout
    assert responses == []  # still pending, no bogus completion
    delegate.response_handler(b"real-report")
    assert responses == [b"real-report"]


def test_multi_packet_response_single_poll_at_a_time():
    """Simulate the idle host: exactly one interrupt-IN poll outstanding,
    re-polling after each completion. A 2-packet response must arrive intact
    and in order."""
    device, delegate = make_device()
    received = []
    counter = [100]

    def submit_poll():
        rid = counter[0]
        counter[0] += 1

        def on_complete(packet):
            received.append(packet)
            submit_poll()

        device.handle_message(rid, on_complete, FIDO_IN_EP, usb.DIR_IN, b"\x00" * 8, b"")

    submit_poll()
    delegate.response_handler(b"packet-1")
    delegate.response_handler(b"packet-2")
    assert received == [b"packet-1", b"packet-2"]


def test_invalid_endpoint_raises():
    import pytest

    from virtual_fido._util import ProtocolError

    device, _ = make_device()
    with pytest.raises(ProtocolError):
        device.handle_message(1, lambda r: None, 99, usb.DIR_IN, b"\x00" * 8, b"")


def test_unsupported_descriptor_stalls():
    """Optional descriptors we don't provide (e.g. debug/BOS, type 10) must
    stall so the host gives up immediately instead of hanging (regression:
    a real host's debug-descriptor probe stalled enumeration for 5s each)."""
    from virtual_fido import usbip

    device, _ = make_device()
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR, w_value=0x0A00, w_length=4  # type 10
    )
    assert _control_response(device, setup) is usbip.STALL


def test_unknown_string_index_stalls():
    from virtual_fido import usbip

    device, _ = make_device()
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=(usb.DESCRIPTOR_STRING << 8) | 99,
        w_length=255,
    )
    assert _control_response(device, setup) is usbip.STALL


def test_get_status_returns_two_bytes():
    device, _ = make_device()
    setup = usb.USBSetupPacket.make(b_request=usb.REQUEST_GET_STATUS, w_length=2)
    assert _control_response(device, setup) == b"\x01\x00"
