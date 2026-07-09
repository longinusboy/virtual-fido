"""Port of usb/usb_device_test.go."""

import struct

from virtual_fido import usb
from virtual_fido._util import cstring_to_str


class DummyDelegate:
    def __init__(self):
        self.transfer_buffer = None
        self.response_handler = None

    def handle_message(self, transfer_buffer):
        self.transfer_buffer = transfer_buffer

    def set_response_handler(self, handler):
        self.response_handler = handler


def _control_response(device, setup):
    responses = []
    device.handle_message(0, responses.append, usb.ENDPOINT_CONTROL, setup.pack(), b"")
    assert len(responses) == 1
    return responses[0]


def test_get_device_descriptor():
    device = usb.USBDevice(DummyDelegate())
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
    device = usb.USBDevice(DummyDelegate())
    setup = usb.USBSetupPacket.make(
        b_request=usb.REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_CONFIGURATION << 8,
        w_length=64,
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
    assert b_num_interfaces == 1
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

    for _ in range(b_num_endpoints):
        b_length, b_descriptor_type = struct.unpack_from("<BB", response, offset)
        assert b_descriptor_type == usb.DESCRIPTOR_ENDPOINT
        assert b_length == 7
        offset += b_length
    assert offset == len(response)


def test_get_string_descriptors():
    device = usb.USBDevice(DummyDelegate())
    for index in range(5):
        setup = usb.USBSetupPacket.make(
            b_request=usb.REQUEST_GET_DESCRIPTOR,
            w_value=(usb.DESCRIPTOR_STRING << 8) | index,
            w_length=64,
        )
        response = _control_response(device, setup)
        assert cstring_to_str(response + b"\x00") != ""
        assert response[0] == len(response)
        assert response[1] == usb.DESCRIPTOR_STRING


def test_get_hid_report():
    device = usb.USBDevice(DummyDelegate())
    setup = usb.USBSetupPacket.make(
        recipient=usb.RECIPIENT_INTERFACE,
        b_request=usb.HID_REQUEST_GET_DESCRIPTOR,
        w_value=usb.DESCRIPTOR_HID_REPORT << 8,
        w_length=64,
    )
    response = _control_response(device, setup)
    assert response == usb.HID_REPORT_DESCRIPTOR
    assert len(response) > 0


def test_bus_id():
    device = usb.USBDevice(DummyDelegate())
    assert device.bus_id() == "2-2"


def test_device_summary():
    device = usb.USBDevice(DummyDelegate())
    summary = device.device_summary()
    assert summary.header.busnum == 2
    assert summary.header.devnum == 2
    assert cstring_to_str(summary.header.bus_id) == "2-2"
    assert cstring_to_str(summary.header.path) == "/device/0"


def test_input_endpoint_forwards_to_delegate():
    delegate = DummyDelegate()
    device = usb.USBDevice(delegate)
    responses = []
    device.handle_message(
        7, responses.append, usb.ENDPOINT_INPUT, b"\x00" * 8, b"hello fido"
    )
    assert responses == [None]
    # Delegate is invoked on a worker thread; wait for it.
    import time

    deadline = time.monotonic() + 2.0
    while delegate.transfer_buffer is None and time.monotonic() < deadline:
        time.sleep(0.01)
    assert delegate.transfer_buffer == b"hello fido"


def test_output_endpoint_waits_for_response():
    delegate = DummyDelegate()
    device = usb.USBDevice(delegate)
    responses = []
    device.handle_message(9, responses.append, usb.ENDPOINT_OUTPUT, b"\x00" * 8, b"")
    assert responses == []  # no data yet
    delegate.response_handler(b"report!")
    assert responses == [b"report!"]


def test_output_endpoint_cancel():
    delegate = DummyDelegate()
    device = usb.USBDevice(delegate)
    responses = []
    device.handle_message(11, responses.append, usb.ENDPOINT_OUTPUT, b"\x00" * 8, b"")
    assert device.remove_waiting_request(11)
    assert not device.remove_waiting_request(11)
    delegate.response_handler(b"late")
    assert responses == []  # cancelled request must not fire
