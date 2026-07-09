"""Wire-format and server-loop tests for virtual_fido.usbip."""

import socket
import struct
import threading
import time

from virtual_fido import usb, usbip


class DummyDelegate:
    def __init__(self):
        self.messages = []
        self.response_handler = None

    def handle_message(self, transfer_buffer):
        self.messages.append(transfer_buffer)

    def set_response_handler(self, handler):
        self.response_handler = handler


def test_device_summary_pack_sizes():
    device = usb.USBDevice(DummyDelegate())
    summary = device.device_summary()
    assert len(summary.header.pack()) == 312
    assert len(summary.pack()) == 315


def test_control_header_roundtrip():
    header = usbip._pack_control_header(usbip.OP_REP_IMPORT, status=0)
    assert len(header) == 8
    version, command, status = struct.unpack(">HHI", header)
    assert version == usbip.USBIP_VERSION
    assert command == usbip.OP_REP_IMPORT
    assert status == 0


def _start_server(port):
    device = usb.USBDevice(DummyDelegate())
    server = usbip.USBIPServer([device], bind_address="127.0.0.1", port=port)
    thread = threading.Thread(target=server.start, daemon=True)
    thread.start()
    time.sleep(0.2)
    return server


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        assert chunk, "server closed connection early"
        data += chunk
    return data


def test_devlist_and_import_over_tcp():
    port = 13240
    _start_server(port)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        # OP_REQ_DEVLIST
        sock.sendall(struct.pack(">HHI", usbip.USBIP_VERSION, usbip.OP_REQ_DEVLIST, 0))
        version, command, status = struct.unpack(">HHI", _recv_exact(sock, 8))
        assert (version, command, status) == (usbip.USBIP_VERSION, usbip.OP_REP_DEVLIST, 0)
        (num_devices,) = struct.unpack(">I", _recv_exact(sock, 4))
        assert num_devices == 1
        summary = _recv_exact(sock, 315)
        assert summary[:256].rstrip(b"\x00") == b"/device/0"
        assert summary[256:288].rstrip(b"\x00") == b"2-2"

    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        # OP_REQ_IMPORT for bus 2-2
        sock.sendall(struct.pack(">HHI", usbip.USBIP_VERSION, usbip.OP_REQ_IMPORT, 0))
        sock.sendall(b"2-2".ljust(32, b"\x00"))
        version, command, status = struct.unpack(">HHI", _recv_exact(sock, 8))
        assert (version, command, status) == (usbip.USBIP_VERSION, usbip.OP_REP_IMPORT, 0)
        _recv_exact(sock, 312)  # device summary header

        # Now in command phase: submit a control GET_DESCRIPTOR (device)
        setup = usb.USBSetupPacket.make(
            direction=usb.DEVICE_TO_HOST,
            b_request=usb.REQUEST_GET_DESCRIPTOR,
            w_value=usb.DESCRIPTOR_DEVICE << 8,
            w_length=18,
        )
        sock.sendall(
            struct.pack(">IIIII", usbip.CMD_SUBMIT, 1234, 0, usbip.DIR_IN, 0)
            + struct.pack(">IIIII8s", 0, 18, 0, 0, 0, setup.pack())
        )
        command, seq, devid, direction, ep = struct.unpack(">IIIII", _recv_exact(sock, 20))
        assert command == usbip.RET_SUBMIT
        assert seq == 1234
        body = _recv_exact(sock, 28)
        status, actual_length = struct.unpack(">II", body[:8])
        assert status == 0
        assert actual_length == 18
        descriptor = _recv_exact(sock, actual_length)
        assert descriptor[0] == 18  # bLength
        assert descriptor[1] == usb.DESCRIPTOR_DEVICE


def test_import_unknown_device():
    port = 13241
    _start_server(port)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(struct.pack(">HHI", usbip.USBIP_VERSION, usbip.OP_REQ_IMPORT, 0))
        sock.sendall(b"9-9".ljust(32, b"\x00"))
        version, command, status = struct.unpack(">HHI", _recv_exact(sock, 8))
        assert command == usbip.OP_REP_IMPORT
        assert status == 1
