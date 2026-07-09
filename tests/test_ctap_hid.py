"""Port of ctap_hid/ctap_hid_test.go and transaction_test.go, plus keepalive
coverage for the CBOR path."""

import os
import struct
import time

from virtual_fido import ctap_hid


class DummyService:
    """CTAP/U2F stand-in; returns a canned response after an optional delay."""

    def __init__(self, response=None, delay=0.0):
        self.response = response
        self.delay = delay
        self.received = []

    def handle_message(self, data):
        self.received.append(data)
        if self.delay:
            time.sleep(self.delay)
        return self.response


def make_header(channel_id, command, payload_length):
    return struct.pack("<IB", channel_id, command) + struct.pack(">H", payload_length)


def make_server(ctap=None, u2f=None):
    server = ctap_hid.CTAPHIDServer(ctap or DummyService(), u2f or DummyService())
    packets = []
    server.set_response_handler(packets.append)
    return server, packets


def open_channel(server, packets):
    """Run INIT on the broadcast channel; returns the new channel ID."""
    nonce = os.urandom(8)
    server.handle_message(
        make_header(ctap_hid.BROADCAST_CHANNEL, ctap_hid.COMMAND_INIT, 8) + nonce
    )
    response = packets.pop()
    assert response[:4] == struct.pack("<I", ctap_hid.BROADCAST_CHANNEL)
    assert response[4] == ctap_hid.COMMAND_INIT
    assert response[7:15] == nonce
    return struct.unpack("<I", response[15:19])[0]


def test_open_channel_golden():
    """Byte-exact port of TestOpenChannel."""
    server, packets = make_server()
    nonce = os.urandom(8)
    message = make_header(0xFFFFFFFF, (1 << 7) | 0x06, 8) + nonce
    server.handle_message(message)
    correct = (
        struct.pack("<I", 0xFFFFFFFF)
        + bytes([(1 << 7) | 0x06])
        + struct.pack(">H", 17)
        + nonce
        + struct.pack("<I", 1)
        + bytes([2, 0, 0, 1, 0b00000100])
    ).ljust(64, b"\x00")
    assert packets == [correct]


def test_single_message_transaction():
    payload = bytes([1, 2, 3, 4])
    message = make_header(1, ctap_hid.COMMAND_CBOR, len(payload)) + payload
    transaction = ctap_hid.Transaction(message)
    assert transaction.done
    assert transaction.result.channel_id == 1
    assert transaction.result.command == ctap_hid.COMMAND_CBOR
    assert transaction.result.payload_length == len(payload)
    assert transaction.payload == payload


def test_multiple_message_transaction():
    channel_id = 1
    payload = bytes([1, 2, 3, 4, 5, 6, 7, 8])
    message = make_header(channel_id, ctap_hid.COMMAND_CBOR, len(payload)) + payload[:4]
    transaction = ctap_hid.Transaction(message)
    assert not transaction.done
    transaction.add_message(struct.pack("<I", channel_id) + b"\x00" + payload[4:])
    assert transaction.done
    assert transaction.result.channel_id == channel_id
    assert transaction.result.command == ctap_hid.COMMAND_CBOR
    assert transaction.result.payload_length == len(payload)
    assert transaction.payload == payload


def test_transaction_invalid_command():
    # High bit unset -> not a command
    message = make_header(1, 0x06, 0)
    transaction = ctap_hid.Transaction(message)
    assert transaction.done
    assert transaction.error_code == ctap_hid.ERR_INVALID_COMMAND


def test_transaction_cancel():
    message = make_header(1, ctap_hid.COMMAND_CANCEL, 0)
    transaction = ctap_hid.Transaction(message)
    assert transaction.done
    assert transaction.cancelled
    assert transaction.error_code == 0


def test_transaction_wrong_sequence():
    payload = bytes(range(8))
    message = make_header(1, ctap_hid.COMMAND_CBOR, len(payload)) + payload[:4]
    transaction = ctap_hid.Transaction(message)
    transaction.add_message(struct.pack("<I", 1) + b"\x01" + payload[4:])  # expect 0
    assert transaction.done
    assert transaction.error_code == ctap_hid.ERR_INVALID_SEQUENCE


def test_transaction_wrong_channel_continuation():
    payload = bytes(range(8))
    message = make_header(1, ctap_hid.COMMAND_CBOR, len(payload)) + payload[:4]
    transaction = ctap_hid.Transaction(message)
    transaction.add_message(struct.pack("<I", 2) + b"\x00" + payload[4:])
    assert transaction.done
    assert transaction.error_code == ctap_hid.ERR_INVALID_CHANNEL


def test_unknown_channel_returns_error():
    server, packets = make_server()
    server.handle_message(make_header(42, ctap_hid.COMMAND_PING, 0) + b"")
    assert len(packets) == 1
    assert packets[0][4] == ctap_hid.COMMAND_ERROR
    assert packets[0][7] == ctap_hid.ERR_INVALID_CHANNEL


def test_ping_roundtrip_on_channel():
    server, packets = make_server()
    channel_id = open_channel(server, packets)
    payload = b"ping-pong"
    server.handle_message(
        make_header(channel_id, ctap_hid.COMMAND_PING, len(payload)) + payload
    )
    assert len(packets) == 1
    response = packets[0]
    assert response[:4] == struct.pack("<I", channel_id)
    assert response[4] == ctap_hid.COMMAND_PING
    assert struct.unpack(">H", response[5:7])[0] == len(payload)
    assert response[7 : 7 + len(payload)] == payload


def test_msg_routes_to_u2f():
    u2f = DummyService(response=b"u2f says hi")
    server, packets = make_server(u2f=u2f)
    channel_id = open_channel(server, packets)
    server.handle_message(make_header(channel_id, ctap_hid.COMMAND_MSG, 3) + b"abc")
    assert u2f.received == [b"abc"]
    assert packets[0][4] == ctap_hid.COMMAND_MSG
    assert packets[0][7:18] == b"u2f says hi"


def test_cbor_routes_to_ctap_with_keepalives():
    ctap = DummyService(response=b"\x00", delay=0.18)
    server, packets = make_server(ctap=ctap)
    channel_id = open_channel(server, packets)
    server.handle_message(make_header(channel_id, ctap_hid.COMMAND_CBOR, 2) + b"\x04\x00")
    assert ctap.received == [b"\x04\x00"]
    commands = [packet[4] for packet in packets]
    # Slow CTAP handler (user approval) must produce keepalives before the
    # final CBOR response.
    assert commands[-1] == ctap_hid.COMMAND_CBOR
    assert commands.count(ctap_hid.COMMAND_KEEPALIVE) >= 2
    keepalive = next(p for p in packets if p[4] == ctap_hid.COMMAND_KEEPALIVE)
    assert keepalive[7] == ctap_hid.STATUS_UPNEEDED


def test_multi_packet_response_split():
    # 100-byte response: 57 bytes fit in the first packet, rest continues
    ctap = DummyService(response=bytes(range(100)))
    server, packets = make_server(ctap=ctap)
    channel_id = open_channel(server, packets)
    server.handle_message(make_header(channel_id, ctap_hid.COMMAND_CBOR, 1) + b"\x04")
    data_packets = [p for p in packets if p[4] != ctap_hid.COMMAND_KEEPALIVE]
    assert len(data_packets) == 2
    first, second = data_packets
    assert first[4] == ctap_hid.COMMAND_CBOR
    assert struct.unpack(">H", first[5:7])[0] == 100
    assert first[7:64] == bytes(range(57))
    assert second[:4] == struct.pack("<I", channel_id)
    assert second[4] == 0  # sequence number
    assert second[5 : 5 + 43] == bytes(range(57, 100))
    assert len(first) == len(second) == 64


def test_multi_packet_request_reassembly():
    ctap = DummyService(response=b"\x00")
    server, packets = make_server(ctap=ctap)
    channel_id = open_channel(server, packets)
    payload = bytes(range(80))
    server.handle_message(
        make_header(channel_id, ctap_hid.COMMAND_CBOR, len(payload)) + payload[:57]
    )
    assert ctap.received == []  # transaction not complete yet
    server.handle_message(struct.pack("<I", channel_id) + b"\x00" + payload[57:])
    assert ctap.received == [payload]
