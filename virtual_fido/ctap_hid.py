"""CTAPHID transport layer.

Port of the Go ctap_hid/ package: reassembles fixed-size HID packets into
messages (transactions), tracks concurrent logical connections (channels),
and routes complete messages to the CTAP2 or U2F server.

Wire format quirk inherited from the CTAPHID spec: the channel ID is
little-endian while the payload length is big-endian.
"""

from __future__ import annotations

import logging
import struct
import threading
from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from ._util import ProtocolError, start_recurring

logger = logging.getLogger("virtual_fido.ctap_hid")

MAX_PACKET_SIZE = 64
BROADCAST_CHANNEL = 0xFFFFFFFF
STATUS_UPNEEDED = 2

# ctapHIDCommand — each command has its high bit set
COMMAND_PING = 0x81
COMMAND_MSG = 0x83
COMMAND_LOCK = 0x84
COMMAND_INIT = 0x86
COMMAND_WINK = 0x88
COMMAND_CBOR = 0x90
COMMAND_CANCEL = 0x91
COMMAND_KEEPALIVE = 0xBB
COMMAND_ERROR = 0xBF

# ctapHIDErrorCode
ERR_INVALID_COMMAND = 0x01
ERR_INVALID_PARAMETER = 0x02
ERR_INVALID_LENGTH = 0x03
ERR_INVALID_SEQUENCE = 0x04
ERR_MESSAGE_TIMEOUT = 0x05
ERR_CHANNEL_BUSY = 0x06
ERR_LOCK_REQUIRED = 0x0A
ERR_INVALID_CHANNEL = 0x0B
ERR_OTHER = 0x7F

# ctapHIDCapabilityFlag
CAPABILITY_WINK = 0x1
CAPABILITY_CBOR = 0x4
CAPABILITY_NO_MSG = 0x8

_KEEPALIVE_INTERVAL = 0.05  # seconds; keep short so Windows doesn't drop us

_INIT_RESPONSE = struct.Struct("<8sIBBBBB")  # nonce, new channel, proto, ver x3, caps


class CTAPHIDService(Protocol):
    """A message consumer behind the transport: the CTAP2 or U2F server."""

    def handle_message(self, data: bytes) -> Optional[bytes]: ...


@dataclass
class MessageHeader:
    channel_id: int
    command: int
    payload_length: int


def create_response_packets(channel_id: int, command: int, payload: bytes) -> list[bytes]:
    """Split a payload into an initialization packet plus continuation packets."""
    packets = []
    sequence = -1
    remaining = payload
    while remaining:
        if sequence < 0:
            packet = struct.pack("<IB", channel_id, command) + struct.pack(
                ">H", len(remaining)
            )
        else:
            packet = struct.pack("<IB", channel_id, sequence)
        sequence += 1
        chunk = remaining[: MAX_PACKET_SIZE - len(packet)]
        remaining = remaining[len(chunk) :]
        packet = (packet + chunk).ljust(MAX_PACKET_SIZE, b"\x00")
        packets.append(packet)
    return packets


class Transaction:
    """Reassembles one or more HID packets into a single message
    (upstream ctap_hid/transaction.go)."""

    def __init__(self, message: bytes) -> None:
        self.done = False
        self.cancelled = False
        self.error_code = 0
        self.result: Optional[MessageHeader] = None
        self.payload = b""
        self._expected_sequence = 0

        channel_id = int.from_bytes(message[0:4], "little")
        command = message[4]
        if command & 0x80 == 0:
            # Non-command byte (likely a stray sequence number)
            logger.warning("Invalid command: 0x%02x", command)
            self._error(ERR_INVALID_COMMAND)
            return
        if command == COMMAND_CANCEL:
            self._cancel()  # No response to a cancel message
            return
        payload_length = int.from_bytes(message[5:7], "big")
        self.result = MessageHeader(channel_id, command, payload_length)
        self.payload = message[7:]
        if len(self.payload) >= payload_length:
            self.payload = self.payload[:payload_length]
            self.done = True
        else:
            logger.debug(
                "Transaction: read %d bytes, need %d more",
                len(self.payload),
                payload_length - len(self.payload),
            )

    def add_message(self, message: bytes) -> None:
        if self.done:
            logger.error("Message added after transaction completed")
            self._error(ERR_OTHER)
            return
        assert self.result is not None
        channel_id = int.from_bytes(message[0:4], "little")
        if channel_id != self.result.channel_id:
            self._error(ERR_INVALID_CHANNEL)
            return
        sequence_number = message[4]
        if sequence_number == COMMAND_CANCEL:
            self._cancel()
            return
        if sequence_number & 0x80 != 0:
            self._error(ERR_INVALID_SEQUENCE)
            return
        if sequence_number != self._expected_sequence:
            self._error(ERR_INVALID_SEQUENCE)
            return
        self.payload += message[5:]
        if len(self.payload) >= self.result.payload_length:
            self.payload = self.payload[: self.result.payload_length]
            self.done = True
        else:
            logger.debug(
                "Transaction: read %d bytes, need %d more",
                len(self.payload),
                self.result.payload_length - len(self.payload),
            )
            self._expected_sequence += 1

    def _error(self, code: int) -> None:
        logger.warning("Transaction error: 0x%02x", code)
        self.done = True
        self.error_code = code
        self.result = None
        self.payload = b""

    def _cancel(self) -> None:
        logger.debug("Transaction cancelled")
        self.done = True
        self.cancelled = True
        self.result = None
        self.payload = b""


class Channel:
    """One logical CTAPHID connection (upstream ctap_hid/channel.go)."""

    def __init__(self, server: "CTAPHIDServer", channel_id: int) -> None:
        self._server = server
        self.channel_id = channel_id
        self._message_lock = threading.Lock()
        self._transaction: Optional[Transaction] = None

    def handle_message(self, message: bytes) -> None:
        with self._message_lock:
            if self._transaction is None:
                self._transaction = Transaction(message)
            else:
                self._transaction.add_message(message)
            if self._transaction.done:
                transaction = self._transaction
                self._transaction = None
                if transaction.error_code:
                    self._server.send_error(self.channel_id, transaction.error_code)
                elif not transaction.cancelled:
                    assert transaction.result is not None
                    self._handle_finalized_message(
                        transaction.result, transaction.payload
                    )

    def _handle_finalized_message(self, header: MessageHeader, payload: bytes) -> None:
        logger.debug("Finalized message: %s payload=%s", header, payload.hex())
        if self.channel_id == BROADCAST_CHANNEL:
            self._handle_broadcast_message(header, payload)
        else:
            self._handle_data_message(header, payload)

    def _handle_broadcast_message(self, header: MessageHeader, payload: bytes) -> None:
        if header.command == COMMAND_INIT:
            new_channel = self._server.new_channel()
            response = _INIT_RESPONSE.pack(
                payload[:8],  # nonce
                new_channel.channel_id,
                2,  # protocol version
                0,  # device version major
                0,  # device version minor
                1,  # device version build
                CAPABILITY_CBOR,
            )
            logger.debug("INIT: new channel %d", new_channel.channel_id)
            self._server.send_response(BROADCAST_CHANNEL, COMMAND_INIT, response)
        elif header.command == COMMAND_PING:
            self._server.send_response(BROADCAST_CHANNEL, COMMAND_PING, payload)
        else:
            raise ProtocolError(f"Invalid CTAPHID broadcast command: {header}")

    def _handle_data_message(self, header: MessageHeader, payload: bytes) -> None:
        if header.command == COMMAND_MSG:
            response = self._server.u2f_server.handle_message(payload)
            logger.debug("MSG response: %s", response.hex() if response else response)
            self._server.send_response(header.channel_id, COMMAND_MSG, response or b"")
        elif header.command == COMMAND_CBOR:
            # CTAP2 commands can block on user approval; emit keepalives so
            # the host doesn't time out the transaction (this cadence fixed
            # errors on Windows in the reference implementation).
            stop_keepalive = start_recurring(
                _KEEPALIVE_INTERVAL,
                lambda: self._server.send_response(
                    self.channel_id, COMMAND_KEEPALIVE, bytes([STATUS_UPNEEDED])
                ),
            )
            try:
                response = self._server.ctap_server.handle_message(payload)
            finally:
                stop_keepalive()
            logger.debug("CBOR response: %s", response.hex() if response else response)
            self._server.send_response(header.channel_id, COMMAND_CBOR, response or b"")
        elif header.command == COMMAND_PING:
            self._server.send_response(header.channel_id, COMMAND_PING, payload)
        else:
            raise ProtocolError(f"Invalid CTAPHID channel command: {header}")


class CTAPHIDServer:
    """Routes HID packets to channels and responses back to USB
    (upstream ctap_hid/ctap_hid.go)."""

    def __init__(self, ctap_server: CTAPHIDService, u2f_server: CTAPHIDService) -> None:
        self.ctap_server = ctap_server
        self.u2f_server = u2f_server
        self._max_channel_id = 0
        self._channels_lock = threading.Lock()
        self._channels: dict[int, Channel] = {
            BROADCAST_CHANNEL: Channel(self, BROADCAST_CHANNEL)
        }
        self._response_lock = threading.Lock()
        self._response_handler: Optional[Callable[[bytes], None]] = None

    def set_response_handler(self, handler: Callable[[bytes], None]) -> None:
        self._response_handler = handler

    def handle_message(self, message: bytes) -> None:
        if len(message) < 5:
            logger.warning("Runt HID packet: %s", message.hex())
            return
        channel_id = int.from_bytes(message[0:4], "little")
        with self._channels_lock:
            channel = self._channels.get(channel_id)
        if channel is None:
            self.send_error(channel_id, ERR_INVALID_CHANNEL)
            return
        channel.handle_message(message)

    def new_channel(self) -> Channel:
        with self._channels_lock:
            self._max_channel_id += 1
            channel = Channel(self, self._max_channel_id)
            self._channels[channel.channel_id] = channel
        return channel

    def send_response(self, channel_id: int, command: int, payload: bytes) -> None:
        self._send_packets(create_response_packets(channel_id, command, payload))

    def send_error(self, channel_id: int, error_code: int) -> None:
        logger.warning("CTAPHID error 0x%02x on channel %d", error_code, channel_id)
        self._send_packets(
            create_response_packets(channel_id, COMMAND_ERROR, bytes([error_code]))
        )

    def _send_packets(self, packets: list[bytes]) -> None:
        # Packets of one transaction must be sequential and contiguous.
        with self._response_lock:
            if self._response_handler is not None:
                for packet in packets:
                    self._response_handler(packet)
