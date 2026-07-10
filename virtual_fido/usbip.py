"""USB/IP protocol server.

Port of the Go usbip/ package. Speaks the USB/IP wire protocol (as
implemented by the Linux vhci-hcd driver) over TCP and forwards URBs to an
attached virtual device.

Security note: the server does no encryption or authentication. It binds to
127.0.0.1 by default; for the two-machine setup, bind it to the WireGuard
(or other tunnel) interface address — never to a plain LAN/WAN interface.
"""

from __future__ import annotations

import errno
import logging
import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol

from ._util import ProtocolError, cstring_to_str

logger = logging.getLogger("virtual_fido.usbip")

USBIP_VERSION = 0x0111

# usbipDirection
DIR_OUT = 0
DIR_IN = 1

# Control-phase commands (usbipControlCommand)
OP_REQ_DEVLIST = 0x8005
OP_REP_DEVLIST = 0x0005
OP_REQ_IMPORT = 0x8003
OP_REP_IMPORT = 0x0003

# Command-phase commands (usbipCommand)
CMD_SUBMIT = 0x1
CMD_UNLINK = 0x2
RET_SUBMIT = 0x3
RET_UNLINK = 0x4

# All USB/IP wire structs are big-endian and packed (Go: util.ToBE/ReadBE).
_CONTROL_HEADER = struct.Struct(">HHI")  # version, command, status
_MESSAGE_HEADER = struct.Struct(">IIIII")  # command, seqnum, devid, direction, endpoint
_SUBMIT_BODY = struct.Struct(">IIIII8s")  # flags, buflen, start_frame, num_packets, interval, setup
_RETURN_SUBMIT_BODY = struct.Struct(">IIIIIQ")  # status, actual_length, start_frame, num_packets, error_count, padding
_UNLINK_BODY = struct.Struct(">I24s")  # unlink_seqnum, padding
_RETURN_UNLINK_BODY = struct.Struct(">i24s")  # status (signed), padding
_SUMMARY_HEADER = struct.Struct(">256s32sIIIHHHBBBBBB")
_SUMMARY_INTERFACE = struct.Struct(">BBB")


@dataclass
class USBIPDeviceSummaryHeader:
    path: bytes  # padded to 256
    bus_id: bytes  # padded to 32
    busnum: int
    devnum: int
    speed: int
    id_vendor: int = 0
    id_product: int = 0
    bcd_device: int = 0
    b_device_class: int = 0
    b_device_subclass: int = 0
    b_device_protocol: int = 0
    b_configuration_value: int = 0
    b_num_configurations: int = 1
    b_num_interfaces: int = 1

    def pack(self) -> bytes:
        return _SUMMARY_HEADER.pack(
            self.path,
            self.bus_id,
            self.busnum,
            self.devnum,
            self.speed,
            self.id_vendor,
            self.id_product,
            self.bcd_device,
            self.b_device_class,
            self.b_device_subclass,
            self.b_device_protocol,
            self.b_configuration_value,
            self.b_num_configurations,
            self.b_num_interfaces,
        )


@dataclass
class USBIPDeviceInterface:
    b_interface_class: int
    b_interface_subclass: int
    padding: int = 0

    def pack(self) -> bytes:
        return _SUMMARY_INTERFACE.pack(
            self.b_interface_class, self.b_interface_subclass, self.padding
        )


@dataclass
class USBIPDeviceSummary:
    # Only one interface is supported, mirroring the Go original.
    header: USBIPDeviceSummaryHeader
    device_interface: USBIPDeviceInterface = field(
        default_factory=lambda: USBIPDeviceInterface(3, 0)
    )

    def pack(self) -> bytes:
        return self.header.pack() + self.device_interface.pack()


class USBIPDevice(Protocol):
    """What the usbip layer needs from a virtual device (usbip.USBIPDevice)."""

    def handle_message(
        self,
        request_id: int,
        on_finish: Callable[[Optional[bytes]], None],
        endpoint: int,
        setup_bytes: bytes,
        transfer_buffer: bytes,
    ) -> None: ...

    def remove_waiting_request(self, request_id: int) -> bool: ...

    def bus_id(self) -> str: ...

    def device_summary(self) -> USBIPDeviceSummary: ...


def _pack_control_header(command: int, status: int = 0) -> bytes:
    return _CONTROL_HEADER.pack(USBIP_VERSION, command, status)


def _pack_reply_header(command: int, sequence_number: int) -> bytes:
    # Reply headers zero out devid/direction/endpoint (usbipMessageHeader.replyHeader)
    return _MESSAGE_HEADER.pack(command, sequence_number, 0, 0, 0)


class _Disconnected(Exception):
    """The peer closed the TCP connection."""


class USBIPServer:
    """TCP server implementing the USB/IP device-side protocol."""

    def __init__(
        self,
        devices: list[USBIPDevice],
        bind_address: str = "127.0.0.1",
        port: int = 3240,
    ) -> None:
        self._devices = devices
        self._bind_address = bind_address
        self._port = port

    def start(self) -> None:
        """Accept connections until interrupted (blocking).

        Returns cleanly on KeyboardInterrupt (Ctrl+C); connection threads are
        daemons and are torn down with the process.
        """
        logger.info("Starting USB/IP server on %s:%d", self._bind_address, self._port)
        with socket.create_server(
            (self._bind_address, self._port), reuse_port=False
        ) as listener:
            try:
                while True:
                    connection, address = listener.accept()
                    logger.info("Connection from %s", address)
                    thread = threading.Thread(
                        target=_Connection(self, connection).handle, daemon=True
                    )
                    thread.start()
            except KeyboardInterrupt:
                logger.info("Shutting down USB/IP server")

    def _get_device(self, bus_id: str) -> Optional[USBIPDevice]:
        for device in self._devices:
            if device.bus_id() == bus_id:
                return device
        return None


class _Connection:
    """One attached USB/IP client connection."""

    def __init__(self, server: USBIPServer, sock: socket.socket) -> None:
        self._server = server
        self._sock = sock
        self._reader = sock.makefile("rb")
        self._write_lock = threading.Lock()

    def _read(self, length: int) -> bytes:
        data = self._reader.read(length)
        if data is None or len(data) < length:
            raise _Disconnected()
        return data

    def _write(self, data: bytes) -> None:
        # Responses may arrive from timer/delegate threads concurrently;
        # serialize whole messages (Go: conn.writeResponse mutex).
        with self._write_lock:
            self._sock.sendall(data)

    def handle(self) -> None:
        try:
            while True:
                version, command, status = _CONTROL_HEADER.unpack(
                    self._read(_CONTROL_HEADER.size)
                )
                logger.debug(
                    "[CONTROL] version=0x%04x command=0x%04x status=%d",
                    version,
                    command,
                    status,
                )
                if command == OP_REQ_DEVLIST:
                    self._write(self._op_rep_devlist())
                elif command == OP_REQ_IMPORT:
                    bus_id = cstring_to_str(self._read(32))
                    device = self._server._get_device(bus_id)
                    if device is None:
                        logger.warning("Import request for unknown bus ID %r", bus_id)
                        self._write(_pack_control_header(OP_REP_IMPORT, status=1))
                        continue
                    self._write(
                        _pack_control_header(OP_REP_IMPORT)
                        + device.device_summary().header.pack()
                    )
                    self._handle_commands(device)
                    return
                else:
                    logger.warning("Unknown control command: 0x%04x", command)
        except _Disconnected:
            logger.info("Client disconnected")
        except OSError as err:
            logger.warning("Connection error: %s", err)
        finally:
            self._close()

    def _close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def _op_rep_devlist(self) -> bytes:
        devices = self._server._devices
        reply = _pack_control_header(OP_REP_DEVLIST) + struct.pack(">I", len(devices))
        for device in devices:
            reply += device.device_summary().pack()
        return reply

    def _handle_commands(self, device: USBIPDevice) -> None:
        while True:
            header = self._read(_MESSAGE_HEADER.size)
            command, seqnum, devid, direction, endpoint = _MESSAGE_HEADER.unpack(header)
            logger.debug(
                "[MESSAGE] command=%d seq=%d devid=%d direction=%d endpoint=%d",
                command,
                seqnum,
                devid,
                direction,
                endpoint,
            )
            try:
                if command == CMD_SUBMIT:
                    self._handle_command_submit(device, seqnum, direction, endpoint)
                elif command == CMD_UNLINK:
                    self._handle_command_unlink(device, seqnum)
                else:
                    logger.warning("Unsupported command: %d", command)
            except ProtocolError as err:
                # Protocol errors are per-URB; keep the connection alive
                # (Go: util.Try around each command).
                logger.error("Error handling command: %s", err)

    def _handle_command_submit(
        self, device: USBIPDevice, seqnum: int, direction: int, endpoint: int
    ) -> None:
        (
            transfer_flags,
            buffer_length,
            start_frame,
            number_of_packets,
            interval,
            setup_bytes,
        ) = _SUBMIT_BODY.unpack(self._read(_SUBMIT_BODY.size))
        del transfer_flags, start_frame, number_of_packets, interval
        if direction == DIR_OUT and buffer_length > 0:
            transfer_buffer = self._read(buffer_length)
        else:
            transfer_buffer = bytes(buffer_length)

        # The response may not be immediate (interrupt-IN transfers wait for
        # data), so completion happens through this callback, possibly from
        # another thread.
        def on_finish(response: Optional[bytes]) -> None:
            buffer = bytearray(transfer_buffer)
            if response:
                n = min(len(response), len(buffer))
                buffer[:n] = response[:n]
            # Bug-compat with the Go original: actual_length is always the
            # full buffer length and IN data is zero-padded to it; the
            # vhci-hcd driver accepts this.
            reply = _pack_reply_header(RET_SUBMIT, seqnum) + _RETURN_SUBMIT_BODY.pack(
                0, len(buffer), 0, 0, 0, 0
            )
            if direction == DIR_IN:
                reply += bytes(buffer)
            self._write(reply)

        device.handle_message(seqnum, on_finish, endpoint, setup_bytes, transfer_buffer)

    def _handle_command_unlink(self, device: USBIPDevice, seqnum: int) -> None:
        unlink_seqnum, _padding = _UNLINK_BODY.unpack(self._read(_UNLINK_BODY.size))
        logger.debug("[UNLINK] seq=%d", unlink_seqnum)
        if device.remove_waiting_request(unlink_seqnum):
            status = -errno.ECONNRESET
        else:
            status = -errno.ENOENT
        reply = _pack_reply_header(RET_UNLINK, seqnum) + _RETURN_UNLINK_BODY.pack(
            status, b""
        )
        self._write(reply)
