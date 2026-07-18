"""CCID smartcard interface + ISO 7816-4 APDU dispatch.

A real YubiKey's CCID function is a USB smartcard reader (class 0x0B) with an
always-present virtual card. The host (pcscd/libccid) exchanges CCID messages
over two bulk endpoints; the payload of an XfrBlock is an ISO 7816-4 APDU.

This module implements:
  - the CCID message layer (IccPowerOn -> ATR, GetSlotStatus, XfrBlock, ...)
  - APDU parsing (short and extended)
  - a SmartCard that routes SELECT-by-AID to registered applets and applies
    GET RESPONSE (61xx / 00 C0) chaining for responses longer than 256 bytes.

Applets (OATH, PIV) subclass `Applet` and implement `select` / `process_apdu`.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass, replace
from typing import Callable, Optional

from ._util import RequestBuffer
from .usb import ATTR_BULK, ATTR_INTERRUPT, DIR_IN, EndpointSpec, USBInterface

logger = logging.getLogger("virtual_fido.ccid")

# PC_to_RDR (bulk OUT) message types
PC_TO_RDR_SET_PARAMETERS = 0x61
PC_TO_RDR_ICC_POWER_ON = 0x62
PC_TO_RDR_ICC_POWER_OFF = 0x63
PC_TO_RDR_GET_SLOT_STATUS = 0x65
PC_TO_RDR_ESCAPE = 0x6B
PC_TO_RDR_GET_PARAMETERS = 0x6C
PC_TO_RDR_RESET_PARAMETERS = 0x6D
PC_TO_RDR_XFR_BLOCK = 0x6F
PC_TO_RDR_ABORT = 0x71

# RDR_to_PC (bulk IN) message types
RDR_TO_PC_DATA_BLOCK = 0x80
RDR_TO_PC_SLOT_STATUS = 0x81
RDR_TO_PC_PARAMETERS = 0x82

# Interrupt-IN notification (RDR_to_PC_NotifySlotChange). Bitmap byte per the
# CCID spec: bit0 = slot 0 present, bit1 = slot 0 changed since last notify.
RDR_TO_PC_NOTIFY_SLOT_CHANGE = 0x50
_SLOT_PRESENT_UNCHANGED = 0x01

# ISO 7816 status words
SW_SUCCESS = 0x9000
SW_BYTES_REMAINING = 0x6100  # | count
SW_WRONG_LENGTH = 0x6700
SW_FILE_NOT_FOUND = 0x6A82
SW_INS_NOT_SUPPORTED = 0x6D00
SW_CLA_NOT_SUPPORTED = 0x6E00
SW_UNKNOWN = 0x6F00

INS_SELECT = 0xA4
INS_GET_RESPONSE = 0xC0
# ykoath continues a chained response with SEND REMAINING (0xA5) instead of the
# ISO GET RESPONSE (0xC0); treat both as "return the next chunk".
INS_SEND_REMAINING = 0xA5

# CCID functional descriptor (bDescriptorType 0x21), 54 bytes. dwFeatures
# advertises short+extended APDU-level exchange (0x00040000) so the host hands
# us whole APDUs instead of TPDUs; dwMaxCCIDMessageLength is generous enough
# for certificate imports.
_CCID_FUNCTIONAL = struct.Struct("<BBHBBIIIBIIBIIIIIBBHBB")
CCID_FUNCTIONAL_DESCRIPTOR = _CCID_FUNCTIONAL.pack(
    54,          # bLength
    0x21,        # bDescriptorType (CCID)
    0x0110,      # bcdCCID
    0,           # bMaxSlotIndex (1 slot)
    0x07,        # bVoltageSupport (5V/3V/1.8V)
    0x00000003,  # dwProtocols (T=0 | T=1)
    4000,        # dwDefaultClock (kHz)
    4000,        # dwMaximumClock
    0,           # bNumClockSupported
    9600,        # dwDataRate
    9600,        # dwMaxDataRate
    0,           # bNumDataRatesSupported
    0xFE,        # dwMaxIFSD
    0,           # dwSynchProtocols
    0,           # dwMechanical
    0x00040840,  # dwFeatures (auto negotiation + short/extended APDU level)
    0x1000,      # dwMaxCCIDMessageLength
    0xFF,        # bClassGetResponse (echo)
    0xFF,        # bClassEnvelope (echo)
    0,           # wLcdLayout
    0,           # bPINSupport
    1,           # bMaxCCIDBusySlots
)

# YubiKey 5 ATR (T=1). Historical bytes spell "YubiKey"; the final byte (0x40)
# is the T=1 checksum (TCK = XOR of all bytes after TS) and must stay valid —
# libccid rejects the card and retries IccPowerOn forever on a bad TCK.
ATR = bytes.fromhex("3bfd1300008131fe158073c021c057597562694b657940")

# T=1 parameter block returned for Get/Set/ResetParameters.
_T1_PARAMETERS = bytes([0x11, 0x10, 0x00, 0x4D, 0x00, 0xFE, 0x00])

_HEADER = struct.Struct("<BIBBBBB")  # msg_type, dwLength, slot, seq, +3 bytes


def sw_bytes(sw: int) -> bytes:
    return struct.pack(">H", sw)


def _rdr_to_pc(msg_type: int, slot: int, seq: int, data: bytes = b"", status: int = 0,
               error: int = 0, extra: int = 0) -> bytes:
    """Build an RDR_to_PC message. `extra` is the 3rd status byte
    (bChainParameter / bClockStatus / bProtocolNum depending on type)."""
    return _HEADER.pack(msg_type, len(data), slot, seq, status, error, extra) + data


@dataclass
class APDU:
    cla: int
    ins: int
    p1: int
    p2: int
    data: bytes
    le: int  # 0 means "not specified" for commands, "up to 256" for GET RESPONSE

    @classmethod
    def parse(cls, raw: bytes) -> "APDU":
        if len(raw) < 4:
            raise ValueError(f"APDU too short: {raw.hex()}")
        cla, ins, p1, p2 = raw[0], raw[1], raw[2], raw[3]
        body = raw[4:]
        if not body:
            return cls(cla, ins, p1, p2, b"", 0)
        if body[0] != 0 or len(body) == 1:
            # Short form: body[0] is Lc (with data) or Le (alone).
            if len(body) == 1:
                return cls(cla, ins, p1, p2, b"", body[0])
            lc = body[0]
            data = body[1 : 1 + lc]
            le = body[1 + lc] if len(body) > 1 + lc else 0
            return cls(cla, ins, p1, p2, data, le)
        # Extended form: leading 0 then 2-byte lengths.
        if len(body) == 3:
            le = struct.unpack(">H", body[1:3])[0]
            return cls(cla, ins, p1, p2, b"", le or 65536)
        lc = struct.unpack(">H", body[1:3])[0]
        data = body[3 : 3 + lc]
        rest = body[3 + lc :]
        le = struct.unpack(">H", rest[:2])[0] if len(rest) >= 2 else 0
        return cls(cla, ins, p1, p2, data, le)


class Applet:
    """Base class for a CCID applet. Subclasses set `aid` and implement the
    command handling."""

    aid: bytes = b""
    name: str = ""

    def matches(self, selected_aid: bytes) -> bool:
        # Partial AID selection: the host may select a prefix of the full AID.
        return bool(selected_aid) and self.aid[: len(selected_aid)] == selected_aid

    def select(self) -> tuple[bytes, int]:
        """Return (data, sw) for SELECT of this applet."""
        return b"", SW_SUCCESS

    def process_apdu(self, apdu: APDU) -> tuple[bytes, int]:
        """Handle a non-SELECT APDU addressed to this applet."""
        return b"", SW_INS_NOT_SUPPORTED


class SmartCard:
    """A virtual card: routes APDUs to the selected applet and handles the
    CCID message framing + GET RESPONSE response chaining."""

    def __init__(self, applets: list[Applet]) -> None:
        self.applets = applets
        self.selected: Optional[Applet] = None
        self._pending = b""  # response tail awaiting GET RESPONSE
        self._pending_sw = SW_SUCCESS
        self._chain = b""  # command data accumulated across CLA-0x10 chained APDUs
        self._chain_header = None  # (ins, p1, p2) of the chain in progress

    # ---- CCID message layer -------------------------------------------

    def handle_ccid(self, message: bytes) -> bytes:
        if len(message) < 10:
            raise ValueError(f"Runt CCID message: {message.hex()}")
        msg_type, dw_length, slot, seq, _b, _c, _d = _HEADER.unpack(message[:10])
        ab_data = message[10 : 10 + dw_length]

        if msg_type == PC_TO_RDR_ICC_POWER_ON:
            return _rdr_to_pc(RDR_TO_PC_DATA_BLOCK, slot, seq, ATR)
        if msg_type in (PC_TO_RDR_ICC_POWER_OFF, PC_TO_RDR_GET_SLOT_STATUS,
                        PC_TO_RDR_ABORT):
            return _rdr_to_pc(RDR_TO_PC_SLOT_STATUS, slot, seq)
        if msg_type in (PC_TO_RDR_GET_PARAMETERS, PC_TO_RDR_SET_PARAMETERS,
                        PC_TO_RDR_RESET_PARAMETERS):
            return _rdr_to_pc(RDR_TO_PC_PARAMETERS, slot, seq, _T1_PARAMETERS, extra=1)
        if msg_type == PC_TO_RDR_XFR_BLOCK:
            response = self.process_apdu_bytes(ab_data)
            return _rdr_to_pc(RDR_TO_PC_DATA_BLOCK, slot, seq, response)
        logger.warning("Unsupported CCID message type 0x%02x", msg_type)
        return _rdr_to_pc(RDR_TO_PC_SLOT_STATUS, slot, seq, status=0x40)

    # ---- APDU dispatch ------------------------------------------------

    def process_apdu_bytes(self, raw: bytes) -> bytes:
        try:
            apdu = APDU.parse(raw)
        except ValueError:
            return sw_bytes(SW_WRONG_LENGTH)

        # ISO 7816-4 command chaining: CLA bit 0x10 marks a non-final chunk of
        # a command too long for one APDU (OpenSC sends >255-byte commands this
        # way; ykman uses extended length instead). Accumulate until the final
        # chunk (bit clear), then dispatch the reassembled command. A header
        # change aborts an unfinished chain, as on a real card.
        header = (apdu.ins, apdu.p1, apdu.p2)
        if self._chain and header != self._chain_header:
            self._chain = b""
            self._chain_header = None
        if apdu.cla & 0x10:
            self._chain += apdu.data
            self._chain_header = header
            return sw_bytes(SW_SUCCESS)
        if self._chain:
            apdu = replace(apdu, data=self._chain + apdu.data)
            self._chain = b""
            self._chain_header = None

        if apdu.cla & ~0x10 == 0x00 and apdu.ins in (INS_GET_RESPONSE, INS_SEND_REMAINING):
            return self._get_response(apdu.le)

        if apdu.ins == INS_SELECT and apdu.p1 == 0x04:
            for applet in self.applets:
                if applet.matches(apdu.data):
                    self.selected = applet
                    self._pending = b""
                    return self._respond(*applet.select())
            self.selected = None
            return sw_bytes(SW_FILE_NOT_FOUND)

        if self.selected is None:
            return sw_bytes(SW_FILE_NOT_FOUND)
        return self._respond(*self.selected.process_apdu(apdu))

    def _respond(self, data: bytes, sw: int) -> bytes:
        """Attach the status word, chunking with 61xx if data exceeds 256."""
        if len(data) <= 256:
            return data + sw_bytes(sw)
        self._pending = data[256:]
        self._pending_sw = sw
        remaining = len(self._pending)
        return data[:256] + sw_bytes(SW_BYTES_REMAINING | (min(remaining, 256) & 0xFF))

    def _get_response(self, le: int) -> bytes:
        count = le or 256
        chunk = self._pending[:count]
        self._pending = self._pending[len(chunk) :]
        if self._pending:
            remaining = len(self._pending)
            return chunk + sw_bytes(SW_BYTES_REMAINING | (min(remaining, 256) & 0xFF))
        return chunk + sw_bytes(self._pending_sw)


class CCIDInterface(USBInterface):
    interface_class = 0x0B  # smartcard
    interface_subclass = 0
    interface_protocol = 0
    interface_string = None
    endpoint_specs = [
        EndpointSpec(is_in=False, attributes=ATTR_BULK, max_packet_size=64, interval=0),  # bulk OUT
        EndpointSpec(is_in=True, attributes=ATTR_BULK, max_packet_size=64, interval=0),   # bulk IN
        # Interrupt IN for slot-change notifications. Without it libccid has no
        # way to wait for card events and spins on GetSlotStatus polling; with
        # it, the host does a blocking read here instead.
        EndpointSpec(is_in=True, attributes=ATTR_INTERRUPT, max_packet_size=8, interval=255),
    ]

    def __init__(self, applets: Optional[list[Applet]] = None) -> None:
        self.card = SmartCard(applets or [])
        self._buffer = RequestBuffer()
        self._notified = False

    def class_descriptors(self) -> bytes:
        return CCID_FUNCTIONAL_DESCRIPTOR

    def handle_data(
        self,
        endpoint: int,
        direction: int,
        request_id: int,
        transfer_buffer: bytes,
        on_finish: Callable[[Optional[bytes]], None],
    ) -> None:
        # endpoint_numbers = [bulk OUT, bulk IN, interrupt IN]
        interrupt_ep = self.endpoint_numbers[2] if len(self.endpoint_numbers) > 2 else None

        if endpoint == interrupt_ep:
            # Slot-change notifications. The card is present and never changes,
            # so report the current state once, then hold every later poll
            # pending forever — the host blocks here instead of polling status.
            if not self._notified:
                self._notified = True
                on_finish(
                    bytes([RDR_TO_PC_NOTIFY_SLOT_CHANGE, _SLOT_PRESENT_UNCHANGED])
                )
            # else: leave pending (never call on_finish); host UNLINKs on detach.
            return

        if direction == DIR_IN:
            # Host polls bulk IN for a CCID response; hold until we have one.
            self._buffer.request(request_id, on_finish)
        else:
            # Bulk OUT: a complete CCID message. APDU handling is fast (no user
            # interaction), so process inline and queue the response.
            try:
                response = self.card.handle_ccid(transfer_buffer)
                self._buffer.respond(response)
            except Exception:
                logger.exception("CCID processing error")
            on_finish(None)

    def cancel_request(self, request_id: int) -> bool:
        return self._buffer.cancel_request(request_id)
