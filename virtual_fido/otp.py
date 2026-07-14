"""OTP HID keyboard interface.

A real YubiKey's OTP function is a USB HID keyboard that "types" a one-time
password when the button is touched. This virtual device has no button, so
output is triggered explicitly (see the control channel / `otp type` CLI).

Two slot types are supported:
  - Yubico OTP: a 16-byte token (private id, counters, timestamp, random,
    CRC), AES-128-ECB encrypted and emitted as public-id ‖ 32 ModHex chars.
  - Static password: a fixed string typed verbatim.

Caveat: HID keyboards send *keycodes*, and the host maps keycodes to
characters using its keyboard layout. Yubico's ModHex alphabet
(`cbdefghijklnrtuv`) is chosen to land on the same letters across most
layouts; arbitrary static passwords with symbols are layout-sensitive.
"""

from __future__ import annotations

import logging
import struct
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import crypto
from ._util import RequestBuffer
from .usb import (
    ATTR_INTERRUPT,
    DIR_IN,
    EndpointSpec,
    USBInterface,
)

logger = logging.getLogger("virtual_fido.otp")

MODHEX_ALPHABET = "cbdefghijklnrtuv"

# Standard HID boot-keyboard report descriptor (8-byte input report).
KEYBOARD_REPORT_DESCRIPTOR = bytes(
    [
        0x05, 0x01,  # Usage Page (Generic Desktop)
        0x09, 0x06,  # Usage (Keyboard)
        0xA1, 0x01,  # Collection (Application)
        0x05, 0x07,  # Usage Page (Keyboard/Keypad)
        0x19, 0xE0,  # Usage Minimum (Left Control)
        0x29, 0xE7,  # Usage Maximum (Right GUI)
        0x15, 0x00,  # Logical Minimum (0)
        0x25, 0x01,  # Logical Maximum (1)
        0x75, 0x01,  # Report Size (1)
        0x95, 0x08,  # Report Count (8)
        0x81, 0x02,  # Input (Data, Var, Abs) — modifier byte
        0x95, 0x01,  # Report Count (1)
        0x75, 0x08,  # Report Size (8)
        0x81, 0x01,  # Input (Const) — reserved byte
        0x95, 0x06,  # Report Count (6)
        0x75, 0x08,  # Report Size (8)
        0x15, 0x00,  # Logical Minimum (0)
        0x25, 0xFF,  # Logical Maximum (255)
        0x05, 0x07,  # Usage Page (Keyboard/Keypad)
        0x19, 0x00,  # Usage Minimum (0)
        0x29, 0xFF,  # Usage Maximum (255)
        0x81, 0x00,  # Input (Data, Array) — 6 keycodes
        0xC0,        # End Collection
    ]
)

_MOD_SHIFT = 0x02
_KEY_ENTER = 0x28

# Minimal US-layout keycode map (enough for ModHex + typical static passwords).
_KEYCODES: dict[str, tuple[int, int]] = {}
for _i, _c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _KEYCODES[_c] = (0x04 + _i, 0)
    _KEYCODES[_c.upper()] = (0x04 + _i, _MOD_SHIFT)
for _i, _c in enumerate("1234567890"):
    _KEYCODES[_c] = (0x1E + _i, 0)
_KEYCODES.update(
    {
        "\n": (_KEY_ENTER, 0),
        " ": (0x2C, 0),
        "-": (0x2D, 0),
        "_": (0x2D, _MOD_SHIFT),
        "=": (0x2E, 0),
        "+": (0x2E, _MOD_SHIFT),
        ".": (0x37, 0),
        "/": (0x38, 0),
    }
)


def modhex_encode(data: bytes) -> str:
    out = []
    for byte in data:
        out.append(MODHEX_ALPHABET[byte >> 4])
        out.append(MODHEX_ALPHABET[byte & 0x0F])
    return "".join(out)


def modhex_decode(text: str) -> bytes:
    if len(text) % 2 != 0:
        raise ValueError("ModHex string must have even length")
    out = bytearray()
    for i in range(0, len(text), 2):
        hi = MODHEX_ALPHABET.index(text[i])
        lo = MODHEX_ALPHABET.index(text[i + 1])
        out.append((hi << 4) | lo)
    return bytes(out)


def crc16(data: bytes) -> int:
    """ISO 13239 / X-25 CRC (no final XOR), as used by Yubico OTP. A valid
    16-byte token satisfies crc16(token) == 0xF0B8."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0x8408
            else:
                crc >>= 1
    return crc & 0xFFFF


CRC_RESIDUAL_OK = 0xF0B8


def keyboard_reports(text: str) -> list[bytes]:
    """Key-down + key-up report pairs that 'type' `text` (8-byte reports)."""
    reports = []
    release = bytes(8)
    for char in text:
        keycode, modifier = _KEYCODES.get(char, (0, 0))
        if keycode == 0:
            logger.warning("OTP: no keycode for %r, skipping", char)
            continue
        reports.append(bytes([modifier, 0, keycode, 0, 0, 0, 0, 0]))
        reports.append(release)  # release between keys (and repeats)
    return reports


@dataclass
class OTPSlot:
    kind: str  # "yubico" or "static"
    # Yubico OTP
    aes_key: bytes = b""
    public_id: bytes = b""  # raw bytes, emitted as ModHex prefix
    private_id: bytes = b""  # 6-byte private UID
    usage_counter: int = 1
    session_counter: int = 0
    # Static password
    password: str = ""

    def to_json_obj(self) -> dict:
        import base64

        obj = {"kind": self.kind}
        if self.kind == "yubico":
            obj.update(
                aes_key=base64.b64encode(self.aes_key).decode(),
                public_id=base64.b64encode(self.public_id).decode(),
                private_id=base64.b64encode(self.private_id).decode(),
                usage_counter=self.usage_counter,
            )
        else:
            obj["password"] = self.password
        return obj

    @classmethod
    def from_json_obj(cls, obj: dict) -> "OTPSlot":
        import base64

        kind = obj.get("kind", "static")
        if kind == "yubico":
            return cls(
                kind="yubico",
                aes_key=base64.b64decode(obj["aes_key"]),
                public_id=base64.b64decode(obj.get("public_id", "")),
                private_id=base64.b64decode(obj["private_id"]),
                usage_counter=obj.get("usage_counter", 1),
            )
        return cls(kind="static", password=obj.get("password", ""))


def build_yubico_otp(slot: OTPSlot) -> str:
    """Generate one Yubico OTP string (public id + 32 ModHex chars)."""
    slot.session_counter = (slot.session_counter + 1) & 0xFF
    timestamp = crypto.random_bytes(3)  # 8Hz timer on real hardware; random here
    token = (
        slot.private_id[:6].ljust(6, b"\x00")
        + struct.pack("<H", slot.usage_counter & 0xFFFF)
        + timestamp
        + bytes([slot.session_counter])
        + crypto.random_bytes(2)
    )
    # Yubico stores the complement of the CRC over the first 14 bytes, so that
    # a CRC over the whole 16-byte token yields the residual 0xF0B8.
    token += struct.pack("<H", (~crc16(token)) & 0xFFFF)
    assert crc16(token) == CRC_RESIDUAL_OK
    ciphertext = crypto.aes_ecb_encrypt(slot.aes_key, token)
    return modhex_encode(slot.public_id) + modhex_encode(ciphertext)


class OTPKeyboardInterface(USBInterface):
    interface_class = 3  # HID
    interface_subclass = 1  # boot
    interface_protocol = 1  # keyboard
    interface_string = None
    endpoint_specs = [EndpointSpec(is_in=True, attributes=ATTR_INTERRUPT, max_packet_size=8, interval=10)]

    def __init__(self, slots: Optional[dict[int, OTPSlot]] = None) -> None:
        self._buffer = RequestBuffer()
        self.slots: dict[int, OTPSlot] = slots or {}

    def class_descriptors(self) -> bytes:
        from .usb import hid_descriptor

        return hid_descriptor(len(KEYBOARD_REPORT_DESCRIPTOR))

    def report_descriptor(self) -> bytes:
        return KEYBOARD_REPORT_DESCRIPTOR

    def handle_data(
        self,
        endpoint: int,
        direction: int,
        request_id: int,
        transfer_buffer: bytes,
        on_finish: Callable[[Optional[bytes]], None],
    ) -> None:
        if direction == DIR_IN:
            # Host polls for the next keyboard report; hold pending until we
            # have something to "type".
            self._buffer.request(request_id, on_finish)
        else:
            on_finish(None)

    def cancel_request(self, request_id: int) -> bool:
        return self._buffer.cancel_request(request_id)

    # ------------------------------------------------------------------
    # Emitting output (called from the control channel)
    # ------------------------------------------------------------------

    def type_string(self, text: str) -> None:
        for report in keyboard_reports(text):
            self._buffer.respond(report)

    def type_otp(self, slot_number: int) -> None:
        slot = self.slots.get(slot_number)
        if slot is None:
            raise KeyError(f"OTP slot {slot_number} is not configured")
        if slot.kind == "yubico":
            output = build_yubico_otp(slot) + "\n"
        else:
            output = slot.password + "\n"
        logger.info("Typing OTP from slot %d (%d chars)", slot_number, len(output))
        self.type_string(output)
