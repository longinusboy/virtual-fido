"""OATH applet (ykoath protocol), as used by `ykman oath` / Yubico Authenticator.

Implements the YubiKey OATH application over ISO 7816 APDUs: storing TOTP/HOTP
credentials, listing them, and computing codes. The client (ykman) provisions
credentials over the wire with PUT; codes are produced with CALCULATE /
CALCULATE_ALL, where the client supplies the time-step challenge.

Protocol reference: https://developers.yubico.com/OATH/YKOATH_Protocol.html

Credentials are persisted through a save callback into the encrypted vault.
Optional password protection follows the ykoath VALIDATE/SET CODE flow.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging

from .. import crypto
from ..ccid import (
    SW_FILE_NOT_FOUND,
    SW_SUCCESS,
    SW_WRONG_LENGTH,
    Applet,
)

logger = logging.getLogger("virtual_fido.oath")

OATH_AID = bytes.fromhex("a0000005272101")

# Instructions
INS_PUT = 0x01
INS_DELETE = 0x02
INS_SET_CODE = 0x03
INS_RESET = 0x04
INS_LIST = 0xA1
INS_CALCULATE = 0xA2
INS_VALIDATE = 0xA3
INS_CALCULATE_ALL = 0xA4

# TLV tags
TAG_NAME = 0x71
TAG_NAME_LIST = 0x72
TAG_KEY = 0x73
TAG_CHALLENGE = 0x74
TAG_RESPONSE = 0x75
TAG_TRUNCATED = 0x76
TAG_HOTP = 0x77  # marker in CALCULATE_ALL: HOTP credential, calculate separately
TAG_PROPERTY = 0x78
TAG_VERSION = 0x79
TAG_IMF = 0x7A
TAG_ALGORITHM = 0x7B
TAG_TOUCH = 0x7C  # marker in CALCULATE_ALL: requires touch

# Key type (high nibble) | hash algorithm (low nibble)
TYPE_HOTP = 0x10
TYPE_TOTP = 0x20
TYPE_MASK = 0xF0
ALG_MASK = 0x0F
ALG_SHA1 = 0x01
ALG_SHA256 = 0x02
ALG_SHA512 = 0x03

PROPERTY_REQUIRE_TOUCH = 0x02

# Status words specific to OATH
SW_NO_SUCH_OBJECT = 0x6984
SW_AUTH_REQUIRED = 0x6982
SW_WRONG_SYNTAX = 0x6A80

_HASHES = {ALG_SHA1: hashlib.sha1, ALG_SHA256: hashlib.sha256, ALG_SHA512: hashlib.sha512}
_HASH_NAMES = {ALG_SHA1: "sha1", ALG_SHA256: "sha256", ALG_SHA512: "sha512"}
_HASH_IDS = {v: k for k, v in _HASH_NAMES.items()}
_VERSION = bytes([5, 4, 3])


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(value: str) -> bytes:
    return base64.b64decode(value)


def tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


def parse_tlvs(data: bytes) -> dict:
    """Parse a sequence of single-byte-length TLVs into {tag: value}. Later
    duplicate tags overwrite earlier ones (OATH APDUs don't repeat tags)."""
    out: dict[int, bytes] = {}
    i = 0
    while i + 2 <= len(data):
        tag = data[i]
        length = data[i + 1]
        value = data[i + 2 : i + 2 + length]
        out[tag] = value
        i += 2 + length
    return out


def truncate(digest: bytes) -> int:
    """RFC 4226 dynamic truncation. Returns the 31-bit value; the client
    applies `% 10**digits`."""
    offset = digest[-1] & 0x0F
    return int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF


class OATHApplet(Applet):
    aid = OATH_AID
    name = "oath"

    def __init__(self, state: dict, save):
        """`state` is the persisted JSON dict (see fido_client.oath_state);
        `save(state)` writes it back to the vault."""
        self._state = state if state is not None else {}
        self._save = save
        if "device_id" not in self._state:
            self._state["device_id"] = _b64(crypto.random_bytes(8))
        self._credentials: dict = self._state.setdefault("credentials", {})
        self._pending_challenge: bytes = b""
        self._authenticated = "password_key" not in self._state

    # ------------------------------------------------------------------

    @property
    def _device_id(self) -> bytes:
        return _unb64(self._state["device_id"])

    def _persist(self) -> None:
        if self._save:
            self._save(self._state)

    def select(self) -> tuple[bytes, int]:
        response = tlv(TAG_VERSION, _VERSION) + tlv(TAG_NAME, self._device_id)
        if "password_key" in self._state:
            self._pending_challenge = crypto.random_bytes(8)
            self._authenticated = False
            response += tlv(TAG_CHALLENGE, self._pending_challenge)
            response += tlv(TAG_ALGORITHM, bytes([ALG_SHA1]))
        else:
            self._authenticated = True
        return response, SW_SUCCESS

    def process_apdu(self, apdu) -> tuple[bytes, int]:
        ins = apdu.ins
        # RESET and VALIDATE are allowed before authentication; everything else
        # requires a validated password when one is set.
        if not self._authenticated and ins not in (INS_VALIDATE, INS_RESET):
            return b"", SW_AUTH_REQUIRED

        if ins == INS_PUT:
            return self._put(apdu)
        if ins == INS_DELETE:
            return self._delete(apdu)
        if ins == INS_LIST:
            return self._list()
        if ins == INS_CALCULATE:
            return self._calculate(apdu)
        if ins == INS_CALCULATE_ALL:
            return self._calculate_all(apdu)
        if ins == INS_SET_CODE:
            return self._set_code(apdu)
        if ins == INS_VALIDATE:
            return self._validate(apdu)
        if ins == INS_RESET:
            return self._reset(apdu)
        return b"", SW_FILE_NOT_FOUND

    # ------------------------------------------------------------------
    # Credential management
    # ------------------------------------------------------------------

    def _put(self, apdu) -> tuple[bytes, int]:
        tlvs = parse_tlvs(apdu.data)
        name = tlvs.get(TAG_NAME)
        key = tlvs.get(TAG_KEY)
        if not name or not key or len(key) < 2:
            return b"", SW_WRONG_SYNTAX
        key_type = key[0] & TYPE_MASK
        hash_id = key[0] & ALG_MASK
        if hash_id not in _HASHES or key_type not in (TYPE_HOTP, TYPE_TOTP):
            return b"", SW_WRONG_SYNTAX
        digits = key[1]
        secret = key[2:]
        credential = {
            "type": "hotp" if key_type == TYPE_HOTP else "totp",
            "hash": _HASH_NAMES[hash_id],
            "secret": _b64(secret),
            "digits": digits,
            "touch": bool(tlvs.get(TAG_PROPERTY, b"\x00")[0] & PROPERTY_REQUIRE_TOUCH),
        }
        if TAG_IMF in tlvs:
            credential["counter"] = int.from_bytes(tlvs[TAG_IMF], "big")
        else:
            credential["counter"] = 0
        self._credentials[name.decode("utf-8", "replace")] = credential
        self._persist()
        return b"", SW_SUCCESS

    def _delete(self, apdu) -> tuple[bytes, int]:
        tlvs = parse_tlvs(apdu.data)
        name = tlvs.get(TAG_NAME)
        if not name:
            return b"", SW_WRONG_SYNTAX
        if self._credentials.pop(name.decode("utf-8", "replace"), None) is None:
            return b"", SW_NO_SUCH_OBJECT
        self._persist()
        return b"", SW_SUCCESS

    def _reset(self, apdu) -> tuple[bytes, int]:
        # ykoath requires P1=0xDE P2=0xAD as a safety interlock.
        if apdu.p1 != 0xDE or apdu.p2 != 0xAD:
            return b"", SW_WRONG_SYNTAX
        self._credentials.clear()
        self._state.pop("password_key", None)
        self._authenticated = True
        self._persist()
        return b"", SW_SUCCESS

    def _list(self) -> tuple[bytes, int]:
        response = b""
        for name, cred in self._credentials.items():
            type_byte = (TYPE_HOTP if cred["type"] == "hotp" else TYPE_TOTP) | _HASH_IDS[
                cred["hash"]
            ]
            response += tlv(TAG_NAME_LIST, bytes([type_byte]) + name.encode())
        return response, SW_SUCCESS

    # ------------------------------------------------------------------
    # Code calculation
    # ------------------------------------------------------------------

    def _compute(self, cred: dict, challenge: bytes) -> bytes:
        secret = _unb64(cred["secret"])
        digestmod = _HASHES[_HASH_IDS[cred["hash"]]]
        return hmac.new(secret, challenge, digestmod).digest()

    def _truncated_tlv(self, cred: dict, digest: bytes) -> bytes:
        code = truncate(digest)
        return tlv(TAG_TRUNCATED, bytes([cred["digits"]]) + code.to_bytes(4, "big"))

    def _calculate(self, apdu) -> tuple[bytes, int]:
        tlvs = parse_tlvs(apdu.data)
        name = tlvs.get(TAG_NAME)
        if not name:
            return b"", SW_WRONG_SYNTAX
        cred = self._credentials.get(name.decode("utf-8", "replace"))
        if cred is None:
            return b"", SW_NO_SUCH_OBJECT

        if cred["type"] == "hotp":
            challenge = cred.get("counter", 0).to_bytes(8, "big")
            cred["counter"] = cred.get("counter", 0) + 1
            self._persist()
        else:
            challenge = tlvs.get(TAG_CHALLENGE, b"")
            if len(challenge) != 8:
                return b"", SW_WRONG_SYNTAX

        digest = self._compute(cred, challenge)
        # P2 == 0x01 -> truncated response; 0x00 -> full response
        if apdu.p2 == 0x00:
            return tlv(TAG_RESPONSE, bytes([cred["digits"]]) + digest), SW_SUCCESS
        return self._truncated_tlv(cred, digest), SW_SUCCESS

    def _calculate_all(self, apdu) -> tuple[bytes, int]:
        tlvs = parse_tlvs(apdu.data)
        challenge = tlvs.get(TAG_CHALLENGE, b"")
        response = b""
        for name, cred in self._credentials.items():
            response += tlv(TAG_NAME, name.encode())
            if cred["type"] == "hotp":
                response += tlv(TAG_HOTP, b"")  # client must CALCULATE explicitly
            elif cred.get("touch"):
                response += tlv(TAG_TOUCH, b"")
            elif len(challenge) == 8:
                response += self._truncated_tlv(cred, self._compute(cred, challenge))
            else:
                response += tlv(TAG_HOTP, b"")
        return response, SW_SUCCESS

    # ------------------------------------------------------------------
    # Password protection
    # ------------------------------------------------------------------

    def _set_code(self, apdu) -> tuple[bytes, int]:
        tlvs = parse_tlvs(apdu.data)
        key = tlvs.get(TAG_KEY, b"")
        if not key:
            # Empty key clears the password.
            self._state.pop("password_key", None)
            self._authenticated = True
            self._persist()
            return b"", SW_SUCCESS
        # key = [algorithm byte][16-byte PBKDF2 key]; verify the client's proof.
        secret = key[1:]
        challenge = tlvs.get(TAG_CHALLENGE, b"")
        response = tlvs.get(TAG_RESPONSE, b"")
        expected = hmac.new(secret, challenge, hashlib.sha1).digest()
        if not hmac.compare_digest(expected, response):
            return b"", SW_WRONG_SYNTAX
        self._state["password_key"] = _b64(secret)
        self._authenticated = True
        self._persist()
        return b"", SW_SUCCESS

    def _validate(self, apdu) -> tuple[bytes, int]:
        if "password_key" not in self._state:
            return b"", SW_WRONG_SYNTAX
        key = _unb64(self._state["password_key"])
        tlvs = parse_tlvs(apdu.data)
        response = tlvs.get(TAG_RESPONSE, b"")
        challenge = tlvs.get(TAG_CHALLENGE, b"")
        # The client proves it knows the key by HMAC'ing the challenge we sent
        # in SELECT; we prove it back by HMAC'ing the client's challenge.
        expected = hmac.new(key, self._pending_challenge, hashlib.sha1).digest()
        if not hmac.compare_digest(expected, response):
            return b"", SW_AUTH_REQUIRED
        self._authenticated = True
        proof = hmac.new(key, challenge, hashlib.sha1).digest()
        return tlv(TAG_RESPONSE, proof), SW_SUCCESS
