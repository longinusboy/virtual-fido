"""PIV applet (NIST SP 800-73 / YubiKey PIV), as used by `ykman piv` and OpenSC.

Implements the subset of PIV that the common tooling exercises:
  - SELECT, GET VERSION / GET SERIAL / GET METADATA (YubiKey extensions)
  - VERIFY (PIN), CHANGE REFERENCE DATA (PIN/PUK), RESET RETRY COUNTER (PUK)
  - GENERAL AUTHENTICATE: 3DES management-key mutual auth, plus RSA/ECDSA
    sign and RSA decrypt with the key slots
  - GENERATE ASYMMETRIC KEY PAIR (RSA-2048, ECC P-256/P-384)
  - GET DATA / PUT DATA for data objects (certificates, CHUID, CCC)

Keys, certificates and PIN/PUK/management-key state persist in the encrypted
vault through a save callback. Management operations (generate, put data)
require prior management-key authentication; signing requires the PIN.
"""

from __future__ import annotations

import base64
import logging

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from .. import crypto
from ..ccid import SW_SUCCESS, Applet

logger = logging.getLogger("virtual_fido.piv")

# Right-truncated PIV application AID (RID A0000003 08 + PIX 00 00 10 00).
PIV_AID = bytes.fromhex("a0000003080000100000")

# Instructions
INS_VERIFY = 0x20
INS_CHANGE_REFERENCE = 0x24
INS_RESET_RETRY = 0x2C
INS_GENERATE_ASYMMETRIC = 0x47
INS_GENERAL_AUTHENTICATE = 0x87
INS_GET_DATA = 0xCB
INS_PUT_DATA = 0xDB
INS_GET_METADATA = 0xF7  # YubiKey extension
INS_GET_VERSION = 0xFD  # YubiKey extension
INS_GET_SERIAL = 0xF8  # YubiKey extension

# Key references
KEY_PIN = 0x80
KEY_PUK = 0x81
KEY_MGMT = 0x9B
KEY_SLOTS = (0x9A, 0x9C, 0x9D, 0x9E)
SLOT_NO_PIN = 0x9E  # card authentication slot needs no PIN

# Algorithm identifiers
ALG_3DES = 0x03
ALG_RSA_1024 = 0x06
ALG_RSA_2048 = 0x07
ALG_ECC_P256 = 0x11
ALG_ECC_P384 = 0x14

# BER-TLV tags
TAG_DYN_AUTH = 0x7C
TAG_AUTH_WITNESS = 0x80
TAG_AUTH_CHALLENGE = 0x81
TAG_AUTH_RESPONSE = 0x82
TAG_DATA_TAG_LIST = 0x5C
TAG_DATA_OBJECT = 0x53
TAG_GENERATE_TEMPLATE = 0xAC
TAG_ALGORITHM = 0x80
TAG_PUBLIC_KEY = 0x7F49
TAG_RSA_MODULUS = 0x81
TAG_RSA_EXPONENT = 0x82
TAG_ECC_POINT = 0x86

# Status words
SW_SECURITY_NOT_SATISFIED = 0x6982
SW_AUTH_BLOCKED = 0x6983
SW_INCORRECT_DATA = 0x6A80
SW_FILE_NOT_FOUND = 0x6A82  # missing data object (GET DATA)
SW_WRONG_PARAMS = 0x6A86
SW_REFERENCE_NOT_FOUND = 0x6A88  # bad key/PIN reference
SW_INS_NOT_SUPPORTED = 0x6D00

DEFAULT_PIN = "123456"
DEFAULT_PUK = "12345678"
DEFAULT_MGMT_KEY = bytes.fromhex("010203040506070801020304050607080102030405060708")
DEFAULT_RETRIES = 3
FIRMWARE_VERSION = bytes([5, 7, 4])

_ECC_CURVES = {ALG_ECC_P256: ec.SECP256R1, ALG_ECC_P384: ec.SECP384R1}
_PREHASH_BY_LEN = {20: hashes.SHA1, 32: hashes.SHA256, 48: hashes.SHA384, 64: hashes.SHA512}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(value: str) -> bytes:
    return base64.b64decode(value)


# ---------------------------------------------------------------------------
# BER-TLV
# ---------------------------------------------------------------------------


def ber_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return bytes([0x81, n])
    if n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])


def ber_tlv(tag: int, value: bytes) -> bytes:
    tag_bytes = tag.to_bytes(max(1, (tag.bit_length() + 7) // 8), "big")
    return tag_bytes + ber_len(len(value)) + value


def parse_ber(data: bytes) -> list[tuple[int, bytes]]:
    """Parse concatenated BER-TLVs (1-2 byte tags, short/long lengths)."""
    result: list[tuple[int, bytes]] = []
    i = 0
    n = len(data)
    while i < n:
        tag = data[i]
        i += 1
        if tag & 0x1F == 0x1F:  # multi-byte tag
            tag = (tag << 8) | data[i]
            i += 1
        if i >= n:
            break
        length = data[i]
        i += 1
        if length & 0x80:
            num = length & 0x7F
            length = int.from_bytes(data[i : i + num], "big")
            i += num
        result.append((tag, data[i : i + length]))
        i += length
    return result


def find_tag(tlvs: list[tuple[int, bytes]], tag: int):
    for t, v in tlvs:
        if t == tag:
            return v
    return None


def _pad_pin(pin: str) -> bytes:
    return pin.encode().ljust(8, b"\xff")[:8]


def _des3(key: bytes, block: bytes) -> bytes:
    cipher = Cipher(TripleDES(key), modes.ECB())
    encryptor = cipher.encryptor()
    return encryptor.update(block) + encryptor.finalize()


class PIVApplet(Applet):
    aid = PIV_AID
    name = "piv"

    def __init__(self, state: dict, save):
        self._state = state if state is not None else {}
        self._save = save
        self._state.setdefault("pin", DEFAULT_PIN)
        self._state.setdefault("puk", DEFAULT_PUK)
        self._state.setdefault("pin_retries", DEFAULT_RETRIES)
        self._state.setdefault("puk_retries", DEFAULT_RETRIES)
        self._state.setdefault("mgmt_key", DEFAULT_MGMT_KEY.hex())
        self._state.setdefault("slots", {})  # slot_hex -> {alg, key(PEM b64), origin}
        self._state.setdefault("objects", {})  # tag_hex -> data b64
        self._pin_verified = False
        self._mgmt_authenticated = False
        self._mgmt_witness = b""

    # ------------------------------------------------------------------

    def _persist(self) -> None:
        if self._save:
            self._save(self._state)

    def _mgmt_key(self) -> bytes:
        return bytes.fromhex(self._state["mgmt_key"])

    def select(self) -> tuple[bytes, int]:
        # PIV Application Property Template (tag 0x61).
        template = ber_tlv(0x4F, PIV_AID) + ber_tlv(0x79, ber_tlv(0x4F, bytes.fromhex("a000000308")))
        self._pin_verified = False
        self._mgmt_authenticated = False
        return ber_tlv(0x61, template), SW_SUCCESS

    def process_apdu(self, apdu) -> tuple[bytes, int]:
        ins = apdu.ins
        handlers = {
            INS_VERIFY: self._verify,
            INS_CHANGE_REFERENCE: self._change_reference,
            INS_RESET_RETRY: self._reset_retry,
            INS_GENERAL_AUTHENTICATE: self._general_authenticate,
            INS_GENERATE_ASYMMETRIC: self._generate,
            INS_GET_DATA: self._get_data,
            INS_PUT_DATA: self._put_data,
            INS_GET_METADATA: self._get_metadata,
            INS_GET_VERSION: lambda a: (FIRMWARE_VERSION, SW_SUCCESS),
            INS_GET_SERIAL: lambda a: ((0x00C0FFEE).to_bytes(4, "big"), SW_SUCCESS),
        }
        handler = handlers.get(ins)
        if handler is None:
            return b"", SW_INS_NOT_SUPPORTED
        return handler(apdu)

    # ------------------------------------------------------------------
    # PIN / PUK
    # ------------------------------------------------------------------

    def _verify(self, apdu) -> tuple[bytes, int]:
        if apdu.p2 != KEY_PIN:
            return b"", SW_REFERENCE_NOT_FOUND
        if not apdu.data:
            # Query remaining attempts.
            if self._pin_verified:
                return b"", SW_SUCCESS
            return b"", 0x63C0 | (self._state["pin_retries"] & 0x0F)
        if self._state["pin_retries"] <= 0:
            return b"", SW_AUTH_BLOCKED
        if apdu.data == _pad_pin(self._state["pin"]):
            self._pin_verified = True
            self._state["pin_retries"] = DEFAULT_RETRIES
            return b"", SW_SUCCESS
        self._state["pin_retries"] -= 1
        self._persist()
        return b"", 0x63C0 | (self._state["pin_retries"] & 0x0F)

    def _change_reference(self, apdu) -> tuple[bytes, int]:
        which = apdu.p2  # 0x80 PIN, 0x81 PUK
        if which not in (KEY_PIN, KEY_PUK):
            return b"", SW_REFERENCE_NOT_FOUND
        current, new = apdu.data[:8], apdu.data[8:16]
        field = "pin" if which == KEY_PIN else "puk"
        retries = "pin_retries" if which == KEY_PIN else "puk_retries"
        if self._state[retries] <= 0:
            return b"", SW_AUTH_BLOCKED
        if current != _pad_pin(self._state[field]):
            self._state[retries] -= 1
            self._persist()
            return b"", 0x63C0 | (self._state[retries] & 0x0F)
        self._state[field] = new.rstrip(b"\xff").decode()
        self._state[retries] = DEFAULT_RETRIES
        self._persist()
        return b"", SW_SUCCESS

    def _reset_retry(self, apdu) -> tuple[bytes, int]:
        # Unblock the PIN using the PUK. data = PUK(8) + new PIN(8).
        if self._state["puk_retries"] <= 0:
            return b"", SW_AUTH_BLOCKED
        puk, new_pin = apdu.data[:8], apdu.data[8:16]
        if puk != _pad_pin(self._state["puk"]):
            self._state["puk_retries"] -= 1
            self._persist()
            return b"", 0x63C0 | (self._state["puk_retries"] & 0x0F)
        self._state["pin"] = new_pin.rstrip(b"\xff").decode()
        self._state["pin_retries"] = DEFAULT_RETRIES
        self._state["puk_retries"] = DEFAULT_RETRIES
        self._persist()
        return b"", SW_SUCCESS

    # ------------------------------------------------------------------
    # GENERAL AUTHENTICATE
    # ------------------------------------------------------------------

    def _general_authenticate(self, apdu) -> tuple[bytes, int]:
        slot = apdu.p2
        outer = parse_ber(apdu.data)
        template = find_tag(outer, TAG_DYN_AUTH)
        if template is None:
            return b"", SW_INCORRECT_DATA
        fields = parse_ber(template)

        if slot == KEY_MGMT:
            return self._mgmt_authenticate(fields)
        return self._private_key_op(slot, fields)

    def _mgmt_authenticate(self, fields) -> tuple[bytes, int]:
        witness = find_tag(fields, TAG_AUTH_WITNESS)
        challenge = find_tag(fields, TAG_AUTH_CHALLENGE)
        key = self._mgmt_key()

        # Step 1: client requests a witness (empty tag 0x80).
        if witness is not None and len(witness) == 0 and challenge is None:
            self._mgmt_witness = crypto.random_bytes(8)
            encrypted = _des3(key, self._mgmt_witness)
            return ber_tlv(TAG_DYN_AUTH, ber_tlv(TAG_AUTH_WITNESS, encrypted)), SW_SUCCESS

        # Step 2: client returns the decrypted witness + its own challenge.
        if witness and challenge is not None:
            if witness != self._mgmt_witness or not self._mgmt_witness:
                return b"", SW_SECURITY_NOT_SATISFIED
            self._mgmt_authenticated = True
            self._mgmt_witness = b""
            response = _des3(key, challenge)
            return ber_tlv(TAG_DYN_AUTH, ber_tlv(TAG_AUTH_RESPONSE, response)), SW_SUCCESS

        return b"", SW_INCORRECT_DATA

    def _private_key_op(self, slot, fields) -> tuple[bytes, int]:
        slot_hex = f"{slot:02x}"
        entry = self._state["slots"].get(slot_hex)
        if entry is None:
            return b"", SW_REFERENCE_NOT_FOUND
        # Signing/decryption requires the PIN (except the card-auth slot 9E).
        if slot != SLOT_NO_PIN and not self._pin_verified:
            return b"", SW_SECURITY_NOT_SATISFIED
        challenge = find_tag(fields, TAG_AUTH_CHALLENGE)
        if challenge is None:
            return b"", SW_INCORRECT_DATA

        private_key = serialization.load_pem_private_key(_unb64(entry["key"]), None)
        try:
            result = self._raw_sign_or_decrypt(private_key, challenge)
        except Exception:
            logger.exception("PIV private-key operation failed")
            return b"", SW_INCORRECT_DATA
        return ber_tlv(TAG_DYN_AUTH, ber_tlv(TAG_AUTH_RESPONSE, result)), SW_SUCCESS

    @staticmethod
    def _raw_sign_or_decrypt(private_key, data: bytes) -> bytes:
        if isinstance(private_key, rsa.RSAPrivateKey):
            # Raw RSA private-key operation (client pre-pads for sign, or sends
            # ciphertext for decrypt): m^d mod n.
            numbers = private_key.private_numbers()
            n = numbers.public_numbers.n
            size = (n.bit_length() + 7) // 8
            m = int.from_bytes(data, "big")
            return pow(m, numbers.d, n).to_bytes(size, "big")
        # ECDSA over the supplied digest (PIV cards sign the hash as-is).
        hash_cls = _PREHASH_BY_LEN.get(len(data))
        if hash_cls is None:
            raise ValueError(f"Unsupported ECDSA digest length {len(data)}")
        return private_key.sign(data, ec.ECDSA(utils.Prehashed(hash_cls())))

    # ------------------------------------------------------------------
    # Key generation
    # ------------------------------------------------------------------

    def _generate(self, apdu) -> tuple[bytes, int]:
        if not self._mgmt_authenticated:
            return b"", SW_SECURITY_NOT_SATISFIED
        slot = apdu.p2
        if slot not in KEY_SLOTS:
            return b"", SW_REFERENCE_NOT_FOUND
        template = find_tag(parse_ber(apdu.data), TAG_GENERATE_TEMPLATE)
        if template is None:
            return b"", SW_INCORRECT_DATA
        alg = find_tag(parse_ber(template), TAG_ALGORITHM)
        if not alg:
            return b"", SW_INCORRECT_DATA
        alg = alg[0]

        if alg in (ALG_RSA_1024, ALG_RSA_2048):
            bits = 1024 if alg == ALG_RSA_1024 else 2048
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            public = self._rsa_public_tlv(private_key.public_key())
        elif alg in _ECC_CURVES:
            private_key = ec.generate_private_key(_ECC_CURVES[alg]())
            public = self._ecc_public_tlv(private_key.public_key())
        else:
            return b"", SW_WRONG_PARAMS

        self._state["slots"][f"{slot:02x}"] = {
            "alg": alg,
            "key": _b64(
                private_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            ),
            "origin": "generated",
        }
        self._persist()
        return public, SW_SUCCESS

    @staticmethod
    def _rsa_public_tlv(public_key) -> bytes:
        numbers = public_key.public_numbers()
        size = (numbers.n.bit_length() + 7) // 8
        inner = ber_tlv(TAG_RSA_MODULUS, numbers.n.to_bytes(size, "big")) + ber_tlv(
            TAG_RSA_EXPONENT, numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
        )
        return ber_tlv(TAG_PUBLIC_KEY, inner)

    @staticmethod
    def _ecc_public_tlv(public_key) -> bytes:
        point = public_key.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        return ber_tlv(TAG_PUBLIC_KEY, ber_tlv(TAG_ECC_POINT, point))

    # ------------------------------------------------------------------
    # Data objects
    # ------------------------------------------------------------------

    def _get_data(self, apdu) -> tuple[bytes, int]:
        tag_value = find_tag(parse_ber(apdu.data), TAG_DATA_TAG_LIST)
        if not tag_value:
            return b"", SW_INCORRECT_DATA
        obj = self._state["objects"].get(tag_value.hex())
        if obj is None:
            # A real card returns FILE NOT FOUND for an absent data object;
            # ykman relies on this (get_pivman_data) to detect uninitialized
            # objects and fall back to defaults instead of erroring.
            return b"", SW_FILE_NOT_FOUND
        return ber_tlv(TAG_DATA_OBJECT, _unb64(obj)), SW_SUCCESS

    def _put_data(self, apdu) -> tuple[bytes, int]:
        if not self._mgmt_authenticated:
            return b"", SW_SECURITY_NOT_SATISFIED
        tlvs = parse_ber(apdu.data)
        tag_value = find_tag(tlvs, TAG_DATA_TAG_LIST)
        obj = find_tag(tlvs, TAG_DATA_OBJECT)
        if tag_value is None or obj is None:
            return b"", SW_INCORRECT_DATA
        self._state["objects"][tag_value.hex()] = _b64(obj)
        self._persist()
        return b"", SW_SUCCESS

    # ------------------------------------------------------------------
    # Metadata (YubiKey extension) — lets `ykman piv info` report state
    # ------------------------------------------------------------------

    def _get_metadata(self, apdu) -> tuple[bytes, int]:
        ref = apdu.p2
        if ref == KEY_MGMT:
            # algorithm (3DES) + policy (pin,touch) + is-default. ykman reads
            # the policy tag unconditionally (TOUCH_POLICY = policy[1]).
            return (
                ber_tlv(0x01, bytes([ALG_3DES]))
                + ber_tlv(0x02, bytes([0x00, 0x00]))  # pin/touch policy: default
                + ber_tlv(0x05, bytes([1])),  # is default
                SW_SUCCESS,
            )
        if ref in (KEY_PIN, KEY_PUK):
            retries = self._state["pin_retries" if ref == KEY_PIN else "puk_retries"]
            return (
                ber_tlv(0x05, bytes([1]))  # default
                + ber_tlv(0x06, bytes([DEFAULT_RETRIES, retries])),
                SW_SUCCESS,
            )
        if ref in KEY_SLOTS:
            entry = self._state["slots"].get(f"{ref:02x}")
            if entry is None:
                return b"", SW_REFERENCE_NOT_FOUND
            private_key = serialization.load_pem_private_key(_unb64(entry["key"]), None)
            if isinstance(private_key, rsa.RSAPrivateKey):
                public = self._rsa_public_tlv(private_key.public_key())
            else:
                public = self._ecc_public_tlv(private_key.public_key())
            origin = 1 if entry.get("origin") == "generated" else 2
            return (
                ber_tlv(0x01, bytes([entry["alg"]]))
                + ber_tlv(0x02, bytes([0x00, 0x00]))  # pin/touch policy: default/never
                + ber_tlv(0x03, bytes([origin]))
                + ber_tlv(0x04, public),
                SW_SUCCESS,
            )
        return b"", SW_REFERENCE_NOT_FOUND
