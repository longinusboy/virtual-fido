"""COSE key encoding/decoding (RFC 9052) as used by WebAuthn/CTAP2.

Port of the Go cose/ package. Supports ES256 (ECDSA P-256) and Ed25519.
RSA (PS256) is intentionally not ported: the reference client never creates
RSA credentials and omitting it keeps the security-relevant surface smaller.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import cbor2
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from . import crypto

# COSEAlgorithmID
ALGORITHM_ES256 = -7
ALGORITHM_ED25519 = -8
ALGORITHM_ECDH_HKDF_256 = -25
ALGORITHM_ES512 = -36
ALGORITHM_PS256 = -37

# coseCurveID
CURVE_P256 = 1
CURVE_ED25519 = 6

# coseKeyType
KEY_TYPE_OKP = 0b001
KEY_TYPE_EC2 = 0b010
KEY_TYPE_RSA = 0b011
KEY_TYPE_SYMMETRIC = 0b100

# COSE map labels (RFC 9052 §7)
_LABEL_KTY = 1
_LABEL_ALG = 3
_LABEL_CRV = -1
_LABEL_X = -2
_LABEL_Y = -3
_LABEL_D = -4

_COORD_SIZE = 32


def marshal_cbor(value) -> bytes:
    """CTAP2 canonical CBOR (matches Go's cbor.CTAP2EncOptions)."""
    return cbor2.dumps(value, canonical=True)


@dataclass
class COSEPublicKey:
    """SupportedCOSEPublicKey: exactly one member is set."""

    ecdsa: Optional[ec.EllipticCurvePublicKey] = None
    ed25519: Optional[ed25519.Ed25519PublicKey] = None

    def verify(self, data: bytes, signature: bytes) -> bool:
        if self.ecdsa is not None:
            return crypto.verify_ecdsa(self.ecdsa, data, signature)
        if self.ed25519 is not None:
            return crypto.verify_ed25519(self.ed25519, data, signature)
        raise ValueError("No supported public key data")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, COSEPublicKey):
            return NotImplemented
        return marshal_cose_public_key(self) == marshal_cose_public_key(other)


@dataclass
class COSEPrivateKey:
    """SupportedCOSEPrivateKey: exactly one member is set."""

    ecdsa: Optional[ec.EllipticCurvePrivateKey] = None
    ed25519: Optional[ed25519.Ed25519PrivateKey] = None

    def public(self) -> COSEPublicKey:
        if self.ecdsa is not None:
            return COSEPublicKey(ecdsa=self.ecdsa.public_key())
        if self.ed25519 is not None:
            return COSEPublicKey(ed25519=self.ed25519.public_key())
        raise ValueError("No supported private key data")

    def sign(self, data: bytes) -> bytes:
        if self.ecdsa is not None:
            return crypto.sign_ecdsa(self.ecdsa, data)
        if self.ed25519 is not None:
            return crypto.sign_ed25519(self.ed25519, data)
        raise ValueError("No supported private key data")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, COSEPrivateKey):
            return NotImplemented
        return marshal_cose_private_key(self) == marshal_cose_private_key(other)


def _int_to_coord(value: int) -> bytes:
    return value.to_bytes(_COORD_SIZE, "big")


def marshal_cose_public_key(key: COSEPublicKey) -> bytes:
    if key.ecdsa is not None:
        numbers = key.ecdsa.public_numbers()
        return marshal_cbor(
            {
                _LABEL_KTY: KEY_TYPE_EC2,
                _LABEL_ALG: ALGORITHM_ES256,
                _LABEL_CRV: CURVE_P256,
                _LABEL_X: _int_to_coord(numbers.x),
                _LABEL_Y: _int_to_coord(numbers.y),
            }
        )
    if key.ed25519 is not None:
        from cryptography.hazmat.primitives import serialization

        raw = key.ed25519.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return marshal_cbor(
            {
                _LABEL_KTY: KEY_TYPE_OKP,
                _LABEL_ALG: ALGORITHM_ED25519,
                _LABEL_CRV: CURVE_ED25519,
                _LABEL_X: raw,
            }
        )
    raise ValueError("No key provided in public key struct")


def unmarshal_cose_public_key(data: bytes) -> COSEPublicKey:
    obj = cbor2.loads(data)
    algorithm = obj.get(_LABEL_ALG)
    if algorithm == ALGORITHM_ES256:
        if obj.get(_LABEL_CRV) != CURVE_P256:
            raise ValueError("Curve is not P-256")
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(obj[_LABEL_X], "big"),
            int.from_bytes(obj[_LABEL_Y], "big"),
            crypto.P256,
        )
        return COSEPublicKey(ecdsa=numbers.public_key())
    if algorithm == ALGORITHM_ED25519:
        return COSEPublicKey(
            ed25519=ed25519.Ed25519PublicKey.from_public_bytes(obj[_LABEL_X])
        )
    raise ValueError(f"Unsupported COSE public key algorithm: {algorithm}")


def marshal_cose_private_key(key: COSEPrivateKey) -> bytes:
    if key.ecdsa is not None:
        private_numbers = key.ecdsa.private_numbers()
        public_numbers = private_numbers.public_numbers
        return marshal_cbor(
            {
                _LABEL_KTY: KEY_TYPE_EC2,
                _LABEL_ALG: ALGORITHM_ES256,
                _LABEL_CRV: CURVE_P256,
                _LABEL_X: _int_to_coord(public_numbers.x),
                _LABEL_Y: _int_to_coord(public_numbers.y),
                _LABEL_D: _int_to_coord(private_numbers.private_value),
            }
        )
    if key.ed25519 is not None:
        from cryptography.hazmat.primitives import serialization

        public_raw = key.ed25519.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        seed = key.ed25519.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        return marshal_cbor(
            {
                _LABEL_KTY: KEY_TYPE_OKP,
                _LABEL_ALG: ALGORITHM_ED25519,
                _LABEL_CRV: CURVE_ED25519,
                _LABEL_X: public_raw,
                _LABEL_D: seed,
            }
        )
    raise ValueError("No key provided in private key struct")


def unmarshal_cose_private_key(data: bytes) -> COSEPrivateKey:
    obj = cbor2.loads(data)
    if not isinstance(obj, dict):
        raise ValueError("COSE private key is not a CBOR map")
    algorithm = obj.get(_LABEL_ALG)
    if algorithm == ALGORITHM_ES256:
        if obj.get(_LABEL_CRV) != CURVE_P256:
            raise ValueError("Curve is not P-256")
        private_value = int.from_bytes(obj[_LABEL_D], "big")
        key = ec.derive_private_key(private_value, crypto.P256)
        # Sanity check the embedded public coordinates when present.
        numbers = key.public_key().public_numbers()
        if _LABEL_X in obj and int.from_bytes(obj[_LABEL_X], "big") != numbers.x:
            raise ValueError("COSE private key X does not match derived key")
        return COSEPrivateKey(ecdsa=key)
    if algorithm == ALGORITHM_ED25519:
        return COSEPrivateKey(
            ed25519=ed25519.Ed25519PrivateKey.from_private_bytes(obj[_LABEL_D])
        )
    raise ValueError(f"Unsupported COSE private key algorithm: {algorithm}")
