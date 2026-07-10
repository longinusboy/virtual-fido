"""Cryptographic primitives.

Port of the Go crypto/ package on top of the `cryptography` library:
ECDSA (P-256), Ed25519, AES-256-GCM, AES-CBC (zero IV, for the CTAP PIN
protocol), SHA-256 and P-256 ECDH.

Deliberate deviation from Go: coordinates and ECDH shared secrets are
fixed-length 32-byte values as the FIDO spec requires. The Go original uses
big.Int.Bytes(), which strips leading zero bytes and breaks ~1/256 of
exchanges.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

P256 = ec.SECP256R1()
_COORD_SIZE = 32


def random_bytes(length: int) -> bytes:
    return os.urandom(length)


def generate_symmetric_key() -> bytes:
    return random_bytes(32)


def generate_ecdsa_key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(P256)


def generate_ed25519_key() -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.generate()


def encode_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Uncompressed X9.62 point: 0x04 || X || Y (crypto.EncodePublicKey)."""
    return public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )


def decode_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(P256, data)


def encrypt(key: bytes, data: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM; returns (ciphertext-with-tag, nonce)."""
    nonce = random_bytes(12)
    return AESGCM(key).encrypt(nonce, data, None), nonce


def decrypt(key: bytes, data: bytes, nonce: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, data, None)


@dataclass
class EncryptedBox:
    """AES-GCM payload with its IV; CBOR-encoded as {1: data, 2: iv}
    (crypto.EncryptedBox, used for U2F key handles)."""

    data: bytes
    iv: bytes

    def to_cbor_obj(self) -> dict:
        return {1: self.data, 2: self.iv}

    @classmethod
    def from_cbor_obj(cls, obj: dict) -> "EncryptedBox":
        return cls(data=obj[1], iv=obj[2])


def seal(key: bytes, data: bytes) -> EncryptedBox:
    encrypted, iv = encrypt(key, data)
    return EncryptedBox(data=encrypted, iv=iv)


def open_box(key: bytes, box: EncryptedBox) -> bytes:
    return decrypt(key, box.data, box.iv)


def sign_ecdsa(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """SHA-256 + ECDSA, ASN.1/DER signature (crypto.SignECDSA)."""
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def verify_ecdsa(key: ec.EllipticCurvePublicKey, data: bytes, signature: bytes) -> bool:
    try:
        key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False


def sign_ed25519(key: ed25519.Ed25519PrivateKey, data: bytes) -> bytes:
    return key.sign(data)


def verify_ed25519(key: ed25519.Ed25519PublicKey, data: bytes, signature: bytes) -> bool:
    try:
        key.verify(signature, data)
        return True
    except Exception:
        return False


def hash_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()


def encrypt_aes_cbc(key: bytes, data: bytes) -> bytes:
    """AES-CBC with a zero IV — PIN/UV auth protocol 1, where the plaintext
    is itself unpredictable (crypto.EncryptAESCBC)."""
    return aes_cbc_encrypt(key, b"\x00" * 16, data)


def decrypt_aes_cbc(key: bytes, data: bytes) -> bytes:
    return aes_cbc_decrypt(key, b"\x00" * 16, data)


class ECDHKey:
    """P-256 ECDH key agreement for the CTAP PIN protocol (crypto.ECDHKey)."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._private_key = private_key or ec.generate_private_key(P256)

    def public_key_bytes(self) -> bytes:
        return encode_public_key(self._private_key.public_key())

    def public_numbers(self) -> tuple[int, int]:
        numbers = self._private_key.public_key().public_numbers()
        return numbers.x, numbers.y

    def ecdh(self, remote_x: int, remote_y: int) -> bytes:
        """Shared secret: the X coordinate of the ECDH point, fixed 32 bytes."""
        remote = ec.EllipticCurvePublicNumbers(remote_x, remote_y, P256).public_key()
        return self._private_key.exchange(ec.ECDH(), remote)
