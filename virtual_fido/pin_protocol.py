"""PIN/UV auth protocols 1 and 2 (CTAP2.1 §6.5).

The two protocols differ in how the ECDH output becomes a shared secret and
how that secret encrypts/authenticates data:

- Protocol 1: shared secret = SHA-256(Z); AES-256-CBC with a zero IV;
  authenticate = left 16 bytes of HMAC-SHA-256.
- Protocol 2: shared secret = HKDF(Z) -> 32-byte HMAC key ‖ 32-byte AES key;
  AES-256-CBC with a random IV prepended to the ciphertext; authenticate =
  full HMAC-SHA-256.

`Z` is the X coordinate of the ECDH shared point (crypto.ECDHKey.ecdh).
"""

from __future__ import annotations

import hmac
from typing import Optional

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from . import crypto

PROTOCOL_V1 = 1
PROTOCOL_V2 = 2
SUPPORTED_PROTOCOLS = (PROTOCOL_V1, PROTOCOL_V2)


class _PinProtocolV1:
    version = PROTOCOL_V1

    def derive_shared_secret(self, ecdh_key: crypto.ECDHKey, x: int, y: int) -> bytes:
        return crypto.hash_sha256(ecdh_key.ecdh(x, y))

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        return crypto.aes_cbc_encrypt(key, b"\x00" * 16, plaintext)

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        return crypto.aes_cbc_decrypt(key, b"\x00" * 16, ciphertext)

    def authenticate(self, key: bytes, message: bytes) -> bytes:
        return hmac.new(key, message, "sha256").digest()[:16]


class _PinProtocolV2:
    version = PROTOCOL_V2

    def derive_shared_secret(self, ecdh_key: crypto.ECDHKey, x: int, y: int) -> bytes:
        z = ecdh_key.ecdh(x, y)
        hmac_key = HKDF(SHA256(), 32, salt=b"\x00" * 32, info=b"CTAP2 HMAC key").derive(z)
        aes_key = HKDF(SHA256(), 32, salt=b"\x00" * 32, info=b"CTAP2 AES key").derive(z)
        return hmac_key + aes_key

    def encrypt(self, key: bytes, plaintext: bytes) -> bytes:
        aes_key = key[32:] if len(key) > 32 else key
        iv = crypto.random_bytes(16)
        return iv + crypto.aes_cbc_encrypt(aes_key, iv, plaintext)

    def decrypt(self, key: bytes, ciphertext: bytes) -> bytes:
        aes_key = key[32:] if len(key) > 32 else key
        iv, body = ciphertext[:16], ciphertext[16:]
        return crypto.aes_cbc_decrypt(aes_key, iv, body)

    def authenticate(self, key: bytes, message: bytes) -> bytes:
        # Use the HMAC-key portion of the shared secret, or the whole key
        # when it is a bare 32-byte pinUvAuthToken.
        hmac_key = key[:32]
        return hmac.new(hmac_key, message, "sha256").digest()


_PROTOCOLS = {PROTOCOL_V1: _PinProtocolV1(), PROTOCOL_V2: _PinProtocolV2()}


def get(version: int) -> Optional["_PinProtocolV1 | _PinProtocolV2"]:
    """Return the protocol implementation, or None if unsupported."""
    return _PROTOCOLS.get(version)
