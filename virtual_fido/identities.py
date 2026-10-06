"""Credential storage: identity vault, attestation certificates and the
passphrase-encrypted saved state.

Port of the Go identities/ package. The vault file format (JSON with
base64-encoded bytes, scrypt N=32768/r=8/p=1, AES-256-GCM key wrapping) is
compatible with vaults written by the Go implementation.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from . import cose, crypto
from .webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRPEntity,
    PublicKeyCredentialUserEntity,
)

# Vault blob versions:
#   v1 — Go-compatible: scrypt(N=32768) -> AES-GCM key wrap, no version field.
#        Read-only for backward compatibility.
#   v2 — current: stronger scrypt, KDF parameters stored in the blob, and an
#        optional keyfile mixed into the KDF via HKDF so an attacker needs
#        vault + keyfile + passphrase, not just the vault file.
_VAULT_VERSION = 2

_SCRYPT_N_V1 = 32768
# The vault is opened once at startup, so a few hundred ms of KDF is cheap.
_SCRYPT_N_V2 = 131072
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_KEY_LENGTH = 32
_HKDF_INFO = b"virtual-fido vault v2"

# Sanity caps when honoring KDF parameters from a (possibly hostile) blob,
# so a crafted vault file can't demand gigabytes of KDF memory.
_SCRYPT_MAX_N = 2**22
_SCRYPT_MAX_R = 32
_SCRYPT_MAX_P = 16

KEYFILE_SIZE = 32
_KEYFILE_MIN_SIZE = 16


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(value: Optional[str]) -> bytes:
    return base64.b64decode(value) if value else b""


# ---------------------------------------------------------------------------
# Credential sources and the vault (upstream identities/identity_vault.go)
# ---------------------------------------------------------------------------


@dataclass
class CredentialSource:
    type: str
    id: bytes
    private_key: cose.COSEPrivateKey
    relying_party: PublicKeyCredentialRPEntity
    user: PublicKeyCredentialUserEntity
    signature_counter: int = 0

    def ctap_descriptor(self) -> PublicKeyCredentialDescriptor:
        return PublicKeyCredentialDescriptor(type="public-key", id=self.id)


class IdentityVault:
    def __init__(self) -> None:
        self.credential_sources: list[CredentialSource] = []

    def new_identity(
        self,
        relying_party: PublicKeyCredentialRPEntity,
        user: PublicKeyCredentialUserEntity,
    ) -> CredentialSource:
        source = CredentialSource(
            type="public-key",
            id=crypto.random_bytes(16),
            private_key=cose.COSEPrivateKey(ecdsa=crypto.generate_ecdsa_key()),
            relying_party=relying_party,
            user=user,
            signature_counter=0,
        )
        self.add_identity(source)
        return source

    def add_identity(self, source: CredentialSource) -> None:
        self.credential_sources.append(source)

    def delete_identity(self, credential_id: bytes) -> bool:
        for i, source in enumerate(self.credential_sources):
            if source.id == credential_id:
                del self.credential_sources[i]
                return True
        return False

    def get_matching_credential_sources(
        self,
        relying_party_id: str,
        allow_list: Optional[list[PublicKeyCredentialDescriptor]] = None,
    ) -> list[CredentialSource]:
        sources = []
        for source in self.credential_sources:
            if source.relying_party.id != relying_party_id:
                continue
            if allow_list is not None:
                if any(allowed.id == source.id for allowed in allow_list):
                    sources.append(source)
            else:
                sources.append(source)
        return sources

    def export(self) -> list[dict]:
        """Vault-file JSON objects (SavedCredentialSource)."""
        return [
            {
                "type": source.type,
                "id": _b64(source.id),
                "private_key": _b64(cose.marshal_cose_private_key(source.private_key)),
                "relying_party": source.relying_party.to_json_obj(),
                "user": source.user.to_json_obj(),
                "signature_counter": source.signature_counter,
            }
            for source in self.credential_sources
        ]

    def import_sources(self, sources: list[dict]) -> None:
        for obj in sources:
            key_bytes = _unb64(obj.get("private_key"))
            try:
                private_key = cose.unmarshal_cose_private_key(key_bytes)
            except Exception:
                # Vaults written by old Go versions store SEC1 EC keys
                ecdsa_key = serialization.load_der_private_key(key_bytes, None)
                if not isinstance(ecdsa_key, ec.EllipticCurvePrivateKey):
                    raise ValueError("Invalid private key for credential source")
                private_key = cose.COSEPrivateKey(ecdsa=ecdsa_key)
            self.add_identity(
                CredentialSource(
                    type=obj.get("type", "public-key"),
                    id=_unb64(obj.get("id")),
                    private_key=private_key,
                    relying_party=PublicKeyCredentialRPEntity.from_json_obj(
                        obj.get("relying_party", {})
                    ),
                    user=PublicKeyCredentialUserEntity.from_json_obj(
                        obj.get("user", {})
                    ),
                    signature_counter=obj.get("signature_counter", 0),
                )
            )


# ---------------------------------------------------------------------------
# Encrypted saved state (upstream identities/saved_state.go)
# ---------------------------------------------------------------------------


@dataclass
class FIDODeviceConfig:
    encryption_key: bytes
    attestation_certificate: bytes  # DER
    attestation_private_key: bytes  # COSE-marshalled
    authentication_counter: int
    pin_enabled: bool = False
    pin_hash: bytes = b""
    sources: list[dict] = field(default_factory=list)
    # Additive, optional sections for the non-FIDO YubiKey applications.
    # Keyed by slot/credential; opaque JSON owned by the respective subsystem.
    otp_slots: dict = field(default_factory=dict)
    oath: dict = field(default_factory=dict)  # CCID OATH applet state
    piv: dict = field(default_factory=dict)  # CCID PIV applet state


class VaultDecryptionError(Exception):
    """The vault could not be decrypted (wrong passphrase/keyfile, missing
    keyfile, or corrupted file)."""


def _scrypt(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return hashlib.scrypt(
        passphrase.encode(),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=_SCRYPT_KEY_LENGTH,
        maxmem=128 * n * r * 2,
    )


def _derive_kek_v2(
    passphrase: str, salt: bytes, n: int, r: int, p: int, keyfile: Optional[bytes]
) -> bytes:
    """v2 key-encryption key: HKDF over scrypt(passphrase) plus the keyfile.

    The keyfile is a second, independent secret: without it the KDF output
    cannot be brute-forced from the vault file alone.
    """
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm = _scrypt(passphrase, salt, n, r, p) + (keyfile or b"")
    return HKDF(
        algorithm=SHA256(), length=_SCRYPT_KEY_LENGTH, salt=salt, info=_HKDF_INFO
    ).derive(ikm)


def _check_keyfile(keyfile: Optional[bytes]) -> None:
    if keyfile is not None and len(keyfile) < _KEYFILE_MIN_SIZE:
        raise ValueError(f"Keyfile must be at least {_KEYFILE_MIN_SIZE} bytes")


def generate_keyfile() -> bytes:
    """Fresh keyfile material; store it on separate media from the vault."""
    return crypto.random_bytes(KEYFILE_SIZE)


def encrypt_with_passphrase(
    passphrase: str, data: bytes, keyfile: Optional[bytes] = None
) -> bytes:
    """Encrypt to the current (v2) vault blob format.

    scrypt(passphrase) — mixed with the keyfile when one is configured —
    wraps a fresh random key which encrypts the data.
    """
    _check_keyfile(keyfile)
    salt = crypto.random_bytes(16)
    key_encryption_key = _derive_kek_v2(
        passphrase, salt, _SCRYPT_N_V2, _SCRYPT_R, _SCRYPT_P, keyfile
    )
    encryption_key = crypto.generate_symmetric_key()
    encrypted_key, key_nonce = crypto.encrypt(key_encryption_key, encryption_key)
    encrypted_data, data_nonce = crypto.encrypt(encryption_key, data)
    blob = {
        "version": _VAULT_VERSION,
        "kdf": {"name": "scrypt", "n": _SCRYPT_N_V2, "r": _SCRYPT_R, "p": _SCRYPT_P},
        "keyfile": keyfile is not None,
        "salt": _b64(salt),
        "encryption_key": _b64(encrypted_key),
        "key_nonce": _b64(key_nonce),
        "encrypted_data": _b64(encrypted_data),
        "data_nonce": _b64(data_nonce),
    }
    return json.dumps(blob).encode()


def decrypt_with_passphrase(
    passphrase: str, data: bytes, keyfile: Optional[bytes] = None
) -> bytes:
    """Decrypt a vault blob: current v2 format, or legacy v1 (Go-compatible,
    identified by the absence of a version field)."""
    _check_keyfile(keyfile)
    try:
        blob = json.loads(data)
        version = blob.get("version", 1)
        salt = _unb64(blob["salt"])
    except (ValueError, KeyError, TypeError) as err:
        raise VaultDecryptionError(f"Vault file is not a valid vault blob: {err}") from err

    if version == 1:
        # Keyfiles did not exist in v1; ignore one if supplied so a v1 vault
        # opened with a newly configured keyfile still loads (the next save
        # rewrites it as v2 with the keyfile mixed in).
        key_encryption_key = _scrypt(passphrase, salt, _SCRYPT_N_V1, _SCRYPT_R, _SCRYPT_P)
    elif version == 2:
        kdf = blob.get("kdf", {})
        n, r, p = kdf.get("n", 0), kdf.get("r", 0), kdf.get("p", 0)
        if (
            kdf.get("name") != "scrypt"
            or not (0 < n <= _SCRYPT_MAX_N and (n & (n - 1)) == 0)
            or not (0 < r <= _SCRYPT_MAX_R)
            or not (0 < p <= _SCRYPT_MAX_P)
        ):
            raise VaultDecryptionError(f"Unsupported vault KDF parameters: {kdf}")
        if blob.get("keyfile"):
            if keyfile is None:
                raise VaultDecryptionError(
                    "This vault is protected by a keyfile; provide it (--keyfile)"
                )
        else:
            keyfile = None
        key_encryption_key = _derive_kek_v2(passphrase, salt, n, r, p, keyfile)
    else:
        raise VaultDecryptionError(f"Unsupported vault version: {version}")

    try:
        encryption_key = crypto.decrypt(
            key_encryption_key, _unb64(blob["encryption_key"]), _unb64(blob["key_nonce"])
        )
        return crypto.decrypt(
            encryption_key, _unb64(blob["encrypted_data"]), _unb64(blob["data_nonce"])
        )
    except Exception as err:
        raise VaultDecryptionError(
            "Could not decrypt vault: wrong passphrase or keyfile"
        ) from err


def encrypt_fido_state(
    state: FIDODeviceConfig, passphrase: str, keyfile: Optional[bytes] = None
) -> bytes:
    obj = {
        "encryption_key": _b64(state.encryption_key),
        "attestation_certificate": _b64(state.attestation_certificate),
        "attestation_private_key": _b64(state.attestation_private_key),
        "authentication_counter": state.authentication_counter,
        "sources": state.sources,
    }
    # Go uses omitempty for the PIN fields
    if state.pin_enabled:
        obj["pin_enabled"] = True
    if state.pin_hash:
        obj["pin_hash"] = _b64(state.pin_hash)
    if state.otp_slots:
        obj["otp_slots"] = state.otp_slots
    if state.oath:
        obj["oath"] = state.oath
    if state.piv:
        obj["piv"] = state.piv
    return encrypt_with_passphrase(passphrase, json.dumps(obj).encode(), keyfile)


def decrypt_fido_state(
    data: bytes, passphrase: str, keyfile: Optional[bytes] = None
) -> FIDODeviceConfig:
    obj = json.loads(decrypt_with_passphrase(passphrase, data, keyfile))
    return FIDODeviceConfig(
        encryption_key=_unb64(obj.get("encryption_key")),
        attestation_certificate=_unb64(obj.get("attestation_certificate")),
        attestation_private_key=_unb64(obj.get("attestation_private_key")),
        authentication_counter=obj.get("authentication_counter", 0),
        pin_enabled=obj.get("pin_enabled", False),
        pin_hash=_unb64(obj.get("pin_hash")),
        sources=obj.get("sources", []) or [],
        otp_slots=obj.get("otp_slots", {}) or {},
        oath=obj.get("oath", {}) or {},
        piv=obj.get("piv", {}) or {},
    )


# ---------------------------------------------------------------------------
# Attestation certificates (upstream identities/attestation.go)
# ---------------------------------------------------------------------------


def _crypto_key(key: cose.COSEPrivateKey):
    if key.ecdsa is not None:
        return key.ecdsa
    if key.ed25519 is not None:
        return key.ed25519
    raise ValueError("No supported private key data")


def create_ca_private_key() -> cose.COSEPrivateKey:
    return cose.COSEPrivateKey(ecdsa=crypto.generate_ecdsa_key())


def create_self_signed_ca(private_key: cose.COSEPrivateKey) -> x509.Certificate:
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Self-Signed Virtual FIDO"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    key = _crypto_key(private_key)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        # Deviation: the Go original uses serial 0 (flagged TODO there);
        # the cryptography library requires a positive serial.
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 10))
        .public_key(key.public_key())
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


def create_self_signed_attestation_certificate(
    certificate_authority: x509.Certificate,
    ca_private_key: cose.COSEPrivateKey,
    target_private_key: cose.COSEPrivateKey,
) -> x509.Certificate:
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Self-Signed Virtual FIDO"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Self-Signed Virtual FIDO"),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"
            ),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(certificate_authority.subject)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now.replace(year=now.year + 10))
        .public_key(_crypto_key(target_private_key).public_key())
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]
            ),
            critical=False,
        )
        .sign(_crypto_key(ca_private_key), hashes.SHA256())
    )
