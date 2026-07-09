"""Vault, saved-state and attestation tests, including decryption of a
golden vault file written by the Go implementation (tests/data/go_vault.json,
passphrase "test-passphrase")."""

from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from virtual_fido import cose, crypto, identities
from virtual_fido.webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialRPEntity,
    PublicKeyCredentialUserEntity,
)

GO_VAULT = Path(__file__).parent / "data" / "go_vault.json"


def make_vault_with_identity():
    vault = identities.IdentityVault()
    rp = PublicKeyCredentialRPEntity(id="example.com", name="Example")
    user = PublicKeyCredentialUserEntity(id=b"\x01\x02", display_name="U", name="u@example.com")
    source = vault.new_identity(rp, user)
    return vault, source


def test_new_identity_and_matching():
    vault, source = make_vault_with_identity()
    assert len(source.id) == 16
    assert vault.get_matching_credential_sources("example.com") == [source]
    assert vault.get_matching_credential_sources("other.com") == []
    allow = [PublicKeyCredentialDescriptor(type="public-key", id=source.id)]
    assert vault.get_matching_credential_sources("example.com", allow) == [source]
    wrong = [PublicKeyCredentialDescriptor(type="public-key", id=b"nope")]
    assert vault.get_matching_credential_sources("example.com", wrong) == []


def test_delete_identity():
    vault, source = make_vault_with_identity()
    assert not vault.delete_identity(b"missing")
    assert vault.delete_identity(source.id)
    assert vault.credential_sources == []


def test_vault_export_import_roundtrip():
    vault, source = make_vault_with_identity()
    source.signature_counter = 9
    exported = vault.export()
    restored = identities.IdentityVault()
    restored.import_sources(exported)
    assert len(restored.credential_sources) == 1
    got = restored.credential_sources[0]
    assert got.id == source.id
    assert got.private_key == source.private_key
    assert got.relying_party == source.relying_party
    assert got.user == source.user
    assert got.signature_counter == 9


def test_passphrase_encryption_roundtrip():
    data = b"secret vault contents"
    blob = identities.encrypt_with_passphrase("hunter2", data)
    assert identities.decrypt_with_passphrase("hunter2", blob) == data
    with pytest.raises(Exception):
        identities.decrypt_with_passphrase("wrong", blob)


def test_fido_state_roundtrip():
    vault, _ = make_vault_with_identity()
    ca_key = identities.create_ca_private_key()
    ca = identities.create_self_signed_ca(ca_key)
    state = identities.FIDODeviceConfig(
        encryption_key=crypto.generate_symmetric_key(),
        attestation_certificate=ca.public_bytes(serialization.Encoding.DER),
        attestation_private_key=cose.marshal_cose_private_key(ca_key),
        authentication_counter=5,
        pin_enabled=True,
        pin_hash=crypto.hash_sha256(b"1234")[:16],
        sources=vault.export(),
    )
    blob = identities.encrypt_fido_state(state, "pw")
    restored = identities.decrypt_fido_state(blob, "pw")
    assert restored.encryption_key == state.encryption_key
    assert restored.attestation_certificate == state.attestation_certificate
    assert restored.authentication_counter == 5
    assert restored.pin_enabled is True
    assert restored.pin_hash == state.pin_hash
    assert restored.sources == state.sources


def test_decrypt_go_written_vault():
    """Format compatibility: a vault created by the Go implementation must
    decrypt and import cleanly."""
    state = identities.decrypt_fido_state(GO_VAULT.read_bytes(), "test-passphrase")
    assert len(state.encryption_key) == 32
    assert state.authentication_counter == 7
    assert state.pin_enabled is True
    assert state.pin_hash == crypto.hash_sha256(b"1234")[:16]

    # Attestation certificate parses and matches the private key
    cert = x509.load_der_x509_certificate(state.attestation_certificate)
    ca_key = cose.unmarshal_cose_private_key(state.attestation_private_key)
    assert cert.public_key().public_numbers() == ca_key.ecdsa.public_key().public_numbers()

    # Credential source imports and is usable for signing
    vault = identities.IdentityVault()
    vault.import_sources(state.sources)
    assert len(vault.credential_sources) == 1
    source = vault.credential_sources[0]
    assert source.relying_party.id == "example.com"
    assert source.relying_party.name == "Example"
    assert source.user.id == b"\x01\x02\x03\x04"
    assert source.user.display_name == "Test User"
    assert source.user.name == "test@example.com"
    assert source.signature_counter == 42
    signature = source.private_key.sign(b"challenge")
    assert source.private_key.public().verify(b"challenge", signature)


def test_attestation_certificate_chain():
    ca_key = identities.create_ca_private_key()
    ca = identities.create_self_signed_ca(ca_key)
    target_key = cose.COSEPrivateKey(ecdsa=crypto.generate_ecdsa_key())
    cert = identities.create_self_signed_attestation_certificate(ca, ca_key, target_key)
    assert cert.issuer == ca.subject
    # Signature chain verifies against the CA key
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256())
    )
