"""Vault v2 encryption: keyfile+passphrase KDF, versioning, v1 migration,
and the CLI passphrase/keyfile plumbing."""

import json
from pathlib import Path

import pytest

from virtual_fido import crypto, identities
from virtual_fido.demo import cli
from virtual_fido.identities import VaultDecryptionError

GO_VAULT = Path(__file__).parent / "data" / "go_vault.json"


def test_v2_blob_shape():
    blob = json.loads(identities.encrypt_with_passphrase("pw", b"data"))
    assert blob["version"] == 2
    assert blob["kdf"] == {"name": "scrypt", "n": 131072, "r": 8, "p": 1}
    assert blob["keyfile"] is False
    for field in ("salt", "encryption_key", "key_nonce", "encrypted_data", "data_nonce"):
        assert field in blob


def test_v2_roundtrip_without_keyfile():
    blob = identities.encrypt_with_passphrase("pw", b"secret")
    assert identities.decrypt_with_passphrase("pw", blob) == b"secret"
    with pytest.raises(VaultDecryptionError, match="wrong passphrase or keyfile"):
        identities.decrypt_with_passphrase("wrong", blob)


def test_v2_roundtrip_with_keyfile():
    keyfile = identities.generate_keyfile()
    blob = identities.encrypt_with_passphrase("pw", b"secret", keyfile)
    assert json.loads(blob)["keyfile"] is True
    assert identities.decrypt_with_passphrase("pw", blob, keyfile) == b"secret"

    with pytest.raises(VaultDecryptionError, match="keyfile"):
        identities.decrypt_with_passphrase("pw", blob)  # missing keyfile
    with pytest.raises(VaultDecryptionError, match="wrong passphrase or keyfile"):
        identities.decrypt_with_passphrase("pw", blob, identities.generate_keyfile())
    with pytest.raises(VaultDecryptionError, match="wrong passphrase or keyfile"):
        identities.decrypt_with_passphrase("wrong", blob, keyfile)


def test_keyfile_ignored_when_blob_has_none():
    """A newly configured keyfile must not break opening an older vault."""
    blob = identities.encrypt_with_passphrase("pw", b"secret")
    keyfile = identities.generate_keyfile()
    assert identities.decrypt_with_passphrase("pw", blob, keyfile) == b"secret"


def test_short_keyfile_rejected():
    with pytest.raises(ValueError, match="at least 16 bytes"):
        identities.encrypt_with_passphrase("pw", b"data", b"short")


def test_hostile_kdf_params_rejected():
    blob = json.loads(identities.encrypt_with_passphrase("pw", b"data"))
    for bad_kdf in (
        {"name": "scrypt", "n": 2**30, "r": 8, "p": 1},  # gigabytes of memory
        {"name": "scrypt", "n": 12345, "r": 8, "p": 1},  # not a power of two
        {"name": "pbkdf1", "n": 131072, "r": 8, "p": 1},
        {},
    ):
        tampered = dict(blob, kdf=bad_kdf)
        with pytest.raises(VaultDecryptionError, match="KDF"):
            identities.decrypt_with_passphrase("pw", json.dumps(tampered).encode())


def test_garbage_vault_file():
    with pytest.raises(VaultDecryptionError, match="not a valid vault blob"):
        identities.decrypt_with_passphrase("pw", b"not json at all")


def test_v1_go_vault_still_decrypts_and_migrates():
    """The Go-written v1 vault opens (even with a keyfile configured, which
    v1 predates), and re-encrypting produces a v2 blob that requires it."""
    keyfile = identities.generate_keyfile()
    state = identities.decrypt_fido_state(GO_VAULT.read_bytes(), "test-passphrase")
    # keyfile is ignored for v1
    state_again = identities.decrypt_fido_state(
        GO_VAULT.read_bytes(), "test-passphrase", keyfile
    )
    assert state_again.encryption_key == state.encryption_key

    migrated = identities.encrypt_fido_state(state, "test-passphrase", keyfile)
    assert json.loads(migrated)["version"] == 2
    assert json.loads(migrated)["keyfile"] is True
    restored = identities.decrypt_fido_state(migrated, "test-passphrase", keyfile)
    assert restored.sources == state.sources
    with pytest.raises(VaultDecryptionError):
        identities.decrypt_fido_state(migrated, "test-passphrase")


def test_client_adopts_keyfile_on_save(tmp_path):
    """DefaultFIDOClient with a keyfile-bearing data saver: vault saved with
    the keyfile mixed in, reload works, reload without keyfile fails."""
    import hashlib

    from virtual_fido import cose
    from virtual_fido.fido_client import DefaultFIDOClient
    from virtual_fido.webauthn import (
        PublicKeyCredentialParams,
        PublicKeyCredentialRPEntity,
        PublicKeyCredentialUserEntity,
    )

    class KeyfileSupport:
        def __init__(self, keyfile_bytes):
            self.data = None
            self.keyfile_bytes = keyfile_bytes

        def approve_client_action(self, action, params):
            return True

        def save_data(self, data):
            self.data = data

        def retrieve_data(self):
            return self.data

        def passphrase(self):
            return "pw"

        def keyfile(self):
            return self.keyfile_bytes

    def make_client(support):
        ca_key = identities.create_ca_private_key()
        ca = identities.create_self_signed_ca(ca_key)
        return DefaultFIDOClient(
            attestation_ca_certificate=ca,
            attestation_ca_private_key=ca_key,
            secret_encryption_key=hashlib.sha256(b"test").digest(),
            enable_pin=False,
            request_approver=support,
            data_saver=support,
        )

    keyfile = identities.generate_keyfile()
    support = KeyfileSupport(keyfile)
    client = make_client(support)
    rp = PublicKeyCredentialRPEntity(id="example.com", name="Example")
    user = PublicKeyCredentialUserEntity(id=b"\x01", display_name="A", name="alice")
    params = [PublicKeyCredentialParams(type="public-key", algorithm=cose.ALGORITHM_ES256)]
    client.new_credential_source(params, [], rp, user)
    assert json.loads(support.data)["keyfile"] is True

    # Reload with the keyfile works
    reloaded = make_client(support)
    assert len(reloaded.identities()) == 1

    # Reload without it fails
    support.keyfile_bytes = None
    with pytest.raises(VaultDecryptionError, match="keyfile"):
        make_client(support)


# ---------------------------------------------------------------------------
# CLI plumbing
# ---------------------------------------------------------------------------


def test_cli_generate_keyfile(tmp_path, capsys):
    keyfile_path = tmp_path / "vault.key"
    cli.main(["--keyfile", str(keyfile_path), "generate-keyfile"])
    assert keyfile_path.stat().st_size == identities.KEYFILE_SIZE
    assert (keyfile_path.stat().st_mode & 0o777) == 0o600
    # Refuses to overwrite an existing keyfile
    with pytest.raises(FileExistsError):
        cli.main(["--keyfile", str(keyfile_path), "generate-keyfile"])


def test_cli_passphrase_file_and_keyfile(tmp_path, capsys):
    vault = tmp_path / "vault.json"
    keyfile_path = tmp_path / "vault.key"
    passphrase_file = tmp_path / "pass.txt"
    passphrase_file.write_text("cli-secret\n")
    cli.main(["--keyfile", str(keyfile_path), "generate-keyfile"])

    cli.main(
        ["--vault", str(vault), "--passphrase-file", str(passphrase_file),
         "--keyfile", str(keyfile_path), "pin", "set", "--pin", "4321"]
    )
    blob = json.loads(vault.read_bytes())
    assert blob["version"] == 2
    assert blob["keyfile"] is True
    state = identities.decrypt_fido_state(
        vault.read_bytes(), "cli-secret", keyfile_path.read_bytes()
    )
    assert state.pin_hash == crypto.hash_sha256(b"4321")[:16]


def test_cli_passphrase_flag_warns(tmp_path, capsys):
    vault = tmp_path / "vault.json"
    cli.main(["--vault", str(vault), "--passphrase", "pw", "list"])
    assert "WARNING" in capsys.readouterr().err


def test_cli_interactive_prompt(tmp_path, monkeypatch, capsys):
    vault = tmp_path / "vault.json"
    monkeypatch.setattr("getpass.getpass", lambda prompt: "prompted-secret")
    cli.main(["--vault", str(vault), "pin", "set", "--pin", "9876"])
    state = identities.decrypt_fido_state(vault.read_bytes(), "prompted-secret")
    assert state.pin_hash == crypto.hash_sha256(b"9876")[:16]


@pytest.mark.parametrize("pin", ["0000", "0123", "00000000"])
def test_cli_pin_preserves_leading_zeros(tmp_path, pin):
    """Regression: '--pin 0000' must not be parsed as the integer 0."""
    vault = tmp_path / "vault.json"
    cli.main(["--vault", str(vault), "--passphrase", "pw", "pin", "set", "--pin", pin])
    state = identities.decrypt_fido_state(vault.read_bytes(), "pw")
    assert state.pin_hash == crypto.hash_sha256(pin.encode())[:16]


def test_cli_pin_too_short_rejected(tmp_path, capsys):
    vault = tmp_path / "vault.json"
    with pytest.raises(SystemExit):
        cli.main(["--vault", str(vault), "--passphrase", "pw", "pin", "set", "--pin", "12"])
    assert "at least 4" in capsys.readouterr().err
