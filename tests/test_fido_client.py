"""DefaultFIDOClient persistence and approval-delegation tests."""

import hashlib

from virtual_fido import cose, crypto, identities
from virtual_fido.fido_client import (
    ClientAction,
    ClientActionRequestParams,
    DefaultFIDOClient,
)
from virtual_fido.webauthn import (
    PublicKeyCredentialParams,
    PublicKeyCredentialRPEntity,
    PublicKeyCredentialUserEntity,
)


class MemorySupport:
    def __init__(self, passphrase="pw", approve=True):
        self.data = None
        self.passphrase_value = passphrase
        self.approve = approve
        self.actions = []

    def approve_client_action(self, action, params):
        self.actions.append((action, params))
        return self.approve

    def save_data(self, data):
        self.data = data

    def retrieve_data(self):
        return self.data

    def passphrase(self):
        return self.passphrase_value


def make_client(support=None):
    support = support or MemorySupport()
    ca_key = identities.create_ca_private_key()
    ca = identities.create_self_signed_ca(ca_key)
    client = DefaultFIDOClient(
        attestation_ca_certificate=ca,
        attestation_ca_private_key=ca_key,
        secret_encryption_key=hashlib.sha256(b"test").digest(),
        enable_pin=False,
        request_approver=support,
        data_saver=support,
    )
    return client, support


ES256_PARAM = [PublicKeyCredentialParams(type="public-key", algorithm=cose.ALGORITHM_ES256)]


def test_new_credential_persists_and_reloads():
    client, support = make_client()
    rp = PublicKeyCredentialRPEntity(id="example.com", name="Example")
    user = PublicKeyCredentialUserEntity(id=b"\x01", display_name="A", name="alice")
    source = client.new_credential_source(ES256_PARAM, [], rp, user)
    assert source is not None
    assert support.data is not None  # saved on creation

    # A new client over the same storage sees the credential
    reloaded, _ = make_client(support)
    assert len(reloaded.identities()) == 1
    got = reloaded.identities()[0]
    assert got.id == source.id
    assert got.relying_party.id == "example.com"
    assert got.private_key == source.private_key


def test_unsupported_algorithm_returns_none():
    client, _ = make_client()
    rp = PublicKeyCredentialRPEntity(id="x", name="x")
    user = PublicKeyCredentialUserEntity(id=b"\x01", display_name="A", name="a")
    bad = [PublicKeyCredentialParams(type="public-key", algorithm=cose.ALGORITHM_ED25519)]
    assert client.new_credential_source(bad, [], rp, user) is None


def test_assertion_increments_counter():
    client, support = make_client()
    rp = PublicKeyCredentialRPEntity(id="example.com", name="Example")
    user = PublicKeyCredentialUserEntity(id=b"\x01", display_name="A", name="alice")
    source = client.new_credential_source(ES256_PARAM, [], rp, user)
    start = source.signature_counter
    got = client.get_assertion_source("example.com", None)
    assert got.signature_counter == start + 1


def test_approval_delegation():
    support = MemorySupport(approve=False)
    client, _ = make_client(support)
    assert client.approve_account_creation("bank.com") is False
    action, params = support.actions[-1]
    assert action == ClientAction.FIDO_MAKE_CREDENTIAL
    assert params.relying_party == "bank.com"


def test_delete_identity():
    client, _ = make_client()
    rp = PublicKeyCredentialRPEntity(id="example.com", name="Example")
    user = PublicKeyCredentialUserEntity(id=b"\x01", display_name="A", name="alice")
    source = client.new_credential_source(ES256_PARAM, [], rp, user)
    assert client.delete_identity(source.id)
    assert client.identities() == []


def test_pin_lifecycle_persists():
    client, support = make_client()
    assert not client.supports_pin()
    client.enable_pin()
    client.set_pin(b"1234")
    reloaded, _ = make_client(support)
    assert reloaded.supports_pin()
    assert reloaded.pin_hash() == crypto.hash_sha256(b"1234")[:16]
