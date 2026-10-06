"""Port of upstream ctap/ctap_test.go, plus ClientPIN protocol coverage."""

import hashlib

import cbor2
from cryptography.hazmat.primitives import serialization

from virtual_fido import cose, crypto, ctap, identities
from virtual_fido.webauthn import (
    PublicKeyCredentialRPEntity,
    PublicKeyCredentialUserEntity,
)


class DummyCTAPClient:
    def __init__(self, pin_enabled=False):
        self.vault = identities.IdentityVault()
        self.pin_enabled = pin_enabled
        self._pin_hash = None
        self._pin_retries = 8
        self._pin_key = crypto.ECDHKey()
        self._pin_token = crypto.random_bytes(32)
        self.ca_key = identities.create_ca_private_key()
        self.ca = identities.create_self_signed_ca(self.ca_key)

    def supports_resident_key(self):
        return True

    def supports_pin(self):
        return self.pin_enabled

    def new_credential_source(self, params, exclude_list, relying_party, user):
        return self.vault.new_identity(relying_party, user)

    def get_assertion_source(self, relying_party_id, allow_list):
        sources = self.vault.get_matching_credential_sources(relying_party_id, allow_list)
        return sources[0] if sources else None

    def create_attestation_certificate(self, private_key):
        cert = identities.create_self_signed_attestation_certificate(
            self.ca, self.ca_key, private_key
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def pin_hash(self):
        return self._pin_hash

    def set_pin_hash(self, pin_hash):
        self._pin_hash = pin_hash

    def pin_retries(self):
        return self._pin_retries

    def set_pin_retries(self, retries):
        self._pin_retries = retries

    def pin_key_agreement(self):
        return self._pin_key

    def pin_token(self):
        return self._pin_token

    def approve_account_creation(self, relying_party):
        return True

    def approve_account_login(self, credential_source):
        return True


def make_credential_message(rp_id="example.com"):
    args = {
        1: b"\x00" * 32,
        2: {"id": rp_id, "name": "Example"},
        3: {"id": bytes([0, 1, 2, 3, 4]), "displayName": "DisplayAlice", "name": "Alice"},
        4: [{"type": "public-key", "alg": cose.ALGORITHM_ES256}],
        5: [],
        7: {"rk": True},
    }
    return bytes([ctap.COMMAND_MAKE_CREDENTIAL]) + cbor2.dumps(args)


def test_make_credential():
    server = ctap.CTAPServer(DummyCTAPClient())
    response = server.handle_message(make_credential_message())
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    body = cbor2.loads(response[1:])
    assert body[1] == "packed"
    auth_data = body[2]
    # rpIdHash + flags + counter + AAGUID + credential id length
    assert auth_data[:32] == hashlib.sha256(b"example.com").digest()
    flags = auth_data[32]
    assert flags & ctap.FLAG_USER_PRESENT
    assert flags & ctap.FLAG_ATTESTED_DATA_INCLUDED
    assert auth_data[37 : 37 + 16] == ctap.AAGUID
    att_stmt = body[3]
    assert att_stmt["alg"] == cose.ALGORITHM_ES256
    assert att_stmt["sig"]
    assert att_stmt["x5c"]
    # Verify attestation signature with the attested public key
    cred_id_len = int.from_bytes(auth_data[53:55], "big")
    public_key = cose.unmarshal_cose_public_key(auth_data[55 + cred_id_len :])
    assert public_key.verify(auth_data + b"\x00" * 32, att_stmt["sig"])


def test_make_credential_unsupported_algorithm():
    server = ctap.CTAPServer(DummyCTAPClient())
    args = {
        1: b"\x00" * 32,
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01", "displayName": "A", "name": "A"},
        4: [{"type": "public-key", "alg": cose.ALGORITHM_ED25519}],
    }
    response = server.handle_message(
        bytes([ctap.COMMAND_MAKE_CREDENTIAL]) + cbor2.dumps(args)
    )
    assert response == bytes([ctap.CTAP2_ERR_UNSUPPORTED_ALGORITHM])


def test_get_assertion():
    client = DummyCTAPClient()
    server = ctap.CTAPServer(client)
    identity = client.vault.new_identity(
        PublicKeyCredentialRPEntity(id="rp", name="rp"),
        PublicKeyCredentialUserEntity(id=bytes([0, 1, 2, 3, 4]), display_name="Alice", name="Alice"),
    )
    client_data_hash = crypto.hash_sha256(bytes([0, 1, 2, 3, 4]))
    args = {
        1: "rp",
        2: client_data_hash,
        3: [{"type": "public-key", "id": identity.id, "transports": ["USB"]}],
        5: {},
    }
    response = server.handle_message(
        bytes([ctap.COMMAND_GET_ASSERTION]) + cbor2.dumps(args)
    )
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    body = cbor2.loads(response[1:])
    assert body[1]["id"] == identity.id
    # Signature verifies against the credential public key
    auth_data, signature = body[2], body[3]
    assert identity.private_key.public().verify(auth_data + client_data_hash, signature)


def test_get_assertion_no_credentials():
    server = ctap.CTAPServer(DummyCTAPClient())
    args = {1: "unknown-rp", 2: b"\x00" * 32, 3: [], 5: {}}
    response = server.handle_message(
        bytes([ctap.COMMAND_GET_ASSERTION]) + cbor2.dumps(args)
    )
    assert response == bytes([ctap.CTAP2_ERR_NO_CREDENTIALS])


def test_get_info():
    server = ctap.CTAPServer(DummyCTAPClient())
    response = server.handle_message(bytes([ctap.COMMAND_GET_INFO]))
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    body = cbor2.loads(response[1:])
    assert "U2F_V2" in body[1]
    assert "FIDO_2_0" in body[1]
    assert body[3] == ctap.AAGUID
    assert body[4]["rk"] is True
    assert body[4]["plat"] is False
    assert 6 not in body  # no PIN protocols when PIN unsupported


def test_get_info_with_pin():
    server = ctap.CTAPServer(DummyCTAPClient(pin_enabled=True))
    body = cbor2.loads(server.handle_message(bytes([ctap.COMMAND_GET_INFO]))[1:])
    assert body[4]["clientPin"] is False  # supported but not set
    # CTAP2.1 advertised so modern browsers use the permissions token flow
    assert "FIDO_2_1" in body[1]
    assert body[4]["pinUvAuthToken"] is True
    assert set(body[6]) == {1, 2}  # both PIN/UV auth protocols


# ---------------------------------------------------------------------------
# ClientPIN protocols 1 and 2 — full platform-side simulation
# ---------------------------------------------------------------------------

import pytest  # noqa: E402

from virtual_fido import pin_protocol  # noqa: E402


class PlatformPIN:
    """Simulates the platform side of a PIN/UV auth protocol, driving the
    server exactly as a browser would (getKeyAgreement -> token -> use)."""

    def __init__(self, server, version=1):
        self.server = server
        self.version = version
        self.protocol = pin_protocol.get(version)
        self.key = crypto.ECDHKey()
        response = self._send({1: version, 2: ctap.PIN_SUBCOMMAND_GET_KEY_AGREEMENT})
        authenticator_key = response[1]
        self.shared_secret = self.protocol.derive_shared_secret(
            self.key,
            int.from_bytes(authenticator_key[-2], "big"),
            int.from_bytes(authenticator_key[-3], "big"),
        )

    def _send(self, args):
        response = self._send_raw(args)
        assert response[0] == ctap.CTAP1_ERR_SUCCESS, f"PIN error 0x{response[0]:02x}"
        return cbor2.loads(response[1:]) if len(response) > 1 else {}

    def _send_raw(self, args):
        return self.server.handle_message(
            bytes([ctap.COMMAND_CLIENT_PIN]) + cbor2.dumps(args)
        )

    def key_agreement_obj(self):
        x, y = self.key.public_numbers()
        return {
            1: cose.KEY_TYPE_EC2,
            3: cose.ALGORITHM_ECDH_HKDF_256,
            -1: cose.CURVE_P256,
            -2: x.to_bytes(32, "big"),
            -3: y.to_bytes(32, "big"),
        }

    def set_pin(self, pin: bytes):
        new_pin_encoding = self.protocol.encrypt(self.shared_secret, pin.ljust(64, b"\x00"))
        pin_auth = self.protocol.authenticate(self.shared_secret, new_pin_encoding)
        return self._send_raw(
            {
                1: self.version,
                2: ctap.PIN_SUBCOMMAND_SET_PIN,
                3: self.key_agreement_obj(),
                4: pin_auth,
                5: new_pin_encoding,
            }
        )

    def get_pin_token(self, pin: bytes, with_permissions=False):
        pin_hash_encoding = self.protocol.encrypt(
            self.shared_secret, crypto.hash_sha256(pin)[:16]
        )
        if with_permissions:
            args = {
                1: self.version,
                2: ctap.PIN_SUBCOMMAND_GET_TOKEN_USING_PIN_WITH_PERMISSIONS,
                3: self.key_agreement_obj(),
                6: pin_hash_encoding,
                9: 0x01,  # permissions: mc
                10: "example.com",  # rpId
            }
        else:
            args = {
                1: self.version,
                2: ctap.PIN_SUBCOMMAND_GET_PIN_TOKEN,
                3: self.key_agreement_obj(),
                6: pin_hash_encoding,
            }
        return self._send_raw(args)

    def decrypt_token(self, response) -> bytes:
        return self.protocol.decrypt(self.shared_secret, cbor2.loads(response[1:])[2])

    def pin_uv_auth_param(self, token: bytes, message: bytes) -> bytes:
        return self.protocol.authenticate(token, message)


@pytest.mark.parametrize("version", [1, 2])
def test_pin_set_and_get_token(version):
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    platform = PlatformPIN(server, version)

    assert platform.set_pin(b"1234") == bytes([ctap.CTAP1_ERR_SUCCESS])
    assert client.pin_hash() == crypto.hash_sha256(b"1234")[:16]

    response = platform.get_pin_token(b"1234")
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    assert platform.decrypt_token(response) == client.pin_token()
    assert client.pin_retries() == 8

    response = platform.get_pin_token(b"9999")
    assert response == bytes([ctap.CTAP2_ERR_PIN_INVALID])
    assert client.pin_retries() == 7


@pytest.mark.parametrize("version", [1, 2])
def test_get_token_using_pin_with_permissions(version):
    """Subcommand 0x09 — the modern browser flow that previously failed."""
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    platform = PlatformPIN(server, version)
    platform.set_pin(b"1234")

    response = platform.get_pin_token(b"1234", with_permissions=True)
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    assert platform.decrypt_token(response) == client.pin_token()


@pytest.mark.parametrize("version", [1, 2])
def test_full_pin_make_credential_and_get_assertion(version):
    """End-to-end: set PIN, get a permissions token, then MakeCredential and
    GetAssertion carrying a valid pinUvAuthParam — the flow a PIN-required
    site drives."""
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    platform = PlatformPIN(server, version)
    platform.set_pin(b"1234")
    token = platform.decrypt_token(platform.get_pin_token(b"1234", with_permissions=True))

    # MakeCredential with pinUvAuthParam over the clientDataHash
    client_data_hash = crypto.hash_sha256(b"reg")
    make_args = {
        1: client_data_hash,
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01", "displayName": "A", "name": "alice"},
        4: [{"type": "public-key", "alg": cose.ALGORITHM_ES256}],
        8: platform.pin_uv_auth_param(token, client_data_hash),
        9: version,
    }
    response = server.handle_message(
        bytes([ctap.COMMAND_MAKE_CREDENTIAL]) + cbor2.dumps(make_args)
    )
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    assert cbor2.loads(response[1:])[2][32] & ctap.FLAG_USER_VERIFIED

    # GetAssertion with pinUvAuthParam
    login_hash = crypto.hash_sha256(b"login")
    get_args = {
        1: "example.com",
        2: login_hash,
        5: {},
        6: platform.pin_uv_auth_param(token, login_hash),
        7: version,
    }
    response = server.handle_message(
        bytes([ctap.COMMAND_GET_ASSERTION]) + cbor2.dumps(get_args)
    )
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    assert cbor2.loads(response[1:])[2][32] & ctap.FLAG_USER_VERIFIED


@pytest.mark.parametrize("version", [1, 2])
def test_make_credential_bad_pin_auth_rejected(version):
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    platform = PlatformPIN(server, version)
    platform.set_pin(b"1234")
    make_args = {
        1: crypto.hash_sha256(b"reg"),
        2: {"id": "example.com", "name": "Example"},
        3: {"id": b"\x01", "displayName": "A", "name": "alice"},
        4: [{"type": "public-key", "alg": cose.ALGORITHM_ES256}],
        8: b"\x00" * 16,  # bogus pinUvAuthParam
        9: version,
    }
    response = server.handle_message(
        bytes([ctap.COMMAND_MAKE_CREDENTIAL]) + cbor2.dumps(make_args)
    )
    assert response == bytes([ctap.CTAP2_ERR_PIN_AUTH_INVALID])


@pytest.mark.parametrize("version", [1, 2])
def test_pin_policy_violation(version):
    client = DummyCTAPClient(pin_enabled=True)
    platform = PlatformPIN(ctap.CTAPServer(client), version)
    assert platform.set_pin(b"123") == bytes([ctap.CTAP2_ERR_PIN_POLICY_VIOLATION])


def test_pin_get_retries():
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    response = server.handle_message(
        bytes([ctap.COMMAND_CLIENT_PIN]) + cbor2.dumps({1: 1, 2: ctap.PIN_SUBCOMMAND_GET_RETRIES})
    )
    assert response[0] == ctap.CTAP1_ERR_SUCCESS
    assert cbor2.loads(response[1:])[3] == 8


def test_client_pin_rejected_when_unsupported():
    server = ctap.CTAPServer(DummyCTAPClient(pin_enabled=False))
    response = server.handle_message(
        bytes([ctap.COMMAND_CLIENT_PIN]) + cbor2.dumps({1: 1, 2: 1})
    )
    assert response == bytes([ctap.CTAP1_ERR_INVALID_COMMAND])


def test_unsupported_pin_protocol_rejected():
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    # Protocol 3 doesn't exist; set-pin with it must be rejected, not crash
    response = server.handle_message(
        bytes([ctap.COMMAND_CLIENT_PIN]) + cbor2.dumps({1: 3, 2: ctap.PIN_SUBCOMMAND_SET_PIN})
    )
    assert response == bytes([ctap.CTAP1_ERR_INVALID_PARAMETER])


def test_make_credential_requires_pin_when_set():
    client = DummyCTAPClient(pin_enabled=True)
    server = ctap.CTAPServer(client)
    platform = PlatformPIN(server)
    platform.set_pin(b"1234")
    response = server.handle_message(make_credential_message())
    assert response == bytes([ctap.CTAP2_ERR_PIN_REQUIRED])
