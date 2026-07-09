"""Port of u2f/u2f_test.go, plus authenticate-flow coverage."""

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from virtual_fido import crypto, identities, u2f


class DummyU2FClient:
    def __init__(self):
        self.encryption_key = crypto.hash_sha256(b"test")
        self.ca_key = identities.create_ca_private_key()
        self.ca = identities.create_self_signed_ca(self.ca_key)
        self.counter = 0
        self.approve_registration = True
        self.approve_authentication = True

    def sealing_encryption_key(self):
        return self.encryption_key

    def new_private_key(self):
        return crypto.generate_ecdsa_key()

    def new_authentication_counter_id(self):
        value = self.counter
        self.counter += 1
        return value

    def create_attestation_certificate(self, private_key):
        cert = identities.create_self_signed_attestation_certificate(
            self.ca, self.ca_key, private_key
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def approve_u2f_registration(self, key_handle):
        return self.approve_registration

    def approve_u2f_authentication(self, key_handle):
        return self.approve_authentication


def u2f_message(command, param1=0, param2=0, request=b""):
    message = bytes([0, command, param1, param2])
    if request:
        message += b"\x00" + len(request).to_bytes(2, "big") + request
    return message


def parse_der_length(data):
    """Total length of the DER element at the start of `data`."""
    assert data[0] == 0x30  # SEQUENCE
    first = data[1]
    if first < 0x80:
        return 2 + first
    num_bytes = first & 0x7F
    return 2 + num_bytes + int.from_bytes(data[2 : 2 + num_bytes], "big")


def register(server):
    challenge = crypto.random_bytes(32)
    application = crypto.random_bytes(32)
    response = server.handle_message(
        u2f_message(u2f.COMMAND_REGISTER, request=challenge + application)
    )
    return challenge, application, response


def test_version():
    server = u2f.U2FServer(DummyU2FClient())
    response = server.handle_message(u2f_message(u2f.COMMAND_VERSION))
    assert response == b"U2F_V2" + (0x9000).to_bytes(2, "big")


def test_registration():
    server = u2f.U2FServer(DummyU2FClient())
    challenge, application, response = register(server)

    assert response[0] == 0x05
    encoded_public_key = response[1:66]
    public_key = crypto.decode_public_key(encoded_public_key)
    key_handle_length = response[66]
    key_handle = response[67 : 67 + key_handle_length]
    rest = response[67 + key_handle_length :]
    cert_length = parse_der_length(rest)
    certificate = x509.load_der_x509_certificate(rest[:cert_length])
    signature = rest[cert_length:-2]
    status = int.from_bytes(response[-2:], "big")
    assert status == u2f.SW_NO_ERROR

    # Certificate carries the same public key that was returned
    cert_public = certificate.public_key()
    assert crypto.encode_public_key(cert_public) == encoded_public_key

    # Registration signature verifies (same layout as the Go test)
    signature_data = b"\x00" + application + challenge + key_handle + encoded_public_key
    assert crypto.verify_ecdsa(public_key, signature_data, signature)


def test_registration_denied():
    client = DummyU2FClient()
    client.approve_registration = False
    server = u2f.U2FServer(client)
    _, _, response = register(server)
    assert response == u2f.SW_CONDITIONS_NOT_SATISFIED.to_bytes(2, "big")


def test_authenticate_roundtrip():
    client = DummyU2FClient()
    server = u2f.U2FServer(client)
    challenge, application, response = register(server)
    encoded_public_key = response[1:66]
    public_key = crypto.decode_public_key(encoded_public_key)
    key_handle_length = response[66]
    key_handle = response[67 : 67 + key_handle_length]

    new_challenge = crypto.random_bytes(32)
    request = new_challenge + application + bytes([key_handle_length]) + key_handle

    # CHECK_ONLY on a valid key handle reports "conditions not satisfied"
    response = server.handle_message(
        u2f_message(u2f.COMMAND_AUTHENTICATE, param1=u2f.AUTH_CONTROL_CHECK_ONLY, request=request)
    )
    assert response == u2f.SW_CONDITIONS_NOT_SATISFIED.to_bytes(2, "big")

    # ENFORCE_USER_PRESENCE_AND_SIGN produces a valid signature
    response = server.handle_message(
        u2f_message(
            u2f.COMMAND_AUTHENTICATE,
            param1=u2f.AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN,
            request=request,
        )
    )
    assert int.from_bytes(response[-2:], "big") == u2f.SW_NO_ERROR
    assert response[0] == 0x01  # user presence
    counter = response[1:5]
    signature = response[5:-2]
    signature_data = application + b"\x01" + counter + new_challenge
    assert crypto.verify_ecdsa(public_key, signature_data, signature)


def test_authenticate_wrong_application():
    client = DummyU2FClient()
    server = u2f.U2FServer(client)
    challenge, application, response = register(server)
    key_handle_length = response[66]
    key_handle = response[67 : 67 + key_handle_length]

    wrong_application = crypto.random_bytes(32)
    request = challenge + wrong_application + bytes([key_handle_length]) + key_handle
    response = server.handle_message(
        u2f_message(u2f.COMMAND_AUTHENTICATE, param1=u2f.AUTH_CONTROL_SIGN, request=request)
    )
    assert response == u2f.SW_WRONG_DATA.to_bytes(2, "big")


def test_authenticate_garbage_key_handle():
    server = u2f.U2FServer(DummyU2FClient())
    garbage = crypto.random_bytes(40)
    request = crypto.random_bytes(64) + bytes([len(garbage)]) + garbage
    response = server.handle_message(
        u2f_message(u2f.COMMAND_AUTHENTICATE, param1=u2f.AUTH_CONTROL_SIGN, request=request)
    )
    assert response == u2f.SW_WRONG_DATA.to_bytes(2, "big")
