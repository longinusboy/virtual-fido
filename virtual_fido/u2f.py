"""U2F / CTAP1 command server (legacy 2FA protocol).

Port of the Go u2f/ package: REGISTER, AUTHENTICATE and VERSION over the
APDU-style U2F framing. Credentials are stateless: the private key travels
inside an AES-GCM-sealed key handle held by the relying party.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Protocol

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import cose, crypto
from ._util import ProtocolError
from .webauthn import KeyHandle

logger = logging.getLogger("virtual_fido.u2f")

# U2FCommand
COMMAND_REGISTER = 0x01
COMMAND_AUTHENTICATE = 0x02
COMMAND_VERSION = 0x03

# U2FStatusWord
SW_NO_ERROR = 0x9000
SW_CONDITIONS_NOT_SATISFIED = 0x6985
SW_WRONG_DATA = 0x6A80
SW_WRONG_LENGTH = 0x6700
SW_CLA_NOT_SUPPORTED = 0x6E00
SW_INS_NOT_SUPPORTED = 0x6D00

# U2FAuthenticateControl
AUTH_CONTROL_CHECK_ONLY = 0x07
AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN = 0x03
AUTH_CONTROL_SIGN = 0x08


def _sw(status_word: int) -> bytes:
    return status_word.to_bytes(2, "big")


@dataclass
class U2FMessageHeader:
    cla: int
    command: int
    param1: int
    param2: int


class U2FClient(Protocol):
    """What the U2F server needs from the embedding client (u2f.U2FClient)."""

    def sealing_encryption_key(self) -> bytes: ...

    def new_private_key(self) -> ec.EllipticCurvePrivateKey: ...

    def new_authentication_counter_id(self) -> int: ...

    def create_attestation_certificate(self, private_key: cose.COSEPrivateKey) -> bytes: ...

    def approve_u2f_registration(self, key_handle: KeyHandle) -> bool: ...

    def approve_u2f_authentication(self, key_handle: KeyHandle) -> bool: ...


def decode_u2f_message(message: bytes) -> tuple[U2FMessageHeader, bytes, int]:
    """Split an APDU-style U2F message into header, request payload and
    expected response length (u2f.decodeU2FMessage)."""
    header = U2FMessageHeader(message[0], message[1], message[2], message[3])
    rest = message[4:]
    if not rest:
        # No request length, no response length
        return header, b"", 0
    # Extended-length APDU: a request or response length starts with a 0 byte
    if rest[0] != 0:
        raise ProtocolError(f"Invalid U2F payload length: {message.hex()}")
    length = int.from_bytes(rest[1:3], "big")
    rest = rest[3:]
    if not rest:
        # No payload, so length must be the response length
        return header, b"", length
    request = rest[:length]
    rest = rest[length:]
    if not rest:
        return header, request, 0
    return header, request, int.from_bytes(rest[:2], "big")


class U2FServer:
    def __init__(self, client: U2FClient) -> None:
        self._client = client

    def handle_message(self, message: bytes) -> bytes:
        header, request, response_length = decode_u2f_message(message)
        logger.debug(
            "U2F command=0x%02x request=%d bytes response_length=%d",
            header.command,
            len(request),
            response_length,
        )
        if header.command == COMMAND_VERSION:
            return b"U2F_V2" + _sw(SW_NO_ERROR)
        if header.command == COMMAND_REGISTER:
            return self._handle_register(header, request)
        if header.command == COMMAND_AUTHENTICATE:
            return self._handle_authenticate(header, request)
        logger.warning("Invalid U2F command: 0x%02x", header.command)
        return _sw(SW_INS_NOT_SUPPORTED)

    # ------------------------------------------------------------------
    # Key handles
    # ------------------------------------------------------------------

    def _seal_key_handle(self, key_handle: KeyHandle) -> bytes:
        box = crypto.seal(
            self._client.sealing_encryption_key(),
            cose.marshal_cbor(key_handle.to_cbor_obj()),
        )
        return cose.marshal_cbor(box.to_cbor_obj())

    def _open_key_handle(self, box_bytes: bytes) -> Optional[KeyHandle]:
        try:
            box = crypto.EncryptedBox.from_cbor_obj(cbor2.loads(box_bytes))
            data = crypto.open_box(self._client.sealing_encryption_key(), box)
            return KeyHandle.from_cbor_obj(cbor2.loads(data))
        except Exception as err:
            logger.warning("Invalid key handle: %s", err)
            return None

    # ------------------------------------------------------------------
    # Commands
    # ------------------------------------------------------------------

    def _handle_register(self, header: U2FMessageHeader, request: bytes) -> bytes:
        challenge = request[:32]
        application = request[32:]
        if len(challenge) != 32 or len(application) != 32:
            raise ProtocolError("U2F REGISTER: challenge/application not 32 bytes")

        private_key = self._client.new_private_key()
        encoded_public_key = crypto.encode_public_key(private_key.public_key())
        # SEC1 DER, same as Go's x509.MarshalECPrivateKey
        encoded_private_key = private_key.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        unencrypted_key_handle = KeyHandle(
            private_key=encoded_private_key, application_id=application
        )
        key_handle = self._seal_key_handle(unencrypted_key_handle)

        if not self._client.approve_u2f_registration(unencrypted_key_handle):
            return _sw(SW_CONDITIONS_NOT_SATISFIED)

        cose_private_key = cose.COSEPrivateKey(ecdsa=private_key)
        cert = self._client.create_attestation_certificate(cose_private_key)
        signature_data = (
            b"\x00" + application + challenge + key_handle + encoded_public_key
        )
        signature = cose_private_key.sign(signature_data)
        return (
            b"\x05"
            + encoded_public_key
            + bytes([len(key_handle)])
            + key_handle
            + cert
            + signature
            + _sw(SW_NO_ERROR)
        )

    def _handle_authenticate(self, header: U2FMessageHeader, request: bytes) -> bytes:
        control = header.param1
        challenge = request[:32]
        application = request[32:64]
        key_handle_length = request[64]
        encrypted_key_handle = request[65 : 65 + key_handle_length]

        key_handle = self._open_key_handle(encrypted_key_handle)
        if key_handle is None:
            return _sw(SW_WRONG_DATA)
        if not key_handle.private_key or key_handle.application_id != application:
            logger.warning("U2F AUTHENTICATE: invalid key handle contents")
            return _sw(SW_WRONG_DATA)
        private_key = serialization.load_der_private_key(key_handle.private_key, None)
        if not isinstance(private_key, ec.EllipticCurvePrivateKey):
            return _sw(SW_WRONG_DATA)
        cose_private_key = cose.COSEPrivateKey(ecdsa=private_key)

        if control == AUTH_CONTROL_CHECK_ONLY:
            return _sw(SW_CONDITIONS_NOT_SATISFIED)
        if control in (AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN, AUTH_CONTROL_SIGN):
            if control == AUTH_CONTROL_ENFORCE_USER_PRESENCE_AND_SIGN:
                if not self._client.approve_u2f_authentication(key_handle):
                    return _sw(SW_CONDITIONS_NOT_SATISFIED)
            counter = self._client.new_authentication_counter_id()
            counter_bytes = (counter & 0xFFFFFFFF).to_bytes(4, "big")
            signature_data = application + b"\x01" + counter_bytes + challenge
            signature = cose_private_key.sign(signature_data)
            return b"\x01" + counter_bytes + signature + _sw(SW_NO_ERROR)
        # No error specific to an invalid control byte; match the Go original
        return _sw(SW_WRONG_LENGTH)
