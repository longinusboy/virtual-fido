"""CTAP2 command server (CBOR-encoded FIDO2 commands).

Port of the Go ctap/ package: MakeCredential, GetAssertion, GetInfo and the
ClientPIN protocol (PIN protocol v1). Behavior mirrors the Go reference;
responses use CTAP2 canonical CBOR.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
from typing import Optional, Protocol

import cbor2

from . import cose, crypto
from .identities import CredentialSource
from .webauthn import (
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParams,
    PublicKeyCredentialRPEntity,
    PublicKeyCredentialUserEntity,
)

logger = logging.getLogger("virtual_fido.ctap")

AAGUID = bytes([117, 108, 90, 245, 236, 166, 1, 163, 47, 198, 211, 12, 226, 242, 1, 197])

# ctapCommand
COMMAND_MAKE_CREDENTIAL = 0x01
COMMAND_GET_ASSERTION = 0x02
COMMAND_GET_INFO = 0x04
COMMAND_CLIENT_PIN = 0x06
COMMAND_RESET = 0x07
COMMAND_GET_NEXT_ASSERTION = 0x08

# ctapStatusCode
CTAP1_ERR_SUCCESS = 0x00
CTAP1_ERR_INVALID_COMMAND = 0x01
CTAP1_ERR_INVALID_PARAMETER = 0x02
CTAP2_ERR_INVALID_CBOR = 0x12
CTAP2_ERR_MISSING_PARAM = 0x14
CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26
CTAP2_ERR_OPERATION_DENIED = 0x27
CTAP2_ERR_NO_CREDENTIALS = 0x2E
CTAP2_ERR_PIN_INVALID = 0x31
CTAP2_ERR_PIN_BLOCKED = 0x32
CTAP2_ERR_PIN_AUTH_INVALID = 0x33
CTAP2_ERR_NO_PIN_SET = 0x35
CTAP2_ERR_PIN_REQUIRED = 0x36
CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37

# authDataFlags
FLAG_USER_PRESENT = 0b00000001
FLAG_USER_VERIFIED = 0b00000100
FLAG_ATTESTED_DATA_INCLUDED = 0b01000000
FLAG_EXTENSION_DATA_INCLUDED = 0b10000000

# clientPINSubcommand
PIN_SUBCOMMAND_GET_RETRIES = 1
PIN_SUBCOMMAND_GET_KEY_AGREEMENT = 2
PIN_SUBCOMMAND_SET_PIN = 3
PIN_SUBCOMMAND_CHANGE_PIN = 4
PIN_SUBCOMMAND_GET_PIN_TOKEN = 5


class CTAPClient(Protocol):
    """What the CTAP2 server needs from the embedding client (ctap.CTAPClient)."""

    def supports_resident_key(self) -> bool: ...

    def supports_pin(self) -> bool: ...

    def new_credential_source(
        self,
        pub_key_cred_params: list[PublicKeyCredentialParams],
        exclude_list: list[PublicKeyCredentialDescriptor],
        relying_party: PublicKeyCredentialRPEntity,
        user: PublicKeyCredentialUserEntity,
    ) -> Optional[CredentialSource]: ...

    def get_assertion_source(
        self,
        relying_party_id: str,
        allow_list: Optional[list[PublicKeyCredentialDescriptor]],
    ) -> Optional[CredentialSource]: ...

    def create_attestation_certificate(self, private_key: cose.COSEPrivateKey) -> bytes: ...

    def pin_hash(self) -> Optional[bytes]: ...

    def set_pin_hash(self, pin_hash: bytes) -> None: ...

    def pin_retries(self) -> int: ...

    def set_pin_retries(self, retries: int) -> None: ...

    def pin_key_agreement(self) -> crypto.ECDHKey: ...

    def pin_token(self) -> bytes: ...

    def approve_account_creation(self, relying_party: str) -> bool: ...

    def approve_account_login(self, credential_source: CredentialSource) -> bool: ...


def make_attested_credential_data(source: CredentialSource) -> bytes:
    encoded_public_key = cose.marshal_cose_public_key(source.private_key.public())
    return (
        AAGUID
        + len(source.id).to_bytes(2, "big")
        + source.id
        + encoded_public_key
    )


def make_auth_data(
    rp_id: str,
    source: CredentialSource,
    attested_credential_data: Optional[bytes],
    flags: int,
) -> bytes:
    if attested_credential_data is not None:
        flags |= FLAG_ATTESTED_DATA_INCLUDED
    else:
        attested_credential_data = b""
    rp_id_hash = hashlib.sha256(rp_id.encode()).digest()
    counter = (source.signature_counter & 0xFFFFFFFF).to_bytes(4, "big")
    return rp_id_hash + bytes([flags]) + counter + attested_credential_data


def _status(code: int) -> bytes:
    return bytes([code])


def _success(response_obj) -> bytes:
    return bytes([CTAP1_ERR_SUCCESS]) + cose.marshal_cbor(response_obj)


class CTAPServer:
    def __init__(self, client: CTAPClient) -> None:
        self._client = client

    def handle_message(self, data: bytes) -> bytes:
        command = data[0]
        logger.debug("CTAP command: 0x%02x", command)
        if command == COMMAND_MAKE_CREDENTIAL:
            return self._handle_make_credential(data[1:])
        if command == COMMAND_GET_INFO:
            return self._handle_get_info()
        if command == COMMAND_GET_ASSERTION:
            return self._handle_get_assertion(data[1:])
        if command == COMMAND_CLIENT_PIN:
            return self._handle_client_pin(data[1:])
        logger.warning("Invalid CTAP command: 0x%02x", command)
        return _status(CTAP1_ERR_INVALID_COMMAND)

    # ------------------------------------------------------------------
    # MakeCredential
    # ------------------------------------------------------------------

    def _handle_make_credential(self, data: bytes) -> bytes:
        try:
            args = cbor2.loads(data)
        except Exception:
            return _status(CTAP2_ERR_INVALID_CBOR)
        client_data_hash: bytes = args.get(1, b"")
        rp = PublicKeyCredentialRPEntity.from_cbor_obj(args.get(2, {}))
        user = PublicKeyCredentialUserEntity.from_cbor_obj(args.get(3, {}))
        params = [PublicKeyCredentialParams.from_cbor_obj(p) for p in args.get(4, [])]
        exclude_list = [
            PublicKeyCredentialDescriptor.from_cbor_obj(d) for d in args.get(5, [])
        ]
        pin_uv_auth_param: Optional[bytes] = args.get(8)
        pin_uv_auth_protocol: int = args.get(9, 0)
        logger.debug("MAKE_CREDENTIAL rp=%s user=%s", rp, user)

        flags = 0
        if not any(
            p.algorithm == cose.ALGORITHM_ES256 and p.type == "public-key"
            for p in params
        ):
            logger.warning("MAKE_CREDENTIAL: unsupported algorithm")
            return _status(CTAP2_ERR_UNSUPPORTED_ALGORITHM)

        if self._client.supports_pin():
            if pin_uv_auth_protocol == 1 and pin_uv_auth_param is not None:
                pin_auth = self._derive_pin_auth(self._client.pin_token(), client_data_hash)
                if not hmac.compare_digest(pin_auth, pin_uv_auth_param):
                    return _status(CTAP2_ERR_PIN_AUTH_INVALID)
                flags |= FLAG_USER_VERIFIED
            elif pin_uv_auth_param is None and self._client.pin_hash() is not None:
                return _status(CTAP2_ERR_PIN_REQUIRED)
            elif pin_uv_auth_param is not None and pin_uv_auth_protocol != 1:
                return _status(CTAP2_ERR_PIN_AUTH_INVALID)

        if not self._client.approve_account_creation(rp.name):
            logger.warning("MAKE_CREDENTIAL: denied by user")
            return _status(CTAP2_ERR_OPERATION_DENIED)
        flags |= FLAG_USER_PRESENT

        source = self._client.new_credential_source(params, exclude_list, rp, user)
        if source is None:
            return _status(CTAP2_ERR_UNSUPPORTED_ALGORITHM)
        attested_credential_data = make_attested_credential_data(source)
        auth_data = make_auth_data(rp.id, source, attested_credential_data, flags)

        attestation_cert = self._client.create_attestation_certificate(source.private_key)
        attestation_signature = source.private_key.sign(auth_data + client_data_hash)
        return _success(
            {
                1: "packed",
                2: auth_data,
                3: {
                    "alg": cose.ALGORITHM_ES256,
                    "sig": attestation_signature,
                    "x5c": [attestation_cert],
                },
            }
        )

    # ------------------------------------------------------------------
    # GetInfo
    # ------------------------------------------------------------------

    def _handle_get_info(self) -> bytes:
        options = {
            "plat": False,
            "rk": self._client.supports_resident_key(),
            "up": True,
        }
        response = {
            1: ["FIDO_2_0", "U2F_V2"],
            3: AAGUID,
            4: options,
        }
        if self._client.supports_pin():
            options["clientPin"] = self._client.pin_hash() is not None
            response[6] = [1]
        logger.debug("GET_INFO response: %s", response)
        return _success(response)

    # ------------------------------------------------------------------
    # GetAssertion
    # ------------------------------------------------------------------

    def _handle_get_assertion(self, data: bytes) -> bytes:
        try:
            args = cbor2.loads(data)
        except Exception:
            return _status(CTAP2_ERR_INVALID_CBOR)
        rp_id: str = args.get(1, "")
        client_data_hash: bytes = args.get(2, b"")
        allow_list_raw = args.get(3)
        allow_list = (
            [PublicKeyCredentialDescriptor.from_cbor_obj(d) for d in allow_list_raw]
            if allow_list_raw is not None
            else None
        )
        options: dict = args.get(5, {}) or {}
        pin_uv_auth_param: Optional[bytes] = args.get(6)
        pin_uv_auth_protocol: int = args.get(7, 0)
        logger.debug("GET_ASSERTION rp_id=%s", rp_id)

        flags = 0
        if self._client.supports_pin() and pin_uv_auth_param is not None:
            if pin_uv_auth_protocol != 1:
                return _status(CTAP2_ERR_PIN_AUTH_INVALID)
            pin_auth = self._derive_pin_auth(self._client.pin_token(), client_data_hash)
            if not hmac.compare_digest(pin_auth, pin_uv_auth_param):
                return _status(CTAP2_ERR_PIN_AUTH_INVALID)
            flags |= FLAG_USER_VERIFIED

        source = self._client.get_assertion_source(rp_id, allow_list)
        if source is None:
            logger.warning("GET_ASSERTION: no credentials")
            return _status(CTAP2_ERR_NO_CREDENTIALS)

        user_presence = options.get("up", True)
        if user_presence:
            if not self._client.approve_account_login(source):
                logger.warning("GET_ASSERTION: denied by user")
                return _status(CTAP2_ERR_OPERATION_DENIED)
            flags |= FLAG_USER_PRESENT

        auth_data = make_auth_data(rp_id, source, None, flags)
        signature = source.private_key.sign(auth_data + client_data_hash)
        return _success(
            {
                1: source.ctap_descriptor().to_cbor_obj(),
                2: auth_data,
                3: signature,
            }
        )

    # ------------------------------------------------------------------
    # ClientPIN (PIN protocol v1)
    # ------------------------------------------------------------------

    def _get_pin_shared_secret(self, key_agreement: dict) -> bytes:
        remote_x = int.from_bytes(key_agreement[-2], "big")
        remote_y = int.from_bytes(key_agreement[-3], "big")
        return crypto.hash_sha256(
            self._client.pin_key_agreement().ecdh(remote_x, remote_y)
        )

    def _derive_pin_auth(self, shared_secret: bytes, data: bytes) -> bytes:
        return hmac.new(shared_secret, data, hashlib.sha256).digest()[:16]

    @staticmethod
    def _decrypt_pin(shared_secret: bytes, pin_encoding: bytes) -> bytes:
        padded = crypto.decrypt_aes_cbc(shared_secret, pin_encoding)
        index = padded.find(b"\x00")
        return padded[:index] if index >= 0 else b""

    def _handle_client_pin(self, data: bytes) -> bytes:
        if not self._client.supports_pin():
            return _status(CTAP1_ERR_INVALID_COMMAND)
        try:
            args = cbor2.loads(data)
        except Exception:
            return _status(CTAP2_ERR_INVALID_CBOR)
        if args.get(1) != 1:  # pinUvAuthProtocol
            return _status(CTAP1_ERR_INVALID_PARAMETER)
        subcommand = args.get(2)
        key_agreement: Optional[dict] = args.get(3)
        pin_uv_auth_param: Optional[bytes] = args.get(4)
        new_pin_encoding: Optional[bytes] = args.get(5)
        pin_hash_encoding: Optional[bytes] = args.get(6)
        logger.debug("CLIENT_PIN subcommand=%s", subcommand)

        if subcommand == PIN_SUBCOMMAND_GET_RETRIES:
            return _success({3: self._client.pin_retries()})
        if subcommand == PIN_SUBCOMMAND_GET_KEY_AGREEMENT:
            x, y = self._client.pin_key_agreement().public_numbers()
            return _success(
                {
                    1: {
                        1: cose.KEY_TYPE_EC2,
                        3: cose.ALGORITHM_ECDH_HKDF_256,
                        -1: cose.CURVE_P256,
                        -2: x.to_bytes(32, "big"),
                        -3: y.to_bytes(32, "big"),
                    }
                }
            )
        if subcommand == PIN_SUBCOMMAND_SET_PIN:
            return self._handle_set_pin(key_agreement, pin_uv_auth_param, new_pin_encoding)
        if subcommand == PIN_SUBCOMMAND_CHANGE_PIN:
            return self._handle_change_pin(
                key_agreement, pin_uv_auth_param, new_pin_encoding, pin_hash_encoding
            )
        if subcommand == PIN_SUBCOMMAND_GET_PIN_TOKEN:
            return self._handle_get_pin_token(key_agreement, pin_hash_encoding)
        return _status(CTAP2_ERR_MISSING_PARAM)

    def _handle_set_pin(
        self,
        key_agreement: Optional[dict],
        pin_uv_auth_param: Optional[bytes],
        new_pin_encoding: Optional[bytes],
    ) -> bytes:
        if self._client.pin_hash() is not None:
            return _status(CTAP2_ERR_PIN_AUTH_INVALID)
        if key_agreement is None or pin_uv_auth_param is None or new_pin_encoding is None:
            return _status(CTAP2_ERR_MISSING_PARAM)
        shared_secret = self._get_pin_shared_secret(key_agreement)
        pin_auth = self._derive_pin_auth(shared_secret, new_pin_encoding)
        if not hmac.compare_digest(pin_auth, pin_uv_auth_param):
            return _status(CTAP2_ERR_PIN_AUTH_INVALID)
        pin = self._decrypt_pin(shared_secret, new_pin_encoding)
        if len(pin) < 4:
            return _status(CTAP2_ERR_PIN_POLICY_VIOLATION)
        self._client.set_pin_retries(8)
        self._client.set_pin_hash(crypto.hash_sha256(pin)[:16])
        return _status(CTAP1_ERR_SUCCESS)

    def _handle_change_pin(
        self,
        key_agreement: Optional[dict],
        pin_uv_auth_param: Optional[bytes],
        new_pin_encoding: Optional[bytes],
        pin_hash_encoding: Optional[bytes],
    ) -> bytes:
        if key_agreement is None or pin_uv_auth_param is None:
            return _status(CTAP2_ERR_MISSING_PARAM)
        if self._client.pin_retries() == 0:
            return _status(CTAP2_ERR_PIN_BLOCKED)
        shared_secret = self._get_pin_shared_secret(key_agreement)
        pin_auth = self._derive_pin_auth(
            shared_secret, (new_pin_encoding or b"") + (pin_hash_encoding or b"")
        )
        if not hmac.compare_digest(pin_auth, pin_uv_auth_param):
            return _status(CTAP2_ERR_PIN_AUTH_INVALID)
        self._client.set_pin_retries(self._client.pin_retries() - 1)
        decrypted_pin_hash = crypto.decrypt_aes_cbc(shared_secret, pin_hash_encoding or b"")
        if not hmac.compare_digest(self._client.pin_hash() or b"", decrypted_pin_hash):
            return _status(CTAP2_ERR_PIN_INVALID)
        self._client.set_pin_retries(8)
        new_pin = self._decrypt_pin(shared_secret, new_pin_encoding or b"")
        if len(new_pin) < 4:
            return _status(CTAP2_ERR_PIN_POLICY_VIOLATION)
        self._client.set_pin_hash(crypto.hash_sha256(new_pin)[:16])
        return _status(CTAP1_ERR_SUCCESS)

    def _handle_get_pin_token(
        self, key_agreement: Optional[dict], pin_hash_encoding: Optional[bytes]
    ) -> bytes:
        if pin_hash_encoding is None or key_agreement is None:
            return _status(CTAP2_ERR_MISSING_PARAM)
        if self._client.pin_retries() <= 0:
            return _status(CTAP2_ERR_PIN_BLOCKED)
        shared_secret = self._get_pin_shared_secret(key_agreement)
        self._client.set_pin_retries(self._client.pin_retries() - 1)
        pin_hash = crypto.decrypt_aes_cbc(shared_secret, pin_hash_encoding)
        if not hmac.compare_digest(pin_hash, self._client.pin_hash() or b""):
            logger.warning("GET_PIN_TOKEN: PIN mismatch")
            return _status(CTAP2_ERR_PIN_INVALID)
        self._client.set_pin_retries(8)
        return _success(
            {2: crypto.encrypt_aes_cbc(shared_secret, self._client.pin_token())}
        )
