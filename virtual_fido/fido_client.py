"""Default FIDO client: credential storage, approvals and PIN state.

Port of the Go fido_client/ package. This is the piece embedders customize:
`DefaultFIDOClient` implements both the CTAP2 and U2F client interfaces, and
delegates user approval and vault persistence to two small interfaces.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Optional, Protocol

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from . import cose, crypto, identities
from .identities import CredentialSource, FIDODeviceConfig, IdentityVault
from .webauthn import (
    KeyHandle,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialParams,
    PublicKeyCredentialRPEntity,
    PublicKeyCredentialUserEntity,
)

logger = logging.getLogger("virtual_fido.client")


class ClientAction(enum.IntEnum):
    U2F_REGISTER = 0
    U2F_AUTHENTICATE = 1
    FIDO_MAKE_CREDENTIAL = 2
    FIDO_GET_ASSERTION = 3


@dataclass
class ClientActionRequestParams:
    relying_party: str = ""
    user_name: str = ""


class ClientRequestApprover(Protocol):
    """Approves or denies each registration/login (terminal prompt, UI, ...)."""

    def approve_client_action(
        self, action: ClientAction, params: ClientActionRequestParams
    ) -> bool: ...


class ClientDataSaver(Protocol):
    """Persists the encrypted vault and provides its passphrase.

    Implementations may additionally expose `keyfile() -> Optional[bytes]`
    to mix a second secret into the vault KDF — an attacker then needs the
    vault file, the keyfile AND the passphrase. Store the keyfile on
    separate media from the vault (USB stick, different mount, ...).
    """

    def save_data(self, data: bytes) -> None: ...

    def retrieve_data(self) -> Optional[bytes]: ...

    def passphrase(self) -> str: ...


class DefaultFIDOClient:
    """Reference implementation of the CTAP2 + U2F client interfaces
    (fido_client.DefaultFIDOClient)."""

    def __init__(
        self,
        attestation_ca_certificate: x509.Certificate,
        attestation_ca_private_key: cose.COSEPrivateKey,
        secret_encryption_key: bytes,
        enable_pin: bool,
        request_approver: ClientRequestApprover,
        data_saver: ClientDataSaver,
    ) -> None:
        assert len(secret_encryption_key) == 32
        self._device_encryption_key = secret_encryption_key
        self._certificate_authority = attestation_ca_certificate
        self._cert_private_key = attestation_ca_private_key
        self._authentication_counter = 1
        self._pin_enabled = enable_pin
        # 32 bytes: required by PIN/UV auth protocol 2, works for protocol 1 too
        self._pin_token = crypto.random_bytes(32)
        self._pin_key_agreement = crypto.ECDHKey()
        self._pin_retries = 8
        self._pin_hash: Optional[bytes] = None
        self.vault = IdentityVault()
        # OTP slots: {slot_number: opaque JSON dict owned by the otp module}.
        self.otp_slots: dict[int, dict] = {}
        # OATH applet state: opaque JSON dict owned by the ccid/oath module.
        self.oath_state: dict = {}
        self._request_approver = request_approver
        self._data_saver = data_saver
        self._load_data()

    # ------------------------------------------------------------------
    # CTAP2 client interface
    # ------------------------------------------------------------------

    def supports_resident_key(self) -> bool:
        return True

    def new_credential_source(
        self,
        pub_key_cred_params: list[PublicKeyCredentialParams],
        exclude_list: list[PublicKeyCredentialDescriptor],
        relying_party: PublicKeyCredentialRPEntity,
        user: PublicKeyCredentialUserEntity,
    ) -> Optional[CredentialSource]:
        if not any(
            p.algorithm == cose.ALGORITHM_ES256 and p.type == "public-key"
            for p in pub_key_cred_params
        ):
            return None
        source = self.vault.new_identity(relying_party, user)
        self._save_data()
        return source

    def get_assertion_source(
        self,
        relying_party_id: str,
        allow_list: Optional[list[PublicKeyCredentialDescriptor]],
    ) -> Optional[CredentialSource]:
        sources = self.vault.get_matching_credential_sources(relying_party_id, allow_list)
        if not sources:
            logger.warning("No credentials for %s", relying_party_id)
            return None
        # TODO (inherited from Go): let the user pick between sources
        source = sources[0]
        source.signature_counter += 1
        self._save_data()
        return source

    def approve_account_creation(self, relying_party: str) -> bool:
        return self._request_approver.approve_client_action(
            ClientAction.FIDO_MAKE_CREDENTIAL,
            ClientActionRequestParams(relying_party=relying_party),
        )

    def approve_account_login(self, credential_source: CredentialSource) -> bool:
        return self._request_approver.approve_client_action(
            ClientAction.FIDO_GET_ASSERTION,
            ClientActionRequestParams(
                relying_party=credential_source.relying_party.name,
                user_name=credential_source.user.name,
            ),
        )

    # ------------------------------------------------------------------
    # PIN management
    # ------------------------------------------------------------------

    def enable_pin(self) -> None:
        self._pin_enabled = True
        self._save_data()

    def disable_pin(self) -> None:
        self._pin_enabled = False
        self._save_data()

    def supports_pin(self) -> bool:
        return self._pin_enabled

    def pin_hash(self) -> Optional[bytes]:
        return self._pin_hash

    def set_pin(self, pin: bytes) -> None:
        self.set_pin_hash(crypto.hash_sha256(pin)[:16])

    def set_pin_hash(self, pin_hash: Optional[bytes]) -> None:
        self._pin_hash = pin_hash
        self._save_data()

    def pin_retries(self) -> int:
        assert 0 < self._pin_retries <= 8, "Invalid PIN retries"
        return self._pin_retries

    def set_pin_retries(self, retries: int) -> None:
        self._pin_retries = retries

    def pin_key_agreement(self) -> crypto.ECDHKey:
        return self._pin_key_agreement

    def pin_token(self) -> bytes:
        return self._pin_token

    # ------------------------------------------------------------------
    # U2F client interface
    # ------------------------------------------------------------------

    def sealing_encryption_key(self) -> bytes:
        return self._device_encryption_key

    def new_private_key(self) -> ec.EllipticCurvePrivateKey:
        return crypto.generate_ecdsa_key()

    def new_authentication_counter_id(self) -> int:
        value = self._authentication_counter
        self._authentication_counter += 1
        return value

    def create_attestation_certificate(self, private_key: cose.COSEPrivateKey) -> bytes:
        cert = identities.create_self_signed_attestation_certificate(
            self._certificate_authority, self._cert_private_key, private_key
        )
        return cert.public_bytes(serialization.Encoding.DER)

    def approve_u2f_registration(self, key_handle: KeyHandle) -> bool:
        return self._request_approver.approve_client_action(
            ClientAction.U2F_REGISTER, ClientActionRequestParams()
        )

    def approve_u2f_authentication(self, key_handle: KeyHandle) -> bool:
        return self._request_approver.approve_client_action(
            ClientAction.U2F_AUTHENTICATE, ClientActionRequestParams()
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _keyfile(self) -> Optional[bytes]:
        getter = getattr(self._data_saver, "keyfile", None)
        return getter() if callable(getter) else None

    def export_data(self, passphrase: str, keyfile: Optional[bytes] = None) -> bytes:
        state = FIDODeviceConfig(
            encryption_key=self._device_encryption_key,
            attestation_certificate=self._certificate_authority.public_bytes(
                serialization.Encoding.DER
            ),
            attestation_private_key=cose.marshal_cose_private_key(self._cert_private_key),
            authentication_counter=self._authentication_counter,
            pin_enabled=self._pin_enabled,
            pin_hash=self._pin_hash or b"",
            sources=self.vault.export(),
            otp_slots={str(n): obj for n, obj in self.otp_slots.items()},
            oath=self.oath_state,
        )
        return identities.encrypt_fido_state(state, passphrase, keyfile)

    def import_data(
        self, data: bytes, passphrase: str, keyfile: Optional[bytes] = None
    ) -> None:
        state = identities.decrypt_fido_state(data, passphrase, keyfile)
        certificate = x509.load_der_x509_certificate(state.attestation_certificate)
        try:
            private_key = cose.unmarshal_cose_private_key(state.attestation_private_key)
        except Exception:
            # Vaults written by old Go versions store SEC1 EC keys
            ecdsa_key = serialization.load_der_private_key(
                state.attestation_private_key, None
            )
            if not isinstance(ecdsa_key, ec.EllipticCurvePrivateKey):
                raise ValueError("Could not parse attestation private key")
            private_key = cose.COSEPrivateKey(ecdsa=ecdsa_key)
        self._device_encryption_key = state.encryption_key
        self._certificate_authority = certificate
        self._cert_private_key = private_key
        self._authentication_counter = state.authentication_counter
        self._pin_enabled = state.pin_enabled
        self._pin_hash = state.pin_hash or None
        self.vault = IdentityVault()
        self.vault.import_sources(state.sources)
        self.otp_slots = {int(n): obj for n, obj in (state.otp_slots or {}).items()}
        self.oath_state = state.oath or {}

    def set_otp_slot(self, slot_number: int, slot_obj: dict) -> None:
        self.otp_slots[slot_number] = slot_obj
        self._save_data()

    def save_oath_state(self, state: dict) -> None:
        """Persist OATH applet state (called by the applet on mutations)."""
        self.oath_state = state
        self._save_data()

    def reload_otp_slots(self) -> dict[int, dict]:
        """Re-read just the OTP slots from the vault, without disturbing live
        FIDO/PIN state. Lets a running server pick up slots provisioned after
        it started."""
        data = self._data_saver.retrieve_data()
        if data:
            state = identities.decrypt_fido_state(
                data, self._data_saver.passphrase(), self._keyfile()
            )
            self.otp_slots = {int(n): obj for n, obj in (state.otp_slots or {}).items()}
        return self.otp_slots

    def _save_data(self) -> None:
        self._data_saver.save_data(
            self.export_data(self._data_saver.passphrase(), self._keyfile())
        )

    def _load_data(self) -> None:
        data = self._data_saver.retrieve_data()
        if data:
            self.import_data(data, self._data_saver.passphrase(), self._keyfile())

    # ------------------------------------------------------------------
    # Vault management (for CLIs/embedders)
    # ------------------------------------------------------------------

    def identities(self) -> list[CredentialSource]:
        return list(self.vault.credential_sources)

    def delete_identity(self, credential_id: bytes) -> bool:
        if self.vault.delete_identity(credential_id):
            self._save_data()
            return True
        return False
