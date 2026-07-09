"""Shared WebAuthn data structures (port of the Go webauthn/ package).

Each type carries two serializations, matching the Go struct tags:
- CBOR maps with WebAuthn field names (used on the CTAP2 wire)
- JSON dicts with snake_case names and base64 bytes (used in the vault file,
  format-compatible with vaults written by the Go implementation)
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Optional


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _unb64(value: Optional[str]) -> bytes:
    return base64.b64decode(value) if value else b""


@dataclass
class PublicKeyCredentialRPEntity:
    id: str
    name: str

    def to_json_obj(self) -> dict:
        return {"id": self.id, "name": self.name}

    @classmethod
    def from_json_obj(cls, obj: dict) -> "PublicKeyCredentialRPEntity":
        return cls(id=obj.get("id", ""), name=obj.get("name", ""))

    @classmethod
    def from_cbor_obj(cls, obj: dict) -> "PublicKeyCredentialRPEntity":
        # On the wire "id" may be absent (e.g. U2F AppID flows)
        return cls(id=obj.get("id", ""), name=obj.get("name", ""))

    def to_cbor_obj(self) -> dict:
        return {"id": self.id, "name": self.name}


@dataclass
class PublicKeyCredentialUserEntity:
    id: bytes
    display_name: str
    name: str

    def to_json_obj(self) -> dict:
        # Matches Go json tags: id (base64), display_name, name
        return {"id": _b64(self.id), "display_name": self.display_name, "name": self.name}

    @classmethod
    def from_json_obj(cls, obj: dict) -> "PublicKeyCredentialUserEntity":
        return cls(
            id=_unb64(obj.get("id")),
            display_name=obj.get("display_name", ""),
            name=obj.get("name", ""),
        )

    @classmethod
    def from_cbor_obj(cls, obj: dict) -> "PublicKeyCredentialUserEntity":
        return cls(
            id=obj.get("id", b""),
            display_name=obj.get("displayName", ""),
            name=obj.get("name", ""),
        )

    def to_cbor_obj(self) -> dict:
        return {"id": self.id, "displayName": self.display_name, "name": self.name}


@dataclass
class PublicKeyCredentialDescriptor:
    type: str
    id: bytes
    transports: list[str] = field(default_factory=list)

    @classmethod
    def from_cbor_obj(cls, obj: dict) -> "PublicKeyCredentialDescriptor":
        return cls(
            type=obj.get("type", ""),
            id=obj.get("id", b""),
            transports=obj.get("transports", []) or [],
        )

    def to_cbor_obj(self) -> dict:
        return {"type": self.type, "id": self.id}


@dataclass
class PublicKeyCredentialParams:
    type: str
    algorithm: int

    @classmethod
    def from_cbor_obj(cls, obj: dict) -> "PublicKeyCredentialParams":
        return cls(type=obj.get("type", ""), algorithm=obj.get("alg", 0))


@dataclass
class KeyHandle:
    """U2F key handle payload; CBOR-encoded as {1: private_key, 2: application_id}."""

    private_key: bytes
    application_id: bytes

    def to_cbor_obj(self) -> dict:
        return {1: self.private_key, 2: self.application_id}

    @classmethod
    def from_cbor_obj(cls, obj: dict) -> "KeyHandle":
        return cls(private_key=obj[1], application_id=obj[2])
