"""Unit tests for the PIN/UV auth protocol primitives (CTAP2.1 §6.5)."""

import pytest

from virtual_fido import crypto, pin_protocol


@pytest.mark.parametrize("version", [1, 2])
def test_shared_secret_agreement(version):
    protocol = pin_protocol.get(version)
    a, b = crypto.ECDHKey(), crypto.ECDHKey()
    ax, ay = a.public_numbers()
    bx, by = b.public_numbers()
    secret_ab = protocol.derive_shared_secret(a, bx, by)
    secret_ba = protocol.derive_shared_secret(b, ax, ay)
    assert secret_ab == secret_ba
    assert len(secret_ab) == (32 if version == 1 else 64)


@pytest.mark.parametrize("version", [1, 2])
def test_encrypt_decrypt_roundtrip(version):
    protocol = pin_protocol.get(version)
    a, b = crypto.ECDHKey(), crypto.ECDHKey()
    ax, ay = a.public_numbers()
    bx, by = b.public_numbers()
    key_a = protocol.derive_shared_secret(a, bx, by)
    key_b = protocol.derive_shared_secret(b, ax, ay)
    plaintext = b"\x11" * 32  # multiple of the AES block size
    assert protocol.decrypt(key_b, protocol.encrypt(key_a, plaintext)) == plaintext


def test_v1_authenticate_is_truncated():
    assert len(pin_protocol.get(1).authenticate(b"\x00" * 32, b"msg")) == 16


def test_v2_authenticate_is_full_length():
    assert len(pin_protocol.get(2).authenticate(b"\x00" * 32, b"msg")) == 32


def test_v2_encrypt_prepends_random_iv():
    protocol = pin_protocol.get(2)
    key = b"\x00" * 64
    c1 = protocol.encrypt(key, b"\x11" * 16)
    c2 = protocol.encrypt(key, b"\x11" * 16)
    assert c1[:16] != c2[:16]  # random IV each time
    assert protocol.decrypt(key, c1) == protocol.decrypt(key, c2) == b"\x11" * 16


def test_v1_encrypt_is_deterministic_zero_iv():
    protocol = pin_protocol.get(1)
    key = b"\x00" * 32
    assert protocol.encrypt(key, b"\x11" * 16) == protocol.encrypt(key, b"\x11" * 16)


def test_unsupported_protocol_returns_none():
    assert pin_protocol.get(3) is None
    assert pin_protocol.get(0) is None
    assert pin_protocol.get(None) is None
