"""Port of upstream crypto/crypto_test.go (minus RSA, which is not ported)."""

from virtual_fido import crypto


def test_encrypt_decrypt():
    data = b"data"
    key = crypto.generate_symmetric_key()
    encrypted, nonce = crypto.encrypt(key, data)
    assert crypto.decrypt(key, encrypted, nonce) == data


def test_sign_verify_ecdsa():
    data = b"data"
    key = crypto.generate_ecdsa_key()
    signature = crypto.sign_ecdsa(key, data)
    assert crypto.verify_ecdsa(key.public_key(), data, signature)
    assert not crypto.verify_ecdsa(key.public_key(), b"other", signature)


def test_sign_verify_ed25519():
    data = b"data"
    key = crypto.generate_ed25519_key()
    signature = crypto.sign_ed25519(key, data)
    assert crypto.verify_ed25519(key.public_key(), data, signature)
    assert not crypto.verify_ed25519(key.public_key(), b"other", signature)


def test_seal_open():
    data = b"data"
    key = crypto.generate_symmetric_key()
    box = crypto.seal(key, data)
    assert crypto.open_box(key, box) == data


def test_hash_sha256():
    assert (
        crypto.hash_sha256(b"test").hex()
        == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    )


def test_encrypt_decrypt_aes_cbc():
    data = crypto.random_bytes(32)
    key = crypto.generate_symmetric_key()
    assert crypto.decrypt_aes_cbc(key, crypto.encrypt_aes_cbc(key, data)) == data


def test_public_key_encode_decode():
    key = crypto.generate_ecdsa_key()
    encoded = crypto.encode_public_key(key.public_key())
    assert len(encoded) == 65 and encoded[0] == 0x04
    decoded = crypto.decode_public_key(encoded)
    assert decoded.public_numbers() == key.public_key().public_numbers()


def test_ecdh_shared_secret():
    a = crypto.ECDHKey()
    b = crypto.ECDHKey()
    ax, ay = a.public_numbers()
    bx, by = b.public_numbers()
    secret_ab = a.ecdh(bx, by)
    secret_ba = b.ecdh(ax, ay)
    assert secret_ab == secret_ba
    assert len(secret_ab) == 32  # fixed-length, unlike the Go original
