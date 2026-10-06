"""Port of upstream cose/cose_test.go (minus RSA), plus Go-interop vector checks."""

import cbor2
import pytest

from virtual_fido import cose, crypto


def _roundtrip(key: cose.COSEPrivateKey):
    data = b"test"
    signature = key.sign(data)
    assert key.public().verify(data, signature)
    encoded = cose.marshal_cose_private_key(key)
    decoded = cose.unmarshal_cose_private_key(encoded)
    assert decoded == key
    pub_encoded = cose.marshal_cose_public_key(key.public())
    pub_decoded = cose.unmarshal_cose_public_key(pub_encoded)
    assert pub_decoded == key.public()


def test_ecdsa_key():
    _roundtrip(cose.COSEPrivateKey(ecdsa=crypto.generate_ecdsa_key()))


def test_ed25519_key():
    _roundtrip(cose.COSEPrivateKey(ed25519=crypto.generate_ed25519_key()))


def test_ec2_key_map_labels():
    """The CBOR map must use the exact COSE labels the Go code writes."""
    key = cose.COSEPrivateKey(ecdsa=crypto.generate_ecdsa_key())
    obj = cbor2.loads(cose.marshal_cose_private_key(key))
    assert obj[1] == cose.KEY_TYPE_EC2
    assert obj[3] == cose.ALGORITHM_ES256
    assert obj[-1] == cose.CURVE_P256
    assert len(obj[-2]) == 32 and len(obj[-3]) == 32 and len(obj[-4]) == 32


def test_unsupported_algorithm_rejected():
    data = cbor2.dumps({1: cose.KEY_TYPE_RSA, 3: cose.ALGORITHM_PS256})
    with pytest.raises(ValueError, match="Unsupported"):
        cose.unmarshal_cose_private_key(data)


def test_variable_length_go_coordinates_accepted():
    """Go strips leading zeros from coordinates; decoding must cope."""
    key = crypto.generate_ecdsa_key()
    numbers = key.private_numbers()
    x = numbers.public_numbers.x.to_bytes(32, "big").lstrip(b"\x00")
    y = numbers.public_numbers.y.to_bytes(32, "big").lstrip(b"\x00")
    d = numbers.private_value.to_bytes(32, "big").lstrip(b"\x00")
    data = cbor2.dumps(
        {1: cose.KEY_TYPE_EC2, 3: cose.ALGORITHM_ES256, -1: cose.CURVE_P256, -2: x, -3: y, -4: d}
    )
    decoded = cose.unmarshal_cose_private_key(data)
    assert decoded.ecdsa.private_numbers().private_value == numbers.private_value
