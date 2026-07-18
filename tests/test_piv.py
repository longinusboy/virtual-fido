"""PIV applet: management-key mutual auth, key generation + signature
verification, RSA decrypt, PIN flows, and GET/PUT DATA, driven through the
CCID SmartCard as ykman/OpenSC would."""

import hashlib

from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, modes

from virtual_fido import ccid
from virtual_fido.applets import piv
from virtual_fido.applets.piv import PIVApplet


def apdu(ins, p1=0, p2=0, data=b""):
    raw = bytes([0x00, ins, p1, p2])
    if not data:
        return raw
    if len(data) < 256:
        return raw + bytes([len(data)]) + data
    # Extended-length Lc (the reader advertises extended APDU support).
    return raw + b"\x00" + len(data).to_bytes(2, "big") + data


def make_card(save=None):
    state = {}
    card = ccid.SmartCard([PIVApplet(state, save or (lambda s: None))])
    resp = card.process_apdu_bytes(apdu(ccid.INS_SELECT, p1=0x04, data=piv.PIV_AID))
    assert resp[-2:] == ccid.sw_bytes(ccid.SW_SUCCESS)
    return card, state


def send(card, ins, p1=0, p2=0, data=b""):
    resp = card.process_apdu_bytes(apdu(ins, p1, p2, data))
    body, sw = resp[:-2], int.from_bytes(resp[-2:], "big")
    # Follow GET RESPONSE chaining (61xx), as a real client does.
    while sw >> 8 == 0x61:
        resp = card.process_apdu_bytes(apdu(ccid.INS_GET_RESPONSE, 0, 0, b""))
        body += resp[:-2]
        sw = int.from_bytes(resp[-2:], "big")
    return body, sw


def _des3(key, block):
    c = Cipher(TripleDES(key), modes.ECB()).encryptor()
    return c.update(block) + c.finalize()


def authenticate_mgmt(card, key=piv.DEFAULT_MGMT_KEY):
    """Perform the 3DES management-key mutual authentication."""
    # Step 1: request witness
    req = piv.ber_tlv(piv.TAG_DYN_AUTH, piv.ber_tlv(piv.TAG_AUTH_WITNESS, b""))
    data, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_3DES, p2=piv.KEY_MGMT,
                    data=req)
    assert sw == ccid.SW_SUCCESS
    enc_witness = piv.find_tag(
        piv.parse_ber(piv.find_tag(piv.parse_ber(data), piv.TAG_DYN_AUTH)),
        piv.TAG_AUTH_WITNESS,
    )
    # Decrypt witness with the key (3DES is symmetric: decrypt == inverse encrypt)
    dec = Cipher(TripleDES(key), modes.ECB()).decryptor()
    witness = dec.update(enc_witness) + dec.finalize()
    # Step 2: return witness + our challenge
    challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    step2 = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_WITNESS, witness)
        + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, challenge),
    )
    data, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_3DES, p2=piv.KEY_MGMT,
                    data=step2)
    assert sw == ccid.SW_SUCCESS
    # Card proves itself: response == 3DES(key, challenge)
    response = piv.find_tag(
        piv.parse_ber(piv.find_tag(piv.parse_ber(data), piv.TAG_DYN_AUTH)),
        piv.TAG_AUTH_RESPONSE,
    )
    assert response == _des3(key, challenge)


def verify_pin(card, pin="123456"):
    _, sw = send(card, piv.INS_VERIFY, p2=piv.KEY_PIN, data=piv._pad_pin(pin))
    assert sw == ccid.SW_SUCCESS


def generate_key(card, slot, alg):
    template = piv.ber_tlv(piv.TAG_GENERATE_TEMPLATE, piv.ber_tlv(piv.TAG_ALGORITHM, bytes([alg])))
    data, sw = send(card, piv.INS_GENERATE_ASYMMETRIC, p2=slot, data=template)
    assert sw == ccid.SW_SUCCESS, f"generate sw=0x{sw:04x}"
    return piv.find_tag(piv.parse_ber(data), piv.TAG_PUBLIC_KEY)


# ---------------------------------------------------------------------------
# Management-key auth
# ---------------------------------------------------------------------------


def test_mgmt_auth_success():
    card, _ = make_card()
    authenticate_mgmt(card)  # asserts the mutual proof internally


def test_mgmt_auth_wrong_key():
    card, _ = make_card()
    req = piv.ber_tlv(piv.TAG_DYN_AUTH, piv.ber_tlv(piv.TAG_AUTH_WITNESS, b""))
    data, _ = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_3DES, p2=piv.KEY_MGMT,
                   data=req)
    # Return a bogus witness
    step2 = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_WITNESS, b"\x00" * 8)
        + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, b"\x01" * 8),
    )
    _, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_3DES, p2=piv.KEY_MGMT,
                 data=step2)
    assert sw == piv.SW_SECURITY_NOT_SATISFIED


def test_generate_requires_mgmt_auth():
    card, _ = make_card()
    template = piv.ber_tlv(piv.TAG_GENERATE_TEMPLATE, piv.ber_tlv(piv.TAG_ALGORITHM, bytes([piv.ALG_ECC_P256])))
    _, sw = send(card, piv.INS_GENERATE_ASYMMETRIC, p2=0x9A, data=template)
    assert sw == piv.SW_SECURITY_NOT_SATISFIED


# ---------------------------------------------------------------------------
# Key generation + signing
# ---------------------------------------------------------------------------


def test_generate_ecc_and_sign():
    card, _ = make_card()
    authenticate_mgmt(card)
    pubkey_tlv = generate_key(card, 0x9A, piv.ALG_ECC_P256)
    point = piv.find_tag(piv.parse_ber(pubkey_tlv), piv.TAG_ECC_POINT)
    public_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)

    verify_pin(card)
    digest = hashlib.sha256(b"sign me").digest()
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"") + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, digest),
    )
    data, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_ECC_P256, p2=0x9A, data=auth)
    assert sw == ccid.SW_SUCCESS
    signature = piv.find_tag(
        piv.parse_ber(piv.find_tag(piv.parse_ber(data), piv.TAG_DYN_AUTH)),
        piv.TAG_AUTH_RESPONSE,
    )
    # Signature verifies against the generated public key
    public_key.verify(signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def test_generate_rsa_and_sign():
    card, _ = make_card()
    authenticate_mgmt(card)
    pubkey_tlv = generate_key(card, 0x9C, piv.ALG_RSA_2048)
    tlvs = piv.parse_ber(pubkey_tlv)
    modulus = piv.find_tag(tlvs, piv.TAG_RSA_MODULUS)
    exponent = piv.find_tag(tlvs, piv.TAG_RSA_EXPONENT)
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(exponent, "big"), int.from_bytes(modulus, "big")
    ).public_key()

    verify_pin(card)
    # Client builds the PKCS#1 v1.5 DigestInfo + padding; card does raw RSA.
    digest = hashlib.sha256(b"rsa message").digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    key_size = 256
    padded = b"\x00\x01" + b"\xff" * (key_size - len(digest_info) - 3) + b"\x00" + digest_info
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"") + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, padded),
    )
    data, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_RSA_2048, p2=0x9C, data=auth)
    assert sw == ccid.SW_SUCCESS
    signature = piv.find_tag(
        piv.parse_ber(piv.find_tag(piv.parse_ber(data), piv.TAG_DYN_AUTH)),
        piv.TAG_AUTH_RESPONSE,
    )
    public_key.verify(signature, b"rsa message", padding.PKCS1v15(), hashes.SHA256())


def test_rsa_sign_via_command_chaining():
    """OpenSC sends >255-byte commands as ISO 7816 chained short APDUs
    (CLA 0x10) rather than extended length; the card must reassemble them."""
    card, _ = make_card()
    authenticate_mgmt(card)
    pubkey_tlv = generate_key(card, 0x9A, piv.ALG_RSA_2048)
    tlvs = piv.parse_ber(pubkey_tlv)
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(piv.find_tag(tlvs, piv.TAG_RSA_EXPONENT), "big"),
        int.from_bytes(piv.find_tag(tlvs, piv.TAG_RSA_MODULUS), "big"),
    ).public_key()

    verify_pin(card)
    digest = hashlib.sha256(b"chained message").digest()
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + digest
    padded = b"\x00\x01" + b"\xff" * (256 - len(digest_info) - 3) + b"\x00" + digest_info
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"") + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, padded),
    )
    # Send in 255-byte chunks: CLA 0x10 on all but the last APDU.
    chunks = [auth[i : i + 255] for i in range(0, len(auth), 255)]
    for chunk in chunks[:-1]:
        resp = card.process_apdu_bytes(
            bytes([0x10, piv.INS_GENERAL_AUTHENTICATE, piv.ALG_RSA_2048, 0x9A, len(chunk)])
            + chunk
        )
        assert resp == ccid.sw_bytes(ccid.SW_SUCCESS)
    resp = card.process_apdu_bytes(
        bytes([0x00, piv.INS_GENERAL_AUTHENTICATE, piv.ALG_RSA_2048, 0x9A, len(chunks[-1])])
        + chunks[-1]
    )
    body, sw = resp[:-2], int.from_bytes(resp[-2:], "big")
    while sw >> 8 == 0x61:
        resp = card.process_apdu_bytes(apdu(ccid.INS_GET_RESPONSE))
        body += resp[:-2]
        sw = int.from_bytes(resp[-2:], "big")
    assert sw == ccid.SW_SUCCESS
    signature = piv.find_tag(
        piv.parse_ber(piv.find_tag(piv.parse_ber(body), piv.TAG_DYN_AUTH)),
        piv.TAG_AUTH_RESPONSE,
    )
    public_key.verify(signature, b"chained message", padding.PKCS1v15(), hashes.SHA256())


def test_rsa_decrypt():
    card, _ = make_card()
    authenticate_mgmt(card)
    pubkey_tlv = generate_key(card, 0x9D, piv.ALG_RSA_2048)
    tlvs = piv.parse_ber(pubkey_tlv)
    public_key = rsa.RSAPublicNumbers(
        int.from_bytes(piv.find_tag(tlvs, piv.TAG_RSA_EXPONENT), "big"),
        int.from_bytes(piv.find_tag(tlvs, piv.TAG_RSA_MODULUS), "big"),
    ).public_key()

    verify_pin(card)
    plaintext = b"secret payload"
    ciphertext = public_key.encrypt(plaintext, padding.PKCS1v15())
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"") + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, ciphertext),
    )
    data, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_RSA_2048, p2=0x9D, data=auth)
    assert sw == ccid.SW_SUCCESS
    raw = piv.find_tag(
        piv.parse_ber(piv.find_tag(piv.parse_ber(data), piv.TAG_DYN_AUTH)),
        piv.TAG_AUTH_RESPONSE,
    )
    # raw is the PKCS#1 v1.5 encryption block; strip padding to recover plaintext
    assert raw[0] == 0x00 and raw[1] == 0x02
    recovered = raw[raw.index(0, 2) + 1 :]
    assert recovered == plaintext


def test_sign_requires_pin():
    card, _ = make_card()
    authenticate_mgmt(card)
    generate_key(card, 0x9A, piv.ALG_ECC_P256)
    # No PIN verification -> signing is refused
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"")
        + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, b"\x00" * 32),
    )
    _, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_ECC_P256, p2=0x9A, data=auth)
    assert sw == piv.SW_SECURITY_NOT_SATISFIED


def test_card_auth_slot_9e_no_pin():
    card, _ = make_card()
    authenticate_mgmt(card)
    generate_key(card, 0x9E, piv.ALG_ECC_P256)
    # Slot 9E signs without a PIN
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"")
        + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, hashlib.sha256(b"x").digest()),
    )
    _, sw = send(card, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_ECC_P256, p2=0x9E, data=auth)
    assert sw == ccid.SW_SUCCESS


# ---------------------------------------------------------------------------
# PIN / PUK
# ---------------------------------------------------------------------------


def test_pin_verify_and_retry_counter():
    card, state = make_card()
    # Wrong PIN decrements retries and reports remaining
    _, sw = send(card, piv.INS_VERIFY, p2=piv.KEY_PIN, data=piv._pad_pin("999999"))
    assert sw == 0x63C0 | 2
    assert state["pin_retries"] == 2
    # Correct PIN resets
    verify_pin(card)
    assert state["pin_retries"] == piv.DEFAULT_RETRIES
    # Query retries with empty data
    _, sw = send(card, piv.INS_VERIFY, p2=piv.KEY_PIN)
    assert sw == ccid.SW_SUCCESS  # already verified


def test_pin_block_after_exhaustion():
    card, state = make_card()
    for _ in range(piv.DEFAULT_RETRIES):
        send(card, piv.INS_VERIFY, p2=piv.KEY_PIN, data=piv._pad_pin("000000"))
    _, sw = send(card, piv.INS_VERIFY, p2=piv.KEY_PIN, data=piv._pad_pin("123456"))
    assert sw == piv.SW_AUTH_BLOCKED


def test_change_pin():
    card, _ = make_card()
    _, sw = send(card, piv.INS_CHANGE_REFERENCE, p2=piv.KEY_PIN,
                 data=piv._pad_pin("123456") + piv._pad_pin("654321"))
    assert sw == ccid.SW_SUCCESS
    verify_pin(card, "654321")


def test_reset_retry_with_puk():
    card, state = make_card()
    for _ in range(piv.DEFAULT_RETRIES):
        send(card, piv.INS_VERIFY, p2=piv.KEY_PIN, data=piv._pad_pin("000000"))
    # Unblock with PUK, set a new PIN
    _, sw = send(card, piv.INS_RESET_RETRY, p2=piv.KEY_PIN,
                 data=piv._pad_pin("12345678") + piv._pad_pin("111111"))
    assert sw == ccid.SW_SUCCESS
    assert state["pin_retries"] == piv.DEFAULT_RETRIES
    verify_pin(card, "111111")


# ---------------------------------------------------------------------------
# Data objects (certificates)
# ---------------------------------------------------------------------------


def test_put_and_get_data():
    card, _ = make_card()
    authenticate_mgmt(card)
    cert_tag = bytes.fromhex("5fc105")  # 9A authentication cert
    cert_object = b"\x70\x03ABC\x71\x01\x00\xfe\x00"  # cert wrapper, opaque here
    put = piv.ber_tlv(piv.TAG_DATA_TAG_LIST, cert_tag) + piv.ber_tlv(
        piv.TAG_DATA_OBJECT, cert_object
    )
    _, sw = send(card, piv.INS_PUT_DATA, p1=0x3F, p2=0xFF, data=put)
    assert sw == ccid.SW_SUCCESS

    get = piv.ber_tlv(piv.TAG_DATA_TAG_LIST, cert_tag)
    data, sw = send(card, piv.INS_GET_DATA, p1=0x3F, p2=0xFF, data=get)
    assert sw == ccid.SW_SUCCESS
    assert piv.find_tag(piv.parse_ber(data), piv.TAG_DATA_OBJECT) == cert_object


def test_get_data_missing():
    card, _ = make_card()
    get = piv.ber_tlv(piv.TAG_DATA_TAG_LIST, bytes.fromhex("5fc105"))
    _, sw = send(card, piv.INS_GET_DATA, p1=0x3F, p2=0xFF, data=get)
    # Absent data object -> FILE NOT FOUND (what ykman's get_pivman_data expects)
    assert sw == piv.SW_FILE_NOT_FOUND


def test_pivman_object_missing_is_file_not_found():
    """`ykman piv info` reads the pivman data object (5FFF00) on a fresh card;
    it must get FILE NOT FOUND (0x6A82) so it falls back to defaults instead of
    crashing with an unhandled ApduError."""
    card, _ = make_card()
    get = piv.ber_tlv(piv.TAG_DATA_TAG_LIST, bytes.fromhex("5fff00"))
    _, sw = send(card, piv.INS_GET_DATA, p1=0x3F, p2=0xFF, data=get)
    assert sw == 0x6A82


def test_put_data_requires_mgmt_auth():
    card, _ = make_card()
    put = piv.ber_tlv(piv.TAG_DATA_TAG_LIST, bytes.fromhex("5fc105")) + piv.ber_tlv(
        piv.TAG_DATA_OBJECT, b"x"
    )
    _, sw = send(card, piv.INS_PUT_DATA, p1=0x3F, p2=0xFF, data=put)
    assert sw == piv.SW_SECURITY_NOT_SATISFIED


# ---------------------------------------------------------------------------
# Version / metadata / persistence
# ---------------------------------------------------------------------------


def test_get_version():
    card, _ = make_card()
    data, sw = send(card, piv.INS_GET_VERSION)
    assert sw == ccid.SW_SUCCESS
    assert data == bytes([5, 7, 4])


def test_metadata_mgmt_reports_3des():
    card, _ = make_card()
    data, sw = send(card, piv.INS_GET_METADATA, p2=piv.KEY_MGMT)
    assert sw == ccid.SW_SUCCESS
    tlvs = piv.parse_ber(data)
    assert piv.find_tag(tlvs, 0x01) == bytes([piv.ALG_3DES])  # algorithm
    # ykman's get_management_key_metadata reads policy[1] unconditionally, so
    # the policy tag (0x02, 2 bytes) must be present.
    policy = piv.find_tag(tlvs, 0x02)
    assert policy is not None and len(policy) == 2
    assert piv.find_tag(tlvs, 0x05) == bytes([1])  # is-default


def test_metadata_slot_reports_public_key():
    card, _ = make_card()
    authenticate_mgmt(card)
    generate_key(card, 0x9A, piv.ALG_ECC_P256)
    data, sw = send(card, piv.INS_GET_METADATA, p2=0x9A)
    assert sw == ccid.SW_SUCCESS
    tlvs = piv.parse_ber(data)
    assert piv.find_tag(tlvs, 0x01) == bytes([piv.ALG_ECC_P256])
    assert piv.find_tag(tlvs, 0x03) == bytes([1])  # generated on-device
    assert piv.find_tag(tlvs, 0x04) is not None  # public key present


def test_persistence_reload():
    saved = []
    card, _ = make_card(save=saved.append)
    authenticate_mgmt(card)
    generate_key(card, 0x9A, piv.ALG_ECC_P256)
    assert saved and "9a" in saved[-1]["slots"]

    # Rebuild from saved state: the key survives, signing works after re-auth
    card2 = ccid.SmartCard([PIVApplet(saved[-1], lambda s: None)])
    card2.process_apdu_bytes(apdu(ccid.INS_SELECT, p1=0x04, data=piv.PIV_AID))
    verify_pin(card2)
    auth = piv.ber_tlv(
        piv.TAG_DYN_AUTH,
        piv.ber_tlv(piv.TAG_AUTH_RESPONSE, b"")
        + piv.ber_tlv(piv.TAG_AUTH_CHALLENGE, hashlib.sha256(b"y").digest()),
    )
    _, sw = send(card2, piv.INS_GENERAL_AUTHENTICATE, p1=piv.ALG_ECC_P256, p2=0x9A, data=auth)
    assert sw == ccid.SW_SUCCESS
