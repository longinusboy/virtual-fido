"""OATH applet (ykoath): credential management and TOTP/HOTP calculation,
driven through the CCID SmartCard exactly as ykman would, with RFC 6238/4226
test vectors."""

import hashlib
import hmac

from virtual_fido import ccid
from virtual_fido.applets import oath
from virtual_fido.applets.oath import OATHApplet

# RFC 6238 / RFC 4226 shared secret
RFC_SECRET = b"12345678901234567890"


def apdu(ins, p1=0, p2=0, data=b""):
    raw = bytes([0x00, ins, p1, p2])
    if data:
        raw += bytes([len(data)]) + data
    return raw


def select_oath(card):
    return card.process_apdu_bytes(apdu(ccid.INS_SELECT, p1=0x04, data=oath.OATH_AID))


def make_card(save=None):
    state = {}
    applet = OATHApplet(state, save or (lambda s: None))
    card = ccid.SmartCard([applet])
    resp = select_oath(card)
    assert resp[-2:] == ccid.sw_bytes(ccid.SW_SUCCESS)
    return card, state


def send(card, ins, p1=0, p2=0, data=b""):
    resp = card.process_apdu_bytes(apdu(ins, p1, p2, data))
    return resp[:-2], int.from_bytes(resp[-2:], "big")


def put_credential(card, name, secret, oath_type=oath.TYPE_TOTP, hash_id=oath.ALG_SHA1,
                   digits=6, imf=None):
    key = bytes([oath_type | hash_id, digits]) + secret
    data = oath.tlv(oath.TAG_NAME, name.encode()) + oath.tlv(oath.TAG_KEY, key)
    if imf is not None:
        data += oath.tlv(oath.TAG_IMF, imf.to_bytes(4, "big"))
    return send(card, oath.INS_PUT, data=data)


def read_truncated(value):
    tlvs = oath.parse_tlvs(value)
    trunc = tlvs[oath.TAG_TRUNCATED]
    digits = trunc[0]
    code = int.from_bytes(trunc[1:5], "big")
    return code % (10 ** digits), digits


def test_select_returns_version_and_name():
    card, _ = make_card()
    # Re-select to inspect the response
    resp = select_oath(card)
    tlvs = oath.parse_tlvs(resp[:-2])
    assert tlvs[oath.TAG_VERSION] == bytes([5, 4, 3])
    assert len(tlvs[oath.TAG_NAME]) == 8  # device id
    assert oath.TAG_CHALLENGE not in tlvs  # no password set


def test_put_and_list():
    card, _ = make_card()
    _, sw = put_credential(card, "Example:alice", RFC_SECRET, digits=6)
    assert sw == ccid.SW_SUCCESS
    data, sw = send(card, oath.INS_LIST)
    assert sw == ccid.SW_SUCCESS
    tlvs_raw = data
    # LIST entries: TAG_NAME_LIST [type-byte][name]
    assert b"Example:alice" in tlvs_raw
    entry = oath.parse_tlvs(tlvs_raw)[oath.TAG_NAME_LIST]
    assert entry[0] == (oath.TYPE_TOTP | oath.ALG_SHA1)
    assert entry[1:] == b"Example:alice"


def test_totp_rfc6238_vector():
    """RFC 6238 SHA1, T=59s, step=30 -> counter 1 -> code 94287082 (8 digits)."""
    card, _ = make_card()
    put_credential(card, "rfc:totp", RFC_SECRET, oath.TYPE_TOTP, oath.ALG_SHA1, digits=8)
    challenge = (59 // 30).to_bytes(8, "big")
    data, sw = send(card, oath.INS_CALCULATE, p2=0x01,
                    data=oath.tlv(oath.TAG_NAME, b"rfc:totp")
                    + oath.tlv(oath.TAG_CHALLENGE, challenge))
    assert sw == ccid.SW_SUCCESS
    code, digits = read_truncated(data)
    assert digits == 8
    assert code == 94287082


def test_totp_sha256_vector():
    """RFC 6238 SHA256, T=59s -> 46119246 (8 digits). Secret is 32 bytes."""
    secret = b"12345678901234567890123456789012"
    card, _ = make_card()
    put_credential(card, "rfc:s256", secret, oath.TYPE_TOTP, oath.ALG_SHA256, digits=8)
    challenge = (59 // 30).to_bytes(8, "big")
    data, sw = send(card, oath.INS_CALCULATE, p2=0x01,
                    data=oath.tlv(oath.TAG_NAME, b"rfc:s256")
                    + oath.tlv(oath.TAG_CHALLENGE, challenge))
    code, _ = read_truncated(data)
    assert code == 46119246


def test_hotp_rfc4226_sequence():
    """RFC 4226 SHA1: counter 0 -> 755224, counter 1 -> 287082."""
    card, state = make_card()
    put_credential(card, "rfc:hotp", RFC_SECRET, oath.TYPE_HOTP, oath.ALG_SHA1,
                   digits=6, imf=0)
    data, _ = send(card, oath.INS_CALCULATE, p2=0x01,
                   data=oath.tlv(oath.TAG_NAME, b"rfc:hotp"))
    code0, _ = read_truncated(data)
    assert code0 == 755224
    data, _ = send(card, oath.INS_CALCULATE, p2=0x01,
                   data=oath.tlv(oath.TAG_NAME, b"rfc:hotp"))
    code1, _ = read_truncated(data)
    assert code1 == 287082
    # Counter advanced and was persisted
    assert state["credentials"]["rfc:hotp"]["counter"] == 2


def test_calculate_all():
    card, _ = make_card()
    put_credential(card, "a:totp", RFC_SECRET, oath.TYPE_TOTP, digits=8)
    put_credential(card, "b:hotp", RFC_SECRET, oath.TYPE_HOTP, digits=6, imf=0)
    challenge = (59 // 30).to_bytes(8, "big")
    data, sw = send(card, oath.INS_CALCULATE_ALL,
                    data=oath.tlv(oath.TAG_CHALLENGE, challenge))
    assert sw == ccid.SW_SUCCESS
    # TOTP credential yields a truncated response; HOTP yields the 0x77 marker
    assert b"a:totp" in data and b"b:hotp" in data
    assert bytes([oath.TAG_TRUNCATED]) in data
    assert bytes([oath.TAG_HOTP, 0x00]) in data  # HOTP marker, empty value


def test_delete_and_missing():
    card, _ = make_card()
    put_credential(card, "gone:soon", RFC_SECRET)
    _, sw = send(card, oath.INS_DELETE, data=oath.tlv(oath.TAG_NAME, b"gone:soon"))
    assert sw == ccid.SW_SUCCESS
    _, sw = send(card, oath.INS_DELETE, data=oath.tlv(oath.TAG_NAME, b"gone:soon"))
    assert sw == oath.SW_NO_SUCH_OBJECT
    _, sw = send(card, oath.INS_CALCULATE, p2=0x01,
                 data=oath.tlv(oath.TAG_NAME, b"gone:soon"))
    assert sw == oath.SW_NO_SUCH_OBJECT


def test_reset_requires_interlock_and_clears():
    card, _ = make_card()
    put_credential(card, "x:y", RFC_SECRET)
    _, sw = send(card, oath.INS_RESET, p1=0x00, p2=0x00)  # wrong interlock
    assert sw == oath.SW_WRONG_SYNTAX
    _, sw = send(card, oath.INS_RESET, p1=0xDE, p2=0xAD)
    assert sw == ccid.SW_SUCCESS
    data, _ = send(card, oath.INS_LIST)
    assert data == b""  # empty


def test_persistence_callback():
    saved = []
    card, state = make_card(save=saved.append)
    put_credential(card, "persist:me", RFC_SECRET)
    assert saved  # save called on PUT
    assert "persist:me" in saved[-1]["credentials"]

    # Rebuild an applet from the saved state and confirm the credential is there
    card2 = ccid.SmartCard([OATHApplet(saved[-1], lambda s: None)])
    select_oath(card2)
    data, sw = send(card2, oath.INS_LIST)
    assert sw == ccid.SW_SUCCESS
    assert b"persist:me" in data


# ---------------------------------------------------------------------------
# Password protection (VALIDATE / SET CODE)
# ---------------------------------------------------------------------------


def _derive_password_key(password: bytes, device_id: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", password, device_id, 1000, 16)


def test_password_set_and_validate():
    saved = []
    card, state = make_card(save=saved.append)
    device_id = oath._unb64(state["device_id"])
    key = _derive_password_key(b"hunter2", device_id)

    # SET CODE: prove knowledge of the key over a challenge we pick
    challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    proof = hmac.new(key, challenge, hashlib.sha1).digest()
    set_data = (
        oath.tlv(oath.TAG_KEY, bytes([oath.ALG_SHA1]) + key)
        + oath.tlv(oath.TAG_CHALLENGE, challenge)
        + oath.tlv(oath.TAG_RESPONSE, proof)
    )
    _, sw = send(card, oath.INS_SET_CODE, data=set_data)
    assert sw == ccid.SW_SUCCESS
    assert "password_key" in saved[-1]

    # Re-SELECT: now a challenge is issued and operations are locked
    resp = select_oath(card)
    sel = oath.parse_tlvs(resp[:-2])
    assert oath.TAG_CHALLENGE in sel
    _, sw = send(card, oath.INS_LIST)
    assert sw == oath.SW_AUTH_REQUIRED

    # VALIDATE with the correct key unlocks
    device_challenge = sel[oath.TAG_CHALLENGE]
    my_challenge = b"\xaa" * 8
    validate = (
        oath.tlv(oath.TAG_RESPONSE, hmac.new(key, device_challenge, hashlib.sha1).digest())
        + oath.tlv(oath.TAG_CHALLENGE, my_challenge)
    )
    data, sw = send(card, oath.INS_VALIDATE, data=validate)
    assert sw == ccid.SW_SUCCESS
    # Device proves itself back
    proof_back = oath.parse_tlvs(data)[oath.TAG_RESPONSE]
    assert proof_back == hmac.new(key, my_challenge, hashlib.sha1).digest()
    _, sw = send(card, oath.INS_LIST)
    assert sw == ccid.SW_SUCCESS


def test_wrong_password_rejected():
    card, state = make_card()
    device_id = oath._unb64(state["device_id"])
    key = _derive_password_key(b"correct", device_id)
    challenge = b"\x01" * 8
    proof = hmac.new(key, challenge, hashlib.sha1).digest()
    send(card, oath.INS_SET_CODE, data=(
        oath.tlv(oath.TAG_KEY, bytes([oath.ALG_SHA1]) + key)
        + oath.tlv(oath.TAG_CHALLENGE, challenge)
        + oath.tlv(oath.TAG_RESPONSE, proof)
    ))
    resp = select_oath(card)
    device_challenge = oath.parse_tlvs(resp[:-2])[oath.TAG_CHALLENGE]
    wrong = _derive_password_key(b"wrong", device_id)
    validate = (
        oath.tlv(oath.TAG_RESPONSE, hmac.new(wrong, device_challenge, hashlib.sha1).digest())
        + oath.tlv(oath.TAG_CHALLENGE, b"\xbb" * 8)
    )
    _, sw = send(card, oath.INS_VALIDATE, data=validate)
    assert sw == oath.SW_AUTH_REQUIRED
