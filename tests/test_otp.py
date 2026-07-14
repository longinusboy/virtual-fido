"""OTP keyboard interface: ModHex, CRC16, Yubico OTP token, keyboard reports,
and the interface's typing behavior."""

import struct

import pytest

from virtual_fido import crypto, otp, usb


def test_modhex_roundtrip():
    for data in (b"", b"\x00", b"\x2d\x34\x4a", bytes(range(256))):
        assert otp.modhex_decode(otp.modhex_encode(data)) == data


def test_modhex_known_vector():
    # 0x2d -> nibbles 2,d -> alphabet[2]='d', alphabet[13]='t' -> "dt"
    assert otp.modhex_encode(b"\x2d") == "dt"


def test_crc16_residual():
    """A token whose trailing 2 bytes are crc16(first N) must satisfy the
    Yubico residual check crc16(whole) == 0xF0B8."""
    body = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e"
    token = body + struct.pack("<H", (~otp.crc16(body)) & 0xFFFF)
    assert otp.crc16(token) == otp.CRC_RESIDUAL_OK


def test_yubico_otp_decrypts_and_validates():
    aes_key = bytes.fromhex("00112233445566778899aabbccddeeff")
    private_id = bytes.fromhex("010203040506")
    public_id = bytes.fromhex("1234567890ab")
    slot = otp.OTPSlot(
        kind="yubico", aes_key=aes_key, public_id=public_id, private_id=private_id
    )
    string = otp.build_yubico_otp(slot)
    # public id prefix (12 ModHex chars) + 32 ModHex chars of ciphertext
    assert len(string) == 12 + 32
    assert string.startswith(otp.modhex_encode(public_id))

    ciphertext = otp.modhex_decode(string[12:])
    token = crypto.aes_ecb_decrypt(aes_key, ciphertext)
    assert otp.crc16(token) == otp.CRC_RESIDUAL_OK  # decrypts to a valid token
    assert token[:6] == private_id  # private UID recovered


def test_yubico_otp_counter_increments():
    slot = otp.OTPSlot(
        kind="yubico",
        aes_key=bytes(16),
        private_id=bytes(6),
    )
    otp.build_yubico_otp(slot)
    otp.build_yubico_otp(slot)
    assert slot.session_counter == 2


def test_keyboard_reports_type_lowercase():
    reports = otp.keyboard_reports("cb")
    # 'c' press+release, 'b' press+release
    assert len(reports) == 4
    assert reports[0] == bytes([0, 0, 0x06, 0, 0, 0, 0, 0])  # 'c' = 0x06
    assert reports[1] == bytes(8)  # release
    assert reports[2] == bytes([0, 0, 0x05, 0, 0, 0, 0, 0])  # 'b' = 0x05
    assert reports[3] == bytes(8)


def test_keyboard_reports_enter_and_shift():
    reports = otp.keyboard_reports("A\n")
    assert reports[0] == bytes([0x02, 0, 0x04, 0, 0, 0, 0, 0])  # shift + 'a'
    assert reports[2] == bytes([0, 0, 0x28, 0, 0, 0, 0, 0])  # Enter


def test_slot_json_roundtrip():
    slot = otp.OTPSlot(
        kind="yubico",
        aes_key=bytes(range(16)),
        public_id=b"\x01\x02",
        private_id=bytes(range(6)),
    )
    restored = otp.OTPSlot.from_json_obj(slot.to_json_obj())
    assert restored.aes_key == slot.aes_key
    assert restored.public_id == slot.public_id
    assert restored.private_id == slot.private_id

    static = otp.OTPSlot(kind="static", password="hunter2")
    assert otp.OTPSlot.from_json_obj(static.to_json_obj()).password == "hunter2"


class _Poller:
    """Drives the OTP interface like a host keyboard: one pending IN poll,
    re-polling after each report, collecting the 8-byte reports."""

    def __init__(self, interface):
        self.interface = interface
        self.reports = []
        self._rid = 0
        self._poll()

    def _poll(self):
        self._rid += 1

        def on_report(data):
            self.reports.append(data)
            self._poll()

        self.interface.handle_data(1, usb.DIR_IN, self._rid, b"", on_report)


def test_interface_types_static_password():
    slot = otp.OTPSlot(kind="static", password="abc")
    interface = otp.OTPKeyboardInterface({1: slot})
    poller = _Poller(interface)
    interface.type_otp(1)
    # "abc\n" => 4 chars => 8 reports (press+release each)
    assert len(poller.reports) == 8
    # First keycode is 'a' (0x04)
    assert poller.reports[0][2] == 0x04


def test_interface_unknown_slot_raises():
    interface = otp.OTPKeyboardInterface({})
    with pytest.raises(KeyError):
        interface.type_otp(1)


def test_interface_report_descriptor_and_class():
    interface = otp.OTPKeyboardInterface({})
    assert interface.interface_class == 3
    assert interface.interface_subclass == 1  # boot
    assert interface.interface_protocol == 1  # keyboard
    assert interface.report_descriptor() == otp.KEYBOARD_REPORT_DESCRIPTOR
    assert len(interface.endpoint_specs) == 1
    assert interface.endpoint_specs[0].is_in
