"""CCID transport: APDU parsing, message framing, SELECT routing, GET RESPONSE
chaining, and the interface's bulk request/response behavior."""

import struct

from virtual_fido import ccid, usb


def build_ccid(msg_type, ab_data=b"", slot=0, seq=1, extra=0):
    return struct.pack("<BIBBBBB", msg_type, len(ab_data), slot, seq, 0, 0, extra) + ab_data


def parse_ccid(message):
    msg_type, dw_length, slot, seq, status, error, extra = struct.unpack_from(
        "<BIBBBBB", message, 0
    )
    return msg_type, message[10 : 10 + dw_length], seq, status


# ---------------------------------------------------------------------------
# APDU parsing
# ---------------------------------------------------------------------------


def test_apdu_case1_no_data_no_le():
    a = ccid.APDU.parse(bytes([0x00, 0xA4, 0x04, 0x00]))
    assert (a.cla, a.ins, a.p1, a.p2, a.data, a.le) == (0, 0xA4, 4, 0, b"", 0)


def test_apdu_case2_le_only():
    a = ccid.APDU.parse(bytes([0x00, 0xC0, 0x00, 0x00, 0x10]))
    assert a.data == b"" and a.le == 0x10


def test_apdu_case3_data_no_le():
    a = ccid.APDU.parse(bytes([0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x01]))
    assert a.data == bytes([0xA0, 0x00, 0x01]) and a.le == 0


def test_apdu_case4_data_and_le():
    a = ccid.APDU.parse(bytes([0x00, 0x01, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x05]))
    assert a.data == bytes([0xAA, 0xBB]) and a.le == 5


def test_apdu_extended_length():
    # extended Lc=2, data, extended Le=0x0100
    raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0xAA, 0xBB, 0x01, 0x00])
    a = ccid.APDU.parse(raw)
    assert a.data == bytes([0xAA, 0xBB]) and a.le == 0x100


# ---------------------------------------------------------------------------
# CCID message layer
# ---------------------------------------------------------------------------


def test_power_on_returns_atr():
    card = ccid.SmartCard([])
    resp = card.handle_ccid(build_ccid(ccid.PC_TO_RDR_ICC_POWER_ON))
    msg_type, data, seq, status = parse_ccid(resp)
    assert msg_type == ccid.RDR_TO_PC_DATA_BLOCK
    assert data == ccid.ATR
    assert seq == 1 and status == 0


def test_slot_status_echoes_seq():
    card = ccid.SmartCard([])
    resp = card.handle_ccid(build_ccid(ccid.PC_TO_RDR_GET_SLOT_STATUS, seq=42))
    msg_type, _data, seq, status = parse_ccid(resp)
    assert msg_type == ccid.RDR_TO_PC_SLOT_STATUS
    assert seq == 42


def test_get_parameters_returns_t1_block():
    card = ccid.SmartCard([])
    resp = card.handle_ccid(build_ccid(ccid.PC_TO_RDR_GET_PARAMETERS))
    msg_type, data, _seq, _status = parse_ccid(resp)
    assert msg_type == ccid.RDR_TO_PC_PARAMETERS
    assert len(data) == 7  # T=1 parameter block


# ---------------------------------------------------------------------------
# APDU dispatch + applet routing
# ---------------------------------------------------------------------------


class DummyApplet(ccid.Applet):
    aid = bytes.fromhex("a000000527deadbeef")
    name = "dummy"

    def __init__(self):
        self.selected = False
        self.last_apdu = None
        self.next_response = (b"", ccid.SW_SUCCESS)

    def select(self):
        self.selected = True
        return b"dummy-fci", ccid.SW_SUCCESS

    def process_apdu(self, apdu):
        self.last_apdu = apdu
        return self.next_response


def select_aid(card, aid):
    apdu = bytes([0x00, ccid.INS_SELECT, 0x04, 0x00, len(aid)]) + aid
    return card.process_apdu_bytes(apdu)


def test_select_routes_to_applet():
    applet = DummyApplet()
    card = ccid.SmartCard([applet])
    resp = select_aid(card, applet.aid)
    assert applet.selected
    assert resp == b"dummy-fci" + ccid.sw_bytes(ccid.SW_SUCCESS)
    assert card.selected is applet


def test_select_partial_aid():
    applet = DummyApplet()
    card = ccid.SmartCard([applet])
    select_aid(card, applet.aid[:5])  # prefix selection
    assert card.selected is applet


def test_select_unknown_aid_not_found():
    card = ccid.SmartCard([DummyApplet()])
    resp = select_aid(card, bytes.fromhex("ffffffffff"))
    assert resp == ccid.sw_bytes(ccid.SW_FILE_NOT_FOUND)
    assert card.selected is None


def test_apdu_without_selection_is_rejected():
    card = ccid.SmartCard([DummyApplet()])
    resp = card.process_apdu_bytes(bytes([0x00, 0x01, 0x00, 0x00]))
    assert resp == ccid.sw_bytes(ccid.SW_FILE_NOT_FOUND)


def test_apdu_routed_to_selected_applet():
    applet = DummyApplet()
    card = ccid.SmartCard([applet])
    select_aid(card, applet.aid)
    applet.next_response = (b"\xab\xcd", ccid.SW_SUCCESS)
    resp = card.process_apdu_bytes(bytes([0x00, 0x05, 0x01, 0x02]))
    assert resp == b"\xab\xcd" + ccid.sw_bytes(ccid.SW_SUCCESS)
    assert applet.last_apdu.ins == 0x05
    assert applet.last_apdu.p1 == 0x01


# ---------------------------------------------------------------------------
# GET RESPONSE chaining
# ---------------------------------------------------------------------------


def test_get_response_chaining():
    applet = DummyApplet()
    card = ccid.SmartCard([applet])
    select_aid(card, applet.aid)
    big = bytes(range(256)) * 2  # 512 bytes
    applet.next_response = (big, ccid.SW_SUCCESS)

    # First response: 256 bytes + 61xx (256 remaining -> 0x00)
    resp = card.process_apdu_bytes(bytes([0x00, 0x05, 0x00, 0x00]))
    assert resp[:256] == big[:256]
    assert resp[256:] == bytes([0x61, 0x00])

    # GET RESPONSE for the rest
    resp2 = card.process_apdu_bytes(bytes([0x00, ccid.INS_GET_RESPONSE, 0x00, 0x00, 0x00]))
    assert resp2[:-2] == big[256:]
    assert resp2[-2:] == ccid.sw_bytes(ccid.SW_SUCCESS)


def test_get_response_partial_le():
    applet = DummyApplet()
    card = ccid.SmartCard([applet])
    select_aid(card, applet.aid)
    applet.next_response = (bytes(range(256)) + b"\xaa\xbb\xcc", ccid.SW_SUCCESS)
    first = card.process_apdu_bytes(bytes([0x00, 0x05, 0x00, 0x00]))
    assert first[256:] == bytes([0x61, 0x03])  # 3 bytes remaining
    second = card.process_apdu_bytes(bytes([0x00, ccid.INS_GET_RESPONSE, 0x00, 0x00, 0x02]))
    assert second[:2] == b"\xaa\xbb"
    assert second[2:] == bytes([0x61, 0x01])  # 1 byte still remaining
    third = card.process_apdu_bytes(bytes([0x00, ccid.INS_GET_RESPONSE, 0x00, 0x00, 0x01]))
    assert third == b"\xcc" + ccid.sw_bytes(ccid.SW_SUCCESS)


# ---------------------------------------------------------------------------
# Interface behavior
# ---------------------------------------------------------------------------


def make_ccid_interface(applets):
    interface = ccid.CCIDInterface(applets)
    interface.endpoint_numbers = [4, 5, 6]  # bulk OUT, bulk IN, interrupt IN
    return interface


def test_interface_bulk_request_response():
    applet = DummyApplet()
    interface = make_ccid_interface([applet])
    responses = []

    # Host polls bulk IN first (held pending)
    interface.handle_data(5, usb.DIR_IN, 1, b"", responses.append)
    assert responses == []

    # Host sends IccPowerOn on bulk OUT
    acks = []
    interface.handle_data(
        4, usb.DIR_OUT, 2, build_ccid(ccid.PC_TO_RDR_ICC_POWER_ON), acks.append
    )
    assert acks == [None]  # OUT is acked immediately
    # The pending IN poll now receives the DataBlock with the ATR
    assert len(responses) == 1
    msg_type, data, _seq, _status = parse_ccid(responses[0])
    assert msg_type == ccid.RDR_TO_PC_DATA_BLOCK and data == ccid.ATR


def test_interrupt_endpoint_notifies_once_then_holds():
    """The interrupt-IN endpoint reports the slot state once, then holds later
    polls pending (so the host blocks instead of spinning on GetSlotStatus)."""
    interface = make_ccid_interface([])
    first = []
    interface.handle_data(6, usb.DIR_IN, 1, b"", first.append)
    assert first == [bytes([ccid.RDR_TO_PC_NOTIFY_SLOT_CHANGE, 0x01])]

    second = []
    interface.handle_data(6, usb.DIR_IN, 2, b"", second.append)
    assert second == []  # held pending, no notification


def test_interface_descriptor_and_class():
    interface = ccid.CCIDInterface([])
    assert interface.interface_class == 0x0B
    assert interface.class_descriptors()[0] == 54  # bLength
    assert interface.class_descriptors()[1] == 0x21  # CCID functional descriptor
    assert len(interface.endpoint_specs) == 3
    assert not interface.endpoint_specs[0].is_in  # bulk OUT
    assert interface.endpoint_specs[1].is_in  # bulk IN
    assert interface.endpoint_specs[2].is_in  # interrupt IN (notifications)
    assert interface.endpoint_specs[0].attributes == usb.ATTR_BULK
    assert interface.endpoint_specs[2].attributes == usb.ATTR_INTERRUPT
