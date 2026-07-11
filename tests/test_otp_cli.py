"""OTP provisioning via the CLI and end-to-end trigger over the control socket."""

import threading
import time

from virtual_fido import control, crypto, otp
from virtual_fido.demo import cli


def test_otp_set_persists_to_vault(tmp_path):
    vault = tmp_path / "vault.json"
    cli.main(
        [
            "--vault", str(vault), "--passphrase", "pw",
            "otp", "set", "--slot", "1", "--type", "yubico",
            "--key", "00112233445566778899aabbccddeeff",
            "--private-id", "010203040506",
            "--public-id", otp.modhex_encode(b"\x12\x34\x56"),
        ]
    )
    from virtual_fido import identities

    state = identities.decrypt_fido_state(vault.read_bytes(), "pw")
    assert "1" in state.otp_slots
    slot = otp.OTPSlot.from_json_obj(state.otp_slots["1"])
    assert slot.kind == "yubico"
    assert slot.aes_key == bytes.fromhex("00112233445566778899aabbccddeeff")
    assert slot.private_id == bytes.fromhex("010203040506")


def test_otp_set_static(tmp_path):
    vault = tmp_path / "vault.json"
    cli.main(
        ["--vault", str(vault), "--passphrase", "pw",
         "otp", "set", "--slot", "2", "--type", "static", "--password", "s3cret"]
    )
    from virtual_fido import identities

    state = identities.decrypt_fido_state(vault.read_bytes(), "pw")
    assert otp.OTPSlot.from_json_obj(state.otp_slots["2"]).password == "s3cret"


def test_control_socket_triggers_typing(tmp_path):
    """A ControlServer wired to an OTP interface types when 'otp-type' is sent
    over the socket — the mechanism `otp type` uses against a running server."""
    slot = otp.OTPSlot(kind="static", password="ab")
    interface = otp.OTPKeyboardInterface({1: slot})

    typed = []
    from virtual_fido import usb

    def poll():
        def on_report(data):
            typed.append(data)
            poll()

        interface.handle_data(usb.DIR_IN, len(typed) + 1, b"", on_report)

    poll()

    socket_path = str(tmp_path / "ctl.sock")
    server = control.ControlServer(
        socket_path, {"otp-type": lambda a: (interface.type_otp(int(a[0])), "ok")[1]}
    )
    server.start()
    time.sleep(0.1)

    response = control.send_command(socket_path, "otp-type 1")
    assert response.startswith("ok")
    # "ab\n" => 3 chars => 6 reports
    deadline = time.monotonic() + 2
    while len(typed) < 6 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert len(typed) == 6


def test_control_socket_unknown_command(tmp_path):
    socket_path = str(tmp_path / "ctl.sock")
    server = control.ControlServer(socket_path, {})
    server.start()
    time.sleep(0.1)
    assert control.send_command(socket_path, "nope").startswith("error")


def test_cmd_start_wiring_builds_without_error(tmp_path, monkeypatch):
    """cmd_start builds the OTP interface + control server and reaches
    virtual_fido.start without raising (guards against wiring regressions like
    a stale local-variable reference). We stub the blocking start() call."""
    vault = tmp_path / "vault.json"
    cli.main(
        ["--vault", str(vault), "--passphrase", "pw",
         "otp", "set", "--slot", "1", "--type", "static", "--password", "test1234"]
    )

    started = {}

    def fake_start(client, **kwargs):
        started["otp"] = kwargs.get("otp")
        # Exercise the control handler wiring: trigger a type via the reload path
        kwargs["otp"].type_otp(1)

    monkeypatch.setattr("virtual_fido.start", fake_start)
    socket_path = str(tmp_path / "ctl.sock")
    cli.main(
        ["--vault", str(vault), "--passphrase", "pw", "--control-socket", socket_path,
         "start", "--port", "0"]
    )
    assert started["otp"] is not None
    assert sorted(started["otp"].slots) == [1]


def test_otp_type_no_server(tmp_path, capsys):
    import pytest

    vault = tmp_path / "vault.json"
    with pytest.raises(SystemExit):
        cli.main(["--vault", str(vault), "otp", "type", "--slot", "1", "--delay", "0"])
    assert "No running server" in capsys.readouterr().err


def test_otp_type_delay_waits(tmp_path, monkeypatch):
    """--delay sleeps before contacting the server (time to focus a field)."""
    import pytest

    slept = []
    monkeypatch.setattr("time.sleep", lambda s: slept.append(s))
    vault = tmp_path / "vault.json"
    with pytest.raises(SystemExit):  # no server, but the sleep runs first
        cli.main(["--vault", str(vault), "otp", "type", "--slot", "1", "--delay", "2.5"])
    assert slept == [2.5]
