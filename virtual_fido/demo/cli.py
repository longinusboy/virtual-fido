"""Reference CLI: run the virtual FIDO device and manage its vault.

Port of the upstream Go cmd/demo. Everything about key management here is INSECURE
and for testing only — fresh self-signed CA per vault, hardcoded "test"
encryption key, default passphrase. Do not copy into real deployments.

    virtual-fido-demo start [--bind ADDR] [--port N]
    virtual-fido-demo list
    virtual-fido-demo delete --identity <hash-prefix>
    virtual-fido-demo pin enable|disable|set --pin <pin>
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import logging
import os
import sys
from pathlib import Path
from typing import Optional

import virtual_fido
from virtual_fido import identities
from virtual_fido.keyboard_layouts import LAYOUTS as KEYBOARD_LAYOUTS
from virtual_fido.fido_client import (
    ClientAction,
    ClientActionRequestParams,
    DefaultFIDOClient,
)


def _prompt(message: str) -> bool:
    print(message)
    try:
        response = input("--> ").strip().lower()
    except EOFError:
        return False
    return response in ("y", "yes")


class TerminalSupport:
    """Terminal approver + file-based vault storage (demo ClientSupport)."""

    def __init__(
        self,
        vault_filename: str,
        vault_passphrase: str,
        keyfile: Optional[bytes] = None,
    ) -> None:
        self._vault_path = Path(vault_filename)
        self._passphrase = vault_passphrase
        self._keyfile = keyfile

    # ClientRequestApprover
    def approve_client_action(
        self, action: ClientAction, params: ClientActionRequestParams
    ) -> bool:
        if action == ClientAction.FIDO_GET_ASSERTION:
            return _prompt(
                f'Approve login for "{params.relying_party}"'
                f' with identity "{params.user_name}" (y/N)?'
            )
        if action == ClientAction.FIDO_MAKE_CREDENTIAL:
            return _prompt(f'Approve account creation for "{params.relying_party}" (y/N)?')
        if action == ClientAction.U2F_AUTHENTICATE:
            return _prompt("Approve use of U2F device (y/N)?")
        if action == ClientAction.U2F_REGISTER:
            return _prompt("Approve registration of U2F device (y/N)?")
        print(f"Unknown client action for approval: {action}")
        return False

    # ClientDataSaver
    def save_data(self, data: bytes) -> None:
        self._vault_path.write_bytes(data)

    def retrieve_data(self) -> Optional[bytes]:
        if self._vault_path.exists():
            return self._vault_path.read_bytes()
        return None

    def passphrase(self) -> str:
        return self._passphrase

    def keyfile(self) -> Optional[bytes]:
        return self._keyfile


def resolve_passphrase(args: argparse.Namespace) -> str:
    """--passphrase (discouraged) > --passphrase-file > interactive prompt.

    Environment variables are deliberately NOT supported: they leak through
    /proc/<pid>/environ, shell history and service manager configs — prime
    targets for info stealers.
    """
    if args.passphrase is not None:
        print(
            "WARNING: --passphrase is visible in the process list and shell"
            " history; prefer --passphrase-file or the interactive prompt.",
            file=sys.stderr,
        )
        return args.passphrase
    if args.passphrase_file is not None:
        return Path(args.passphrase_file).read_text().strip("\n")
    return getpass.getpass("Vault passphrase: ")


def load_keyfile(args: argparse.Namespace) -> Optional[bytes]:
    if args.keyfile is None:
        return None
    return Path(args.keyfile).read_bytes()


def create_client(args: argparse.Namespace) -> DefaultFIDOClient:
    # The CA and encryption key below are INSECURE, FOR TESTING PURPOSES ONLY
    ca_private_key = identities.create_ca_private_key()
    certificate_authority = identities.create_self_signed_ca(ca_private_key)
    encryption_key = hashlib.sha256(b"test").digest()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    support = TerminalSupport(args.vault, resolve_passphrase(args), load_keyfile(args))
    return DefaultFIDOClient(
        attestation_ca_certificate=certificate_authority,
        attestation_ca_private_key=ca_private_key,
        secret_encryption_key=encryption_key,
        enable_pin=False,
        request_approver=support,
        data_saver=support,
    )


def control_socket_path(args: argparse.Namespace) -> str:
    if getattr(args, "control_socket", None):
        return args.control_socket
    # Default lives in the runtime dir (short path — AF_UNIX caps at ~108
    # bytes, so a deep vault path can't be used directly), keyed by a hash of
    # the vault so each vault gets its own socket and `otp type --vault X`
    # finds the matching server.
    import tempfile

    runtime = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    digest = hashlib.sha256(str(Path(args.vault).resolve()).encode()).hexdigest()[:8]
    return os.path.join(runtime, f"virtual-fido-{digest}.sock")


def cmd_start(args: argparse.Namespace) -> None:
    from virtual_fido.ccid import CCIDInterface
    from virtual_fido.control import ControlServer
    from virtual_fido.otp import OTPKeyboardInterface, OTPSlot
    from virtual_fido.usb import USBDeviceConfig

    client = create_client(args)
    device_config = USBDeviceConfig(
        id_vendor=args.vendor_id,
        id_product=args.product_id,
        bcd_device=args.bcd_device,
        manufacturer=args.manufacturer,
        product=args.product,
        serial_number=args.serial_number,
    )

    # OTP keyboard interface, loaded with any provisioned slots.
    def load_slots() -> dict:
        return {
            int(n): OTPSlot.from_json_obj(obj) for n, obj in client.otp_slots.items()
        }

    otp_interface = OTPKeyboardInterface(load_slots(), layout=args.layout)

    def handle_otp_type(command_args: list) -> str:
        slot = int(command_args[0]) if command_args else 1
        layout = command_args[1] if len(command_args) > 1 else None
        # Re-read the vault so slots provisioned after the server started are
        # picked up without a restart.
        client.reload_otp_slots()
        otp_interface.slots = load_slots()
        otp_interface.type_otp(slot, layout)
        return f"typed slot {slot}"

    control = ControlServer(
        control_socket_path(args), {"otp-type": handle_otp_type}
    )
    control.start()

    # CCID smartcard interface with the OATH and PIV applets. State lives in
    # the vault; each applet persists changes back through the client.
    from virtual_fido.applets.oath import OATHApplet
    from virtual_fido.applets.piv import PIVApplet

    oath_applet = OATHApplet(client.oath_state, client.save_oath_state)
    piv_applet = PIVApplet(client.piv_state, client.save_piv_state)
    ccid_interface = CCIDInterface(applets=[oath_applet, piv_applet])

    print(f"Serving USB/IP on {args.bind}:{args.port}")
    print(
        f"Device identity: {device_config.manufacturer} {device_config.product}"
        f" ({device_config.id_vendor:04x}:{device_config.id_product:04x})"
    )
    print(
        f"Control socket: {control_socket_path(args)}"
        f"  (OTP slots: {sorted(otp_interface.slots)})"
    )
    print("Attach from the client machine (Linux):")
    print("  sudo modprobe vhci-hcd")
    print(f"  sudo usbip attach -r {args.bind} -b 2-2")
    virtual_fido.start(
        client,
        bind_address=args.bind,
        port=args.port,
        device_config=device_config,
        otp=otp_interface,
        ccid=ccid_interface,
    )


def cmd_list(args: argparse.Namespace) -> None:
    client = create_client(args)
    print(f"------- Identities in file '{args.vault}' -------")
    for source in client.identities():
        print(
            f"({source.id[:4].hex()}): '{source.user.name}'"
            f" for website '{source.relying_party.name}'"
        )


def cmd_delete(args: argparse.Namespace) -> None:
    client = create_client(args)
    targets = [
        source
        for source in client.identities()
        if source.id.hex().startswith(args.identity)
    ]
    if len(targets) > 1:
        print(f"Multiple identities with prefix ({args.identity}):")
        for source in targets:
            print(f"- ({source.id.hex()})")
    elif len(targets) == 1:
        print(f"Deleting identity ({targets[0].id.hex()})...")
        if client.delete_identity(targets[0].id):
            print("Done.")
        else:
            print(f"Could not find ({targets[0].id.hex()}).")
    else:
        print(f"No identity found with prefix ({args.identity})")


def cmd_pin_enable(args: argparse.Namespace) -> None:
    create_client(args).enable_pin()
    print("PIN enabled")


def cmd_pin_disable(args: argparse.Namespace) -> None:
    create_client(args).disable_pin()
    print("PIN disabled")


def cmd_generate_keyfile(args: argparse.Namespace) -> None:
    if args.keyfile is None:
        print("Provide the target path with --keyfile", file=sys.stderr)
        sys.exit(1)
    # 0600 and no-overwrite: losing an in-use keyfile means losing the vault
    fd = os.open(args.keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(identities.generate_keyfile())
    print(f"Keyfile written to {args.keyfile}")
    print("Store it on separate media from the vault; without it the vault")
    print("cannot be decrypted. Existing vaults adopt it on their next save.")


def cmd_otp_set(args: argparse.Namespace) -> None:
    from virtual_fido.otp import OTPSlot, modhex_decode

    if args.type == "yubico":
        try:
            aes_key = bytes.fromhex(args.key or "")
            private_id = bytes.fromhex(args.private_id or "")
        except ValueError:
            print("Invalid hex in --key/--private-id", file=sys.stderr)
            sys.exit(1)
        if len(aes_key) != 16:
            print("--key must be 16 bytes (32 hex chars)", file=sys.stderr)
            sys.exit(1)
        if len(private_id) != 6:
            print("--private-id must be 6 bytes (12 hex chars)", file=sys.stderr)
            sys.exit(1)
        public_id = modhex_decode(args.public_id) if args.public_id else b""
        slot = OTPSlot(
            kind="yubico", aes_key=aes_key, public_id=public_id, private_id=private_id
        )
    else:  # static
        if not args.password:
            print("--password is required for a static slot", file=sys.stderr)
            sys.exit(1)
        slot = OTPSlot(kind="static", password=args.password)

    client = create_client(args)
    client.set_otp_slot(args.slot, slot.to_json_obj())
    print(f"OTP slot {args.slot} set ({args.type})")


def cmd_otp_type(args: argparse.Namespace) -> None:
    import time

    from virtual_fido.control import send_command

    path = control_socket_path(args)
    # Give the user time to focus the target field before the device starts
    # "typing" — otherwise the keystrokes land wherever focus happens to be.
    delay = max(0.0, args.delay)
    if delay:
        print(f"Focus the target field... typing slot {args.slot} in {delay:g}s")
        time.sleep(delay)
    command = f"otp-type {args.slot}"
    if args.layout:
        command += f" {args.layout}"
    try:
        response = send_command(path, command)
    except (FileNotFoundError, ConnectionRefusedError):
        print(f"No running server at control socket {path}", file=sys.stderr)
        sys.exit(1)
    print(response)
    if response.startswith("error"):
        sys.exit(1)


def cmd_pin_set(args: argparse.Namespace) -> None:
    # PINs are strings, not integers: "0000" and "0123" must be preserved
    # exactly (CTAP2 allows 4–63 UTF-8 bytes, not just digits). The minimum
    # is measured in UTF-8 bytes, matching the authenticator's check.
    pin_bytes = args.pin.encode("utf-8")
    if len(pin_bytes) < 4:
        print("Invalid PIN: PIN must be at least 4 characters", file=sys.stderr)
        sys.exit(1)
    create_client(args).set_pin(pin_bytes)
    print("PIN set")


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="virtual-fido-demo",
        description="Run a virtual FIDO2 device for logging in with WebAuthn",
    )
    parser.add_argument("--vault", default="vault.json", help="Identity vault filename")
    parser.add_argument(
        "--passphrase",
        default=None,
        help="Vault passphrase (DISCOURAGED: visible in process list;"
        " prefer --passphrase-file or the interactive prompt)",
    )
    parser.add_argument(
        "--passphrase-file",
        default=None,
        help="Read the vault passphrase from this file (trailing newline stripped)",
    )
    parser.add_argument(
        "--keyfile",
        default=None,
        help="Second vault secret: path to a keyfile (see generate-keyfile)."
        " Keep it on separate media from the vault.",
    )
    parser.add_argument(
        "--control-socket",
        default=None,
        help="Unix socket for controlling a running server (default: <vault>.sock)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    def hex_int(value: str) -> int:
        return int(value, 0)  # accepts 0x1050 as well as decimal

    start_parser = subparsers.add_parser("start", help="Attach virtual FIDO device")
    start_parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Address to bind (use the tunnel interface IP for remote use)",
    )
    start_parser.add_argument("--port", type=int, default=3240)
    start_parser.add_argument(
        "--layout",
        choices=sorted(KEYBOARD_LAYOUTS),
        default="qwerty",
        help="Keyboard layout active on the client machine, used when the OTP "
        "interface 'types' (default: qwerty; override per call with "
        "`otp type --layout`)",
    )
    identity = start_parser.add_argument_group(
        "device identity", "USB identity announced to the host (defaults: YubiKey 5)"
    )
    identity.add_argument("--vendor-id", type=hex_int, default=0x1050, metavar="0x1050")
    identity.add_argument("--product-id", type=hex_int, default=0x0407, metavar="0x0407")
    identity.add_argument("--bcd-device", type=hex_int, default=0x0574, metavar="0x0574")
    identity.add_argument("--manufacturer", default="Yubico")
    identity.add_argument("--product", default="YubiKey OTP+FIDO+CCID")
    identity.add_argument(
        "--serial-number",
        default=None,
        help="Serial number string (omitted entirely by default, like a real YubiKey)",
    )
    start_parser.set_defaults(func=cmd_start)

    list_parser = subparsers.add_parser("list", help="List identities in vault")
    list_parser.set_defaults(func=cmd_list)

    delete_parser = subparsers.add_parser("delete", help="Delete identity in vault")
    delete_parser.add_argument("--identity", required=True, help="Identity hash prefix to delete")
    delete_parser.set_defaults(func=cmd_delete)

    keyfile_parser = subparsers.add_parser(
        "generate-keyfile",
        help="Create a new keyfile at the path given by --keyfile",
    )
    keyfile_parser.set_defaults(func=cmd_generate_keyfile)

    otp_parser = subparsers.add_parser("otp", help="Manage / trigger the OTP keyboard")
    otp_sub = otp_parser.add_subparsers(dest="otp_command", required=True)
    otp_set = otp_sub.add_parser("set", help="Provision an OTP slot")
    otp_set.add_argument("--slot", type=int, choices=(1, 2), required=True)
    otp_set.add_argument("--type", choices=("yubico", "static"), default="yubico")
    otp_set.add_argument("--key", help="Yubico OTP: AES-128 key, 32 hex chars")
    otp_set.add_argument("--private-id", help="Yubico OTP: private UID, 12 hex chars")
    otp_set.add_argument("--public-id", help="Yubico OTP: public id in ModHex (optional)")
    otp_set.add_argument("--password", help="Static slot: text to type")
    otp_set.set_defaults(func=cmd_otp_set)
    otp_type = otp_sub.add_parser("type", help="Make the running device type an OTP")
    otp_type.add_argument("--slot", type=int, default=1)
    otp_type.add_argument(
        "--delay",
        type=float,
        default=3.0,
        help="Seconds to wait before typing, to focus the target field (default 3)",
    )
    otp_type.add_argument(
        "--layout",
        choices=sorted(KEYBOARD_LAYOUTS),
        default=None,
        help="Client keyboard layout for this invocation (default: the "
        "running server's --layout setting)",
    )
    otp_type.set_defaults(func=cmd_otp_type)

    pin_parser = subparsers.add_parser("pin", help="Modify PIN behavior")
    pin_subparsers = pin_parser.add_subparsers(dest="pin_command", required=True)
    pin_subparsers.add_parser("enable", help="Enable PIN protection").set_defaults(
        func=cmd_pin_enable
    )
    pin_subparsers.add_parser("disable", help="Disable PIN protection").set_defaults(
        func=cmd_pin_disable
    )
    pin_set_parser = pin_subparsers.add_parser("set", help="Set the PIN")
    pin_set_parser.add_argument(
        "--pin", required=True, help="New PIN (4-63 characters, e.g. 0000)"
    )
    pin_set_parser.set_defaults(func=cmd_pin_set)

    args = parser.parse_args(argv)
    try:
        args.func(args)
    except identities.VaultDecryptionError as err:
        print(f"Error: {err}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        # Ctrl+C during the passphrase prompt or the server loop: exit
        # quietly instead of dumping a traceback.
        print()
        sys.exit(130)  # conventional exit code for SIGINT


if __name__ == "__main__":
    main()
