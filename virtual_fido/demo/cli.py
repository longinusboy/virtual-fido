"""Reference CLI: run the virtual FIDO device and manage its vault.

Port of the Go cmd/demo. Everything about key management here is INSECURE
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


def cmd_start(args: argparse.Namespace) -> None:
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
    print(f"Serving USB/IP on {args.bind}:{args.port}")
    print(
        f"Device identity: {device_config.manufacturer} {device_config.product}"
        f" ({device_config.id_vendor:04x}:{device_config.id_product:04x})"
    )
    print("Attach from the client machine (Linux):")
    print("  sudo modprobe vhci-hcd")
    print(f"  sudo usbip attach -r {args.bind} -b 2-2")
    virtual_fido.start(
        client, bind_address=args.bind, port=args.port, device_config=device_config
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
