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
import hashlib
import logging
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

    def __init__(self, vault_filename: str, vault_passphrase: str) -> None:
        self._vault_path = Path(vault_filename)
        self._passphrase = vault_passphrase

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


def create_client(args: argparse.Namespace) -> DefaultFIDOClient:
    # ALL OF THIS IS INSECURE, FOR TESTING PURPOSES ONLY
    ca_private_key = identities.create_ca_private_key()
    certificate_authority = identities.create_self_signed_ca(ca_private_key)
    encryption_key = hashlib.sha256(b"test").digest()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    support = TerminalSupport(args.vault, args.passphrase)
    return DefaultFIDOClient(
        attestation_ca_certificate=certificate_authority,
        attestation_ca_private_key=ca_private_key,
        secret_encryption_key=encryption_key,
        enable_pin=False,
        request_approver=support,
        data_saver=support,
    )


def cmd_start(args: argparse.Namespace) -> None:
    client = create_client(args)
    print(f"Serving USB/IP on {args.bind}:{args.port}")
    print("Attach from the client machine (Linux):")
    print("  sudo modprobe vhci-hcd")
    print(f"  sudo usbip attach -r {args.bind} -b 2-2")
    virtual_fido.start(client, bind_address=args.bind, port=args.port)


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


def cmd_pin_set(args: argparse.Namespace) -> None:
    pin = str(args.pin)
    if args.pin < 0 or len(pin) < 4:
        print("Invalid PIN: PIN must be at least 4 digits", file=sys.stderr)
        sys.exit(1)
    create_client(args).set_pin(pin.encode())
    print("PIN set")


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(
        prog="virtual-fido-demo",
        description="Run a virtual FIDO2 device for logging in with WebAuthn",
    )
    parser.add_argument("--vault", default="vault.json", help="Identity vault filename")
    parser.add_argument("--passphrase", default="passphrase", help="Identity vault passphrase")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    subparsers = parser.add_subparsers(dest="command", required=True)

    start_parser = subparsers.add_parser("start", help="Attach virtual FIDO device")
    start_parser.add_argument(
        "--bind",
        default="127.0.0.1",
        help="Address to bind (use the tunnel interface IP for remote use)",
    )
    start_parser.add_argument("--port", type=int, default=3240)
    start_parser.set_defaults(func=cmd_start)

    list_parser = subparsers.add_parser("list", help="List identities in vault")
    list_parser.set_defaults(func=cmd_list)

    delete_parser = subparsers.add_parser("delete", help="Delete identity in vault")
    delete_parser.add_argument("--identity", required=True, help="Identity hash prefix to delete")
    delete_parser.set_defaults(func=cmd_delete)

    pin_parser = subparsers.add_parser("pin", help="Modify PIN behavior")
    pin_subparsers = pin_parser.add_subparsers(dest="pin_command", required=True)
    pin_subparsers.add_parser("enable", help="Enable PIN protection").set_defaults(
        func=cmd_pin_enable
    )
    pin_subparsers.add_parser("disable", help="Disable PIN protection").set_defaults(
        func=cmd_pin_disable
    )
    pin_set_parser = pin_subparsers.add_parser("set", help="Set the PIN")
    pin_set_parser.add_argument("--pin", type=int, required=True, help="New PIN")
    pin_set_parser.set_defaults(func=cmd_pin_set)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
