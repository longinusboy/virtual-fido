"""Walking skeleton: expose the virtual USB HID device with a stub transport.

This exists to prove the risky layer (USB/IP + USB + HID enumeration against
the Linux kernel) works before the CTAP stack is ported.

Server:  python -m virtual_fido.skeleton [--bind 127.0.0.1] [--port 3240] [-v]
Client:  sudo modprobe vhci-hcd
         sudo usbip attach -r <server-ip> -b 2-2
Verify:  lsusb   (a "Virtual FIDO" HID device should enumerate)
"""

from __future__ import annotations

import argparse
import logging
from typing import Callable, Optional

from . import usb, usbip

logger = logging.getLogger("virtual_fido.skeleton")


class NullCTAPHIDDelegate:
    """Stand-in for the CTAPHID server: logs traffic, never responds."""

    def __init__(self) -> None:
        self._respond: Optional[Callable[[bytes], None]] = None

    def set_response_handler(self, handler: Callable[[bytes], None]) -> None:
        self._respond = handler

    def handle_message(self, transfer_buffer: bytes) -> None:
        logger.info("HID report received (%d bytes): %s",
                    len(transfer_buffer), transfer_buffer.hex())


def main(argv: Optional[list[str]] = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1",
                        help="Address to bind (use the tunnel interface IP for remote use)")
    parser.add_argument("--port", type=int, default=3240)
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    from .fido_hid import FidoHIDInterface

    device = usb.USBDevice([FidoHIDInterface(NullCTAPHIDDelegate())])
    server = usbip.USBIPServer([device], bind_address=args.bind, port=args.port)
    server.start()


if __name__ == "__main__":
    main()
