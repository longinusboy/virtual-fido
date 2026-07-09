"""Virtual FIDO2/U2F authenticator exposed as a USB device over USB/IP.

Python port of github.com/bulwarkid/virtual-fido (the Go code in the
repository root is the reference implementation).

Usage:
    client = fido_client.DefaultFIDOClient(...)
    virtual_fido.start(client)          # serves USB/IP on 127.0.0.1:3240

Then attach from the machine that should see the dongle (Linux):
    sudo modprobe vhci-hcd
    sudo usbip attach -r <server-ip> -b 2-2

For remote use, bind to a tunnel interface (WireGuard/SSH) — the USB/IP
protocol itself is plaintext and unauthenticated.
"""

from __future__ import annotations

__version__ = "0.1.0"


def start(client, bind_address: str = "127.0.0.1", port: int = 3240) -> None:
    """Wire the full server stack and serve USB/IP (blocking).

    `client` must implement both the CTAP2 and U2F client interfaces —
    see fido_client.DefaultFIDOClient. Equivalent of Go's
    virtual_fido.Start/startClient.
    """
    from . import ctap, ctap_hid, u2f, usb, usbip

    ctap_server = ctap.CTAPServer(client)
    u2f_server = u2f.U2FServer(client)
    ctap_hid_server = ctap_hid.CTAPHIDServer(ctap_server, u2f_server)
    device = usb.USBDevice(ctap_hid_server)
    server = usbip.USBIPServer([device], bind_address=bind_address, port=port)
    server.start()
