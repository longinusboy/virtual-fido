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


def start(
    client,
    bind_address: str = "127.0.0.1",
    port: int = 3240,
    device_config=None,
    otp=None,
) -> None:
    """Wire the full server stack and serve USB/IP (blocking).

    `client` must implement both the CTAP2 and U2F client interfaces —
    see fido_client.DefaultFIDOClient. `device_config` is an optional
    usb.USBDeviceConfig controlling the USB identity the host sees
    (defaults to a YubiKey 5). `otp` is an optional otp.OTPKeyboardInterface;
    when present the device exposes an OTP keyboard interface (interface 0,
    before FIDO, matching a real YubiKey). Equivalent of Go's virtual_fido.Start.
    """
    from . import ctap, ctap_hid, u2f, usb, usbip
    from .fido_hid import FidoHIDInterface

    ctap_server = ctap.CTAPServer(client)
    u2f_server = u2f.U2FServer(client)
    ctap_hid_server = ctap_hid.CTAPHIDServer(ctap_server, u2f_server)
    interfaces = []
    if otp is not None:
        interfaces.append(otp)
    interfaces.append(FidoHIDInterface(ctap_hid_server))
    device = usb.USBDevice(interfaces, config=device_config)
    server = usbip.USBIPServer([device], bind_address=bind_address, port=port)
    server.start()
