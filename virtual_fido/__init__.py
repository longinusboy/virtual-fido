"""Virtual FIDO2/U2F authenticator exposed as a USB device over USB/IP.

Python port of github.com/bulwarkid/virtual-fido (commit 512d8a3), whose
Go code is the reference implementation for the ported layers.

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
    ccid=None,
) -> None:
    """Wire the full server stack and serve USB/IP (blocking).

    `client` must implement both the CTAP2 and U2F client interfaces —
    see fido_client.DefaultFIDOClient. `device_config` is an optional
    usb.USBDeviceConfig controlling the USB identity the host sees
    (defaults to a YubiKey 5). `otp` / `ccid` are optional extra interfaces
    (otp.OTPKeyboardInterface, ccid.CCIDInterface); when present the device
    exposes them as interface 0 (OTP) and interface 2 (CCID), around FIDO, to
    match a real YubiKey's OTP+FIDO+CCID layout. Equivalent of Go's Start.
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
    if ccid is not None:
        interfaces.append(ccid)
    device = usb.USBDevice(interfaces, config=device_config)
    server = usbip.USBIPServer([device], bind_address=bind_address, port=port)
    server.start()
