# Virtual FIDO (Python)

A software security key that emulates a **YubiKey 5 (OTP+FIDO+CCID)** and
presents itself to a host as a real USB device over
[USB/IP](https://usbip.sourceforge.net/). Keys live in an encrypted vault on a
separate machine; the host only sees a USB dongle.

Supported functions, all verified against real tooling (browsers, `ykman`,
OpenSC, `pcsc_scan`):

- **FIDO2 / WebAuthn and U2F** — CTAP2.1 with PIN/UV auth protocols 1 and 2.
- **OTP keyboard** — Yubico OTP and static passwords, typed on demand, with
  per-client keyboard layout support.
- **OATH** (TOTP/HOTP) over the CCID smartcard interface — works with
  `ykman oath`.
- **PIV** smartcard — on-device RSA/ECC keys, certificates, signing and
  decryption — works with `ykman piv` and OpenSC PKCS#11.

## Origin and credits

This project is a Python port of
[bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido), a Go
library by Chris de la Iglesia (BulwarkID) and contributors, based on commit
[`512d8a3`](https://github.com/bulwarkid/virtual-fido/tree/512d8a3fef0e073171a7ef3261f300e8a5e48694)
(June 2024). It started as a simple test for the Claude Fable 5 model: porting
the Go code to Python, then extending it into a full YubiKey 5 emulation (OTP,
CCID, OATH and PIV have no counterpart in the original).

The Go implementation served as the specification for the ported layers; see
[Differences from the upstream Go implementation](#differences-from-the-upstream-go-implementation).
Both projects are MIT-licensed — see [LICENSE](LICENSE).

## Two-machine setup

```
  Machine A (client)                         Machine B (key server)
  ------------------                         ----------------------
  sees a "real" USB               USB/IP     runs this software,
  security key         <───────────────────  stores the keys
  (Linux vhci-hcd)      encrypted tunnel      in an encrypted vault
```

- **Machine A (client)** needs no custom software: Linux with the stock
  `usbip` client and the `vhci-hcd` kernel module.
- **Machine B (key server)** runs this Python server: Python 3.10+, Linux or
  another POSIX system (the OTP control channel uses a Unix socket).

**The USB/IP protocol is plaintext and unauthenticated.** Do not expose the
server port on an untrusted network. Put a WireGuard or SSH tunnel between the
two machines and bind the server to the tunnel interface. With WireGuard (for
example `10.0.0.1` on A and `10.0.0.2` on B), use `--bind 10.0.0.2` on the
server and `usbip attach -r 10.0.0.2` on the client. An SSH tunnel works too:

```bash
# On machine A: forward local 3240 to the server over SSH, then attach locally
ssh -L 3240:127.0.0.1:3240 user@machine-B
sudo usbip attach -r 127.0.0.1 -b 2-2
```

## Install (machine B)

Uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency
management. Clone the repository and install the dependencies:

```bash
git clone https://github.com/longinusboy/virtual-fido.git
cd virtual-fido
uv sync
```

All `uv run` commands below are run from the cloned `virtual-fido` directory.

Dependencies are deliberately minimal —
[`cryptography`](https://cryptography.io) and
[`cbor2`](https://pypi.org/project/cbor2/) — to keep the security-relevant code
auditable.

## Run

Start the server on machine B, bound to its tunnel address:

```bash
# Prompts for the vault passphrase; see "Vault security" for --passphrase-file
# and --keyfile. (Demo attestation keys are testing-only — see SECURITY.md.)
uv run virtual-fido-demo --vault vault.json start --bind 10.0.0.2

# Vault management
uv run virtual-fido-demo list
uv run virtual-fido-demo delete --identity <hash-prefix>
uv run virtual-fido-demo pin enable | disable | set --pin 1234
```

Attach the device on machine A (Linux, needs root):

```bash
sudo modprobe vhci-hcd
sudo usbip attach -r 10.0.0.2 -b 2-2
```

The host now enumerates the device (`lsusb`, `dmesg`) and it is usable by
browsers. Test it against the
[YubiKey WebAuthn demo page](https://demo.yubico.com/webauthn-technical/registration).

### Detach / cleanup (machine A)

When you are done (or before restarting the server), detach the imported
device — otherwise the host keeps a stale USB port around:

```bash
# Find the vhci port the device is attached on ("Port 00", "Port 01", ...)
sudo usbip port

# Detach that port
sudo usbip detach -p 0

# Optional: unload the client driver entirely
sudo modprobe -r vhci-hcd
```

If the server went away first, `usbip detach` may complain; unloading and
reloading `vhci-hcd` clears any leftover state.

## Vault security

The vault file is what an attacker wants, so it is protected in layers:

- **Encryption at rest**: the vault is JSON encrypted with AES-256-GCM; the
  key is wrapped by a key derived from your passphrase with scrypt
  (N=2¹⁷, ~130 MiB memory-hard — parameters are stored in the file).
- **Passphrase input**: interactive prompt by default, or
  `--passphrase-file <path>` for services. `--passphrase` on the command line
  works but warns (visible in the process list). **Environment variables are
  deliberately not supported** — they leak through `/proc/<pid>/environ`,
  shell history and unit files, which are prime info-stealer targets.
- **Keyfile (second secret, recommended)**: with `--keyfile`, a random
  32-byte file is mixed into the key derivation. An attacker then needs the
  vault, the keyfile *and* the passphrase. Keep the keyfile on separate media
  from the vault (USB stick, different mount):

  ```bash
  uv run virtual-fido-demo --keyfile /media/usb/vault.key generate-keyfile
  uv run virtual-fido-demo --vault vault.json --keyfile /media/usb/vault.key start
  ```

  An existing vault adopts the keyfile automatically on its next save; from
  then on it cannot be opened without it — **losing the keyfile means losing
  the vault**, so back it up (separately from the vault).

**Vault format versions.** v1 is the format written by the upstream Go
implementation; it is still read. v2 is the current write format (stronger
scrypt parameters stored in the blob, optional keyfile). The OTP, OATH and PIV
state are additive optional sections inside the encrypted vault.

Honest limits: while the server is running, decrypted keys are in process
memory, and Python cannot reliably zero them — an attacker who can read the
server process's memory wins regardless of file encryption. Keep machine B
minimal and do not browse on it; that is the point of the two-machine split.
See [SECURITY.md](SECURITY.md) for the full trust model.

## OTP (one-time passwords)

The device exposes an OTP HID **keyboard** interface, like a real YubiKey.
Since there is no physical button, output is triggered explicitly: provision a
slot, start the server, then trigger typing while the target field is focused
on the client machine.

```bash
# Provision slot 1 as a Yubico OTP (AES key + private/public id)
uv run virtual-fido-demo --vault vault.json otp set --slot 1 --type yubico \
    --key 00112233445566778899aabbccddeeff \
    --private-id 010203040506 --public-id ccccccbbbbbb

# ...or a static password
uv run virtual-fido-demo --vault vault.json otp set --slot 2 --type static --password "s3cret"

# With the server running, "type" a slot. By default it waits 3s first so you
# can focus the target field on the client; tune with --delay.
uv run virtual-fido-demo --vault vault.json otp type --slot 1 --delay 3
```

`otp type` talks to the running server over a local Unix control socket
(default under `$XDG_RUNTIME_DIR`, keyed by vault; override with
`--control-socket`). Slots provisioned while the server is running are picked
up automatically (no restart needed). Aim `otp type` at a plain text field,
not your terminal.

### Keyboard layouts

HID keyboards send *key positions*, and the client maps positions to
characters using its active layout — so the server must "type" the positions
that produce the right characters *under the client's layout* (real YubiKeys
have the same limitation). Supported layouts: `qwerty` (default), `qwertz`,
`azerty` (French), `dvorak`, `colemak`, `colemak-dh` (ANSI), `colemak-dh-iso`.
The tables are generated from the xkb database
(`tools/gen_keyboard_layouts.py`).

```bash
# Set the default for the attached client at startup...
uv run virtual-fido-demo --vault vault.json start --layout colemak-dh

# ...or override per invocation
uv run virtual-fido-demo --vault vault.json otp type --slot 1 --layout azerty
```

If a static password contains a character the selected layout cannot produce,
`otp type` fails as a whole (nothing is typed partially).

**Alternative: force US layout for just this device on the client.** This
makes typing layout-agnostic (the default `qwerty` table is then always
correct), at the cost of a one-time client config. On X11, drop this into
`/etc/X11/xorg.conf.d/99-yubikey-us.conf`:

```
Section "InputClass"
    Identifier   "YubiKey OTP uses US layout"
    MatchUSBID   "1050:0407"
    MatchIsKeyboard "on"
    Option       "XkbLayout"  "us"
    Option       "XkbVariant" ""
EndSection
```

On KDE Wayland, per-device layouts can be assigned in System Settings →
Keyboard. GNOME Wayland has no per-device layout setting — use `--layout`
there.

## CCID (smartcard)

The device exposes a CCID smartcard interface, like a real YubiKey. The reader
enumerates, the virtual card answers power-on with a YubiKey ATR (`pcsc_scan`
fingerprints it as a YubiKey 5), and APDUs route to applets by AID. Both
extended-length APDUs (used by `ykman`) and ISO 7816 command chaining (used by
OpenSC) are supported. On the client, `pcscd` must be running.

### OATH (TOTP/HOTP)

Provision and use it from the client with the standard Yubico tooling — no
server-side management needed; credentials are stored in the encrypted vault:

```bash
ykman oath accounts add demo:alice   # paste a base32 secret
ykman oath accounts code demo:alice  # prints the current TOTP
```

Credentials survive restarts and stay in sync with a running server.

### PIV (certificates and keys)

Key slots 9A/9C/9D/9E, PIN/PUK, 3DES management key, on-device RSA (1024/2048)
and ECC (P-256/P-384) key generation, signing, RSA decryption, and certificate
storage. Use it from the client with `ykman piv` or OpenSC.

Defaults match a stock YubiKey: PIN `123456`, PUK `12345678`, 3DES management
key `010203...` (the device reports 3DES via metadata). The PIV PIN is separate
from the FIDO2 PIN (`pin set` in the demo CLI) — change it with
`ykman piv access change-pin`. Keys and certificates persist in the vault.
Only the USB/PIV protocol is emulated — there is no physical touch, so
touch-policy prompts do not apply.

Example workflow (all on the client, with the device attached):

```bash
# Change the well-known defaults first
ykman piv access change-pin        # old PIN: 123456
ykman piv access change-puk        # old PUK: 12345678
ykman piv access change-management-key   # old key: blank prompt = default

# Generate a key on-device in slot 9A (PIV Authentication) + self-signed cert
ykman piv info
ykman piv keys generate 9a pub.pem
ykman piv certificates generate 9a pub.pem --subject "CN=me"

# The key/cert are now visible through OpenSC's PKCS#11 module
pkcs11-tool --list-objects               # public objects
pkcs11-tool -l --list-objects            # + private key (prompts PIN)

# Sign a file through PKCS#11 and verify the signature with openssl
echo "hello world" > msg.txt
pkcs11-tool -l --sign --mechanism SHA256-RSA-PKCS --id 01 -i msg.txt -o msg.sig
ykman piv certificates export 9a cert.pem
openssl x509 -in cert.pem -noout -pubkey > pub_from_cert.pem
openssl dgst -sha256 -verify pub_from_cert.pem -signature msg.sig msg.txt
# -> Verified OK
```

(OpenSC maps PIV slot 9A to PKCS#11 object ID `01`; slots 9C/9D/9E map to
`02`/`03`/`04`.)

## Device identity

By default the device announces itself exactly like a YubiKey 5, matching a
real key's kernel enumeration:

```text
usb 3-2: New USB device found, idVendor=1050, idProduct=0407, bcdDevice= 5.74
usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=0
usb 3-2: Product: YubiKey OTP+FIDO+CCID
usb 3-2: Manufacturer: Yubico
```

It exposes the same three interfaces as the real device: interface 0 is the
OTP keyboard, interface 1 is FIDO HID, and interface 2 is CCID. Every identity
value is overridable — via CLI flags:

```bash
uv run virtual-fido-demo start \
    --vendor-id 0x1050 --product-id 0x0407 --bcd-device 0x0574 \
    --manufacturer Yubico --product "YubiKey OTP+FIDO+CCID" \
    --serial-number 123456   # omitted entirely by default, like a real YubiKey
```

or in code with `usb.USBDeviceConfig`:

```python
from virtual_fido.usb import USBDeviceConfig

config = USBDeviceConfig(id_vendor=0x1050, id_product=0x0407, bcd_device=0x0574,
                         manufacturer="Yubico", product="YubiKey OTP+FIDO+CCID")
virtual_fido.start(client, bind_address="10.0.0.2", device_config=config)
```

## Library use

```python
import virtual_fido
from virtual_fido.fido_client import DefaultFIDOClient

client = DefaultFIDOClient(
    attestation_ca_certificate=...,   # x509.Certificate
    attestation_ca_private_key=...,   # cose.COSEPrivateKey
    secret_encryption_key=...,        # 32 bytes
    enable_pin=False,
    request_approver=my_approver,     # .approve_client_action(action, params) -> bool
    data_saver=my_saver,              # .save_data / .retrieve_data / .passphrase
)
virtual_fido.start(client, bind_address="10.0.0.2")
```

Implement `ClientRequestApprover` and `ClientDataSaver` (see
[`virtual_fido/fido_client.py`](virtual_fido/fido_client.py)) to control how
registrations/logins are approved and how the encrypted vault is stored. The
demo CLI ([`virtual_fido/demo/cli.py`](virtual_fido/demo/cli.py)) is a
complete reference, including the OTP, OATH and PIV wiring — but its
attestation key management is insecure and for testing only.

## Architecture

Each layer wraps the next:

```
USBIPServer (usbip.py)          TCP, USB/IP protocol; bind address configurable
  └─ USBDevice (usb.py)         composite device: descriptors, control transfers,
     │                          endpoint routing across interfaces
     ├─ OTPKeyboardInterface (otp.py)    HID keyboard; Yubico OTP / static password
     ├─ FidoHIDInterface (fido_hid.py)   FIDO HID transport
     │    └─ CTAPHIDServer (ctap_hid.py) packets → transactions → channels; keepalives
     │        ├─ CTAPServer (ctap.py)    FIDO2/CTAP2 (CBOR)
     │        └─ U2FServer (u2f.py)      U2F/CTAP1
     │            └─ DefaultFIDOClient (fido_client.py)  credentials, approval, PIN
     └─ CCIDInterface (ccid.py)          smartcard reader; APDU dispatch to applets
          ├─ OATHApplet (applets/oath.py)  ykoath TOTP/HOTP
          └─ PIVApplet (applets/piv.py)    PIV keys/certificates, sign/decrypt
```

| Module | Purpose |
|--------|---------|
| `usbip.py` | USB/IP wire protocol and TCP server. The server itself does no encryption — remote use goes through a tunnel. |
| `usb.py` | Multi-interface USB device: descriptors, control transfers, endpoint routing. |
| `fido_hid.py` | FIDO HID interface. |
| `ctap_hid.py` | CTAPHID packet reassembly, transactions, channels, keepalives. |
| `ctap.py` | CTAP2 (CBOR) command handling. |
| `pin_protocol.py` | PIN/UV auth protocols 1 and 2 (shared secret, encrypt/decrypt, authenticate). |
| `u2f.py` | U2F / CTAP1. |
| `fido_client.py` | `DefaultFIDOClient`, approval and data-saver interfaces, applet state persistence. |
| `identities.py` | Vault, attestation certificates, encrypted saved state (v1/v2). |
| `crypto.py`, `cose.py`, `webauthn.py` | ECDSA/Ed25519/ECDH/AES via `cryptography`; COSE keys; WebAuthn structures. |
| `otp.py` | OTP HID keyboard, Yubico OTP, ModHex, CRC16. |
| `keyboard_layouts.py` | Per-layout typing tables (generated — edit `tools/gen_keyboard_layouts.py` and re-run it instead). |
| `control.py` | Local Unix-socket control channel (`otp type`). |
| `ccid.py` | CCID message layer, ISO 7816-4 APDU parsing, applet routing, response and command chaining. |
| `applets/oath.py` | OATH applet (ykoath protocol). |
| `applets/piv.py` | PIV applet (NIST SP 800-73 with YubiKey extensions). |
| `demo/cli.py` | `virtual-fido-demo` command-line interface. |

## Differences from the upstream Go implementation

The ported layers follow the Go code closely, including its protocol quirks
(several CTAPHID fixes upstream were hard-won against real USB/IP clients).
Deliberate differences:

- **New functionality:** the OTP keyboard, CCID transport, OATH and PIV
  applets, the multi-interface USB device, the control socket and keyboard
  layouts do not exist upstream.
- **CTAP2.1 PIN support:** upstream implements only PIN/UV auth protocol 1
  with the legacy token command and advertises FIDO_2_0. This port adds
  protocol 2 and the permissions-based token (subcommand 0x09) and advertises
  FIDO_2_1, which modern browsers require for PIN entry. PINs are strings
  (4–63 UTF-8 bytes), never integers.
- **Interrupt-IN polls are held pending, never timed out.** Upstream completes
  an unanswered poll empty after one second; that injects a bogus HID packet
  and races with multi-packet replies (it broke PIN entry). Here a poll waits
  until data is available or the host cancels it, like a real endpoint.
- **IN transfers return exact-length data** instead of zero-padding to the
  requested buffer size (required by CCID bulk transfers).
- **Vault format v2** (stronger scrypt, parameters in the blob, optional
  keyfile). Upstream-written v1 vaults are still read, but the Go code cannot
  read v2.
- **Encoding details:** fixed-length EC coordinates and positive certificate
  serial numbers. RSA is not supported for FIDO credentials (it is supported
  for PIV).
- **No secret logging.** Upstream's `LogLevelUnsafe` tier is intentionally not
  ported.
- **Concurrency** uses threads and callbacks, mirroring the upstream goroutine
  model; protocol errors raise exceptions that are caught at the USB/IP
  connection loop, so one bad packet never kills the server.
- **macOS DriverKit transport** from upstream is not ported; the server uses
  USB/IP only.

## Development

```bash
uv sync                              # set up once
uv run pytest                        # whole suite
uv run pytest tests/test_piv.py      # one module
uv run pytest -k pin_set             # one test by name expression
uv run python tools/gen_keyboard_layouts.py   # regenerate layout tables (needs xkb data)
```

The suite contains ports of the upstream unit tests, test vectors (RFC 4226
and RFC 6238 for OATH, signature verification for PIV), a golden vault written
by the Go implementation (`tests/data/go_vault.json`), and a full-stack
integration test that drives HID packets through the entire server (USB →
CTAPHID → CTAP2/U2F → client). Smartcard tests drive the CCID card exactly as
`ykman` and OpenSC do.

Live `usbip attach` is not exercised by the test suite (it needs the
`vhci-hcd` kernel module, `usbip` userspace tools and root); use the manual
attach steps above to verify the transport end to end.

Conventions for contributions:

- **Keep dependencies minimal** (`cryptography`, `cbor2`). Auditability is a
  core goal; new dependencies need a strong reason.
- **Never log secrets** (keys, PINs, passphrases, OTP material).
- **Wire formats use `struct` with explicit endianness.** USB/IP headers are
  big-endian, USB descriptors little-endian, and CTAPHID mixes little-endian
  channel/command fields with a big-endian payload length.
- **Vault format changes** need a new version number, a migration path, and
  tests; the Go golden vault must keep opening.
- **Validate against real tooling** (browsers, `ykman`, OpenSC) for protocol
  changes, not only unit tests — client libraries are stricter than specs
  suggest (for example, `ykman` reads specific TLV tags unconditionally).

## Security

Please read [SECURITY.md](SECURITY.md) for the trust model and how to report
vulnerabilities privately.

## License

MIT — see [LICENSE](LICENSE). Copyright © 2022 BulwarkID (original Go
implementation) and © 2026 David Silva (Python port and YubiKey emulation).
