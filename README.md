# Virtual FIDO (Python)

A software FIDO2/U2F security key that presents itself to a host as a real USB
HID authenticator over [USB/IP](https://usbip.sourceforge.net/). Credentials
live in an encrypted vault; user approval is delegated to the embedding
application.

This is a Python port of [bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido)
(Go), built for the two-machine setup below. The Go code in the repository
root remains the reference implementation; see [PORTING.md](PORTING.md).

## Two-machine setup

```
  Machine A (client)                         Machine B (key server)
  ------------------                         ----------------------
  sees a "real" USB               USB/IP     runs this software,
  security key         <───────────────────  stores the FIDO keys
  (Linux vhci-hcd)      encrypted tunnel      in an encrypted vault
```

Machine A needs no custom software — just the stock Linux `usbip` client and
the `vhci-hcd` kernel module. Machine B runs the Python server.

**The USB/IP protocol is plaintext and unauthenticated.** Do not expose the
server port on an untrusted network. Put a WireGuard or SSH tunnel between the
two machines and bind the server to the tunnel interface.

## Install (machine B)

Uses [`uv`](https://docs.astral.sh/uv/) for environment and dependency
management:

```bash
cd python
uv sync
```

Requires Python 3.10+. Dependencies are deliberately minimal —
[`cryptography`](https://cryptography.io) and
[`cbor2`](https://pypi.org/project/cbor2/) — to keep the security-relevant code
auditable.

## Run

Start the server on machine B, bound to its tunnel address:

```bash
# Prompts for the vault passphrase; see "Vault security" for --passphrase-file
# and --keyfile. (Demo attestation keys are testing-only — see CLI help.)
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

When you're done (or before restarting the server), detach the imported
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
  (N=2¹⁷, ~130 MiB memory-hard — parameters are stored in the file, and
  vaults written by the Go implementation still open).
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

Honest limits: while the server is running, decrypted keys are in process
memory, and Python cannot reliably zero them — an attacker who can read the
server process's memory wins regardless of file encryption. Keep machine B
minimal and don't browse on it; that's the point of the two-machine split.

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
up automatically (no restart needed). Caveat: HID keyboards send *keycodes*, so
what gets typed depends on the client's keyboard layout — Yubico's ModHex
alphabet is chosen to be layout-stable, but arbitrary static passwords with
symbols are not. Aim `otp type` at a plain text field, not your terminal.

## Device identity

By default the device announces itself exactly like a YubiKey 5, matching a
real key's kernel enumeration:

```text
usb 3-2: New USB device found, idVendor=1050, idProduct=0407, bcdDevice= 5.74
usb 3-2: New USB device strings: Mfr=1, Product=2, SerialNumber=0
usb 3-2: Product: YubiKey OTP+FIDO+CCID
usb 3-2: Manufacturer: Yubico
```

Every value is overridable — via CLI flags:

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

Note: only the USB identity is emulated. The device exposes a single FIDO HID
interface — a real "OTP+FIDO+CCID" YubiKey additionally exposes keyboard (OTP)
and smartcard (CCID) interfaces, so `lsusb -v` output will differ in the
interface list even though enumeration strings match.

### Example WireGuard tunnel

Bring up a WireGuard interface between the machines (e.g. `10.0.0.1` on A,
`10.0.0.2` on B), then `--bind 10.0.0.2` on the server and
`usbip attach -r 10.0.0.2` on the client. An SSH tunnel works too:

```bash
# On machine A: forward local 3240 to the server over SSH, then attach locally
ssh -L 3240:127.0.0.1:3240 user@machine-B
sudo usbip attach -r 127.0.0.1 -b 2-2
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
registrations/logins are approved and how the encrypted vault is stored.

## Tests

```bash
uv run pytest
```

The suite ports the Go unit tests and adds a full-stack integration test that
drives HID packets through the entire server (USB → CTAPHID → CTAP2/U2F →
client). Vault files are format-compatible with the Go implementation, verified
by a golden vault in `tests/data/`.

Live `usbip attach` is not exercised by the test suite (it needs the
`vhci-hcd` kernel module, `usbip` userspace tools and root); use the manual
attach steps above to verify the transport end to end.
