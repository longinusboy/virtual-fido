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

```bash
cd python
python3 -m venv .venv && . .venv/bin/activate
pip install -e .
```

Requires Python 3.10+. Dependencies are deliberately minimal —
[`cryptography`](https://cryptography.io) and
[`cbor2`](https://pypi.org/project/cbor2/) — to keep the security-relevant code
auditable.

## Run

Start the server on machine B, bound to its tunnel address:

```bash
# Insecure demo credentials — testing only (see the warning in the CLI help)
virtual-fido-demo --vault vault.json --passphrase secret start --bind 10.0.0.2

# Vault management
virtual-fido-demo list
virtual-fido-demo delete --identity <hash-prefix>
virtual-fido-demo pin enable | disable | set --pin 1234
```

Attach the device on machine A (Linux, needs root):

```bash
sudo modprobe vhci-hcd
sudo usbip attach -r 10.0.0.2 -b 2-2
```

The host should now enumerate a "Virtual FIDO" HID device (`lsusb`). Test it
against the [YubiKey WebAuthn demo page](https://demo.yubico.com/webauthn-technical/registration).

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
pip install -e '.[dev]'
pytest
```

The suite ports the Go unit tests and adds a full-stack integration test that
drives HID packets through the entire server (USB → CTAPHID → CTAP2/U2F →
client). Vault files are format-compatible with the Go implementation, verified
by a golden vault in `tests/data/`.

> **Live `usbip attach` is not exercised by the test suite** — it needs the
> kernel `vhci-hcd` module and `usbip` userspace tools on the test machine.
> Run the manual attach steps above on a stock-kernel Linux box to verify the
> transport end to end.
