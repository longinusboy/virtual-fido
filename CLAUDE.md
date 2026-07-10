# CLAUDE.md — Python port

This file guides Claude Code when working in the `python/` subtree. It
supplements the root [CLAUDE.md](../CLAUDE.md), which documents the original Go
library (the reference implementation for this port).

## What this is

A Python port of the Go virtual-fido library, built for a two-machine setup:
one machine runs this software and stores the FIDO keys; another machine
attaches the emulated USB security key over USB/IP across an encrypted tunnel.
See [README.md](README.md) for the setup and [PORTING.md](PORTING.md) for the
Go→Python module map and conventions.

## Commands

This project uses [`uv`](https://docs.astral.sh/uv/) — never pip/venv directly.

```bash
# From python/ — set up once
uv sync

# Test
uv run pytest                       # whole suite (~75 tests, ~2s)
uv run pytest tests/test_ctap.py    # one module
uv run pytest -k pin_set            # one test by name expression

# Run the demo server (insecure demo keys — testing only)
uv run virtual-fido-demo --vault vault.json --passphrase pw start --bind 127.0.0.1
uv run python -m virtual_fido.skeleton -v      # transport-only walking skeleton
```

Live `usbip attach` works on this machine (the user fixed the kernel tools)
but needs sudo, so the test suite doesn't exercise it — ask the user to run
attach tests, or hand them the commands (see README "Run"/"Detach").

## Architecture

Same server stack as the Go version — each layer wraps the next. `virtual_fido.start()`
(in `virtual_fido/__init__.py`) wires it up:

```
USBIPServer (usbip.py)       TCP, USB/IP protocol; bind address configurable
  └─ USBDevice (usb.py)      USB descriptors + HID interface + endpoint buffering
     (identity via USBDeviceConfig — defaults announce a YubiKey 5:
      1050:0407, bcdDevice 5.74, "Yubico" / "YubiKey OTP+FIDO+CCID", no serial)
      └─ CTAPHIDServer (ctap_hid.py)   packets → transactions → channels; keepalives
          ├─ CTAPServer (ctap.py)      FIDO2/CTAP2 (CBOR via cbor2)
          └─ U2FServer (u2f.py)        U2F/CTAP1
              └─ DefaultFIDOClient (fido_client.py)   credentials + approval + PIN
```

Supporting modules: `crypto.py` (ECDSA/Ed25519/AES-GCM/AES-CBC/ECDH via
`cryptography`), `pin_protocol.py` (PIN/UV auth protocols 1 and 2 — shared
secret derivation, encrypt/decrypt, authenticate), `cose.py` (COSE key
encode/decode, ES256 + Ed25519),
`identities.py` (vault, attestation certs, scrypt+AES-GCM encrypted saved
state), `webauthn.py` (shared structs with CBOR + JSON serializations),
`_util.py` (`RequestBuffer`, timers, C-string helpers).

## Conventions specific to this port

- **The Go code is the spec.** When behavior is unclear, match the Go
  implementation, including its protocol quirks (e.g. USB/IP `actual_length`
  is always the full buffer length; the CTAPHID keepalive cadence that fixed
  Windows timeouts). Deliberate deviations are commented in the source and
  listed in [PORTING.md](PORTING.md) — notably fixed-length EC coordinates,
  positive cert serial numbers, and no RSA/no `LogLevelUnsafe`.
- **Minimal dependencies** (`cryptography`, `cbor2`) — do not add more without
  a strong reason; auditability is the point of the rewrite.
- **Vault format is versioned.** v1 = Go-compatible (read-only;
  `tests/data/go_vault.json` is a Go-written golden vault — keep it opening).
  v2 = current write format: scrypt N=2¹⁷ with parameters stored in the blob,
  plus an optional keyfile mixed into the KDF via HKDF (second secret; see
  README "Vault security"). Passphrases come from a prompt or file, never env
  vars. Any format change needs a new version, a migration path, and tests.
- **Wire formats use `struct` with explicit endianness.** USB/IP headers are
  big-endian; USB descriptors little-endian; CTAPHID mixes little-endian
  channel/command with big-endian payload length. Match the Go `ToLE`/`ToBE`
  usage exactly.
- **Interrupt-IN polls are held pending, never timed out.** The Go original
  cancels an unanswered interrupt-IN poll after 1s and completes it empty;
  that injects a bogus all-zero HID packet and creates a slow re-poll cadence
  that races with multi-packet responses (it broke the 2-packet
  getKeyAgreement reply during PIN entry — the host aborted mid-flow). We
  instead leave the poll pending until CTAPHID produces data or the host
  UNLINKs it, like a real interrupt endpoint NAKing. Don't reintroduce a
  timeout NAK on `ENDPOINT_OUTPUT`.
- **Concurrency uses threads + callbacks**, mirroring the Go goroutine model
  (chosen so behavior can be checked against the reference without a live
  attach). An asyncio redesign is deferred until after the transport is
  validated against a real `usbip` client.
- Protocol errors raise exceptions caught at the USB/IP connection loop
  (Go uses panic+recover at the same boundary); never let one bad packet kill
  the server.
- **PIN goes beyond the Go reference.** The Go original only did PIN/UV auth
  protocol 1 + legacy getPinToken and advertised FIDO_2_0. Modern browsers use
  protocol 2 + getPinUvAuthTokenUsingPinWithPermissions (subcommand 0x09), so
  this port advertises FIDO_2_1 + `pinUvAuthToken` + both protocols and
  implements them (`pin_protocol.py`, `ctap.py`). PINs are strings (4–63 UTF-8
  bytes), never parsed as integers — "0000" must survive.

## Validation approach (no live USB/IP here)

- Ported Go unit tests, module for module.
- Byte-level golden vectors against the Go implementation (device summary
  bytes; a Go-written vault decrypted by Python and a Python-written vault
  decrypted by Go).
- `tests/test_integration.py` drives HID packets through the entire stack
  in-process — the same path a host exercises after attach.
