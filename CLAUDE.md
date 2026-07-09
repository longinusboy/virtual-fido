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

```bash
# From python/ — set up once
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'

# Test
pytest                       # whole suite (~70 tests, ~2s)
pytest tests/test_ctap.py    # one module
pytest -k pin_set            # one test by name expression

# Run the demo server (insecure demo keys — testing only)
virtual-fido-demo --vault vault.json --passphrase pw start --bind 127.0.0.1
python -m virtual_fido.skeleton -v      # transport-only walking skeleton
```

There is no live `usbip attach` on the primary dev machine (its kernel lacks
the usbip tools/modules). Verify behavior through the test suite and the
in-process full-stack integration test instead; do real attach tests on a
stock-kernel Linux box or VM.

## Architecture

Same server stack as the Go version — each layer wraps the next. `virtual_fido.start()`
(in `virtual_fido/__init__.py`) wires it up:

```
USBIPServer (usbip.py)       TCP, USB/IP protocol; bind address configurable
  └─ USBDevice (usb.py)      USB descriptors + HID interface + endpoint buffering
      └─ CTAPHIDServer (ctap_hid.py)   packets → transactions → channels; keepalives
          ├─ CTAPServer (ctap.py)      FIDO2/CTAP2 (CBOR via cbor2)
          └─ U2FServer (u2f.py)        U2F/CTAP1
              └─ DefaultFIDOClient (fido_client.py)   credentials + approval + PIN
```

Supporting modules: `crypto.py` (ECDSA/Ed25519/AES-GCM/AES-CBC/ECDH via
`cryptography`), `cose.py` (COSE key encode/decode, ES256 + Ed25519),
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
- **Vault file format is compatible with the Go version.** `tests/data/go_vault.json`
  is a golden vault written by Go and decrypted in `test_identities.py`; keep
  it working. When touching `identities.py`/`webauthn.py` serialization,
  re-verify cross-language interop.
- **Wire formats use `struct` with explicit endianness.** USB/IP headers are
  big-endian; USB descriptors little-endian; CTAPHID mixes little-endian
  channel/command with big-endian payload length. Match the Go `ToLE`/`ToBE`
  usage exactly.
- **Concurrency uses threads + callbacks**, mirroring the Go goroutine model
  (chosen so behavior can be checked against the reference without a live
  attach). An asyncio redesign is deferred until after the transport is
  validated against a real `usbip` client.
- Protocol errors raise exceptions caught at the USB/IP connection loop
  (Go uses panic+recover at the same boundary); never let one bad packet kill
  the server.

## Validation approach (no live USB/IP here)

- Ported Go unit tests, module for module.
- Byte-level golden vectors against the Go implementation (device summary
  bytes; a Go-written vault decrypted by Python and a Python-written vault
  decrypted by Go).
- `tests/test_integration.py` drives HID packets through the entire stack
  in-process — the same path a host exercises after attach.
