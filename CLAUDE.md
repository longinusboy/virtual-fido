# CLAUDE.md

Guidance for Claude Code (and other coding agents) working in this repository.

## What this is

A software YubiKey 5 (OTP+FIDO+CCID) exposed as a USB device over USB/IP, for a
two-machine setup: one machine runs this server and stores the keys; another
machine attaches the emulated device with the stock Linux `usbip` client across
an encrypted tunnel. It is a Python port of the Go library
[bulwarkid/virtual-fido](https://github.com/bulwarkid/virtual-fido) (commit
`512d8a3`), extended with OTP, CCID, OATH and PIV. See [README.md](README.md)
for setup, architecture, and the list of deliberate differences from upstream.

## Commands

This project uses [`uv`](https://docs.astral.sh/uv/) — never pip/venv directly.

```bash
uv sync                             # set up once
uv run pytest                       # whole suite
uv run pytest tests/test_ctap.py    # one module
uv run pytest -k pin_set            # one test by name expression

# Run the demo server (insecure demo attestation keys — testing only)
uv run virtual-fido-demo --vault vault.json start --bind 127.0.0.1
uv run python -m virtual_fido.skeleton -v      # transport-only walking skeleton
```

Live `usbip attach` needs root, so the test suite does not exercise it — hand
attach commands to the user instead of running them.

## Architecture

`virtual_fido.start()` (in `virtual_fido/__init__.py`) wires the stack; the
demo CLI (`virtual_fido/demo/cli.py`) adds the OTP control socket and the CCID
applets. The README "Architecture" section has the layer diagram and module
table.

## Conventions

- **Upstream Go code is the spec for the ported layers** (USB/IP, USB,
  CTAPHID, CTAP2, U2F, vault). When behavior is unclear, match upstream,
  including its protocol quirks. Deliberate deviations are commented in the
  source and listed in the README ("Differences from the upstream Go
  implementation") — keep that list current.
- **Minimal dependencies** (`cryptography`, `cbor2`) — do not add more without
  a strong reason; auditability is the point of the project.
- **Never log secrets.** Upstream's `LogLevelUnsafe` tier is intentionally not
  ported. Passphrases come from a prompt or file, never environment variables.
- **Vault format is versioned.** v1 = upstream Go format (read-only;
  `tests/data/go_vault.json` is a Go-written golden vault — keep it opening).
  v2 = current write format. OTP/OATH/PIV state are additive optional
  sections. Any format change needs a new version, a migration path, and
  tests.
- **Wire formats use `struct` with explicit endianness.** USB/IP headers are
  big-endian; USB descriptors little-endian; CTAPHID mixes little-endian
  channel/command with big-endian payload length.
- **Interrupt-IN polls are held pending, never timed out.** Do not reintroduce
  upstream's one-second timeout NAK; it injects bogus HID packets and broke
  multi-packet PIN flows.
- **Unsupported control requests stall** (`usbip.STALL`) rather than raising,
  so the host gives up immediately instead of timing out.
- **Concurrency uses threads + callbacks**, mirroring the upstream goroutine
  model. Protocol errors raise exceptions caught at the USB/IP connection
  loop; never let one bad packet kill the server.
- **PINs are strings** (4–63 UTF-8 bytes), never parsed as integers — "0000"
  must survive.
- **Smartcard applets must satisfy real clients, not just the spec.**
  `ykman`'s metadata parsers index TLV tags directly (every tag they read must
  be present); a missing data object must return `6A82`; OpenSC sends long
  commands with ISO 7816 command chaining while `ykman` uses extended-length
  APDUs.
- `virtual_fido/keyboard_layouts.py` is generated — edit
  `tools/gen_keyboard_layouts.py` and re-run it.

## Validation approach

- Ported upstream unit tests, module for module.
- Byte-level golden vectors against the Go implementation (device summary
  bytes; a Go-written vault).
- `tests/test_integration.py` drives HID packets through the entire stack
  in-process — the same path a host exercises after attach.
- Smartcard tests drive the CCID card exactly as `ykman`/OpenSC would, with
  RFC test vectors and signature verification.
- Protocol changes are additionally verified live against real tooling
  (browsers, `ykman`, OpenSC, `pcsc_scan`).
