# Porting notes: Go → Python

This package is a port of the Go library in the repository root. The Go code is
the executable spec — when behavior is ambiguous, match the Go implementation
(including its quirks; several fixes in the CTAPHID layer were hard-won against
the Windows/Linux USB/IP clients).

## Module map

| Go package    | Python module               | Notes |
|---------------|-----------------------------|-------|
| `usbip/`      | `virtual_fido/usbip.py`     | USB/IP wire protocol + TCP server. Bind address is configurable (`--bind`); default `127.0.0.1`. Remote use is expected to go through a WireGuard/SSH tunnel — the server itself does no encryption. |
| `usb/`        | `virtual_fido/usb.py`       | USB descriptors, control transfers, HID report descriptor, interrupt-endpoint buffering. |
| `ctap_hid/`   | `virtual_fido/ctap_hid.py`  | Packet reassembly → transactions → channels; keepalives. |
| `ctap/`       | `virtual_fido/ctap.py`      | CTAP2 (CBOR) command handling. |
| `u2f/`        | `virtual_fido/u2f.py`       | U2F / CTAP1. |
| `cose/`       | `virtual_fido/cose.py`      | COSE key (ES256) encode/decode. |
| `crypto/`     | `virtual_fido/crypto.py`    | ECDSA/ECDH/AES-GCM/SHA-256 via `cryptography`. |
| `identities/` | `virtual_fido/identities.py`| Vault, attestation certs, encrypted saved state. Vault file format stays compatible with the Go version. |
| `fido_client/`| `virtual_fido/fido_client.py`| `DefaultFIDOClient`, approval + data-saver interfaces. |
| `util/`       | (absorbed)                  | Endianness → `struct`/`int.to_bytes`; logging → `logging`; panics/`Try` → exceptions. |
| `cmd/demo`    | `virtual_fido/demo/`        | argparse CLI: `start`, `list`, `delete`, `pin`. |

## Conventions

- **Dependencies are deliberately minimal** (`cryptography`, `cbor2`) so the
  security-relevant code stays auditable. Do not add dependencies without a
  strong reason.
- Go's `util.CheckErr`/panic style becomes plain Python exceptions; the
  per-connection `Try/recover` in the USB/IP server becomes a `try/except`
  around the connection handler.
- Byte-level protocol structs use `struct.pack`/`unpack` with explicit
  endianness (USB/IP header fields are big-endian; CTAPHID channel/command
  fields little-endian with big-endian payload length — mirror the Go
  `util.ToLE`/`ToBE` usage exactly).
- Never log secrets. The Go `LogLevelUnsafe` tier is intentionally not ported.

## Target environment

- Server (machine B, key storage): Python ≥ 3.10, any OS.
- Client (machine A, sees the dongle): Linux only — `modprobe vhci-hcd`,
  `usbip attach -r <server> -b 2-2`. No custom software on machine A.
