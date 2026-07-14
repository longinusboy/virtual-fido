# Porting notes: Go → Python

This package is a port of the Go library in the repository root. The Go code is
the executable spec — when behavior is ambiguous, match the Go implementation
(including its quirks; several fixes in the CTAPHID layer were hard-won against
the Windows/Linux USB/IP clients).

## Module map

| Go package    | Python module               | Notes |
|---------------|-----------------------------|-------|
| `usbip/`      | `virtual_fido/usbip.py`     | USB/IP wire protocol + TCP server. Bind address is configurable (`--bind`); default `127.0.0.1`. Remote use is expected to go through a WireGuard/SSH tunnel — the server itself does no encryption. |
| `usb/`        | `virtual_fido/usb.py`       | Multi-interface USB device: descriptors, control transfers, endpoint routing. Aggregates `USBInterface`s (FIDO/OTP/CCID). **Diverges from Go**: interrupt-IN polls are held pending (no 1s timeout NAK); IN transfers return exact-length data (not zero-padded to the requested buffer). |
| —             | `virtual_fido/fido_hid.py`  | FIDO HID interface (extracted from the old single-interface usb.py). |
| —             | `virtual_fido/otp.py`       | OTP HID keyboard interface + Yubico OTP / ModHex / CRC16 (no Go equivalent). |
| —             | `virtual_fido/control.py`   | Local Unix-socket control channel used to trigger OTP typing (`otp type`). |
| —             | `virtual_fido/ccid.py`      | CCID smartcard interface: bulk + interrupt(notify) endpoints, CCID message layer, ISO 7816-4 APDU parse + SELECT-by-AID applet routing + GET RESPONSE/SEND REMAINING chaining (no Go equivalent). |
| —             | `virtual_fido/applets/oath.py` | OATH applet (ykoath protocol): TOTP/HOTP PUT/DELETE/LIST/CALCULATE/VALIDATE, persisted in the vault `oath` section (no Go equivalent). |
| `ctap_hid/`   | `virtual_fido/ctap_hid.py`  | Packet reassembly → transactions → channels; keepalives. |
| `ctap/`       | `virtual_fido/ctap.py`      | CTAP2 (CBOR) command handling. **Extends Go**: PIN/UV auth protocols 1 *and* 2 + permissions-based token (subcommand 0x09), advertising FIDO_2_1, so modern browsers' PIN flow works. |
| —             | `virtual_fido/pin_protocol.py` | PIN/UV auth protocol 1 & 2 primitives (no Go equivalent — Go only did protocol 1 inline). |
| `u2f/`        | `virtual_fido/u2f.py`       | U2F / CTAP1. |
| `cose/`       | `virtual_fido/cose.py`      | COSE key (ES256) encode/decode. |
| `crypto/`     | `virtual_fido/crypto.py`    | ECDSA/ECDH/AES-GCM/SHA-256 via `cryptography`. |
| `identities/` | `virtual_fido/identities.py`| Vault, attestation certs, encrypted saved state. Reads Go-written (v1) vaults; **saves in a v2 format Go cannot read** (stronger scrypt, KDF params in the blob, optional keyfile second secret). |
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
