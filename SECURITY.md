# Security policy

Virtual FIDO handles authentication secrets, so security reports are welcome
and taken seriously.

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's
private vulnerability reporting instead: the "Security" tab →
"Report a vulnerability" on
[longinusboy/virtual-fido](https://github.com/longinusboy/virtual-fido/security/advisories/new). Include the affected version or commit, a description
of the issue, and steps to reproduce if possible.

## Scope and known limitations

The following are documented design limits, not vulnerabilities:

- **The USB/IP protocol is plaintext and unauthenticated.** The server must
  only be reachable through an encrypted tunnel (WireGuard, SSH). Exposing the
  server port on an untrusted network gives anyone who connects full use of the
  emulated security key.
- **Decrypted keys live in process memory while the server runs.** Python
  cannot reliably zero memory; an attacker who can read the server process's
  memory can extract the keys regardless of vault encryption.
- **The demo CLI (`virtual-fido-demo`) uses insecure attestation keys** — a
  self-signed CA generated for testing. Relying parties that verify
  attestation will not (and should not) trust it. Do not reuse the demo's key
  management in production code.
- **There is no physical user presence.** Approval is delegated to the
  embedding application (the demo prompts on the server's terminal); OTP
  typing is triggered through a local control socket that anyone with access
  to the socket file can use.
- **PIV/OATH defaults match a stock YubiKey** (PIV PIN `123456`, PUK
  `12345678`, default management key). Change them before real use.

Reports that bypass these assumptions (for example, a way to read vault
contents without the passphrase and keyfile, to trigger actions through the
control socket without file access, or to crash or hijack the server from the
USB/IP connection beyond the documented trust model) are in scope.
