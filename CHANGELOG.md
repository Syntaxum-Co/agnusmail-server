# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may break things.

## Unreleased

- Add: `POST /v1/portal/access` also returns `recipient`, the address the link was made
  for, so a portal reply can carry it as its From. Before, the web client wrote the
  sender's own address there, and answering that reply went back to the sender.
- Change: publishing a device certificate whose primary key is already on another
  device answers `409 DEVICE_KEY_IN_USE` instead of the generic `409 CONFLICT`, which
  tells clients to retry. Clients that matched `CONFLICT` here should match the new code.
- Fix: outbound and secure-portal submissions accept SEIPD packets with partial body
  lengths (RFC 9580 §4.2.1.4), as OpenPGP.js writes them for any message over 512 bytes.
  Before, such messages were refused with `ENVELOPE_INVALID` (`partial_length`).
- Fix: Unix timestamps in signed requests (device certificates and revocations, recovery
  keys, account migrations, passkey registration) are limited to 9999-12-31T23:59:59Z.
  A later value was answered with a 500, including on `POST /v1/recovery/migrations`,
  which needs no session; it is now a 422 `VALIDATION_ERROR`.
- Security: `/openapi.json` is served only in the `local` environment (the interactive
  docs were already off everywhere).

## 0.1.0 — 2026-11-21

First public release.

- End-to-end encrypted e-mail backend: OpenPGP v6 with ML-KEM-768 + X25519, device keys
  attested by the account's Ethereum wallet (EIP-712), Sign-In with Ethereum and
  passkeys.
- Inbound SMTP gateway that encrypts on arrival; outbound SMTP (not end-to-end
  encrypted, clearly labeled); secure portal for external recipients.
- Account recovery with an encrypted backup; per-user audit hash chain; two-operator
  administration; abuse limits from metadata only.
- Extension points (`agnusmail.extensions`) and test helpers (`agnusmail.testing`).
- Licensed under the Apache License 2.0.
