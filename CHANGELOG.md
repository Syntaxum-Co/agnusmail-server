# Changelog

All notable changes are listed here. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, minor versions may break things.

## Unreleased

- Fix: outbound and secure-portal submissions accept SEIPD packets with partial body
  lengths (RFC 9580 §4.2.1.4), as OpenPGP.js writes them for any message over 512 bytes.
  Before, such messages were refused with `ENVELOPE_INVALID` (`partial_length`).

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
