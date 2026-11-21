# Threat model

Method: simplified STRIDE, centered on assets. This document is honest about what the
design does **not** protect against; read section 3 before relying on it.

## 1. Assets and adversaries

**Assets, by sensitivity:**
1. Message and attachment content (end-to-end encrypted — plaintext must never exist on
   the server, except transiently in the SMTP gateways, see section 3).
2. Private keys and their passphrases (must exist **only** on users' devices).
3. Session tokens and infrastructure secrets.
4. Delivery metadata (visible to the server because it has to deliver mail).
5. Integrity of the public key directory.

**Adversaries considered:**
- **The service operator and insiders** — the strongest adversary against E2EE. The whole
  design assumes the server is hostile to content.
- **External attackers** — account takeover (phishing for a SIWE signature), IDOR, spam
  and abuse.
- **Infrastructure providers** — access to disk or memory (mitigated by E2EE and by never
  persisting plaintext).
- **The server itself, lying** — silently replacing public keys (mitigated by the
  wallet-signed device certificates; see the limits below).

## 2. Threats and mitigations (STRIDE)

| Threat | Surface | Mitigation |
|---|---|---|
| **S**poofing | SIWE or passkey login; sending messages | Single-use nonce with expiry; signature, domain, URI and chain id checks (EIP-4361); passkeys bound to the origin by the browser, approved by the wallet, with a clone-detecting counter; messages signed by the sending device |
| **T**ampering with keys | Public key directory | Every active device has an EIP-712 certificate signed by the owner's wallet over its v6 fingerprint, published in the directory; senders that verify it do not accept a key the server swapped without the wallet. Proof of possession on upload |
| **R**epudiation | Sensitive operations | Logins, refused logins, logouts, session revocations, devices and keys are audited; append-only table; a per-user SHA-256 chain the user can verify; retention purge only of old events, with a checkpoint and an `audit.purged` event; runtime roles cannot disable the triggers; administrative actions need two operators |
| **I**nformation disclosure | API, database, storage, logs, queues, backups | E2EE; only ciphertext at rest; redacted logs without payloads; no plaintext persisted by the gateway; non-root containers, isolated networks |
| **D**enial of service | API, SMTP, storage | Rate limits per IP and per user; size and recipient limits; storage quotas; antispam before encryption in the gateway |
| **E**levation of privilege | API, admin, containers | Deny by default; per-resource authorization (anti-IDOR); no mass assignment; least privilege for database roles, containers and services |

## 3. Known limitations

- **Metadata is visible to the server:** sender, recipients, times, size, delivery state.
  They cannot be hidden while still delivering mail.
- **No transparency log:** the server can omit devices or keys from the directory, or show
  different views to different senders. It cannot forge a wallet signature, but omission
  and equivocation are not detectable.
- **The inbound gateway handles plaintext transiently:** it receives external mail in
  clear to encrypt it. Accidental persistence (queues, spool, swap, dumps, crashes, logs,
  antispam) is prevented and tested, but the content is in clear **in memory** of the
  gateway and of Rspamd while a message is processed: whoever controls those processes
  live sees external content. That is why it is labeled "encrypted on arrival", not E2EE.
- **Outbound mail is not end-to-end encrypted:** to reach regular mailboxes the content
  travels in clear after the client decrypts it. The API labels it `protection =
  not-e2ee`. Until delivery (at most 72 h) it waits encrypted to the outbound service's
  key, which decrypts it **in memory** to send it: whoever controls that process live, or
  steals the queue key, reads external mail still in the queue. TLS to the recipient's
  server is opportunistic (MTA-STS/DANE are not implemented yet).
- **Secure portal:** anyone with the link and the password can read and reply (the replier's
  identity is not verified); the server delivers the portal's code to the browser and
  could deliver malicious code; password strength is the client's responsibility.
- **Audit chain without external anchoring:** whoever controls the database and can
  disable the triggers can rebuild a consistent chain; detection depends on a client
  having kept an earlier head hash.
- **Lost keys:** if a user loses every device and the recovery phrase, old messages are
  unrecoverable **by design**. No administrative mechanism may bypass this.
- **Compromised user device:** E2EE does not protect against malware on the endpoint.
- **Signatures are not post-quantum** in protocol v1 (Ed25519); encryption is hybrid.
- **No external review yet** of the protocol or the code.
