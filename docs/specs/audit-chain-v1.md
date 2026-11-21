# Audit hash chain — format version 1

- **Code:** `src/agnusmail/modules/audit/chain.py`.
- **Scope:** integrity of each user's `audit_events` trail. This is not a new
  cryptographic protocol: it is a chain of SHA-256 hashes over a canonical encoding.
- Any change that alters a hash creates **version 2**; version 1 is never edited. The
  migration `20261111_0003` holds a frozen copy of this algorithm (tested against the
  code).

## 1. Chain

- Each user has their own chain. `chain_seq` starts at 1 and grows by 1.
- The first event uses `prev_hash = 00…00` (32 zero bytes, `GENESIS`).
- Every following event uses `prev_hash = event_hash` of the same user's previous event.
- `event_hash = SHA-256(DOMAIN || C)`, where:
  - `DOMAIN` = the 24 ASCII bytes `agnusmail/audit-event/v1` followed by `\n` (0x0A), 25
    bytes in total;
  - `C` = the JSON object of section 2 in canonical encoding (section 3).

## 2. Object fields

| Key | Value |
|---|---|
| `v` | `1` (number) |
| `user_id` | the owner's UUID, lowercase with hyphens |
| `seq` | `chain_seq` (number) |
| `prev_hash` | lowercase hex, 64 characters |
| `event_type` | e.g. `device.registered`, `audit.purged` |
| `actor_user_id` | UUID or `null` (system) |
| `device_id` | UUID or `null` |
| `public_key_id` | UUID or `null` |
| `details` | the event's JSON object, unchanged |
| `created_at` | UTC, `YYYY-MM-DDTHH:MM:SS.ffffffZ` (always 6 fraction digits) |

## 3. Canonical encoding

- JSON without whitespace (`,` and `:` as separators), the keys of every object in
  lexicographic order, recursively.
- ASCII-only output: non-ASCII characters become `\uXXXX` (surrogate pairs above
  U+FFFF). No `NaN`/`Infinity`.
- `details` accepts only objects (with string keys), lists, strings, integers, booleans
  and `null`. **Floating-point numbers are forbidden**: their textual form may change on
  the way through JSONB. The server refuses to store events outside these rules.

## 4. Head and checkpoint

`GET /v1/audit/chain` returns:

- `head_seq` / `head_hash`: the last event of the chain;
- `purged_through_seq` / `purged_through_hash`: how far the retention purge has deleted
  (`0` / GENESIS if there was never a purge).

## 5. Verification by the client

1. Read `GET /v1/audit/chain`.
2. Read `GET /v1/audit/events?after_seq=<purged_through_seq>` and keep paging with
   `after_seq` = the last `chain_seq` received while `has_more` is true.
3. Starting from `purged_through_hash`, check for each event: contiguous `chain_seq`,
   `prev_hash` equal to the previous hash, and the recomputed `event_hash` (sections 1–3)
   equal to the one returned. The last hash must be `head_hash`.
4. Keep `head_seq`/`head_hash`. On a later verification, the event at the previous
   `head_seq` must still have the same hash. If it changed, the history was rewritten.
5. If `purged_through_seq > 0`, the most recent `audit.purged` event must carry
   `details.through_seq` and `details.through_hash` equal to the checkpoint.

## 6. Limits (accepted risk)

- There is no secret and no external anchoring: whoever can write to the database **and**
  disable the triggers can rebuild a whole consistent chain. Detection depends on someone
  (the user's client or the operator) having kept an earlier `head_hash`.
- The chain shows tampering; it does not prevent it. Prevention relies on the triggers and
  on the separate database roles (see `src/agnusmail/infrastructure/database/roles.py`).

## 7. Test vectors

Vector 1: `user_id` = `00000000-0000-4000-8000-000000000001` (also the actor),
`device_id` = `00000000-0000-4000-8000-000000000002`, `seq` 1, `prev_hash` GENESIS,
`event_type` `device.registered`, `public_key_id` `null`,
`details` = `{"status":"pending","client":{"ua":"sha256:abab…ab"}}` (64 hex),
`created_at` = `2026-11-11T12:00:00.123456Z`.

```
C = {"actor_user_id":"00000000-0000-4000-8000-000000000001","created_at":"2026-11-11T12:00:00.123456Z","details":{"client":{"ua":"sha256:abababababababababababababababababababababababababababababababab"},"status":"pending"},"device_id":"00000000-0000-4000-8000-000000000002","event_type":"device.registered","prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","public_key_id":null,"seq":1,"user_id":"00000000-0000-4000-8000-000000000001","v":1}
event_hash = b03855c21a5e7ebff30871591e7c3d41f99e08d7fe63be4341f7e30245c54630
```

Vector 2 (continues vector 1): `seq` 2, `prev_hash` = the hash of vector 1,
`event_type` `audit.purged`, actor/device/key `null`,
`details` = `{"through_seq":1,"through_hash":"<hash of vector 1>","deleted":1}`,
`created_at` = `2027-11-12T00:00:00.000000Z`.

```
event_hash = a1d2567b8957acd427504d71f2b8520aa3b031acaab440683944999d22b49e92
```

Vector 1 was checked against an independent implementation (only `hashlib` over the JSON
above). Both vectors are in `tests/unit/test_audit_chain.py`.
