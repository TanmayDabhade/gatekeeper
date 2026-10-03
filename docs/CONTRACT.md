# Gatekeeper wire contract

The single source of truth shared by the firmware (`src/main.cpp`), the mock
(`mock_device.py`), and the host (`executor.py` via `protocol.py`). All three
**must** produce byte-identical signed messages. Change this file first, with
both people's sign-off, before touching code (see `DECISIONS.md`).

## Transport
One JSON object per line (`\n`-terminated), request in → response out.
Requests: `{"t": "req" | "ping" | "pubkey", ...}`. Responses:
`{"t": "res" | "pong" | "pubkey", ...}`. Malformed / unknown / over-length
(> 4096 bytes) lines get `{"t":"res","v":"denied","sig":""}`.

## v2 (current) — frozen 2026-10-03
Switched from v1 together at F4. v2 adds `pay_invoice`, an amount, and a
subject/body hash. The signed string is:

```
v2|<act>|<to>|<file>|<fh>|<bh>|<amt>|<nonce>|<exp>|<taint>
```

| field | meaning |
|-------|---------|
| `act` | `send_email` \| `delete_file` \| `pay_invoice` |
| `to`  | recipient (send_email) or **payee id** (pay_invoice); `""` for delete_file |
| `file`| absolute, canonical path or `""` |
| `fh`  | sha256 hex of the file, or `""` when no file |
| `bh`  | sha256 hex of `subject + "\n" + body` for send_email; `""` otherwise |
| `amt` | integer **cents** for pay_invoice; `0` otherwise |
| `nonce` | 32 lowercase hex, issued by the host, single-use |
| `exp` | unix seconds; the host rejects an expired approval |
| `taint` | `0` or `1`; set only by `read_inbox`, never the caller |

Signature: Ed25519 over the UTF-8 bytes of that string, under the device's
pinned key. Only `allow` and `approved` carry a signature.

### Verdicts
`allow` · `approved` · `denied` · `blocked` · `locked` · `hold` (bench only).

### Device policy (firmware == mock)
- **send_email:** sensitive file to a non-contact → `blocked`; contact + public + untainted → `allow`; else → needs a human (`approved`/`hold`).
- **delete_file:** sensitive, or >5 deletes/10 min, **or tainted session** → needs a human; else `allow`. *(F6/atk-07.)*
- **pay_invoice:** payee **not** on the device allowlist → `blocked`; listed payee ≤ **$500** (`amt ≤ 50000`) → needs a human hold; listed payee > **$500** → needs a human hold **plus an RFID co-sign** (card tap). *(S3.)*
- A `low` claim on anything not `allow` → `locked` (the lie check); bench replies `locked` without latching.

## Co-sign
RFID (RC522) tap required for `pay_invoice` with `amt > 50000`. Enrolled card
UID lives in the firmware.

## v1 (retired)
`v1|act|to|file|fh|nonce|exp|taint` — superseded by v2 at F4. Kept here for
history only; do not emit v1.
