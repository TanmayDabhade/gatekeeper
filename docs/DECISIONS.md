# Decisions

Append-only. Add new entries at the bottom and never edit or delete old ones. To reverse a decision, add a new entry that references the old one.

Format:
```
## YYYY-MM-DD HH:MM | <author> | <short title>
**Decision:** ...
**Why:** ...
**Alternatives considered:** ...
```

---

## 2026-10-03 09:50 | Tanmay | Policy lives on the device, not the host
**Decision:** Contacts, sensitive paths and delete limits live in device firmware (mirrored in `mock_device.py`), not in `config.py`.
**Why:** The host runs the agent and can be compromised. Policy the host can edit is policy an attacker can edit.
**Alternatives considered:** Host-side policy file (simpler, but defeats the point); policy pushed to the device at boot (adds an attack surface).

## 2026-10-03 09:59 | Team (from KT doc) | Tracks
**Decision:** Main track is Beyond the Code (Hardware). Sponsor tracks are Capital One Nessie, ElevenLabs, Best Design and LLM-judged. Fetch.ai is go or no-go at hour 0.
**Why:** Nessie and ElevenLabs map directly onto M6 (payments) and M7 (voice). The hardware track fits the core idea.
**Alternatives considered:** Not recorded.

## 2026-10-03 09:59 | Team (from KT doc) | Ownership split and working agreements
**Decision:** The device owner edits only `firmware/`. The software owner edits `executor/`, `agent/` and `bench/`. Push small and often, pull before starting, sync at every gate, and add nothing new after hour 19.
**Why:** Two people building for 24 hours shouldn't break each other's work, and the last hours go to the video, Devpost and rehearsal.
**Alternatives considered:** Not recorded.

## 2026-10-03 09:59 | Team (from KT doc) | The contract is frozen; v1 now, v2 with F4
**Decision:** v1 signs `v1|act|to|file|fh|nonce|exp|taint`. v2 adds `amt` in cents and `pay_invoice`, signs `v2|act|to|file|fh|amt|nonce|exp|taint`, and both sides switch together at F4. Any change is agreed out loud and written into `CONTRACT.md` before anyone codes it.
**Why:** The contract is the only thing the two halves share, so drift there breaks things silently.
**Alternatives considered:** Not recorded.

## 2026-10-03 09:59 | Team (from KT doc) | One request at a time; executor waits ≥35 s
**Decision:** The device handles one request at a time and auto-denies after 30 s. The executor sends serially and waits at least 35 s. Bench mode returns `hold` instantly and never changes the locked or frozen state.
**Why:** The ESP32 blocks while waiting for a human, and benchmarks need about 40 runs without 40 button presses.
**Alternatives considered:** Not recorded.

## 2026-10-03 09:59 | Team (from KT doc) | Agent prompt defines HIGH risk
**Decision:** The agent's system prompt must call sensitive files, outside recipients and payments HIGH risk.
**Why:** Otherwise an honest agent that says "low" triggers a false lockdown through the lie check.
**Alternatives considered:** Softer lie check (approve-and-flag). The review raised this, and it's still open in `IDEA.md`.

## 2026-10-03 11:00 | Tanmay D | Board-ready alignment: the firmware and mock enforce the same rules
**Decision:** The firmware now matches the mock's request checks. Malformed requests get `denied`, unsigned: wrong types, `|`, control or non-ASCII characters, a bad nonce or fh, or a non-canonical path. The `/data/sensitive/` match ignores case. Signed deletes count toward the rate limit even in bench mode. Bench lies reply `locked` without locking. Unparseable, unknown or too-long lines get a `denied` reply instead of silence. The wire format and signed string are unchanged (still v1).
**Why:** A security review showed `data/SENSITIVE/tax_return.pdf` got past `blocked` on macOS. The firmware also had no input validation, and bench mode let signed deletes skip the rate limit. `smoke_device.py` now checks the mock and the board against the same 30 cases.
**Alternatives considered:** Fixing only the executor (a compromised host could still send the uppercase path). Waiting for the device owner. Not chosen because of demo timing, so this is an **exception to the ownership rule**: the device owner reviews `src/main.cpp` in the PR before flashing.
