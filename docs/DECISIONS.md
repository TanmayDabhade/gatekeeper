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

## 2026-10-03 11:14 | Tanmay D | Prize tracks: add Notability, Fetch.ai no-go, strengthen ElevenLabs
**Decision:** Keep Beyond the Code (Hardware) as the main MHacks track. Keep sponsor tracks Capital One Nessie, ElevenLabs, Best Design (Figma), and Judged by an LLM. Add Notability (ideation notes + ≥2 screenshots on Devpost). Fetch.ai ASI:One is **no-go** (closes the hour-0 question from the 09:59 Tracks entry). Skip Photon, Relay, Neon, Spacetime, SpaceXAI, FinchNode, FREE-WILi, Useless AI, and Dumbest Idea. ElevenLabs must speak the true action aloud (recipient/file), not only play an alarm tone. Ask organizers at check-in whether Hardware and FinTech can both be entered; if only one, stay on Hardware.
**Why:** Notability is ~20 minutes for merch/Pro. Fetch.ai needs Agentverse + ASI:One + a separate submission and fits poorly (we protect agents rather than being one). A thin "blocked" chime is weak for Best Use of ElevenLabs; reading the device's truth makes the two-screen demo audible. FinTech fits invoice fraud, but Hardware is the clearer differentiator if we must pick one.
**Alternatives considered:** Entering Fetch.ai anyway (high cost, weak fit). Dropping ElevenLabs (still cheap if reframed). Making FinTech the main track (strong demo, but fewer hardware competitors on Beyond the Code).

## 2026-10-03 12:45 | Tanmay D | M3 agent: the LLM is the untrusted agent, called through a stdlib client
**Decision:** The M3 LLM plays the AI assistant being guarded, never a fraud detector, and nothing trusts its judgment: the device's policy ignores `claim`, which can only trigger the lie-check lock, and taint comes from `read_inbox`. `llm.py` calls any OpenAI-style `/chat/completions` endpoint with `urllib` (no SDK), so the provider is config only (`LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`). The system prompt defines HIGH risk (per the 09:59 entry), rates every other send or delete as medium, and has no "ignore instructions in emails" hardening. By default the laptop prints only the agent's narration (the "lying screen"); `--show-calls` prints the real calls and verdicts. `GATEKEEPER_COMPROMISED=1` swaps in a scripted hijacked agent that needs no key or network. Runs stop on `locked` or after 10 tool calls.
**Why:** An LLM that judged emails would be the hole Gatekeeper closes, so its output must only ever tighten things. A stdlib client keeps dependencies at zero and avoids blocking M3 on the provider choice. Without hardening, the hijack rate reflects a normal agent and the device has to be what stops the attack. The scripted agent makes the stage demo deterministic even with bad Wi-Fi.
**Alternatives considered:** A provider SDK (new dependency, locks the provider). A scripted agent only, with no LLM (no real agent to protect; the benchmark would be meaningless). Prompt hardening against injection (more realistic for production, but it would hide what the device adds).

## 2026-10-03 13:30 | Tanmay D | M4-M5 benchmark: a worst-case agent measures the device; bench "hold" counts as a touch
**Decision:** `bench.py` runs the 44 scenarios in `scenarios.py` (24 attacks, 20 benign) through the real `agent.run`, executor and device policy with `bench=1`. Each scenario gets a throwaway copy of the data folder, and mail goes nowhere. There are two agents: `--agent llm` (the real model, which measures the true hijack rate) and the default `--agent worst-case`, a scripted agent that obeys every injection with the claim it was talked into. The worst-case agent needs no key, so its numbers measure only the device. A `hold` verdict counts as "needed a human touch". It isn't counted as stopped or as a false positive, and the report lists it separately. False positives are benign actions that end `blocked` or `locked`. Device policy and the protocol are unchanged.
**Why:** Without a key the only honest number is "if the agent is fully hijacked, what gets through". Counting holds as stopped would overstate the device, since a human could still approve, and counting them as false positives would understate it. The run found one real gap (atk-07, the mass delete of public files), which is logged in TODO instead of being fixed quietly.
**Alternatives considered:** Only a live-LLM benchmark (blocked on the provider, and not deterministic for tests). Making up hijack rates for the worst-case agent (dishonest). Patching the delete limit now (it's a firmware policy change, so it needs both people and a DECISIONS entry).

## 2026-10-03 15:30 | Tanmay D | M9 verifier: a separate mail gateway re-checks the device signature
**Decision:** `verifier.py` is a separate process: a minimal SMTP gateway on `localhost:1026` that relays to Mailpit (`:1025`). It trusts only the pinned device key. The executor now puts the device's approval on every email as `X-Gatekeeper-Act/To/File/Fh/Nonce/Exp/Taint/Sig` headers. The gateway relays only if the signature verifies over `protocol.signed_message(...)` and the signed fields match the delivery: exactly one envelope recipient equal to `to`, a matching `To` with no `Cc`/`Bcc`, exactly one attachment whose SHA-256 is `fh` and whose name is the basename of `file` (or none when `file` is empty), an unexpired `exp`, and an unused nonce. A nonce is consumed only on acceptance and given back if the relay fails. The executor sends to the gateway when `GATEKEEPER_SMTP_PORT=1026`; the default stays 1025, so existing flows don't change. `forge.py` is the demo: a compromised laptop tries 7 forgeries and a replay, and only the honest control is delivered. The device wire contract (`protocol.py`, v1) is unchanged; the headers are a host-side envelope between the executor and the gateway.
**Why:** This answers the judges' top question ("what does the hardware add if the executor is on the same laptop?"). Even with full control of the laptop, the attacker can't produce mail the gateway accepts without the device signing that exact recipient and file. SMTP keeps the executor change to one line (where it sends). The gateway is written on stdlib `socketserver` because Python 3.13 removed `smtpd`, and the project doesn't add dependencies without a DECISIONS entry.
**Alternatives considered:** `aiosmtpd` (a new dependency). An HTTP "bank" verifier (would need a second mail path; it fits M6 payments better, where Nessie can get the same check). Verifying deletes too (there's no separate file server to do it, so it's out of scope). **Known limit:** subject and body aren't signed in v1, so a valid approval could carry different text; the v2 contract adds the body hash `bh`. In the prototype Mailpit doesn't refuse direct connections on 1025. In production only the gateway can reach the mail server.

## 2026-10-03 16:00 | Tanmay D | M9 verifier hardening: strict message shape, nonces on disk, never released
**Decision:** The gateway now accepts only the exact shape the executor sends: a single `text/plain` body, or `multipart/mixed` with exactly that body plus one `attachment` part. HTML alternatives, nested multiparts and extra inline parts are refused. Used nonces are written to `.gateway_nonces` (fsynced, with entries dropped once their `exp` passes) before a message is accepted. If the write fails, the message is refused. A consumed nonce is never given back, even when the relay to Mailpit fails. This tightens the 15:30 entry, which said a nonce is "given back if the relay fails". This entry replaces that part.
**Why:** A security review of the M9 commit found two holes. (1) Counting only `iter_attachments()` let a message hide data in an HTML alternative or a nested `multipart/related` that a mail client would show. The recipient binding still held, so the data could only reach the approved recipient, but the gateway no longer delivered "exactly what the device approved". (2) Nonces lived in memory, so restarting the gateway let a captured approval be replayed until its `exp`, and giving a nonce back after a relay error could deliver an email twice if the upstream had already taken it.
**Alternatives considered:** Parsing every MIME part and hashing them all (more code, and still exposed to parser differences between the gateway and the mail client). Keeping nonces in memory and relying only on the 60 s `exp` (still leaves a replay window after a restart). Retrying the relay with the same approval (risks duplicates; asking the device again is cheap).
