# Knowledge transfer prompt

Paste the block below into a fresh AI session (or hand it to a new teammate) to bring them up to
speed on Gatekeeper. It reflects the repo as of 2026-10-04 (after the `tests/` + `hardware/` move).
The repo docs win if anything here goes stale: `docs/CONTRACT.md`, `docs/DECISIONS.md`, `docs/TODO.md`.

---

```
You are joining Gatekeeper, an MHacks hackathon project (two people: Tanmay on host software, Sid
on the device firmware). Read this whole brief before doing anything. Then read docs/IDEA.md, the
latest entries at the bottom of docs/DECISIONS.md, and docs/TODO.md in the repo.

## 1. What it is
"The only screen your AI can't lie to": a hardware wallet for AI agent actions.

Problem: AI agents that read untrusted content (email, invoices) can be hijacked by instructions
hidden in it (prompt injection). Today's confirmations appear on the same screen the software
controls, so a hijacked agent can describe a dangerous action as harmless, and the human approves
something they never saw. Detection alone can't win, because many malicious requests look exactly
like legitimate ones.

Fix: the agent can only ASK. Every consequential action (send_email, delete_file, pay_invoice) goes
to an ESP32 with its own OLED, buttons and RFID reader. The device applies its OWN policy, shows the
real recipient, file and amount, and signs allow/approved verdicts with Ed25519. Everything
downstream acts only on a valid signature from the pinned device key.

Target user: teams letting agents take high-stakes actions (payments, data exports). Headline
threats: business email compromise and invoice fraud.

## 2. Trust model (the core idea, get this right)
- The LLM agent is UNTRUSTED. It holds no credentials. Its risk "claim" can only tighten things
  (it triggers the lie check), never loosen them.
- The host/laptop (executor) is assumed HACKABLE. It can lie about an action. It never holds the
  device's signing key and never holds the Nessie (bank) key.
- The device is TRUSTED. The key is generated on first boot and stored in ESP32 flash, and it never
  leaves the device. Policy lives on the device, never in host config (DECISIONS 09:50).
- The separate verifiers re-check the signature themselves: verifier.py (mail gateway) and bank.py
  (payments). So even a fully compromised laptop can't forge mail or move money. This answers the
  #1 judge question: "what does the hardware add if the executor is on the same laptop?"

## 3. Architecture / data flow
untrusted inbox -> LLM agent (tool calls only) -> executor.py (holds creds, not keys)
  -> one JSON line over serial (or socket:// for the mock) -> ESP32: validate, policy, OLED, human
  -> signed verdict back -> executor checks signature + nonce + exp + file hash, then acts:
     - email: SMTP to verifier.py (:1026), which re-verifies, then relays to Mailpit (:1025)
     - payment: POST request + approval to bank.py (:8099), which re-verifies, then calls Nessie
     - delete: local file delete; run_code: Docker python:3.12-slim with --network none

## 4. Wire contract v2 (docs/CONTRACT.md; protocol.py implements it; FROZEN)
Signed string (Ed25519 over its UTF-8 bytes):
  v2|<act>|<to>|<file>|<fh>|<bh>|<amt>|<nonce>|<exp>|<taint>
- act: send_email | delete_file | pay_invoice
- to: recipient email, or the payee account id for pay_invoice, or "" for delete
- file: canonical path or ""; fh: sha256 hex of the file, or ""
- bh: sha256 of subject + "\n" + body for send_email (the text/plain part as delivered, LF line
  endings, trailing newline), "" otherwise. The payment memo is NOT signed.
- amt: integer cents for pay_invoice, 0 otherwise
- nonce: 32 lowercase hex, single use; exp: unix seconds (host TTL 60 s)
- taint: 0/1, set ONLY by read_inbox, never by the caller
Verdicts: allow, approved (the only two signed), denied, blocked, locked, hold (bench mode only).
Transport: one JSON object per line. Bad, unknown or >4096-byte lines get {"t":"res","v":"denied","sig":""}.
Other device messages: ping/pong, pubkey, plus RFID test and "revoke" (lost-card) commands.
v1 is retired; never emit it.

## 5. Device policy (firmware src/main.cpp == mock_device.py, byte for byte)
- send_email: a sensitive file (/data/sensitive/, case-insensitive) to a non-contact -> blocked.
  Contact + public file + untainted -> allow. Anything else -> needs a human (approved/hold).
  Contacts: boss@ourcompany.com, accountant@trustedcpa.com. Company domain: ourcompany.com.
- delete_file: sensitive, or more than 5 deletes in 10 min, or a tainted session -> needs a human;
  else allow. (The tainted rule closed the atk-07 mass-delete gap.)
- pay_invoice: payee not on the device allowlist -> blocked. Listed payee <= $500 (50000 cents) ->
  button hold. > $500 -> button hold PLUS an RFID card tap (co-sign). Allowlist: Acme Supplies
  7083a93b-e422-4fa6-8188-330034f0c237. Lookalike "Acme Supp1ies" is
  4babab8f-537e-444a-9801-a3463689b686 (NOT allowed).
- Lie check: a "low" claim on anything that isn't allow -> LOCKED (latches until Reset is held for
  3 s). In bench mode it replies locked without latching.
- Validation: wrong types, "|", control or non-ASCII characters, bad nonce/fh, or a non-canonical
  path -> denied (unsigned).
- Human: hold Approve 2 s to approve; auto-deny after 30 s; Kill -> FROZEN.
- Multi-card co-sign: primary card plus a backup fob. "Lost a card": tap the card to KEEP, and every
  other card is revoked live.
- OLED shows the registrable domain (boss@company.com.evil.io shows as evil.io), the full address,
  the file, the amount/payee name, TAINTED, and the AI's claim.
- Pins: buttons Approve 13, Kill 27, Reset 26; RGB LED 25/33/32; RC522 SS 5; I2S amp BCLK 14,
  LRC 17, DIN 16.

## 6. Repo map (flat on purpose; DECISIONS 2026-10-04)
Firmware (PlatformIO, platformio.ini): src/main.cpp (policy, signing, OLED, buttons, RFID),
  src/voice.cpp (ElevenLabs TTS on the device, off without include/secrets.h), lib/monocypher/.
Contract: protocol.py, docs/CONTRACT.md.
Host: executor.py (DeviceLink, key pinning, checks, actions), config.py (host config only),
  gk.py (CLI: pin, send, pay, balances), mock_device.py (keys a/d/r/k/s/q; c = card tap).
Agent: agent.py (tool loop, narration-only "lying screen", --show-calls, compromised modes),
  llm.py (stdlib OpenAI-style client, no SDK; ScriptedLLM).
Verifiers: verifier.py (SMTP gateway :1026), bank.py (HTTP :8099, the only holder of the Nessie
  key), nessie.py (Nessie client, ledger balances, merchants/purchases audit trail).
Bench: scenarios.py (attacks + benign), bench.py (scoring), smoke_device.py (contract/policy cases
  vs the mock or the board).
Demo: demo.sh (bank + dashboard, reads .demo.env), demo_server.py + demo_ui/ (dashboard on :8800),
  demo_hijack.sh (live DeepSeek via OpenRouter), demo_forge.py, forge.py, demo_baseline.py
  (Gatekeeper OFF), voice_host.py (ElevenLabs on the laptop), mailpit_inbox.py.
tests/ (unit tests, conftest.py adds the repo root), hardware/ (board-only scripts that open the
  serial port at import), data/ (inbox.json, inbox_hijack.json, public/, sensitive/),
  docs/ (IDEA, CONTRACT, DECISIONS, TODO, DEMO, DESIGN, RESULTS, SYNC_PROMPT), reports/.

## 7. Run it
python -m venv .venv && .venv/bin/pip install -r requirements.txt   # pynacl, pyserial, pytest
.venv/bin/python make_data.py
.venv/bin/python -m pytest -q                       # 241 unit tests, no hardware/keys needed
.venv/bin/python mock_device.py                     # terminal 1
.venv/bin/python gk.py pin                          # terminal 2
GATEKEEPER_COMPROMISED=1 .venv/bin/python agent.py  # scripted data-theft hijack
GATEKEEPER_COMPROMISED=invoice .venv/bin/python agent.py   # scripted invoice fraud
.venv/bin/python smoke_device.py                    # contract/policy cases vs the mock
.venv/bin/python bench.py                           # worst-case benchmark
.venv/bin/python forge.py --offline ; .venv/bin/python demo_forge.py --offline
cp .demo.env.example .demo.env && ./demo.sh         # dashboard demo (real board)
Real board: GATEKEEPER_PORT=/dev/cu.usbserial-0001. Firmware: pio run -t upload.
Env: NESSIE_API_KEY (bank only), ELEVEN_KEY, GATEKEEPER_VOICE=1, OPENROUTER_KEY, HIJACK_MODEL,
  LLM_BASE_URL/LLM_MODEL/LLM_API_KEY, GATEKEEPER_SMTP_PORT=1026, GATEKEEPER_INBOX,
  NESSIE_ACME_MERCHANT, GATEKEEPER_DEMO_CLEAN=1.

## 8. Demo (docs/DEMO.md; dashboard cards, keys 1-6)
1. Handle my inbox: a phishing email makes the agent send tax_return.pdf to
   records@compliance-archive.io as "low". The laptop narrates calmly; the OLED shows the real
   recipient + TAINTED, then LOCKED. Nothing reaches Mailpit.
2. DeepSeek reads the inbox (live model, OpenRouter): it falls for the fraud invoice; the device blocks it.
3. Pay "Acme Supp1ies" $750: lookalike payee -> BLOCKED, and the Nessie balances don't move.
4. Agent deletes my files: the agent lies about a wipe; the device locks.
5. Pay Acme $750 (legit): button hold + card tap -> SIGNED; the bank verifies; the balances move.
6. Forge an approval: legit accepted; forged (laptop's own key), tampered ($750 -> $75,000) and
   replayed all REJECTED by the bank.
Also: "Beat the Gatekeeper" (judges type any payee; anything unregistered is refused), a live
"fraud blocked this session" $ counter, the lost-card revocation row, and demo_baseline.py to show
the failure with Gatekeeper OFF first.
Startup: plug in the board (shows GATEKEEPER), Docker + Mailpit (localhost:8025 on screen two),
close serial monitors, gk.py pin, verifier.py + GATEKEEPER_SMTP_PORT=1026, bank.py with the
Nessie key in its own terminal, then a benign smoke test.

## 9. Results (docs/RESULTS.md)
- On the real board (24 attacks / 20 benign, worst-case agent): 24/24 caught, 0 executed,
  0 false positives, latency median ~42 ms, p95 ~61 ms.
- Current bench.py on the mock runs 27 attacks / 22 benign: 27 -> 0 executed, 0 false positives,
  50 touches per 100 benign requests. The docs still quote 24/20 in places; reconcile before
  publishing a number.
- Model probe on the fraud invoice: the Grok 4.x models resisted (one Grok variant lied in its
  narration with no tool call). DeepSeek-V3, Ministral-8B and Llama 3.3 70B fell for it, and the
  device stopped every one. Illustrative, 1-2 runs each.

## 10. Rules of the road (from CLAUDE.md, follow them)
- Never contradict a logged DECISIONS entry without flagging it and getting a go-ahead. DECISIONS
  is append-only: reversals are new entries.
- The contract is frozen. Any protocol.py change lands in mock_device.py, executor.py and the
  firmware together, after both people agree in writing.
- Any policy or validation change goes in BOTH src/main.cpp and mock_device.py, plus a case in
  smoke_device.cases().
- Device policy never goes in config.py. The caller never sets taint.
- Stdlib-first; no new dependencies without a DECISIONS entry (llm.py and nessie.py use urllib,
  verifier.py uses socketserver).
- Every executor check gets a test in tests/test_executor.py. Run pytest from the repo root; never
  point it at hardware/.
- Ownership: the software side doesn't touch the firmware except via a logged exception reviewed by
  the device owner (DECISIONS 11:00 and 17:45). Feature freeze after hour 19.
- Git: work on a branch, open a PR with a real body (Conventional Commits titles), and never merge
  it yourself.
- Short module docstrings (what the file does + how to run it); comments explain why.

## 11. Gotchas
- The package is pyserial (import serial), never "serial".
- Opening the port can reboot the ESP32 (CP2102). DeviceLink holds DTR/RTS low and skips non-"{"
  boot lines, but the hardware report saw reboots between separate gk.py runs anyway, which clears
  LOCKED/FROZEN/the delete counter. Demos use one persistent link, so they're fine.
- Only one program can hold the serial port: close monitors and stop ./demo.sh before demo_hijack.sh.
- After using the spare board or `pio run -t erase`, run gk.py pin --force (the key changes).
  Main board pubkey: 4f3339776edac5164f1ba346b3dd105b0648caaf8f6c32d91e546860d1d4cfb6.
- An honest agent hitting LOCKED means the system prompt doesn't define HIGH risk.
- Nessie sandbox: https only, never updates stored balances, truncates to whole dollars. So balances
  are a ledger (stored + deposits - withdrawals); a payment = withdrawal + deposit tagged
  [gk <ref> <cents>c]. Balances are cached ~8 s to avoid rate limits.
- macOS Python HTTPS cert errors: use SSL_CERT_FILE=$(python -m certifi), as demo_hijack.sh does.
- Known limits (say them honestly): Mailpit still accepts direct SMTP on 1025; the bank runs on the
  same machine; the key is in ESP32 flash (no secure element).

## 12. Open items (docs/TODO.md)
- Live LLM benchmark (bench.py --agent llm) for a real hijack rate.
- On-device voice hardware: wire the MAX98357A, create include/secrets.h, flash, verify. The demo
  currently speaks through voice_host.py on the laptop.
- M9 on the board: verifier.py + forge.py with GATEKEEPER_PORT set.
- Policy questions: taint scope, lie-check severity tiers, a "new recipient" OLED warning.
- Devpost: lead with the two-screen GIF; Notability notes + 2 screenshots; Figma OLED mockups; ask
  organizers about Hardware + FinTech; demo video and rehearsal.
Prize tracks: Beyond the Code (Hardware) main; Capital One Nessie, ElevenLabs, Best Design (Figma),
Judged by an LLM, Notability. Fetch.ai is a no-go.
```
