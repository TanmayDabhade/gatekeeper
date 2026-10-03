# TODO

Milestones: F = firmware (device owner), M = software. Feature freeze at **hour 19**.

## Tanmay (software: executor/, agent/, bench/)
- [x] M2 executor: open the port with `dtr=False, rts=False` (otherwise the ESP32 reboots on connect)
- [x] M2 executor: skip reply lines that don't start with `{` (ESP32 boot messages)
- [x] Mock matches the firmware verdict for verdict (`test_mock_device.py`)
- [x] M3: agent loop (`agent.py`, `llm.py`) with narration-only screen, HIGH-risk prompt, compromised mode; 23 tests- [x] M4–M5: scenarios plus a benchmark (`scenarios.py`, `bench.py`): 24 attacks, 20 benign. Worst-case agent: 24/24 hijacked, 1 executed with Gatekeeper (atk-07), 0 false positives, 40 touches per 100 benign requests
- [ ] M4–M5: run `bench.py --agent llm` once a provider is chosen and put the real hijack rate in the Devpost
- [x] M6: Nessie `pay_invoice` (contract v2) on the mock + executor + agent + bench; per CONTRACT v2; verified live against the Nessie sandbox (DECISIONS 16:45)
- [ ] M6: `llm.py` will likely hit the same macOS Python CA-certificate error over HTTPS that `nessie.py` now works around; check it on the first live LLM run
- [ ] M7: ElevenLabs speaks the true action on block/lock (e.g. "Blocked: sending tax_return.pdf to compliance-archive.io"), not just an alarm
- [ ] Update your status rows in the KT doc

## Teammate (device: firmware/)
- [ ] Review the firmware changes in the board-ready PR (validation, case-insensitive sensitive check, bench deletes count, always reply), then flash and run `smoke_device.py` on the board (expect 30/30)
- [ ] F4: RFID co-sign, buzzer, v2 for **all** actions per `docs/CONTRACT.md` (plus the `amt`/`bh` validation rules in DECISIONS 16:45, payee list with Acme `7083a93b-e422-4fa6-8188-330034f0c237`, co-sign over 50000 cents). Flash together with merging M6, then `smoke_device.py` on the board (31 + 20 cases)
- [ ] F5: enclosure, spare board
- [ ] Copy the enrolled RFID card UID into the firmware

## Unassigned
- [x] M9: separate verifier (`verifier.py`, a mail gateway) plus a forged-request demo (`forge.py`): 7 forgeries + a replay rejected, only the device-signed control delivered. Verified live against the mock + Mailpit
- [x] M9 bank: `bank.py` verifies the device signature before Nessie moves money, and `demo_forge.py` shows legit → paid, forged / tampered / replayed → $0 (verified live against the mock + Nessie)
- [ ] M9 on the board: run `verifier.py` + `forge.py` with `GATEKEEPER_PORT` set (the gateway must trust the board's pinned key)
- [ ] Decide the taint scope and the lie-check severity tiers (see `IDEA.md` → Open questions)
- [ ] "New recipient" warning on the OLED
- [ ] Decide on the delete-rate gap the benchmark found (atk-07): 5 non-sensitive deletes per 10 min are auto-signed, so an injection can wipe a small public folder. A fix is a firmware + mock policy change (DECISIONS first)
- [ ] Repo layout: move to `executor/ agent/ bench/ firmware/` plus `CONTRACT.md` per the KT doc, or log a decision to stay flat
- [ ] Notability: ~20 min ideation/wiring/threat-model notes; tag on Devpost; attach ≥2 screenshots
- [ ] Figma: OLED screen mockups + two-screen demo frame (also feeds the Devpost GIF / Best Design)
- [ ] Devpost: lead with the two-screen GIF, keep the scope section, and delete the trailing "I can add this to your plan doc…" line
- [ ] Ask organizers: prior-work rule + whether Hardware and FinTech can both be entered
- [ ] Demo video and rehearsal (after hour 19)

## Blocked
- [x] Acme's Nessie account id: `7083a93b-e422-4fa6-8188-330034f0c237` (in `mock_device.PAYEES`; firmware at F4)
- [x] Co-sign threshold decided: more than 50000 cents ($500) (CONTRACT.md); firmware at F4
- [ ] M3 live run with a real model (run `agent.py` against the mock, note whether it obeys msg-004 and what it claims): blocked on choosing the LLM provider and testing the API key. The code is provider-agnostic, so this is config only
