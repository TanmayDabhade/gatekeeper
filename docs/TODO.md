# TODO

Milestones: F = firmware (device owner), M = software. Feature freeze at **hour 19**.

## Tanmay (software: executor/, agent/, bench/)
- [x] M2 executor: open the port with `dtr=False, rts=False` (otherwise the ESP32 reboots on connect)
- [x] M2 executor: skip reply lines that don't start with `{` (ESP32 boot messages)
- [x] Mock matches the firmware verdict for verdict (`test_mock_device.py`)
- [ ] M3: agent loop with large-text narration; the system prompt defines HIGH risk
- [ ] M4–M5: scenarios plus a benchmark (20–30 attacks, 20 benign; hijack rate, blocked rate, false positives, touches per 100, latency)
- [ ] M6: Nessie `pay_invoice` (contract v2)
- [ ] M7: ElevenLabs voice alerts
- [ ] Update your status rows in the KT doc

## Teammate (device: firmware/)
- [ ] Review the firmware changes in the board-ready PR (validation, case-insensitive sensitive check, bench deletes count, always reply), then flash and run `smoke_device.py` on the board (expect 30/30)
- [ ] F4: RFID co-sign, buzzer, v2 payments (put the subject/body hash `bh` in v2 too, see DECISIONS)
- [ ] F5: enclosure, spare board
- [ ] Copy the enrolled RFID card UID into the firmware

## Unassigned
- [ ] Separate verifier process (bank or mail gateway) plus a forged-request demo. Review priority #3; answers the judges' biggest question.
- [ ] Decide the taint scope and the lie-check severity tiers (see `IDEA.md` → Open questions)
- [ ] "New recipient" warning on the OLED
- [ ] Repo layout: move to `executor/ agent/ bench/ firmware/` plus `CONTRACT.md` per the KT doc, or log a decision to stay flat
- [ ] Devpost: lead with the two-screen GIF, keep the scope section, and delete the trailing "I can add this to your plan doc…" line
- [ ] Demo video and rehearsal (after hour 19)

## Blocked
- [ ] Acme's Nessie account id on the device payee list: blocked on M6 setup
- [ ] Co-sign threshold in firmware: blocked on the $500 vs. every-payment decision
- [ ] M3 agent: blocked on choosing the LLM provider and testing the API key
