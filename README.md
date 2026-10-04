# Gatekeeper

**The only screen your AI can't lie to.** Gatekeeper is a hardware wallet for AI agent actions.

An AI assistant that reads untrusted content (email, invoices) can be steered by instructions hidden
in it. Today's confirmations appear on the same screen the software controls, so a hijacked agent can
describe a dangerous action as harmless and the human approves something they never saw.

Gatekeeper moves the decision onto an ESP32 with its own OLED, buttons and RFID reader. The agent can
only *ask*. Every risky action (send an email, delete a file, pay an invoice) goes to the device, which
applies its own policy, shows the real recipient, file and amount, and signs `allow`/`approved` verdicts
with Ed25519. The executor, the mail gateway and the bank act only on a valid signature from the pinned
device key.

## How it works

```
 untrusted inbox ──► LLM agent ──tool call──► executor ──request──► ESP32 Gatekeeper
                    (no credentials)          (holds creds)         policy + OLED + buttons
                                                   ▲                 Ed25519 signature
                                                   └──── signed verdict ◄──┘
                                                   │
                       mail gateway (verifier.py) ◄┤ re-checks the device signature
                       bank (bank.py, Nessie)     ◄┘ re-checks the device signature
```

- **Device policy:** contacts list, `/data/sensitive/` is blocked, delete rate limit, payee list,
  and an RFID co-sign for payments over $500.
- **Trusted display:** the OLED shows the action, the registrable domain
  (`boss@company.com.evil.io` shows as `evil.io`), the file, the amount and the agent's claim.
- **Lie check:** if the agent calls an action `low` risk and the device disagrees, the session locks.
- **Taint:** reading outside mail tightens every rule for the rest of the session.
- **Separate verifiers:** even a fully compromised laptop can't forge mail or move money, because the
  gateway and the bank check the device's signature themselves.
- **Voice:** the device speaks the true action aloud through ElevenLabs.

The wire contract is in [`docs/CONTRACT.md`](docs/CONTRACT.md) and implemented in `protocol.py`.

## Results

`bench.py` runs 27 prompt-injection attacks and 22 benign tasks through the real agent loop, executor
and device policy, using a worst-case agent that obeys every injection:

| | Without Gatekeeper | With Gatekeeper |
|---|---|---|
| Harmful actions executed | 27 / 27 | **0 / 27** |
| Benign false positives | n/a | **0 / 22** |

Of the 27 attacks, 12 were blocked, 10 locked the session, and 5 were held for a human, who sees the
real action on the device.

## Repo layout

```
src/ include/ lib/   ESP32 firmware (PlatformIO, platformio.ini): policy, signing, OLED, buttons, voice
protocol.py          wire contract v2, byte for byte with the firmware
executor.py          host side: device link, key pinning, checks, email / delete / sandbox / pay
agent.py, llm.py     the untrusted LLM agent (any OpenAI-style endpoint) and a scripted hijacked agent
mock_device.py       software stand-in for the board (same verdicts as the firmware)
verifier.py          separate mail gateway that re-checks the device signature
bank.py, nessie.py   separate bank process: pays through Capital One Nessie only on a valid signature
scenarios.py         injection attacks and benign tasks; bench.py scores them
gk.py                CLI for sending requests by hand
demo_server.py       demo dashboard (UI in demo_ui/), started by demo.sh
forge.py, demo_*.py  forged / tampered / replayed request demos and the "Gatekeeper off" baseline
tests/               unit tests (no hardware, Mailpit, Docker or keys needed)
hardware/            board-only scripts that talk to a real ESP32 over serial
data/                fake inbox and fake public / sensitive files
docs/                idea, contract, decisions, demo runbook, design system
reports/             benchmark and hardware test reports
```

## Run it

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python make_data.py                      # fake PDFs
.venv/bin/python -m pytest -q                      # unit tests

.venv/bin/python mock_device.py                    # terminal 1: mock device (a/d/r/k/s/q)
.venv/bin/python gk.py pin                         # terminal 2: pin the device key
GATEKEEPER_COMPROMISED=1 .venv/bin/python agent.py # a hijacked agent tries to exfiltrate a tax return
.venv/bin/python bench.py                          # benchmark
.venv/bin/python forge.py --offline                # every forged email is rejected by the gateway
.venv/bin/python demo_forge.py --offline           # only the genuine approval moves money
```

With the real board, set `GATEKEEPER_PORT=/dev/cu.usbserial-0001`. Firmware: `pio run -t upload`.
The full demo runbook is in [`docs/DEMO.md`](docs/DEMO.md).

## Built with

ESP32, SSD1306 OLED, MFRC522 RFID, MAX98357A amp, Monocypher (Ed25519), Python (PyNaCl, pyserial),
Mailpit, Docker, Capital One Nessie, ElevenLabs.
