# Gatekeeper

A hardware approval device for AI agents: the one screen your AI cannot lie to.

AI agents are starting to take consequential actions, such as sending email, deleting files,
and moving money. An agent that reads untrusted content can be hijacked by instructions hidden
in it, and today's confirmations appear on the same screen the software controls. A hijacked
agent can describe a dangerous action as harmless, and the human approves something they never
actually saw.

Gatekeeper puts the real action on a separate ESP32 device with its own screen. The agent can
only ask; nothing consequential happens until the device shows the true recipient, file, or
amount and signs it with an Ed25519 key the host never holds. For payments, a separate bank
process verifies that signature before any money moves, so even a fully compromised host cannot
forge an approval.

## How it works

```
  AI agent            Host executor            Gatekeeper device         Bank / verifier
 (untrusted)        (holds no keys)            (ESP32, trusted)          (separate process)
     |                     |                          |                         |
     |  tool call          |   request (JSON)         |                         |
     |-------------------->|------------------------->|  show real action       |
     |                     |                          |  on the OLED,           |
     |                     |                          |  human approves,        |
     |                     |   signed verdict         |  sign (Ed25519)         |
     |                     |<-------------------------|                         |
     |                     |   pay(request, approval) |                         |
     |                     |----------------------------------------------------|
     |                     |                          |   verify signature,     |
     |                     |                          |   then move money        |
```

Trust model: the host and the agent are assumed to be compromisable and may lie about an action.
They never hold the device key or the bank key. The device applies its own policy, shows the
truth, and signs only `allow` and `approved` verdicts. The bank re-verifies the signature before
paying, so a forged, tampered, or replayed approval is rejected by the bank, not the software.

## Repository structure

The project is intentionally flat: the host modules import each other directly and run as
scripts. Files are grouped by role below.

Firmware (the device, PlatformIO):
- `src/main.cpp` validation, policy, OLED, buttons, RFID co-sign, Ed25519 signing
- `lib/monocypher/` Ed25519 implementation for the firmware
- `include/`, `platformio.ini` build configuration

Wire contract:
- `protocol.py` the signed-message format and verdicts, shared by firmware, mock, and host
- `docs/CONTRACT.md` the frozen v2 contract specification

Host (assumed compromisable; holds no keys):
- `executor.py` device link, key pinning, signature checks, email/delete/sandbox actions
- `config.py` host configuration
- `gk.py` command-line interface for sending test requests
- `mock_device.py` software stand-in for the device, byte-identical verdicts

Agent:
- `agent.py` the LLM agent loop and the narration-only "lying screen"
- `llm.py` a stdlib OpenAI-style chat client, plus a scripted client for the compromised mode

Payments:
- `nessie.py` Capital One Nessie client (accounts, transfers, merchants, purchases)
- `bank.py` separate process that verifies the device signature before paying
- `verifier.py` signature, nonce, and expiry verification

Benchmark:
- `bench.py`, `scenarios.py` the attack and benign scenarios and scoring
- `smoke_device.py` contract and policy check against the mock or the real board

Demo:
- `demo.sh` one-command launcher (reads keys from `.demo.env`)
- `demo_server.py`, `demo_ui/` the click-driven dashboard
- `demo_hijack.sh` live weak-model hijack clip
- `demo_forge.py`, `demo_baseline.py` the forged-request and baseline-failure demos
- `voice_host.py` host-side ElevenLabs voice on the laptop speaker
- `mailpit_inbox.py` live email ingestion helper

Data and tests:
- `data/`, `make_data.py` demo inbox and fake PDFs
- `tests/` unit tests for the host (no hardware, Mailpit, Docker, or keys needed)
- `hardware/` board-only scripts that talk to a real ESP32 over serial

Documentation:
- `docs/` IDEA, DECISIONS, TODO, CONTRACT, DEMO, DESIGN
- `reports/` hardware test report and benchmark results

## Quickstart

Host setup:

```
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python make_data.py
```

Firmware (device owner):

```
.venv/bin/pip install platformio
.venv/bin/pio run -t upload
```

Run the demo (see `docs/DEMO.md` for the full runbook):

```
cp .demo.env.example .demo.env   # add your keys
./demo.sh                         # starts the bank and dashboard, opens http://localhost:8800
```

## Demo scenarios

- Hijacked agent: a phishing email makes the agent try to exfiltrate a sensitive file. The device
  locks the session; nothing is sent.
- Invoice fraud: the agent is told to pay a lookalike vendor. The device blocks it; the ledger
  does not move and the payment never enters the purchase record.
- Legitimate payment: a real vendor is paid, but only after a button hold and an RFID card tap.
- Live model: a current model (DeepSeek) reads the same fraud invoice, falls for it, and the
  device blocks it anyway.
- Forged approval: a compromised host forges, edits, and replays approvals; the bank rejects all
  but the genuine one.
- Beat the Gatekeeper: type any account and try to pay it; the device refuses any unregistered
  payee.

## Results

Measured on the real ESP32 (`esp32dev`). See `docs/RESULTS.md`.

- 24 of 24 attacks caught, 0 executed, 0 false positives.
- Device decision latency approximately 42 ms median.
- Model probe against the fraud invoice: Grok 4 resisted; DeepSeek, Ministral-8B, and Llama 3.3
  fell for it. In every case the device was the backstop.

## Hardware

ESP32 (`esp32dev`), SSD1306 OLED (I2C), three buttons (approve, kill, reset), an RGB LED, and an
MFRC522 RFID reader for payment co-signs. The signing key is generated on first boot and stored
in device flash; it never leaves the device.

## Tests

```
.venv/bin/python -m pytest -q                                             # unit tests in tests/
GATEKEEPER_PORT=/dev/cu.usbserial-0001 .venv/bin/python smoke_device.py   # against the board
```

`pytest.ini` limits a bare `pytest` to `tests/`. The scripts in `hardware/` open the serial port
on import, so run them directly against a board, never through pytest.

## Tech stack

Python 3 (stdlib-first), PyNaCl and Monocypher for Ed25519, pyserial for the device link,
PlatformIO and Arduino for the firmware, Capital One Nessie for payments, ElevenLabs for voice,
and an OpenAI-style LLM endpoint for the agent.
