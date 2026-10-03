# Gatekeeper

## Before any task
1. Read `docs/IDEA.md` and the latest entries at the bottom of `docs/DECISIONS.md`.
2. Never contradict a logged decision without flagging it first. Name the entry, explain the conflict, and wait for a go-ahead. Reversals go in as new entries; old entries are never edited.
3. Check `docs/TODO.md` for who owns what.

## Summary
Gatekeeper is a hardware approval device (ESP32 + OLED) that sits between an AI assistant and risky actions like sending email or deleting files. The host executor sends every action to the device, which applies its own policy and signs `allow`/`approved` verdicts with Ed25519. The executor acts only on a valid signature from the pinned key. `mock_device.py` stands in for the hardware over TCP.

## Tech stack
- Python 3, `pynacl` (Ed25519), `pyserial` (serial and `socket://` links), `pytest`
- Mailpit for email (SMTP `localhost:1025`, UI `:8025`)
- Docker `python:3.12-slim` for the no-network `run_code` sandbox
- ESP32 firmware: PlatformIO plus Monocypher (`crypto_ed25519_*`). Not in this repo yet, and owned by the device owner
- Planned: Capital One Nessie (payments, M6), ElevenLabs (voice, M7). The LLM provider isn't chosen yet (M3)

## Folder structure
```
protocol.py       wire contract (signed message format, verdicts). Firmware must match it byte for byte
executor.py       host side: device link, key pinning, checks, email/delete/sandbox
mock_device.py    fake device: policy, signing, OLED render, keyboard approve/deny
config.py         host config only (device policy deliberately lives on the device)
gk.py             CLI for sending test requests by hand
smoke_mock.py     M1: runs every mock policy branch
test_executor.py  M2: unit tests against an in-process fake device
make_data.py      generates the fake PDFs in data/
data/             inbox.json (includes a phishing email), public/ and sensitive/ PDFs
docs/             shared context: IDEA, DECISIONS, TODO, SYNC_PROMPT
```
The KT doc plans `firmware/ executor/ agent/ bench/` plus `CONTRACT.md`, and the repo is still flat. Don't restructure until there's a DECISIONS entry (open item in TODO). Until `CONTRACT.md` exists, `protocol.py` plus the KT doc *is* the contract.

## Conventions
- **Ownership:** software touches only executor, agent and bench code, never `firmware/`. Nothing new after hour 19.
- **The contract is frozen.** Changes are agreed by both people and written down before anyone codes them (see DECISIONS).
- Keep it stdlib-first and small. Don't add dependencies without a DECISIONS entry.
- Any change to `protocol.py` has to land in `mock_device.py`, `executor.py` and the firmware together.
- Device policy lives on the device, never in `config.py`.
- The caller never sets taint; only `read_inbox` does.
- Short module docstrings that say what the file does and how to run it. Comments explain *why*.
- Every executor check gets a test in `test_executor.py`.

## Run locally
```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python make_data.py                    # fake PDFs
.venv/bin/python mock_device.py                  # terminal 1: mock device (a/d/r/k/s/q)
.venv/bin/python gk.py pin                       # terminal 2: pin the device key
.venv/bin/python gk.py send --to boss@ourcompany.com --file data/public/q3_summary.pdf --claim low
.venv/bin/python -m pytest -q test_executor.py   # unit tests (no mock/Mailpit/Docker needed)
.venv/bin/python smoke_mock.py                   # policy smoke test against a fresh mock
```
Mailpit: `docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit`. Sandbox: `docker pull python:3.12-slim`.

**Real device:** `GATEKEEPER_PORT=/dev/cu.usbserial-0001` (CP2102). Close every serial monitor first, because only one program can hold the port. The main board's pubkey is `4f3339776edac5164f1ba346b3dd105b0648caaf8f6c32d91e546860d1d4cfb6`. The spare board has a different key, and `pio run -t erase` rotates it, so re-run `gk.py pin --force` after either.

**Demo startup:** plug in the device (it shows GATEKEEPER), then start Docker and Mailpit with `localhost:8025` on screen two, close the serial monitors, start the executor, and run the benign scenario as a smoke test.

**Hardware gotchas:** the ESP32 reboots on connect unless the port is opened with `dtr`/`rts` False. Skip lines that don't start with `{` (boot noise). The package is `pyserial`, never `serial`. An honest agent hitting LOCKED means the system prompt doesn't define HIGH risk. The full gotcha table is in the KT doc.
