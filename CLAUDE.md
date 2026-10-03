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
- ESP32 firmware: PlatformIO, Arduino, ArduinoJson, Adafruit SSD1306, Monocypher (`crypto_ed25519_*`). Owned by the device owner
- LLM agent (M3): any OpenAI-style `/chat/completions` endpoint through stdlib `urllib` in `llm.py` (no SDK). Provider not chosen yet; set `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY`
- Capital One Nessie sandbox (payments, M6): `nessie.py`, stdlib `urllib`, key in `NESSIE_API_KEY` (env only, never committed)
- Planned: ElevenLabs (voice, M7)

## Folder structure
```
src/main.cpp      ESP32 firmware: validation, policy, signing, OLED, buttons (PlatformIO; platformio.ini)
lib/monocypher/   Ed25519 for the firmware
test_device.py    board-only: ping and a request (device owner)
test_sign.py      board-only: signature and tamper check, needs a button press
test_policy.py    board-only: every policy case with button prompts
protocol.py       wire contract v2 (docs/CONTRACT.md): signed string, verdicts, body_hash. Firmware must match byte for byte
executor.py       host side: device link, key pinning, checks, email/delete/sandbox
mock_device.py    fake device: policy, signing, OLED render, keyboard approve/deny
config.py         host config only (device policy deliberately lives on the device)
gk.py             CLI for sending test requests by hand
agent.py          M3: LLM agent loop (tools -> executor), narration-only "lying screen", compromised mode
llm.py            M3: stdlib OpenAI-style chat client, plus ScriptedLLM (compromised mode and tests)
scenarios.py      M4: 24 injection attacks + 20 benign requests (inbox, task, harmful/wanted action)
nessie.py         M6: Nessie client (withdrawal + deposit per payment) and ledger balances; `setup` makes demo accounts
test_nessie.py    M6: Nessie client against a fake API
verifier.py       M9: separate mail gateway (:1026) that re-checks the device signature before relaying to Mailpit
forge.py          M9: compromised-laptop demo: 7 forgeries + replay vs the gateway (--offline needs nothing)
bench.py          M4-M5: runs every scenario through agent+executor+device (bench mode), prints the metrics
smoke_device.py   30 contract and policy cases (bench, no buttons) against the mock OR the board
test_executor.py  M2: unit tests against an in-process fake device
test_mock_device.py  runs smoke_device's cases against the mock in-process (mock == firmware)
test_agent.py     M3: LLM client and agent loop against the real mock policy in-process
test_verifier.py  M9: gateway checks over real SMTP, executor mail passes, every forgery rejected
test_bench.py     M4-M5: scenario sanity, scoring, and the worst-case numbers we quote
make_data.py      generates the fake PDFs in data/
data/             inbox.json (includes a phishing email), public/ and sensitive/ PDFs
docs/             shared context: IDEA, DECISIONS, TODO, SYNC_PROMPT
```
The KT doc plans `firmware/ executor/ agent/ bench/` plus `CONTRACT.md`, but everything, including the firmware, is at the repo root. Don't restructure until there's a DECISIONS entry (open item in TODO). `docs/CONTRACT.md` is the contract; `protocol.py` implements it.

## Conventions
- **Ownership:** software touches only executor, agent and bench code, never `firmware/`. Nothing new after hour 19.
- **The contract is frozen.** Changes are agreed by both people and written down before anyone codes them (see DECISIONS).
- Keep it stdlib-first and small. Don't add dependencies without a DECISIONS entry.
- Any change to `protocol.py` has to land in `mock_device.py`, `executor.py` and the firmware together.
- The mock must give the firmware's exact verdicts. Change a policy or validation rule in both `src/main.cpp` and `mock_device.py`, and add the case to `smoke_device.cases()`.
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
GATEKEEPER_COMPROMISED=1 .venv/bin/python agent.py   # scripted hijacked agent, no key (demo backup)
.venv/bin/python agent.py "Handle my inbox"          # real LLM (LLM_BASE_URL, LLM_MODEL, LLM_API_KEY); --show-calls to debug
.venv/bin/python -m pytest -q test_executor.py test_mock_device.py test_agent.py test_bench.py test_verifier.py test_nessie.py   # unit tests (no mock/Mailpit/Docker/key needed)
.venv/bin/python smoke_device.py                 # 30 cases against a fresh mock
.venv/bin/python gk.py pay --to 7083a93b-e422-4fa6-8188-330034f0c237 --amt 25000 --memo INV-2290   # M6 (needs NESSIE_API_KEY)
.venv/bin/python gk.py balances                   # Nessie ledger balances: proof nothing moved after a block
GATEKEEPER_COMPROMISED=invoice .venv/bin/python agent.py   # scripted invoice fraud (lookalike payee)
.venv/bin/python verifier.py                      # M9 gateway on :1026 (trusts the pinned key; run gk.py pin first)
GATEKEEPER_SMTP_PORT=1026 .venv/bin/python agent.py   # executor mail goes through the gateway
.venv/bin/python forge.py                         # forged-request demo against the gateway (--offline: no servers)
.venv/bin/python bench.py                         # benchmark, scripted worst-case agent (no key); --json out.json
.venv/bin/python bench.py --agent llm             # benchmark with the real LLM
GATEKEEPER_PORT=/dev/cu.usbserial-0001 .venv/bin/python smoke_device.py   # same cases against the board
~/.platformio/penv/bin/pio run                   # compile firmware (add -t upload to flash)
```
Mailpit: `docker run -d --name mailpit -p 8025:8025 -p 1025:1025 axllent/mailpit`. Sandbox: `docker pull python:3.12-slim`.

Name the test files explicitly. A bare `pytest` also collects the `test_*.py` board scripts, which open the serial port at import.

**Real device:** `GATEKEEPER_PORT=/dev/cu.usbserial-0001` (CP2102). Close every serial monitor first, because only one program can hold the port. The main board's pubkey is `4f3339776edac5164f1ba346b3dd105b0648caaf8f6c32d91e546860d1d4cfb6`. The spare board has a different key, and `pio run -t erase` rotates it, so re-run `gk.py pin --force` after either.

**Demo startup:** plug in the device (it shows GATEKEEPER), then start Docker and Mailpit with `localhost:8025` on screen two, close the serial monitors, pin the key, start `verifier.py` and export `GATEKEEPER_SMTP_PORT=1026`, start the executor, and run the benign scenario as a smoke test.

**Hardware gotchas:** `executor.DeviceLink` already handles the two big ones: it holds `dtr`/`rts` low before opening (otherwise the ESP32 reboots) and skips lines that don't start with `{` (boot noise). The package is `pyserial`, never `serial`. An honest agent hitting LOCKED means the system prompt doesn't define HIGH risk. The full gotcha table is in the KT doc.
