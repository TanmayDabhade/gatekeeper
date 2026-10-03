# Gatekeeper — demo runbook

Four scenarios, ~4 minutes. The pitch: **the only screen your AI can't lie to.**
The laptop narrates; the device shows the truth and signs; the bank verifies the
signature before any money moves.

Accounts (Nessie sandbox): Acme `7083a93b-e422-4fa6-8188-330034f0c237`,
lookalike "Acme Supp1ies" `4babab8f-537e-444a-9801-a3463689b686`.

## Setup (before judges arrive)
- ESP32 plugged in, F4 firmware flashed, OLED on `GATEKEEPER`. Serial monitors closed.
- Docker + **Mailpit** up at http://localhost:8025.
- **Terminal A — the bank** (holds the Nessie key, a separate process/trust domain):
  ```bash
  NESSIE_API_KEY=… .venv/bin/python bank.py       # serves 127.0.0.1:8099
  ```
- **Terminal B — the laptop/presenter** (NO Nessie key — it can't move money on its own):
  ```bash
  export GATEKEEPER_PORT=/dev/cu.usbserial-0001
  .venv/bin/python gk.py pin --force              # should print 4f3339…cfb6
  .venv/bin/python gk.py balances                 # starting balances, read via the bank
  ```

## 1 — The hijack (two screens)
```bash
GATEKEEPER_COMPROMISED=1 .venv/bin/python agent.py
```
- **Laptop:** calm cover story → `SESSION LOCKED BY GATEKEEPER`
- **Device OLED:** `records@compliance-archive.io`, `tax_return.pdf`, `TAINTED`, `LOCKED`
- **Mailpit:** nothing — the tax return never left
- After: **hold Reset (GPIO 26) 3s** → home

## 2 — Invoice fraud (lookalike payee blocked)
```bash
.venv/bin/python gk.py pay --to 4babab8f-537e-444a-9801-a3463689b686 --amt 75000 --memo "INV-2290"
.venv/bin/python gk.py balances
```
- **OLED:** `BLOCKED` · `$750.00` · `to: 4babab8f-…` · `! UNKNOWN PAYEE`
- **JSON:** `ok:false, blocked` · **Balances:** unchanged — $0 to the lookalike

## 3 — Legit payment + RFID co-sign ($750 > $500)
```bash
.venv/bin/python gk.py pay --to 7083a93b-e422-4fa6-8188-330034f0c237 --amt 75000 --memo "INV-2291"
```
- **OLED:** `HOLD TO OK` · **`$750.00`** · `to: Acme Supplies` → hold Approve 2s → `CO-SIGN tap card $750` → **tap card** → `SIGNED`
- The bank verifies the device signature, then moves money:
  ```bash
  .venv/bin/python gk.py balances
  ```
  Acme **+$750**, company **−$750** — only after a button hold **and** a card tap.

## 4 — Why the hardware (forged request rejected by the bank)
```bash
.venv/bin/python demo_forge.py            # live (needs bank.py); or: demo_forge.py --offline
```
- **Legit** → ACCEPTED, money moves
- **Forged** (laptop signs with its own key) → REJECTED, signature doesn't verify
- **Tampered** ($750 → $75,000 after signing) → REJECTED
- **Replay** (same approval twice) → REJECTED, nonce used
- *Only the genuine device approval moved money.*

> "The executor runs on a laptop we assume can be hacked. It can lie about approvals —
> but the bank verifies the device's Ed25519 signature itself, and the laptop never has
> the device's key. A forged or tampered approval is rejected by the bank, not the software.
> That's what the $30 of hardware buys."

## One-liner close
A lying agent, a fraudulent payee, and a tampered approval — all stopped, with real money
on the line, because the truth lives on a screen the software can't touch.

## Gotchas
- Each command briefly **reboots the device on connect** (CP2102) — normal, ~1s pause.
- `demo_forge.py --offline` needs no bank/board/key (in-memory ledger) — reliable fallback if Wi-Fi/Nessie is flaky.
- If the pin ever mismatches (spare board / after `pio run -t erase`): `gk.py pin --force`.
