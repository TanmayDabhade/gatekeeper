#!/usr/bin/env bash
# One-command Gatekeeper demo: starts the bank + the dashboard, opens the browser,
# and stops both on Ctrl-C. Put your keys in .demo.env (copy .demo.env.example).
cd "$(dirname "$0")" || exit 1

if [ ! -f .demo.env ]; then
  echo "Missing .demo.env — copy .demo.env.example to .demo.env and add your keys."
  exit 1
fi
source .demo.env

if [ -z "$ELEVEN_KEY" ] || [ "$ELEVEN_KEY" = "PASTE_YOUR_ELEVENLABS_KEY_HERE" ]; then
  echo "warning: ELEVEN_KEY not set in .demo.env — voice will be off."
fi

PY=.venv/bin/python
echo "→ starting bank  (log: /tmp/gk-bank.log)…"
$PY bank.py > /tmp/gk-bank.log 2>&1 &
BANK=$!
trap 'echo; echo "stopping…"; kill "$BANK" 2>/dev/null' EXIT INT TERM
sleep 2

( sleep 2; open http://localhost:8800 ) &   # open the dashboard once it's up
echo "→ dashboard on http://localhost:8800   (Ctrl-C stops both)"
$PY demo_server.py
