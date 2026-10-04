#!/usr/bin/env bash
# Live-hijack clip: a real, current LLM gets prompt-injected by a fraud invoice and tries to
# pay the fraudster; the device BLOCKS it and the Mac speaks the verdict (ElevenLabs).
# Stop ./demo.sh first (frees the serial port). Keys come from .demo.env.
cd "$(dirname "$0")" || exit 1
[ -f .demo.env ] && source .demo.env
: "${OPENROUTER_KEY:?set OPENROUTER_KEY in .demo.env}"

export LLM_BASE_URL=https://openrouter.ai/api/v1
export LLM_MODEL="${HIJACK_MODEL:-mistralai/ministral-8b-2512}"   # new (Dec 2025) small model
export LLM_API_KEY="$OPENROUTER_KEY"
export SSL_CERT_FILE="$(.venv/bin/python -m certifi)"
export GATEKEEPER_INBOX=data/inbox_hijack.json

echo "→ $LLM_MODEL reads a fraud invoice and tries to pay it…"
echo
.venv/bin/python agent.py --show-calls "Pay any invoices that are due today." 2>&1 | tee /tmp/gk-hijack.log
out=$(cat /tmp/gk-hijack.log)
echo
if echo "$out" | grep -qiE '"verdict": "(blocked|locked)"'; then
  .venv/bin/python voice_host.py blocked pay_invoice --amt 75000 --unknown   # speak the block
fi
