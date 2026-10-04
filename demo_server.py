"""Gatekeeper demo dashboard -- a visual, click-driven stage for judges.

  terminal 1:  NESSIE_API_KEY=... python bank.py
  terminal 2:  GATEKEEPER_VOICE=1 ELEVEN_KEY=... python demo_server.py   (voice optional)
  then open:   http://localhost:8800   (full-screen it next to the physical device)

Buttons trigger real scenarios on the real board over ONE shared serial link (the port has a
single owner, so close other tools first). No typing in front of judges. The laptop shows the
"AI Assistant" screen (which can lie); the device shows the truth and signs; the bank moves
money only on a verified signature.
"""
import contextlib
import io
import json
import os
import re
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import agent
import demo_forge
import executor
import llm
from config import (BANK_URL, DEVICE_PORT, NESSIE_ACME_ACCOUNT, NESSIE_LOOKALIKE_ACCOUNT,
                    PUBKEY_PATH)

try:
    import voice_host            # lands with PR #15; silent until then
except Exception:
    voice_host = None

ANSI = re.compile(r"\x1b\[[0-9;]*m")
PORT = 8800
_lock = threading.Lock()        # one device action at a time (shared link)

print(f"opening device at {DEVICE_PORT} ...")
LINK = executor.DeviceLink(DEVICE_PORT, timeout=60)
VK = executor.load_or_pin(LINK, PUBKEY_PATH)
EX = executor.Executor(LINK, VK)
print("device pinned, link open.")


def _capture(fn, *a, **k):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            out = fn(*a, **k)
    except SystemExit:
        out = None
    return ANSI.sub("", buf.getvalue()).strip(), out


def balances():
    try:
        with urllib.request.urlopen(BANK_URL + "/balances", timeout=5) as r:
            return {b["name"]: b["cents"] for b in json.load(r)["balances"]}
    except Exception:
        return None


def _speak(verdict, act="", amt=0, known=True):
    if voice_host and os.environ.get("GATEKEEPER_VOICE"):
        try:
            voice_host.speak_result({"pay_invoice": "pay"}.get(act, act), "", amt,
                                    {"verdict": verdict}, payee_known=known)
        except Exception:
            pass


# ---- scenarios (each returns narration, verdict, note) ----

def s_inbox():
    model = llm.ScriptedLLM(agent.compromised_turns())
    narration, out = _capture(agent.run, "Go through my inbox and handle anything needed.",
                              model, EX)
    verdict = "locked" if (out and out["status"] == "locked") else "done"
    _speak("locked")
    note = "Hold RESET on the device 3s to unlock before the next step." if verdict == "locked" else ""
    return {"narration": narration or "(agent produced no narration)", "verdict": verdict,
            "note": note}


def s_pay(payee, amt, memo, known):
    narration = ("Paying the Acme Supplies invoice." if known
                 else "Paying the Acme Supplies invoice.")  # the laptop shows the same friendly line
    try:
        res = EX.pay_invoice(payee, amt, memo, "high")
    except Exception as e:
        return {"narration": narration, "verdict": "error", "note": str(e)}
    _speak(res.get("verdict", ""), "pay_invoice", amt, known)
    note = {"blocked": "The payee is not on the device allowlist.",
            "approved": "Signed on the device (button hold + card tap). Money moved."
            }.get(res.get("verdict"), res.get("detail", ""))
    return {"narration": narration, "verdict": res.get("verdict", "?"), "note": note}


def s_forge():
    narration, _ = _capture(demo_forge.run, LINK, BANK_URL)
    return {"narration": narration or "(no output -- is bank.py running?)", "verdict": "forge",
            "note": "Only the genuine device approval moved money."}


SCENARIOS = {
    "inbox": lambda: s_inbox(),
    "pay_legit": lambda: s_pay(NESSIE_ACME_ACCOUNT, 75000, "INV-2291", True),
    "pay_fraud": lambda: s_pay(NESSIE_LOOKALIKE_ACCOUNT, 75000, "INV-2290", False),
    "forge": lambda: s_forge(),
}

PAGE = """<!doctype html><html><head><meta charset=utf-8><title>AI Assistant</title>
<style>
*{box-sizing:border-box;font-family:-apple-system,Segoe UI,Roboto,sans-serif}
body{margin:0;background:#0b0f17;color:#e7ecf3;display:flex;height:100vh}
.main{flex:1;display:flex;flex-direction:column;padding:28px 34px}
.side{width:360px;background:#111726;border-left:1px solid #1e2941;padding:24px}
h1{font-size:20px;margin:0 0 2px}.sub{color:#7f8aa3;font-size:13px;margin-bottom:22px}
.narr{flex:1;background:#0f1522;border:1px solid #1e2941;border-radius:14px;padding:22px;
  font-size:20px;line-height:1.5;white-space:pre-wrap;overflow:auto}
.btns{display:flex;gap:12px;flex-wrap:wrap;margin-top:20px}
button{flex:1;min-width:160px;padding:16px;border:0;border-radius:12px;font-size:15px;
  font-weight:600;cursor:pointer;background:#1d64f2;color:#fff}
button.warn{background:#7a3030}button.ghost{background:#23304d}
button:disabled{opacity:.45;cursor:wait}
.badge{font-size:30px;font-weight:800;padding:16px;border-radius:12px;text-align:center;
  margin-bottom:8px;background:#23304d}
.locked,.blocked,.denied,.error{background:#7a2530}.approved,.allow{background:#1f7a3f}
.note{color:#9fb0cf;font-size:13px;min-height:34px;margin-bottom:18px}
.bal{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid #1b2440;font-size:15px}
.bal b{font-variant-numeric:tabular-nums}.lk{color:#e0894a}
.st{font-size:12px;color:#7f8aa3;margin-top:18px}.dot{color:#2ecc71}.off{color:#e05050}
h3{font-size:12px;letter-spacing:.08em;color:#7f8aa3;text-transform:uppercase;margin:18px 0 8px}
</style></head><body>
<div class=main>
  <h1>⬡ Acme Corp · AI Assistant</h1>
  <div class=sub>Agent view — the screen the attacker can influence</div>
  <div class=narr id=narr>Pick an action. The agent will narrate here; the device shows the truth.</div>
  <div class=btns>
    <button onclick="run('inbox',this)">📥 Handle my inbox</button>
    <button onclick="run('pay_legit',this)">💳 Pay Acme invoice · $750</button>
    <button class=warn onclick="run('pay_fraud',this)">⚠️ Pay “Acme Supp1ies” · $750</button>
    <button class=ghost onclick="run('forge',this)">🔏 Verify a forged approval</button>
  </div>
</div>
<div class=side>
  <h3>Device verdict</h3>
  <div id=badge class=badge>—</div>
  <div id=note class=note></div>
  <h3>Nessie ledger</h3>
  <div id=bals></div>
  <div class=st id=status></div>
</div>
<script>
const $=id=>document.getElementById(id);
function money(c){return "$"+(c/100).toLocaleString(undefined,{minimumFractionDigits:2})}
async function refresh(){
  const s=await (await fetch('/api/state')).json();
  $('bals').innerHTML = s.balances ? Object.entries(s.balances).map(([n,c])=>
    `<div class="bal ${/lookalike|Supp1/.test(n)?'lk':''}"><span>${n}</span><b>${money(c)}</b></div>`).join('')
    : '<div class=note>bank offline — start bank.py</div>';
  $('status').innerHTML = `<span class="${s.device?'dot':'off'}">●</span> device &nbsp; `+
    `<span class="${s.bank?'dot':'off'}">●</span> bank &nbsp; `+
    `<span class="${s.voice?'dot':'off'}">●</span> voice`;
}
async function run(sc,btn){
  document.querySelectorAll('button').forEach(b=>b.disabled=true);
  $('badge').className='badge'; $('badge').textContent='…';
  $('note').textContent='Working — approve on the device if it asks (hold the button, tap the card).';
  $('narr').textContent='…';
  try{
    const r=await (await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({scenario:sc})})).json();
    $('narr').textContent=r.narration||'(no narration)';
    $('badge').textContent=(r.verdict||'?').toUpperCase();
    $('badge').className='badge '+(r.verdict||'');
    $('note').textContent=r.note||'';
  }catch(e){$('note').textContent='error: '+e}
  await refresh();
  document.querySelectorAll('button').forEach(b=>b.disabled=false);
}
setInterval(refresh,2500); refresh();
</script></body></html>"""


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        b = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self.path == "/":
            return self._send(200, PAGE, "text/html; charset=utf-8")
        if self.path == "/api/state":
            bals = balances()
            return self._send(200, json.dumps({
                "balances": bals, "device": True, "bank": bals is not None,
                "voice": bool(voice_host and os.environ.get("GATEKEEPER_VOICE"))}))
        return self._send(404, "{}")

    def do_POST(self):
        if self.path != "/api/run":
            return self._send(404, "{}")
        n = int(self.headers.get("Content-Length", 0))
        sc = json.loads(self.rfile.read(n) or b"{}").get("scenario")
        fn = SCENARIOS.get(sc)
        if not fn:
            return self._send(400, json.dumps({"narration": "unknown scenario", "verdict": "error"}))
        with _lock:                       # serialize device access
            try:
                out = fn()
            except Exception as e:
                out = {"narration": f"error: {e}", "verdict": "error", "note": ""}
        return self._send(200, json.dumps(out))


if __name__ == "__main__":
    print(f"\n  Gatekeeper demo dashboard -> http://localhost:{PORT}\n")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
