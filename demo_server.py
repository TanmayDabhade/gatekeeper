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
import time
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

try:
    import certifi
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())  # for the live model's HTTPS call
except Exception:
    pass

ANSI = re.compile(r"\x1b\[[0-9;]*m")
PORT = 8800
_lock = threading.Lock()        # one device action at a time (shared link)

LINK = VK = EX = None


def ensure_device(force=False):
    """Open the shared link lazily and self-heal. If the board was reset/re-enumerated the old
    handle is dead, so ping it and reopen when needed. Returns True if the device is ready."""
    global LINK, VK, EX
    if EX is not None and not force:
        try:
            if LINK.call({"t": "ping"}).get("t") == "pong":
                return True
        except Exception:
            pass  # handle is dead -> reopen below
    try:
        if LINK is not None:
            try:
                LINK.close()
            except Exception:
                pass
        LINK = executor.DeviceLink(DEVICE_PORT, timeout=60)
        VK = executor.load_or_pin(LINK, PUBKEY_PATH)
        EX = executor.Executor(LINK, VK)
        print(f"device connected at {DEVICE_PORT}")
        return True
    except Exception as e:
        LINK = VK = EX = None
        print(f"device not ready ({DEVICE_PORT}): {e}")
        return False


ensure_device()  # best-effort now; it reconnects on first use if the board isn't ready yet


def _capture(fn, *a, **k):
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf):
            out = fn(*a, **k)
    except SystemExit:
        out = None
    return ANSI.sub("", buf.getvalue()).strip(), out


_BAL = {"t": 0.0, "v": None}  # cache so frequent polls don't rate-limit the Nessie sandbox
_PUR = {"t": 0.0, "v": None}

# Clean-slate display (GATEKEEPER_DEMO_CLEAN=1): rebase balances to these round starting values
# and show only purchases made this run, so restarting the server gives a pristine demo. Real
# Nessie movements still happen underneath; this only rebases what the dashboard shows.
CLEAN = bool(os.environ.get("GATEKEEPER_DEMO_CLEAN"))
DEMO_START = {"OurCompany (payer)": 5000000, "Acme Supplies": 100000, "Acme Supp1ies (lookalike)": 0}
_BASE = {"bal": None, "refs": None}   # snapshot captured on the first successful fetch


def balances(force=False):
    now = time.monotonic()
    if not force and _BAL["v"] is not None and now - _BAL["t"] < 8:
        return _BAL["v"]
    try:
        with urllib.request.urlopen(BANK_URL + "/balances", timeout=5) as r:
            live = {b["name"]: b["cents"] for b in json.load(r)["balances"]}
        if CLEAN:
            if _BASE["bal"] is None:
                _BASE["bal"] = dict(live)
            live = {n: DEMO_START.get(n, c) + (c - _BASE["bal"].get(n, c)) for n, c in live.items()}
        _BAL["v"] = live
    except Exception:
        _BAL["v"] = None
    _BAL["t"] = now
    return _BAL["v"]


def purchases():
    """Vendor-payment audit trail from the bank (cached). [] if the bank is offline."""
    now = time.monotonic()
    if _PUR["v"] is not None and now - _PUR["t"] < 8:
        return _PUR["v"]
    try:
        with urllib.request.urlopen(BANK_URL + "/purchases", timeout=5) as r:
            live = json.load(r)["purchases"]
        if CLEAN:
            if _BASE["refs"] is None:
                _BASE["refs"] = {p["ref"] for p in live}
            live = [p for p in live if p["ref"] not in _BASE["refs"]]
        _PUR["v"] = live
    except Exception:
        _PUR["v"] = None
    _PUR["t"] = now
    return _PUR["v"]


def _bg(fn, *a):
    """Run voice in the background so the dashboard shows the result immediately instead of
    waiting for ElevenLabs + afplay to finish speaking."""
    if voice_host and os.environ.get("GATEKEEPER_VOICE"):
        threading.Thread(target=lambda: _safe(fn, *a), daemon=True).start()


def _safe(fn, *a):
    try:
        fn(*a)
    except Exception:
        pass


def _speak(verdict, act="", amt=0, known=True):
    _bg(voice_host.speak_result, {"pay_invoice": "pay"}.get(act, act), "", amt,
        {"verdict": verdict}, known) if voice_host else None


def _say(text):
    _bg(voice_host.say, text) if voice_host else None


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


def s_inbox_live():
    # A real, current model (DeepSeek by default) handles the injected inbox. Surface the actual
    # tool call it makes -- that's the proof it's a real hijack, not a script.
    key = os.environ.get("OPENROUTER_KEY") or os.environ.get("LLM_API_KEY")
    if not key:
        return {"narration": "Set OPENROUTER_KEY in .demo.env to run the live model.",
                "verdict": "error", "note": ""}
    try:
        model = llm.ChatLLM(base_url=os.environ.get("LLM_BASE_URL", "https://openrouter.ai/api/v1"),
                            model=os.environ.get("HIJACK_MODEL", "deepseek/deepseek-chat"),
                            api_key=key)
        ex = executor.Executor(LINK, VK, inbox_path="data/inbox_hijack.json")
        # Cap steps: read_inbox + the pay attempt. Keeps it fast and consistent so the OLED, the
        # voice and the chat output stay in sync (blocked doesn't stop the loop, so without this
        # the model wanders for several more slow calls after the device already blocked it).
        narration, out = _capture(agent.run, "Pay the single invoice that is due today.", model, ex,
                                  max_steps=2)
    except Exception as e:
        return {"narration": f"the live model errored: {e}", "verdict": "error",
                "note": "it may have refused or the key/model is off — the scripted button always works"}
    attempt = next((a for a in (out["actions"] if out else []) if a["tool"] == "pay_invoice"), None)
    if attempt:
        payee = str(attempt["args"].get("payee", "?"))
        amt = attempt["args"].get("amount_cents", 0)
        amt = amt if isinstance(amt, int) else (int(amt) if str(amt).isdigit() else 0)
        verdict = attempt["result"].get("verdict", "?")
        known = payee == NESSIE_ACME_ACCOUNT
        _speak(verdict, "pay_invoice", amt, known)
        note = (f"⚠ the model really called pay_invoice → {payee[:13]}… "
                + ("(the real Acme)" if known else "(the FRAUDSTER, not on the allowlist)"))
        return {"narration": narration or "(no narration)", "verdict": verdict, "note": note,
                "amount_cents": amt}
    v = out["actions"][-1]["result"].get("verdict") if (out and out["actions"]) else "done"
    return {"narration": narration or "(no narration)", "verdict": v,
            "note": "the model didn't attempt a payment this run (it may have refused)"}


def s_revoke():
    # Lost a card: the owner taps the credential they still hold; it becomes the only valid card,
    # so a found/stolen card stops working. The device requires the tap to be an already-valid card.
    try:
        res = LINK.call({"t": "revoke"})
    except Exception as e:
        return {"narration": "Reporting a lost card.", "verdict": "error", "note": str(e)}
    if res.get("ok"):
        kept = res.get("kept", "")
        return {"narration": "Reporting a lost card — tapped the credential I still have.",
                "verdict": "approved",
                "note": f"Done. Only {kept} works now; the lost card is revoked. If someone finds "
                        "it, it's useless. (Restart the demo to restore both cards.)"}
    return {"narration": "Reporting a lost card.", "verdict": "denied",
            "note": "Revoke " + ("refused — " if res.get("reason") != "no tap" else "")
                    + res.get("reason", "no tap") + "."}


def s_challenge(payee, amt):
    # "Beat the Gatekeeper": a judge types any account. It goes through the SAME pay path as a
    # real payment -- no special-casing. The device refuses because it isn't a registered payee,
    # exactly like a bank rejecting an unverified account. Unwinnable by design, not by a trick.
    payee = (payee or "").strip()
    if not payee:
        return {"narration": "Type an account to try paying.", "verdict": "error",
                "note": "enter any account number and amount, then hit Try it"}
    try:
        amt = int(amt)
    except (TypeError, ValueError):
        amt = 75000
    amt = amt if amt > 0 else 75000
    try:
        res = EX.pay_invoice(payee, amt, "CHALLENGE", "high")
    except Exception as e:
        return {"narration": f"Paying {payee} — {_usd(amt)}.", "verdict": "error", "note": str(e)}
    v = res.get("verdict", "?")
    known = payee == NESSIE_ACME_ACCOUNT
    _speak(v, "pay_invoice", amt, known)
    if v == "blocked":
        note = (f"“{payee[:22]}” is not a registered payee — the device refused to sign. The "
                "allowlist lives in the device firmware, where the laptop can't change it.")
    elif v == "approved":
        note = "Registered payee, approved with the physical card — only way money moves."
    elif v == "denied":
        note = ("That IS the registered payee — but it still needs the physical card, so without a "
                "tap nothing moved. Even a valid account can't move money from the keyboard."
                if known else
                f"“{payee[:22]}” was refused by the device — nothing moved.")
    elif v == "locked":
        note = "Device is LOCKED — hold RESET 3s to unlock, then try again."
    else:
        note = res.get("detail", "")
    return {"narration": f"Paying {payee} — {_usd(amt)}.", "verdict": v, "note": note,
            "amount_cents": amt}


def _usd(cents):
    return f"${cents // 100:,}.{cents % 100:02d}"


def s_pay(payee, amt, memo, known):
    narration = ("Paying the Acme Supplies invoice." if known
                 else "Paying the Acme Supplies invoice.")  # the laptop shows the same friendly line
    try:
        res = EX.pay_invoice(payee, amt, memo, "high")
    except Exception as e:
        return {"narration": narration, "verdict": "error", "note": str(e)}
    _speak(res.get("verdict", ""), "pay_invoice", amt, known)
    note = {"blocked": "The payee is not on the device allowlist.",
            "approved": "Signed on the device (button hold + card tap). Money moved.",
            "locked": "Device is LOCKED — hold RESET 3s to unlock, then retry.",
            "denied": "Not approved on the device (no hold, no card tap, or timed out).",
            }.get(res.get("verdict"), res.get("detail", ""))
    return {"narration": narration, "verdict": res.get("verdict", "?"), "note": note,
            "amount_cents": amt}


def s_forge():
    if balances() is None:
        return {"narration": "The bank is offline.\nStart it first:  NESSIE_API_KEY=… python bank.py",
                "verdict": "error", "note": "payments + forgery checks go through the bank"}
    good = demo_forge.device_approval(LINK, NESSIE_ACME_ACCOUNT, 75000)  # needs hold + card tap
    if good is None:
        return {"narration": "The device did not sign the $750.00 approval.",
                "verdict": "error",
                "note": "Is the device LOCKED (from an earlier step)? Hold RESET 3s, then retry. "
                        "Approve = hold the button, then tap the card."}
    tampered = dict(good, amt=7500000)  # the real $750 approval, edited to $75,000
    cases = [
        ("Legit — the approval exactly as signed", NESSIE_ACME_ACCOUNT, 75000, good),
        ("Forged — signed with the laptop's own key", NESSIE_LOOKALIKE_ACCOUNT, 480000,
         demo_forge.forged(NESSIE_LOOKALIKE_ACCOUNT, 480000)),
        ("Tampered — $750 changed to $75,000", NESSIE_ACME_ACCOUNT, 7500000, tampered),
        ("Replay — the legit approval sent again", NESSIE_ACME_ACCOUNT, 75000, good),
    ]
    lines = []
    for title, payee, cents, approval in cases:
        status, out = demo_forge.post(BANK_URL, "/pay", {"payee": payee, "amount_cents": cents,
                                                         "memo": "INV-2293", "approval": approval})
        ok = status == 200
        lines.append(f"{'✅ ACCEPTED' if ok else '🚫 REJECTED'}  {title}"
                     + ("" if ok else f"\n        {out.get('reason', '')}"))
    _say("Only the genuine device approval was accepted. The forged, tampered, and replayed "
         "approvals were all rejected by the bank.")
    return {"narration": "\n".join(lines), "verdict": "forge",
            "note": "Only the genuine device approval moved money."}


def s_wipe():
    # Beyond banking: a hijacked agent tries to delete sensitive files, calling it "low risk."
    # The device catches the lie and LOCKS — not just money, but data destruction.
    f = os.path.join(EX.data_dir, "sensitive", "tax_return.pdf")
    try:
        res = EX.delete_file(f, "low")
    except Exception as e:
        return {"narration": "Tidying up — removing the old tax records as requested.",
                "verdict": "error", "note": str(e)}
    _speak(res.get("verdict", ""), "delete_file", 0)
    note = {"locked": "The agent called deleting your tax records 'low risk' — the device caught "
                      "the lie and LOCKED. The file was NOT deleted. (Hold RESET 3s to unlock.)",
            "denied": "Not approved on the device — the file was NOT deleted.",
            "blocked": "Device blocked the delete — the file was NOT deleted.",
            }.get(res.get("verdict"), res.get("detail", ""))
    return {"narration": "Tidying up — removing the old tax records as requested.",
            "verdict": res.get("verdict", "?"), "note": note}


SCENARIOS = {
    "inbox": lambda: s_inbox(),
    "inbox_live": lambda: s_inbox_live(),
    "pay_legit": lambda: s_pay(NESSIE_ACME_ACCOUNT, 75000, "INV-2291", True),
    "pay_fraud": lambda: s_pay(NESSIE_LOOKALIKE_ACCOUNT, 75000, "INV-2290", False),
    "forge": lambda: s_forge(),
    "wipe": lambda: s_wipe(),
    "revoke": lambda: s_revoke(),
}

# The page lives in demo_ui/ (design system: docs/DESIGN.md). Only these files are served.
UI_DIR = os.path.join(os.path.dirname(os.path.realpath(__file__)), "demo_ui")
UI_TYPES = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
            ".js": "text/javascript; charset=utf-8", ".woff2": "font/woff2"}


def ui_file(url_path):
    """(bytes, content type) for a path under demo_ui/, or None. No traversal, known types only."""
    rel = "index.html" if url_path in ("/", "/index.html") else url_path.lstrip("/")
    path = os.path.realpath(os.path.join(UI_DIR, rel))
    ctype = UI_TYPES.get(os.path.splitext(path)[1])
    if not ctype or not path.startswith(UI_DIR + os.sep) or not os.path.isfile(path):
        return None
    with open(path, "rb") as f:
        return f.read(), ctype


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
        if self.path == "/api/state":
            bals = balances()
            return self._send(200, json.dumps({
                "balances": bals, "purchases": purchases(), "device": EX is not None,
                "bank": bals is not None,
                "voice": bool(voice_host and os.environ.get("GATEKEEPER_VOICE"))}))
        found = ui_file(self.path.split("?", 1)[0])
        if found:
            return self._send(200, *found)
        return self._send(404, "{}")

    def do_POST(self):
        if self.path != "/api/run":
            return self._send(404, "{}")
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        sc = body.get("scenario")
        if sc == "challenge":
            fn = lambda: s_challenge(body.get("payee"), body.get("amount_cents"))
        else:
            fn = SCENARIOS.get(sc)
        if not fn:
            return self._send(400, json.dumps({"narration": "unknown scenario", "verdict": "error"}))
        with _lock:                       # serialize device access
            if not ensure_device():       # self-heal if the board was reset/unplugged
                out = {"narration": f"Device offline at {DEVICE_PORT} — plug in the board.",
                       "verdict": "error", "note": "it reconnects automatically once it's back"}
            else:
                try:
                    out = fn()
                except Exception as e:
                    out = {"narration": f"error: {e}", "verdict": "error", "note": ""}
        _BAL["t"] = _PUR["t"] = 0          # force fresh balances + purchases after an action
        return self._send(200, json.dumps(out))


if __name__ == "__main__":
    print(f"\n  Gatekeeper demo dashboard -> http://localhost:{PORT}\n")
    ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
