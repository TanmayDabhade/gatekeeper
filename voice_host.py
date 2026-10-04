"""Host-side voice: speak the device's verdict through the MacBook speaker.

Tanmay's M7 voice runs on the ESP32 (I2S amp). Without that amp, use this instead -- same
idea (announce the device's verdict + the real amount/payee), played on the MacBook speaker
via ElevenLabs. Set ELEVEN_KEY (and optionally ELEVEN_VOICE_ID) in the environment.

The text is built from what the executor knows it sent and the verdict it got back -- the same
truth the device shows. Used by gk.py when GATEKEEPER_VOICE=1, and callable directly:
  ELEVEN_KEY=... python voice_host.py blocked pay_invoice --amt 75000 --unknown
"""
import os
import ssl
import subprocess
import sys
import tempfile
import urllib.request

try:
    import certifi
    _SSL = ssl.create_default_context(cafile=certifi.where())  # macOS python lacks a CA bundle
except Exception:
    _SSL = None

ELEVEN_KEY = os.environ.get("ELEVEN_KEY") or os.environ.get("ELEVENLABS_API_KEY")
ELEVEN_VOICE_ID = os.environ.get("ELEVEN_VOICE_ID", "21m00Tcm4TlvDq8ikWAM")

LINES = {
    "blocked": "Blocked.",
    "locked": "Session locked. The agent claimed this was low risk.",
    "approved": "Approved and signed.",
    "denied": "Denied. No signature issued.",
    "allow": "Allowed.",
    "hold": "Approval needed on the device.",
}


def _dollars(cents):
    return f"{cents // 100} dollars" + (f" {cents % 100} cents" if cents % 100 else "")


def sentence(verdict, act="", amt=0, payee_known=True):
    s = LINES.get(verdict, verdict + ".")
    if act == "pay_invoice" and amt:
        who = "to Acme Supplies" if payee_known else "to an unknown account"
        if verdict == "blocked":
            s = f"Blocked. Payment of {_dollars(amt)} {who}."
        elif verdict in ("approved", "hold"):
            s = f"{LINES[verdict]} Payment of {_dollars(amt)} {who}."
    return s


def say(text):
    """Speak on the MacBook speaker via ElevenLabs (afplay plays the returned audio)."""
    if not ELEVEN_KEY:
        print("voice: set ELEVEN_KEY and ELEVEN_VOICE_ID to enable ElevenLabs voice",
              file=sys.stderr)
        return
    try:
        req = urllib.request.Request(
            f"https://api.elevenlabs.io/v1/text-to-speech/{ELEVEN_VOICE_ID}",
            data=('{"text":%s,"model_id":"eleven_flash_v2_5"}' % _json(text)).encode(),
            headers={"xi-api-key": ELEVEN_KEY, "Content-Type": "application/json",
                     "Accept": "audio/mpeg"}, method="POST")
        with urllib.request.urlopen(req, timeout=15, context=_SSL) as r:
            mp3 = r.read()
        f = tempfile.NamedTemporaryFile(suffix=".mp3", delete=False)
        f.write(mp3); f.close()
        subprocess.run(["afplay", f.name], check=False)  # afplay = file player, not a TTS voice
    except Exception as e:
        print(f"voice: ElevenLabs failed ({e})", file=sys.stderr)


def _json(s):
    import json
    return json.dumps(s)


def speak_result(cmd, to, amt, res, payee_known=True):
    """Called by gk.py: announce the verdict for the action just sent."""
    verdict = res.get("verdict", "")
    if verdict in ("error", "rejected", "refused"):
        return
    say(sentence(verdict, act={"pay": "pay_invoice"}.get(cmd, cmd), amt=amt or 0,
                 payee_known=payee_known))


if __name__ == "__main__":
    v = sys.argv[1] if len(sys.argv) > 1 else "blocked"
    act = sys.argv[2] if len(sys.argv) > 2 else ""
    amt = 0
    if "--amt" in sys.argv:
        amt = int(sys.argv[sys.argv.index("--amt") + 1])
    known = "--unknown" not in sys.argv
    say(sentence(v, act, amt, known))
