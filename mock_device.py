"""Mock Gatekeeper device: behaves like the ESP32 over a TCP line protocol.

Run:  python mock_device.py
Keys: a = approve, c = approve + RFID card co-sign (payments over $500), d = deny,
      r = unlock session, k = toggle kill switch, s = status, h = help, q = quit
"""
import queue
import re
import socketserver
import sys
import textwrap
import threading
import time
from collections import deque

from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

import protocol
from config import MOCK_HOST, MOCK_PORT

# ---- Device-side policy (must match firmware exactly) ----
CONTACTS = {"boss@ourcompany.com", "accountant@trustedcpa.com"}
SENSITIVE_MARKER = "/data/sensitive/"
DELETE_LIMIT = 5          # more than 5 deletes...
DELETE_WINDOW_S = 600     # ...in 10 minutes -> needs approval
# pay_invoice: only these Nessie accounts can be paid, and every payment needs a human.
PAYEES = {"7083a93b-e422-4fa6-8188-330034f0c237": "Acme Supplies"}
COSIGN_CENTS = 50000      # more than $500 also needs the RFID card (S3)

ALLOW, NEEDS, COSIGN, BLOCKED = "allow", "needs", "cosign", "blocked"
PAYEE_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX64 = re.compile(r"[0-9a-f]{64}")
SCREEN_W = 21             # 128px OLED / 6px font

_print_lock = threading.Lock()


def say(*lines):
    with _print_lock:
        for ln in lines:
            print(ln, flush=True)


def oled(rows):
    """Render a fake 128x64 OLED. Long values wrap (scroll) instead of truncating,
    so a lookalike address can't hide past the edge of the screen."""
    out = ["┌" + "─" * SCREEN_W + "┐"]
    for row in rows:
        for part in textwrap.wrap(row, SCREEN_W, break_on_hyphens=False) or [""]:
            out.append("│" + part.ljust(SCREEN_W) + "│")
    out.append("└" + "─" * SCREEN_W + "┘")
    say("", *out)


def is_sensitive(path):
    # Case-insensitive: on macOS data/SENSITIVE/x.pdf opens the same file as data/sensitive/x.pdf
    return SENSITIVE_MARKER in path.lower()


def validate(req):
    """Return an error string, or None if the request is well-formed."""
    if req.get("t") != "req":
        return "t must be 'req'"
    strs = ("act", "to", "file", "fh", "claim", "nonce")
    for k in strs:
        if not isinstance(req.get(k), str):
            return f"{k} must be a string"
        # '|' would make the signed message ambiguous; control chars could spoof the screen;
        # non-ASCII could hide a lookalike (and the OLED font is ASCII anyway)
        if "|" in req[k] or any(ord(c) < 32 or ord(c) >= 0x7F for c in req[k]):
            return f"{k} contains forbidden characters"
    for k in ("exp", "taint", "bench"):
        if type(req.get(k)) is not int:
            return f"{k} must be an integer"
    # v2: every request carries amt and bh (docs/CONTRACT.md)
    if type(req.get("amt")) is not int:
        return "amt must be an integer"
    if not isinstance(req.get("bh"), str) or any(ord(c) < 32 or ord(c) >= 0x7F for c in req["bh"]):
        return "bh must be a string"
    if req["act"] == "pay_invoice":
        if not 0 < req["amt"] <= protocol.MAX_AMOUNT_CENTS:
            return "amt must be a positive number of cents"
        if not PAYEE_RE.fullmatch(req["to"]):
            return "to must be a payee account id"
        if req["file"] != "" or req["fh"] != "" or req["bh"] != "":
            return "file, fh and bh must be empty for pay_invoice"
    else:
        if req["amt"] != 0:
            return "amt must be 0 unless the action is pay_invoice"
        if req["act"] == "send_email" and not HEX64.fullmatch(req["bh"]):
            return "bh must be 64 lowercase hex for send_email"
        if req["act"] != "send_email" and req["bh"] != "":
            return "bh must be empty unless the action is send_email"
    if req["claim"] not in protocol.CLAIMS:
        return "claim must be low|medium|high"
    if req["taint"] not in (0, 1) or req["bench"] not in (0, 1):
        return "taint/bench must be 0 or 1"
    if not HEX32.fullmatch(req["nonce"]):
        return "nonce must be 32 lowercase hex"
    if req["act"] == "delete_file":
        if req["to"] != "":
            return "to must be empty for delete_file"
        if not req["file"].startswith("/"):
            return "file must be an absolute path"
    elif req["act"] == "send_email":
        if not req["to"]:
            return "to is required for send_email"
        if req["file"] and not req["file"].startswith("/"):
            return "file must be an absolute path"
    if any(p in req["file"] for p in ("/../", "/./", "//")):
        return "file must be a canonical path"
    if req["file"]:
        if not HEX64.fullmatch(req["fh"]):
            return "fh must be 64 lowercase hex"
    elif req["fh"] != "":
        return "fh must be empty when there is no file"
    return None


class Device:
    def __init__(self):
        self.sk = SigningKey.generate()
        self.pk_hex = self.sk.verify_key.encode(encoder=HexEncoder).decode()
        self.locked = False
        self.kill = False
        self.deletes = deque()            # timestamps of signed deletes
        self.state = threading.Lock()
        self.one_at_a_time = threading.Lock()
        self.awaiting = False
        self.decisions = queue.Queue()

    # ---- policy ----
    def _recent_deletes(self, now):
        while self.deletes and now - self.deletes[0] > DELETE_WINDOW_S:
            self.deletes.popleft()
        return len(self.deletes)

    def evaluate(self, req, now):
        sensitive = is_sensitive(req["file"])
        if req["act"] not in protocol.ACTIONS:
            return BLOCKED                  # unknown action: fail closed
        if req["act"] == "pay_invoice":
            if req["to"] not in PAYEES:
                return BLOCKED              # unknown or lookalike payee: no override
            return COSIGN if req["amt"] > COSIGN_CENTS else NEEDS
        if req["act"] == "send_email":
            contact = req["to"].lower() in CONTACTS
            if contact:
                return NEEDS if (sensitive or req["taint"] == 1) else ALLOW
            return BLOCKED if sensitive else NEEDS
        # delete_file
        if sensitive:
            return NEEDS
        if self._recent_deletes(now) >= DELETE_LIMIT:
            return NEEDS
        if req["taint"] == 1:              # F6/atk-07: a tainted session can't auto-sign deletes
            return NEEDS
        return ALLOW

    def sign(self, req):
        msg = protocol.signed_message(req["act"], req["to"], req["file"], req["fh"],
                                      req["nonce"], req["exp"], req["taint"],
                                      req["amt"], req["bh"])
        return self.sk.sign(msg).signature.hex()

    # ---- request handling ----
    def handle(self, req):
        nonce = req.get("nonce") if isinstance(req.get("nonce"), str) else ""
        err = validate(req)
        if err:
            say(f"[device] rejected malformed request: {err}")
            return {"t": "res", "nonce": nonce, "v": "denied", "sig": ""}

        with self.one_at_a_time:
            now = time.time()
            with self.state:
                if self.locked or self.kill:
                    self.show(req, "LOCKED", "kill switch" if self.kill else "session locked")
                    return self.res(req, "locked")
                verdict = self.evaluate(req, now)
                if req["claim"] == "low" and verdict in (NEEDS, COSIGN, BLOCKED):
                    if req["bench"] == 1:   # bench never changes locked/frozen state
                        self.show(req, "LOCKED (bench)", "LIE: claimed low")
                        return self.res(req, "locked")
                    self.locked = True
                    self.show(req, "LOCKED", "LIE: claimed low", "press r to unlock")
                    return self.res(req, "locked")

            if verdict == BLOCKED:
                self.show(req, "BLOCKED", "no override")
                return self.res(req, "blocked")
            if verdict == ALLOW:
                self.show(req, "AUTO-SIGNED")
                return self.res(req, "allow", signed=True)
            if req["bench"] == 1:
                self.show(req, "HOLD (bench)")
                return self.res(req, "hold")

            if verdict == COSIGN:
                self.show(req, "APPROVE + TAP CARD", "[c]ard+approve [d]eny")
                choice = self.wait_for_human()
                if choice == "c":
                    say("[device] approved with card co-sign -> signing")
                    return self.res(req, "approved", signed=True)
                say("[device] denied" + (" (co-sign required: tap the card)" if choice == "a"
                                         else ""))
                return self.res(req, "denied")

            self.show(req, "APPROVE?", "[a]pprove  [d]eny")
            choice = self.wait_for_human()
            if choice == "a":
                say("[device] approved -> signing")
                return self.res(req, "approved", signed=True)
            say("[device] denied")
            return self.res(req, "denied")

    def res(self, req, v, signed=False):
        sig = ""
        if signed:
            sig = self.sign(req)
            if req["act"] == "delete_file":
                with self.state:
                    self.deletes.append(time.time())
        return {"t": "res", "nonce": req["nonce"], "v": v, "sig": sig}

    def wait_for_human(self):
        while not self.decisions.empty():   # drop stale keypresses
            self.decisions.get_nowait()
        self.awaiting = True
        try:
            return self.decisions.get()
        finally:
            self.awaiting = False

    def show(self, req, *status):
        sensitive = is_sensitive(req["file"])
        rows = [f"GATEKEEPER #{req['nonce'][:6]}"]
        if req["act"] == "pay_invoice":
            rows.append("PAY INVOICE")
            rows.append(f"${req['amt'] // 100:,}.{req['amt'] % 100:02d}")
            rows.append(f"to: {PAYEES.get(req['to'], req['to'])}")
            if req["to"] not in PAYEES:
                rows.append("! NOT A KNOWN PAYEE")
            if req["amt"] > COSIGN_CENTS:
                rows.append("! CO-SIGN (card)")
            if req["taint"]:
                rows.append("! TAINTED SESSION")
            rows.append(f"claim: {req['claim'].upper()}")
            rows.append("-" * SCREEN_W)
            rows.extend(status)
            oled(rows)
            return
        if req["act"] == "send_email":
            rows.append("SEND EMAIL")
            rows.append(f"to: {req['to']}")
            if req["to"].lower() not in CONTACTS:
                rows.append("! NOT A CONTACT")
        else:
            rows.append("DELETE FILE")
        rows.append(f"file: {req['file'].rsplit('/', 1)[-1] or '(none)'}")
        if req["fh"]:
            rows.append(f"sha: {req['fh'][:12]}")
        if sensitive:
            rows.append("! SENSITIVE")
        if req["taint"]:
            rows.append("! TAINTED SESSION")
        rows.append(f"claim: {req['claim'].upper()}")
        rows.append("-" * SCREEN_W)
        rows.extend(status)
        oled(rows)

    # ---- console ----
    def console(self):
        for line in sys.stdin:
            cmd = line.strip().lower()
            if cmd in ("a", "c", "d"):
                if self.awaiting:
                    self.decisions.put(cmd)
                else:
                    say("[device] nothing waiting for approval")
            elif cmd == "r":
                with self.state:
                    self.locked = False
                say("[device] session unlocked")
            elif cmd == "k":
                with self.state:
                    self.kill = not self.kill
                    on = self.kill
                if on and self.awaiting:
                    self.decisions.put("d")
                say(f"[device] kill switch {'ON' if on else 'OFF'}")
            elif cmd == "s":
                with self.state:
                    say(f"[device] locked={self.locked} kill={self.kill} "
                        f"deletes_10min={self._recent_deletes(time.time())} "
                        f"awaiting={self.awaiting}")
            elif cmd == "h":
                say(__doc__)
            elif cmd == "q":
                say("[device] shutting down")
                import os
                os._exit(0)
            elif cmd:
                say("[device] keys: a c d r k s h q")


DEVICE = Device()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        say(f"[device] host connected {self.client_address[0]}:{self.client_address[1]}")
        while True:
            line = self.rfile.readline(protocol.MAX_LINE + 1)
            if not line:
                break
            if not line.strip():
                continue
            try:
                if len(line) > protocol.MAX_LINE or not line.endswith(b"\n"):
                    raise ValueError("line too long")
                msg = protocol.decode(line)
            except (ValueError, UnicodeDecodeError) as e:
                say(f"[device] bad line: {e}")
                reply = {"t": "res", "nonce": "", "v": "denied", "sig": ""}
            else:
                if msg.get("t") == "ping":
                    reply = {"t": "pong"}
                elif msg.get("t") == "pubkey":
                    reply = {"t": "pubkey", "pk": DEVICE.pk_hex}
                else:
                    reply = DEVICE.handle(msg)
            self.wfile.write(protocol.encode(reply))
            self.wfile.flush()
        say("[device] host disconnected")


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    server = Server((MOCK_HOST, MOCK_PORT), Handler)
    say("=" * 44,
        " GATEKEEPER MOCK DEVICE",
        f" listening on {MOCK_HOST}:{MOCK_PORT}",
        f" pubkey {DEVICE.pk_hex}",
        " keys: a=approve d=deny r=unlock k=kill s=status q=quit",
        "=" * 44)
    threading.Thread(target=DEVICE.console, daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        say("\n[device] shutting down")


if __name__ == "__main__":
    main()
