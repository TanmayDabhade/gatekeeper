"""M9 verifier: a mail gateway that checks the device's signature itself, in its own process.

  python verifier.py                 listen on localhost:1026, relay to Mailpit on :1025
  GATEKEEPER_SMTP_PORT=1026 python agent.py ...   send the executor's mail through it

The executor attaches the device's approval to each email as X-Gatekeeper-* headers. The
gateway relays a message only if the signature verifies under the PINNED device key over
protocol.signed_message(...) and the signed fields match what is actually being delivered:
the one envelope recipient, the subject and body (bh), the attachment's name and SHA-256, an
unexpired exp and a nonce
never used before (kept on disk, so a restart doesn't reopen replays). The message must have
exactly the shape the executor sends, so nothing can hide in parts this check doesn't read. So a compromised laptop can't send mail the device didn't sign, even with the
executor's code. In production this runs at the mail provider or bank; here Mailpit stands in,
and only the gateway should be able to reach it. forge.py is the demo.

Contract v2 signs bh, the hash of the subject and body, so the text can't be swapped either.
"""
import argparse
import email
import email.policy
import email.utils
import hashlib
import os
import re
import smtplib
import socketserver
import sys
import threading
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

import protocol
from config import (GATEWAY_HOST, GATEWAY_NONCES, GATEWAY_PORT, PUBKEY_PATH, SMTP_HOST,
                    UPSTREAM_SMTP_PORT)

FIELDS = ("act", "to", "file", "fh", "bh", "amt", "nonce", "exp", "taint", "sig")
HEADER = "X-Gatekeeper-"
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
MAX_MESSAGE = 10 * 1024 * 1024
# Headers that must appear at most once. With two Subjects, this check would hash one and a mail
# client might show the other, so any duplicate is refused outright.
SINGLE = ("Subject", "From", "To", "Cc", "Bcc", "Reply-To", "Sender", "Date", "Message-ID",
          "MIME-Version", "Content-Type", "Content-Transfer-Encoding", "Content-Disposition")


def _duplicate_header(msg):
    """Name of the first header that appears twice in the message or any of its parts, or None."""
    for part in msg.walk():
        seen = [k.lower() for k in part.keys()]
        for name in SINGLE:
            if seen.count(name.lower()) > 1:
                return name
    return None

_print_lock = threading.Lock()


def say(*lines):
    with _print_lock:
        for ln in lines:
            print(ln, flush=True)


# ---------------------------------------------------------------- approval headers

def add_approval(msg, approval):
    """Attach a device approval (the signed fields plus sig) to an EmailMessage."""
    for k in FIELDS:
        msg[HEADER + k.capitalize()] = str(approval[k])


def read_approval(msg):
    """Return (approval dict, error). Ints are parsed; nothing is trusted yet."""
    a = {}
    for k in FIELDS:
        vals = msg.get_all(HEADER + k.capitalize()) or []
        if len(vals) != 1:
            return None, ("no device approval on this message" if not vals
                          else f"duplicate {HEADER}{k.capitalize()} header")
        a[k] = str(vals[0]).strip()
    for k in ("amt", "exp", "taint"):
        if not re.fullmatch(r"-?[0-9]{1,12}", a[k]):
            return None, f"approval {k} is not an integer"
        a[k] = int(a[k])
    return a, None


# ---------------------------------------------------------------- the check

def _attachment(msg, a):
    """Return (attachment part or None, error). The message must have exactly the shape the
    executor sends: one text/plain body, plus one attachment when the approval names a file.
    Anything else (HTML alternatives, nested or inline parts) could carry content a mail client
    shows but this check never looked at, so it's refused outright."""
    def is_body(p):
        return (p.get_content_type() == "text/plain" and not p.is_multipart()
                and p.get_content_disposition() is None and p.get_filename() is None)
    if not a["file"]:
        if not is_body(msg):
            return None, "approval has no attachment, so the message must be plain text only"
        return None, None
    if msg.get_content_type() != "multipart/mixed":
        return None, "approval covers one attachment, but the message isn't text + attachment"
    parts = list(msg.iter_parts())
    if len(parts) != 2 or not is_body(parts[0]):
        return None, "message must be exactly one text/plain body and one attachment"
    att = parts[1]
    if att.is_multipart() or att.get_content_disposition() != "attachment":
        return None, "the second part must be a single attachment"
    return att, None


class NonceStore:
    """Used nonces, saved to disk so restarting the gateway doesn't reopen replays. Each line is
    "<nonce> <exp>"; entries whose approval has expired are dropped, since exp already stops them."""

    def __init__(self, path, clock):
        self.path, self.clock = path, clock
        self.used = {}
        if path and os.path.exists(path):
            with open(path) as f:
                for line in f:
                    nonce, _, exp = line.strip().partition(" ")
                    if exp.lstrip("-").isdigit():
                        self.used[nonce] = int(exp)
        self._prune(rewrite=True)

    def _prune(self, rewrite=False):
        now = self.clock()
        self.used = {n: e for n, e in self.used.items() if e >= now}
        if rewrite and self.path:
            with open(self.path, "w") as f:
                f.writelines(f"{n} {e}\n" for n, e in self.used.items())

    def __contains__(self, nonce):
        return nonce in self.used

    def add(self, nonce, exp):
        """Record a nonce before the message is accepted. Raises OSError if it can't be saved,
        and the caller then refuses the message (fail closed)."""
        if self.path:
            with open(self.path, "a") as f:
                f.write(f"{nonce} {exp}\n")
                f.flush()
                os.fsync(f.fileno())
        self.used[nonce] = exp
        if len(self.used) > 1000:
            self._prune(rewrite=True)


class Verifier:
    """Decides whether one message may be delivered. Keeps its own record of used nonces,
    on disk when `nonce_path` is set (the gateway always sets it)."""

    def __init__(self, verify_key, clock=time.time, nonce_path=None):
        self.vk = verify_key
        self.clock = clock
        self.used = NonceStore(nonce_path, clock)
        self.lock = threading.Lock()

    def check(self, raw, rcpts):
        """Return (ok, reason, nonce). Consumes the nonce only when the message is accepted,
        so failed forgeries can't burn a legitimate approval. A consumed nonce is never given
        back, even if the relay then fails: the upstream may have taken the message anyway."""
        msg = email.message_from_bytes(raw, policy=email.policy.default)
        dup = _duplicate_header(msg)
        if dup:
            return False, f"duplicate {dup} header", None
        a, err = read_approval(msg)
        if err:
            return False, err, None
        if a["act"] != "send_email":
            return False, f"approval is for {a['act']!r}, not send_email", None
        if not HEX128.fullmatch(a["sig"]):
            return False, "malformed signature", None
        signed = protocol.signed_message(a["act"], a["to"], a["file"], a["fh"], a["nonce"],
                                         a["exp"], a["taint"], a["amt"], a["bh"])
        try:
            self.vk.verify(signed, bytes.fromhex(a["sig"]))
        except BadSignatureError:
            return False, "signature does not verify under the pinned device key", None

        # The signature is real. Now it must describe this delivery exactly.
        if [r.lower() for r in rcpts] != [a["to"].lower()]:
            return False, f"approved for {a['to']}, but addressed to {', '.join(rcpts)}", None
        shown = [addr.lower() for _, addr in email.utils.getaddresses(msg.get_all("To", []))]
        if shown != [a["to"].lower()] or msg.get_all("Cc") or msg.get_all("Bcc"):
            return False, f"headers don't match the approved recipient {a['to']}", None
        att, err = _attachment(msg, a)
        if err:
            return False, err, None
        text = (msg if not msg.is_multipart() else next(msg.iter_parts())).get_content()
        if protocol.body_hash(str(msg["Subject"] or ""), text.replace("\r\n", "\n")) != a["bh"]:
            return False, "subject or body is not what the device approved", None
        if att is not None:
            data = att.get_content()
            data = data.encode() if isinstance(data, str) else data
            if hashlib.sha256(data).hexdigest() != a["fh"]:
                return False, "attachment is not the file the device approved (SHA-256 differs)", None
            if (att.get_filename() or "") != os.path.basename(a["file"]):
                return False, "attachment name doesn't match the approved file", None
        if self.clock() > a["exp"]:
            return False, "approval expired", None
        with self.lock:
            if a["nonce"] in self.used:
                return False, "replayed approval (nonce already used)", None
            try:
                self.used.add(a["nonce"], a["exp"])
            except OSError as e:
                return False, f"can't record the nonce, refusing to deliver: {e}", None
        return True, f"device-signed: {os.path.basename(a['file']) or '(no file)'} -> {a['to']}", \
            a["nonce"]


# ---------------------------------------------------------------- minimal SMTP server

class SMTPHandler(socketserver.StreamRequestHandler):
    """Just enough SMTP for smtplib: EHLO/HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT."""

    def reply(self, line):
        self.wfile.write(line.encode() + b"\r\n")
        self.wfile.flush()

    def handle(self):
        self.reply("220 gatekeeper-verifier ESMTP")
        mail_from, rcpts = None, []
        while True:
            line = self.rfile.readline(1024)
            if not line:
                return
            cmd = line.decode("ascii", "replace").strip()
            verb = cmd[:4].upper()
            if verb in ("EHLO", "HELO"):
                self.reply("250 gatekeeper-verifier")
            elif cmd.upper().startswith("MAIL FROM:"):
                mail_from, rcpts = _addr(cmd[10:]), []
                self.reply("250 OK")
            elif cmd.upper().startswith("RCPT TO:"):
                if mail_from is None:
                    self.reply("503 MAIL first")
                    continue
                rcpts.append(_addr(cmd[8:]))
                self.reply("250 OK")
            elif verb == "DATA":
                if not rcpts:
                    self.reply("503 RCPT first")
                    continue
                self.reply("354 end with <CRLF>.<CRLF>")
                raw = self.read_data()
                if raw is None:
                    self.reply("552 message too large")
                else:
                    self.reply(self.server.deliver(mail_from, rcpts, raw))
                mail_from, rcpts = None, []
            elif verb == "RSET":
                mail_from, rcpts = None, []
                self.reply("250 OK")
            elif verb == "NOOP":
                self.reply("250 OK")
            elif verb == "QUIT":
                self.reply("221 bye")
                return
            else:
                self.reply("502 command not implemented")

    def read_data(self):
        lines, size = [], 0
        while True:
            line = self.rfile.readline(65536)
            if not line or line in (b".\r\n", b".\n"):
                break
            size += len(line)
            if size > MAX_MESSAGE:
                return None
            lines.append(line[1:] if line.startswith(b"..") else line)   # dot-unstuffing
        return b"".join(lines)


def _addr(s):
    return email.utils.parseaddr(s.strip().split(" ")[0])[1]


class Gateway(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, verifier, relay):
        super().__init__(addr, SMTPHandler)
        self.verifier = verifier
        self.relay = relay              # relay(mail_from, rcpts, raw); raises OSError on failure

    def deliver(self, mail_from, rcpts, raw):
        ok, reason, _ = self.verifier.check(raw, rcpts)
        if not ok:
            say(f"[gateway] REJECTED  {reason}")
            return f"554 rejected by Gatekeeper verifier: {reason}"
        try:
            self.relay(mail_from, rcpts, raw)
        except (OSError, smtplib.SMTPException) as e:
            say(f"[gateway] verified but relay failed (approval used up; ask the device again): {e}")
            return "451 verified, but the mail server is unreachable; request a new approval"
        say(f"[gateway] DELIVERED {reason}")
        return "250 delivered"


def relay_to(host, port):
    def relay(mail_from, rcpts, raw):
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.sendmail(mail_from, rcpts, raw)
    return relay


def load_key(pubkey_hex=None, path=PUBKEY_PATH):
    if pubkey_hex is None:
        if not os.path.exists(path):
            sys.exit(f"no pinned device key at {path}: run python gk.py pin first")
        with open(path) as f:
            pubkey_hex = f.read().strip()
    if not HEX64.fullmatch(pubkey_hex):
        sys.exit("device key must be 64 lowercase hex characters")
    return VerifyKey(bytes.fromhex(pubkey_hex))


def main():
    ap = argparse.ArgumentParser(description="Gatekeeper mail gateway (M9 verifier)")
    ap.add_argument("--pubkey", help="device pubkey hex (default: the pinned key file)")
    ap.add_argument("--port", type=int, default=GATEWAY_PORT)
    args = ap.parse_args()
    vk = load_key(args.pubkey)
    server = Gateway((GATEWAY_HOST, args.port), Verifier(vk, nonce_path=GATEWAY_NONCES),
                     relay_to(SMTP_HOST,
                                                                         UPSTREAM_SMTP_PORT))
    say("=" * 52,
        " GATEKEEPER VERIFIER (mail gateway)",
        f" listening on {GATEWAY_HOST}:{args.port}, relaying to {SMTP_HOST}:{UPSTREAM_SMTP_PORT}",
        f" trusts device key {vk.encode().hex()[:16]}...",
        "=" * 52)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        say("\n[gateway] shutting down")


if __name__ == "__main__":
    main()
