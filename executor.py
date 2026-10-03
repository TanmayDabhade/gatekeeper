"""Host-side executor: the only code that touches email, files and the sandbox.

Every send_email / delete_file goes to the device first and is carried out only if:
  - the reply matches a nonce we issued and haven't used (no replay),
  - the verdict is allow/approved and the Ed25519 signature verifies under the
    PINNED device key over protocol.signed_message(...),
  - the request hasn't expired,
  - the file still resolves to the same real path with the same SHA-256.
The caller never chooses taint: it comes from what read_inbox has seen.
"""
import email.utils
import hashlib
import json
import os
import re
import secrets
import smtplib
import subprocess
import time
from email.message import EmailMessage

import serial
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

import protocol
from config import (COMPANY_DOMAIN, DATA_DIR, DEVICE_PORT, DEVICE_TIMEOUT_S, DOCKER_IMAGE,
                    INBOX_PATH, PUBKEY_PATH, REQUEST_TTL_S, RUN_CODE_TIMEOUT_S, SENDER,
                    SERIAL_BAUD, SMTP_HOST, SMTP_PORT)

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
MAX_OUTPUT = 8000


class DeviceError(Exception):
    """The device link failed (timeout, garbage, disconnect)."""


class PinError(Exception):
    """The device key doesn't match the pinned key, or is malformed."""


# ---------------------------------------------------------------- device link

class DeviceLink:
    """One JSON line out, one JSON line back. Works for socket:// and real serial."""

    def __init__(self, url=DEVICE_PORT, timeout=DEVICE_TIMEOUT_S):
        try:
            self.port = serial.serial_for_url(url, baudrate=SERIAL_BAUD, timeout=timeout)
        except (serial.SerialException, OSError) as e:
            raise DeviceError(f"cannot open device at {url}: {e}") from e

    def call(self, obj):
        try:
            self.port.reset_input_buffer()     # drop any stale reply from a timed-out call
            self.port.write(protocol.encode(obj))
            line = self.port.readline(protocol.MAX_LINE + 1)
        except (serial.SerialException, OSError) as e:
            raise DeviceError(f"device link error: {e}") from e
        if not line:
            raise DeviceError("no reply from device (timeout)")
        if len(line) > protocol.MAX_LINE or not line.endswith(b"\n"):
            raise DeviceError("reply too long or truncated")
        try:
            return protocol.decode(line)
        except (ValueError, UnicodeDecodeError) as e:
            raise DeviceError(f"unparseable reply: {e}") from e

    def close(self):
        self.port.close()


def load_or_pin(link, path=PUBKEY_PATH, force=False):
    """Return the pinned VerifyKey. First run (or force=True) saves the device's key;
    after that the device must present the same key or we refuse to run."""
    reply = link.call({"t": "pubkey"})
    pk = reply.get("pk") if reply.get("t") == "pubkey" else None
    if not isinstance(pk, str) or not HEX64.fullmatch(pk):
        raise PinError(f"device sent a malformed pubkey: {reply!r}")
    if force or not os.path.exists(path):
        with open(path, "w") as f:
            f.write(pk + "\n")
        return VerifyKey(bytes.fromhex(pk))
    with open(path) as f:
        pinned = f.read().strip()
    if not HEX64.fullmatch(pinned):
        raise PinError(f"pin file {path} is corrupt; re-pin with: python gk.py pin --force")
    if pinned != pk:
        raise PinError(f"device key {pk[:16]}... does not match pinned {pinned[:16]}... "
                       f"If you restarted the mock, re-pin with: python gk.py pin --force")
    return VerifyKey(bytes.fromhex(pinned))


# ---------------------------------------------------------------- helpers

def _result(ok, verdict, detail="", **extra):
    return {"ok": ok, "verdict": verdict, "detail": detail, **extra}


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _smtp_send(msg):
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as s:
        s.send_message(msg)


# ---------------------------------------------------------------- sandbox

def run_code(code, runner=subprocess.run):
    """Run untrusted Python in a throwaway container with no network.
    verdict "ran" means the code actually executed; "error" means the sandbox didn't start."""
    # docker run exits 1 when the daemon is down -- same as failing user code -- so check first.
    try:
        info = runner(["docker", "info", "--format", "{{.ServerVersion}}"],
                      capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return _result(False, "error", "docker not found; install/start Docker")
    except subprocess.TimeoutExpired:
        return _result(False, "error", "docker daemon not responding")
    if info.returncode != 0:
        return _result(False, "error", f"docker daemon not reachable: {info.stderr.strip()[:300]}")

    name = f"gk-run-{secrets.token_hex(4)}"
    cmd = ["docker", "run", "--rm", "-i", "--pull", "never", "--name", name,
           "--network", "none", "--read-only", "--tmpfs", "/tmp:rw,size=16m",
           "--memory", "256m", "--cpus", "1", "--pids-limit", "64",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--user", "65534:65534", DOCKER_IMAGE, "python", "-I", "-"]
    try:
        p = runner(cmd, input=code, capture_output=True, text=True, timeout=RUN_CODE_TIMEOUT_S)
    except FileNotFoundError:
        return _result(False, "error", "docker not found; install/start Docker")
    except subprocess.TimeoutExpired:
        runner(["docker", "kill", name], capture_output=True, text=True, timeout=10)
        return _result(False, "error", f"timeout after {RUN_CODE_TIMEOUT_S}s; container killed")
    if p.returncode in (125, 126, 127):     # docker run's own failures, not the user's code
        return _result(False, "error", f"sandbox failed to start (exit {p.returncode}): "
                                       f"{p.stderr.strip()[:300]} "
                                       f"(first time? run: docker pull {DOCKER_IMAGE})")
    return _result(p.returncode == 0, "ran", f"exit {p.returncode}", exit=p.returncode,
                   stdout=p.stdout[-MAX_OUTPUT:], stderr=p.stderr[-MAX_OUTPUT:])


# ---------------------------------------------------------------- executor

class Executor:
    def __init__(self, link, verify_key, data_dir=DATA_DIR, inbox_path=INBOX_PATH, bench=0,
                 smtp_send=_smtp_send, clock=time.time, company_domain=COMPANY_DOMAIN):
        self.link = link
        self.vk = verify_key
        self.data_dir = os.path.realpath(data_dir)
        self.inbox_path = inbox_path
        self.bench = bench
        self.smtp_send = smtp_send
        self.clock = clock
        self.company_domain = company_domain.lower()
        self._taint = 0
        self._used = set()          # nonces already acted on

    @property
    def taint(self):
        return self._taint

    # ---- tools ----
    def read_inbox(self):
        with open(self.inbox_path) as f:
            msgs = json.load(f)
        for m in msgs:
            addr = email.utils.parseaddr(str(m.get("from", "")))[1].lower()
            if addr.rpartition("@")[2] != self.company_domain:
                self._taint = 1     # sticky for the rest of the session
        return msgs

    def send_email(self, to, file="", claim="high", subject="", body=""):
        if not isinstance(to, str) or not EMAIL_RE.fullmatch(to):
            return _result(False, "rejected", f"bad recipient {to!r}")
        path, fh = "", ""
        if file:
            path, data, err = self._load(file)
            if err:
                return _result(False, "rejected", err)
            fh = _sha256(data)
        res = self._authorize("send_email", to, path, fh, claim)
        if not res["ok"]:
            return res

        msg = EmailMessage()
        msg["From"] = SENDER
        msg["To"] = to
        msg["Subject"] = subject or "Message from your assistant"
        msg.set_content(body or "")
        if path:
            again, data, err = self._load(file)
            if err or again != path or _sha256(data) != fh:
                return _result(False, "refused", "file changed since approval; not sent")
            sub = "pdf" if path.lower().endswith(".pdf") else "octet-stream"
            msg.add_attachment(data, maintype="application", subtype=sub,
                               filename=os.path.basename(path))
        try:
            self.smtp_send(msg)
        except (OSError, smtplib.SMTPException) as e:
            return _result(False, "error", f"approved but SMTP failed: {e}")
        return res

    def delete_file(self, file, claim="high"):
        path, data, err = self._load(file)
        if err:
            return _result(False, "rejected", err)
        fh = _sha256(data)
        res = self._authorize("delete_file", "", path, fh, claim)
        if not res["ok"]:
            return res
        again, data, err = self._load(file)
        if err or again != path or _sha256(data) != fh:
            return _result(False, "refused", "file changed since approval; not deleted")
        os.remove(path)
        return res

    def run_code(self, code):
        return run_code(code)

    # ---- checks ----
    def _load(self, file):
        """Resolve to a real path inside data_dir and read it. Returns (path, bytes, err)."""
        if not isinstance(file, str) or not file:
            return "", b"", "file is required"
        path = os.path.realpath(file)
        if not path.startswith(self.data_dir + os.sep):
            return "", b"", f"{path} is outside {self.data_dir}"
        if not os.path.isfile(path):
            return "", b"", f"{path} is not a regular file"
        with open(path, "rb") as f:
            return path, f.read(), None

    def _authorize(self, act, to, path, fh, claim):
        if claim not in protocol.CLAIMS:
            return _result(False, "rejected", f"claim must be one of {protocol.CLAIMS}")
        nonce = secrets.token_hex(16)
        exp = int(self.clock()) + REQUEST_TTL_S
        taint = self._taint
        req = {"t": "req", "act": act, "to": to, "file": path, "fh": fh, "claim": claim,
               "taint": taint, "nonce": nonce, "exp": exp, "bench": self.bench}
        try:
            res = self.link.call(req)
        except DeviceError as e:
            return _result(False, "error", str(e))

        rn, v, sig = res.get("nonce"), res.get("v"), res.get("sig")
        if res.get("t") != "res" or not isinstance(rn, str):
            return _result(False, "refused", f"bad reply from device: {res!r}")
        if rn in self._used:
            return _result(False, "refused", "replayed device reply (nonce already used)")
        if rn != nonce:
            return _result(False, "refused", "device reply nonce does not match request")
        if v not in protocol.VERDICTS:
            return _result(False, "refused", f"unknown verdict {v!r}")
        if v not in protocol.SIGNED_VERDICTS:
            return _result(False, v, f"device said {v}")

        if not isinstance(sig, str) or not HEX128.fullmatch(sig):
            return _result(False, "refused", "malformed signature")
        msg = protocol.signed_message(act, to, path, fh, nonce, exp, taint)
        try:
            self.vk.verify(msg, bytes.fromhex(sig))
        except BadSignatureError:
            return _result(False, "refused", "bad signature (not from the pinned device)")
        self._used.add(nonce)       # consumed before acting, even if a later check fails
        if self.clock() > exp:
            return _result(False, "refused", "approval expired")
        return _result(True, v, "signed", nonce=nonce)
