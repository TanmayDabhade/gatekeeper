"""Host-side executor: the only code that touches email, files, payments and the sandbox.

Every send_email / delete_file / pay_invoice goes to the device first and is carried out only if:
  - the reply matches a nonce we issued and haven't used (no replay),
  - the verdict is allow/approved and the Ed25519 signature verifies under the
    PINNED device key over protocol.signed_message(...),
  - the request hasn't expired,
  - the file still resolves to the same real path with the same SHA-256.
pay_invoice is signed with v2, which also covers the amount in cents and a hash of the memo,
so a signature for $250 can't move $2,500. Only then does Nessie see the payment.
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
import verifier
from config import (COMPANY_DOMAIN, DATA_DIR, DEVICE_PORT, DEVICE_TIMEOUT_S, DOCKER_IMAGE,
                    INBOX_PATH, NESSIE_COMPANY_ACCOUNT, PUBKEY_PATH, REQUEST_TTL_S,
                    RUN_CODE_TIMEOUT_S, SENDER, SERIAL_BAUD, SMTP_HOST, SMTP_PORT)

HEX64 = re.compile(r"[0-9a-f]{64}")
HEX128 = re.compile(r"[0-9a-f]{128}")
PAYEE_RE = re.compile(r"[A-Za-z0-9-]{1,64}")
MAX_MEMO = 500
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
MAX_OUTPUT = 8000


class DeviceError(Exception):
    """The device link failed (timeout, garbage, disconnect)."""


class PinError(Exception):
    """The device key doesn't match the pinned key, or is malformed."""


# ---------------------------------------------------------------- device link

class DeviceLink:
    """One JSON line out, one JSON line back. Works for socket:// and real serial.

    Real ESP32 quirks: toggling DTR/RTS on open reboots the board, so both are held low
    before the port opens; and the board prints boot/debug text, so any line that isn't a
    JSON object is skipped.
    """

    def __init__(self, url=DEVICE_PORT, timeout=DEVICE_TIMEOUT_S, port=None, settle_s=None):
        self.timeout = timeout
        if port is not None:                # tests inject a fake port
            self.port = port
            return
        try:
            # Open with DTR/RTS deasserted so opening the port doesn't pull the
            # ESP32 into reset (the usbserial auto-reset lines). Harmless/no-op
            # for socket:// and other backends without real control lines.
            self.port = serial.serial_for_url(url, baudrate=SERIAL_BAUD, timeout=timeout,
                                              do_not_open=True, dsrdtr=False)
            for line in ("dtr", "rts"):
                try:
                    setattr(self.port, line, False)
                except (ValueError, AttributeError, OSError):
                    pass
            self.port.open()
            time.sleep(0.3)   # let the usbserial adapter settle before the first write
        except (serial.SerialException, OSError) as e:
            raise DeviceError(f"cannot open device at {url}: {e}") from e
        if settle_s is None:
            settle_s = 0 if url.startswith(("socket://", "loop://")) else 2.0
        if settle_s:
            time.sleep(settle_s)            # in case the board reset anyway: let it boot
            self.port.reset_input_buffer()

    def call(self, obj):
        deadline = time.monotonic() + self.timeout
        try:
            self.port.reset_input_buffer()     # drop any stale reply from a timed-out call
            self.port.write(protocol.encode(obj))
            while True:
                line = self.port.readline(protocol.MAX_LINE + 1)
                if not line:
                    raise DeviceError("no reply from device (timeout)")
                if line.lstrip().startswith(b"{"):
                    break
                if time.monotonic() > deadline:  # endless boot noise counts as a timeout
                    raise DeviceError("no reply from device (only non-JSON output)")
        except (serial.SerialException, OSError) as e:
            raise DeviceError(f"device link error: {e}") from e
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


def _nessie_pay(payee, cents, memo, ref):
    import nessie                   # only needed when a payment is actually signed
    return nessie.Nessie().pay(NESSIE_COMPANY_ACCOUNT, payee, cents, memo, ref)


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
                 smtp_send=_smtp_send, clock=time.time, company_domain=COMPANY_DOMAIN,
                 pay=_nessie_pay):
        self.link = link
        self.vk = verify_key
        self.data_dir = os.path.realpath(data_dir)
        self.inbox_path = inbox_path
        self.bench = bench
        self.smtp_send = smtp_send
        self.pay = pay              # pay(payee, cents, memo, ref) -> Nessie record ids
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
        verifier.add_approval(msg, res["approval"])     # the M9 gateway re-checks it
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

    def pay_invoice(self, payee, amount_cents, memo="", claim="high"):
        """Pay `amount_cents` to a Nessie account, only on a v2 signature over that exact
        payee, amount and memo."""
        if not isinstance(payee, str) or not PAYEE_RE.fullmatch(payee):
            return _result(False, "rejected", f"bad payee account id {payee!r}")
        if type(amount_cents) is not int or not 0 < amount_cents <= protocol.MAX_AMOUNT_CENTS:
            return _result(False, "rejected", "amount_cents must be a positive whole number of "
                                              f"cents up to {protocol.MAX_AMOUNT_CENTS}")
        if not isinstance(memo, str) or len(memo) > MAX_MEMO:
            return _result(False, "rejected", f"memo must be text up to {MAX_MEMO} characters")
        bh = _sha256(memo.encode("utf-8"))
        res = self._authorize("pay_invoice", payee, "", "", claim, amt=amount_cents, bh=bh)
        if not res["ok"]:
            return res
        try:
            res["transfer"] = self.pay(payee, amount_cents, memo, res["nonce"][:12])
        except Exception as e:      # noqa: BLE001 -- any Nessie failure means "not paid"
            return _result(False, "error", f"approved but the payment failed: {e}")
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

    def _authorize(self, act, to, path, fh, claim, amt=0, bh=""):
        if claim not in protocol.CLAIMS:
            return _result(False, "rejected", f"claim must be one of {protocol.CLAIMS}")
        nonce = secrets.token_hex(16)
        exp = int(self.clock()) + REQUEST_TTL_S
        taint = self._taint
        req = {"t": "req", "act": act, "to": to, "file": path, "fh": fh, "claim": claim,
               "taint": taint, "nonce": nonce, "exp": exp, "bench": self.bench}
        if act in protocol.V2_ACTIONS:
            req["amt"], req["bh"] = amt, bh
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
        msg = protocol.signed_message(act, to, path, fh, nonce, exp, taint, amt, bh)
        try:
            self.vk.verify(msg, bytes.fromhex(sig))
        except BadSignatureError:
            return _result(False, "refused", "bad signature (not from the pinned device)")
        self._used.add(nonce)       # consumed before acting, even if a later check fails
        if self.clock() > exp:
            return _result(False, "refused", "approval expired")
        # Everything a separate verifier needs to check the device's signature on its own.
        approval = {"act": act, "to": to, "file": path, "fh": fh, "nonce": nonce, "exp": exp,
                    "taint": taint, "sig": sig}
        if act in protocol.V2_ACTIONS:
            approval |= {"amt": amt, "bh": bh}
        return _result(True, v, "signed", nonce=nonce, approval=approval)
