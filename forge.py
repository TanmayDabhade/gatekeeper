"""M9 demo: a compromised laptop tries to get mail past the verifier without the device.

  python verifier.py          terminal 1: the gateway (needs the pinned key: gk.py pin)
  python forge.py             terminal 2: run the attempts (mock_device.py or the board running)
  python forge.py --offline   everything in-process: no mock, gateway or Mailpit needed

The attacker owns the laptop: it can run any code, read the pinned key, and talk to the device
and the gateway directly. The only thing it can't do is make the device sign something its
policy won't allow. It gets one genuine approval (q3_summary.pdf to the boss, which the device
auto-signs) and an expired one, then tries to stretch them into stealing tax_return.pdf.
Every attempt but the honest control must be rejected by the gateway.
"""
import argparse
import hashlib
import os
import secrets
import smtplib
import sys
import threading
import time
from email.message import EmailMessage

from nacl.signing import SigningKey

import executor
import mock_device
import protocol
import verifier
from config import (DEVICE_PORT, GATEWAY_HOST, GATEWAY_PORT, PUBKEY_PATH, PUBLIC_DIR,
                    SENDER, SENSITIVE_DIR)

Q3 = os.path.realpath(os.path.join(PUBLIC_DIR, "q3_summary.pdf"))
TAX = os.path.realpath(os.path.join(SENSITIVE_DIR, "tax_return.pdf"))
BOSS = "boss@ourcompany.com"
ATTACKER = "records@compliance-archive.io"


def _sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def get_approval(link, path, to, exp):
    """Ask the device to sign one send. Returns the approval, or None if it won't sign."""
    req = {"t": "req", "act": "send_email", "to": to, "file": path, "fh": _sha(path),
           "claim": "low", "taint": 0, "nonce": secrets.token_hex(16), "exp": exp, "bench": 0}
    res = link.call(req)
    if res.get("v") not in protocol.SIGNED_VERDICTS:
        return None
    return {k: req[k] for k in verifier.FIELDS if k != "sig"} | {"sig": res["sig"]}


def self_signed(path, to):
    """What the attacker can sign alone: the right format, the wrong key."""
    a = {"act": "send_email", "to": to, "file": path, "fh": _sha(path),
         "nonce": secrets.token_hex(16), "exp": int(time.time()) + 60, "taint": 0}
    msg = protocol.signed_message(a["act"], a["to"], a["file"], a["fh"], a["nonce"], a["exp"],
                                  a["taint"])
    return a | {"sig": SigningKey.generate().sign(msg).signature.hex()}


def build(to, path, approval=None, name=None):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = SENDER, to, "Requested records"
    msg.set_content("Attached.")
    if approval:
        verifier.add_approval(msg, approval)
    with open(path, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                           filename=name or os.path.basename(path))
    return msg


def attempts(link):
    """(title, rcpts, message, should_deliver). The order matters: the control uses the
    genuine approval once, and the replay after it must fail."""
    good = get_approval(link, Q3, BOSS, int(time.time()) + 60)
    if good is None:
        sys.exit("the device wouldn't auto-sign q3_summary.pdf -> boss (is it locked or frozen?)")
    old = get_approval(link, Q3, BOSS, int(time.time()) - 5)
    edited = dict(good, to=ATTACKER)
    out = [
        ("No device approval at all", [ATTACKER], build(ATTACKER, TAX), False),
        ("Signed with the attacker's own key", [ATTACKER],
         build(ATTACKER, TAX, self_signed(TAX, ATTACKER)), False),
        ("Real approval, recipient swapped to the attacker", [ATTACKER],
         build(ATTACKER, Q3, good), False),
        ("Real approval, extra Bcc to the attacker", [BOSS, ATTACKER], build(BOSS, Q3, good),
         False),
        ("Real approval, tax return renamed q3_summary.pdf", [BOSS],
         build(BOSS, TAX, good, name="q3_summary.pdf"), False),
        ("Real signature, approval edited to the attacker", [ATTACKER],
         build(ATTACKER, Q3, edited), False),
    ]
    if old:
        out.append(("Expired approval", [BOSS], build(BOSS, Q3, old), False))
    out += [
        ("CONTROL: the approval exactly as signed", [BOSS], build(BOSS, Q3, good), True),
        ("Replay of that same approval", [BOSS], build(BOSS, Q3, good), False),
    ]
    return out


def submit(host, port, rcpts, msg):
    """Send straight to the gateway, as malware would. Returns (code, text)."""
    try:
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.send_message(msg, from_addr=SENDER, to_addrs=rcpts)
        return 250, "delivered"
    except smtplib.SMTPResponseException as e:
        return e.smtp_code, e.smtp_error.decode(errors="replace")
    except smtplib.SMTPRecipientsRefused as e:
        return 550, str(e)


def run(link, host, port):
    """Run every attempt and print the result. Returns True if each did what it should."""
    all_ok = True
    for i, (title, rcpts, msg, should) in enumerate(attempts(link), 1):
        code, text = submit(host, port, rcpts, msg)
        delivered = code == 250
        ok = delivered == should
        all_ok &= ok
        mark = "DELIVERED" if delivered else ("RELAY DOWN" if code == 451 else "REJECTED ")
        print(f"{'PASS' if ok else 'FAIL'}  {i}. {title}")
        print(f"        {mark}  {text.replace('rejected by Gatekeeper verifier: ', '')}")
        if code == 451:
            print("        (start Mailpit: the gateway verified it but couldn't relay)")
    return all_ok


def start_offline_gateway():
    """Mock device and gateway in this process; delivered mail goes to a list."""
    mock_device.say = lambda *a: None
    verifier.say = lambda *a: None
    dev = mock_device.Device()
    gw = verifier.Gateway((GATEWAY_HOST, 0), verifier.Verifier(dev.sk.verify_key),
                          relay=lambda *a: None)
    threading.Thread(target=gw.serve_forever, daemon=True).start()

    class Link:
        def call(self, obj):
            return dev.handle(obj)
    return Link(), gw


def main():
    ap = argparse.ArgumentParser(description="Gatekeeper forged-request demo (M9)")
    ap.add_argument("--offline", action="store_true",
                    help="in-process mock device and gateway (no servers needed)")
    ap.add_argument("--port", type=int, default=GATEWAY_PORT, help="gateway port")
    args = ap.parse_args()
    if not (os.path.exists(Q3) and os.path.exists(TAX)):
        sys.exit("demo PDFs missing: run python make_data.py first")
    if args.offline:
        link, gw = start_offline_gateway()
        host, port = gw.server_address
    else:
        try:
            link = executor.DeviceLink(DEVICE_PORT)
            executor.load_or_pin(link, PUBKEY_PATH)   # gateway and device must agree on the key
        except (executor.DeviceError, executor.PinError) as e:
            sys.exit(f"error: {e}")
        host, port = GATEWAY_HOST, args.port
    print(f"Compromised laptop -> gateway {host}:{port}. Goal: get tax_return.pdf to {ATTACKER}\n")
    try:
        ok = run(link, host, port)
    except ConnectionRefusedError:
        sys.exit(f"no gateway on {host}:{port}: start python verifier.py first")
    print("\n" + ("Every forgery was rejected; only the device-signed email got through."
                  if ok else "Something unexpected got through or was blocked; see FAIL above."))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
