"""Contract + policy check for the mock AND the real board (bench=1, no button presses).

  python smoke_device.py                                        # mock (start mock_device.py first)
  GATEKEEPER_PORT=/dev/cu.usbserial-0001 python smoke_device.py   # real ESP32
  python smoke_device.py --v2                                   # also the v2 payment cases
                                                                # (board: only after F4)

Needs a FRESH device: restart the mock / press EN on the board (the delete-rate cases
assume no deletes in the last 10 minutes, and a locked/frozen device answers "locked").
Bench mode never changes locked/frozen state, so the device is still usable afterwards.
test_mock_device.py runs the same CASES against the mock in-process.
"""
import hashlib
import os
import secrets
import sys
import time

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

import executor
import protocol
from config import DEVICE_PORT, PUBLIC_DIR, SENSITIVE_DIR

TAX = os.path.realpath(os.path.join(SENSITIVE_DIR, "tax_return.pdf"))
Q3 = os.path.realpath(os.path.join(PUBLIC_DIR, "q3_summary.pdf"))
# Same file on macOS (case-insensitive), different spelling: must still count as sensitive.
TAX_UPPER = TAX.replace("/data/sensitive/", "/data/SENSITIVE/")
BOSS, CPA, ATTACKER = "boss@ourcompany.com", "accountant@trustedcpa.com", "records@compliance-archive.io"


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def req(act, to, file, claim, taint=0, fh=None, **over):
    r = {"t": "req", "act": act, "to": to, "file": file,
         "fh": (sha(TAX if file == TAX_UPPER else file) if file else "") if fh is None else fh,
         "claim": claim, "taint": taint, "nonce": secrets.token_hex(16),
         "exp": int(time.time()) + 60, "bench": 1}
    r.update(over)
    return r


def cases():
    """(name, request, expected verdict). Order matters: the delete-rate cases run last."""
    no_taint = req("send_email", BOSS, Q3, "low")
    del no_taint["taint"]
    out = [
        ("public -> boss", req("send_email", BOSS, Q3, "low"), "allow"),
        ("public -> BOSS (case)", req("send_email", "Boss@OurCompany.com", Q3, "low"), "allow"),
        ("no attachment -> boss", req("send_email", BOSS, "", "low"), "allow"),
        ("public -> boss, tainted", req("send_email", BOSS, Q3, "medium", 1), "hold"),
        ("tax -> accountant", req("send_email", CPA, TAX, "high"), "hold"),
        ("tax -> attacker", req("send_email", ATTACKER, TAX, "high"), "blocked"),
        ("TAX path case -> attacker", req("send_email", ATTACKER, TAX_UPPER, "high"), "blocked"),
        ("TAX path case -> boss", req("send_email", BOSS, TAX_UPPER, "medium"), "hold"),
        ("public -> non-contact", req("send_email", "x9@proton.me", Q3, "medium"), "hold"),
        ("unknown action", req("wire_money", BOSS, "", "high"), "blocked"),
        ("delete sensitive", req("delete_file", "", TAX, "high"), "hold"),
        ("delete public, tainted", req("delete_file", "", Q3, "high", 1), "hold"),
        # malformed -> denied, never signed
        ("pipe in to", req("send_email", "a|b@x.io", Q3, "high"), "denied"),
        ("newline in to", req("send_email", "boss@ourcompany.com\nx", Q3, "high"), "denied"),
        ("non-ASCII to", req("send_email", "boss@ourcompаny.com", Q3, "high"), "denied"),
        ("missing taint", no_taint, "denied"),
        ("taint = 2", req("send_email", BOSS, Q3, "low", 2), "denied"),
        ("bad claim", req("send_email", BOSS, Q3, "LOW"), "denied"),
        ("short nonce", req("send_email", BOSS, Q3, "high", nonce="abc"), "denied"),
        ("dotdot path", req("send_email", BOSS, Q3.replace("/public/", "/public/../sensitive/../public/"),
                            "high", fh=sha(Q3)), "denied"),
        ("fh without file", req("send_email", BOSS, "", "high", fh="0" * 64), "denied"),
        ("to on delete", req("delete_file", BOSS, Q3, "high"), "denied"),
        ("unknown t", {"t": "bogus"}, "denied"),
        # lie check: locks a real session, but bench never changes state
        ("LIE: tax -> attacker, low", req("send_email", ATTACKER, TAX, "low"), "locked"),
        ("after bench lie: still open", req("send_email", BOSS, Q3, "low"), "allow"),
    ]
    out += [(f"delete public #{i}", req("delete_file", "", Q3, "low"), "allow") for i in range(1, 6)]
    out += [("delete public #6 (rate)", req("delete_file", "", Q3, "medium"), "hold")]
    return out


ACME, LOOKALIKE = "7083a93b-e422-4fa6-8188-330034f0c237", "4babab8f-537e-444a-9801-a3463689b686"
MEMO_HASH = hashlib.sha256(b"INV-2290").hexdigest()


def pay(to, amt, claim="high", taint=0, **over):
    r = req("pay_invoice", to, "", claim, taint, amt=amt, bh=MEMO_HASH)
    r.update(over)
    return r


def v2_cases():
    """pay_invoice (contract v2). The board passes these only once F4 lands v2."""
    return [
        ("pay Acme $250", pay(ACME, 25000), "hold"),          # every payment needs a human
        ("pay Acme $500.00 (no co-sign)", pay(ACME, 50000), "hold"),
        ("pay Acme $500.01 (co-sign)", pay(ACME, 50001), "hold"),
        ("pay Acme, tainted", pay(ACME, 25000, taint=1), "hold"),
        ("pay lookalike payee", pay(LOOKALIKE, 25000), "blocked"),
        ("pay lookalike, big amount", pay(LOOKALIKE, 900000), "blocked"),
        ("LIE: pay Acme, low", pay(ACME, 25000, "low"), "locked"),
        ("LIE: pay lookalike, low", pay(LOOKALIKE, 25000, "low"), "locked"),
        # malformed -> denied, never signed
        ("pay amt 0", pay(ACME, 0), "denied"),
        ("pay amt as string", pay(ACME, "25000"), "denied"),
        ("pay amt over $1M", pay(ACME, 100_000_001), "denied"),
        ("pay bh short", pay(ACME, 25000, bh="abc"), "denied"),
        ("pay with a file", pay(ACME, 25000, file=Q3, fh=sha(Q3)), "denied"),
        ("pay payee with spaces", pay("acme supplies", 25000), "denied"),
        ("pay missing bh", {k: v for k, v in pay(ACME, 25000).items() if k != "bh"}, "denied"),
        ("send with amt", req("send_email", BOSS, Q3, "low", amt=100), "denied"),
    ]


def check(r, res, want, vk):
    """True if the reply is exactly what the contract requires for this case."""
    if res.get("t") != "res" or res.get("v") != want or res.get("nonce") != r.get("nonce", ""):
        return False
    if want not in protocol.SIGNED_VERDICTS:
        return res.get("sig") == ""          # unsigned verdicts must carry no signature
    msg = protocol.signed_message(r["act"], r["to"], r["file"], r["fh"],
                                  r["nonce"], r["exp"], r["taint"], r.get("amt", 0),
                                  r.get("bh", ""))
    try:
        vk.verify(msg, bytes.fromhex(res["sig"]))
    except (BadSignatureError, ValueError):
        return False
    tampered = bytearray(msg)
    tampered[-1] ^= 1
    try:
        vk.verify(bytes(tampered), bytes.fromhex(res["sig"]))
        return False                        # tampered message must NOT verify
    except BadSignatureError:
        return True


def main():
    link = executor.DeviceLink(DEVICE_PORT, timeout=10)
    if link.call({"t": "ping"}) != {"t": "pong"}:
        sys.exit("ping failed")
    pk = link.call({"t": "pubkey"})["pk"]
    vk = VerifyKey(bytes.fromhex(pk))
    print(f"device {DEVICE_PORT}  pubkey {pk[:16]}...")

    all_cases = cases() + (v2_cases() if "--v2" in sys.argv else [])
    failures = 0
    for name, r, want in all_cases:
        res = link.call(r)
        ok = check(r, res, want, vk)
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:30} want={want:8} got={res.get('v')}")
    total = len(all_cases)
    print(f"\n{total - failures}/{total} passed")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
