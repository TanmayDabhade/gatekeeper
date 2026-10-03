"""M1 check: exercise every mock policy branch (bench=1, no keypresses needed).

Run against a FRESH mock: python smoke_mock.py
It ends by locking the session on purpose (lie check); press r in the mock after.
"""
import hashlib
import os
import secrets
import sys
import time

import serial
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

import protocol
from config import DEVICE_PORT, PUBLIC_DIR, SENSITIVE_DIR

TAX = os.path.realpath(os.path.join(SENSITIVE_DIR, "tax_return.pdf"))
Q3 = os.path.realpath(os.path.join(PUBLIC_DIR, "q3_summary.pdf"))


def sha(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()


def call(port, obj):
    port.write(protocol.encode(obj))
    line = port.readline()
    if not line:
        sys.exit("no reply from device (timeout)")
    return protocol.decode(line)


def req(act, to, file, claim, taint=0):
    return {"t": "req", "act": act, "to": to, "file": file,
            "fh": sha(file) if file else "", "claim": claim, "taint": taint,
            "nonce": secrets.token_hex(16), "exp": int(time.time()) + 60, "bench": 1}


def main():
    port = serial.serial_for_url(DEVICE_PORT, timeout=5)
    pk = call(port, {"t": "pubkey"})["pk"]
    vk = VerifyKey(bytes.fromhex(pk))
    print(f"device pubkey {pk[:16]}...")

    cases = [
        ("public -> boss", req("send_email", "boss@ourcompany.com", Q3, "low"), "allow"),
        ("public -> boss, tainted", req("send_email", "boss@ourcompany.com", Q3, "medium", 1), "hold"),
        ("tax -> accountant", req("send_email", "accountant@trustedcpa.com", TAX, "high"), "hold"),
        ("tax -> attacker", req("send_email", "records@compliance-archive.io", TAX, "high"), "blocked"),
        ("public -> non-contact", req("send_email", "x9@proton.me", Q3, "medium"), "hold"),
        ("delete sensitive", req("delete_file", "", TAX, "high"), "hold"),
    ]
    cases += [(f"delete public #{i}", req("delete_file", "", Q3, "low"), "allow") for i in range(1, 6)]
    cases += [
        ("delete public #6 (rate)", req("delete_file", "", Q3, "medium"), "hold"),
        ("malformed (pipe in to)", {**req("send_email", "a|b@x.io", Q3, "high")}, "denied"),
        ("LIE: tax -> attacker, low", req("send_email", "records@compliance-archive.io", TAX, "low"), "locked"),
        ("after lock: public -> boss", req("send_email", "boss@ourcompany.com", Q3, "high"), "locked"),
    ]

    failures = 0
    for name, r, want in cases:
        res = call(port, r)
        ok = res["v"] == want and res["nonce"] == r["nonce"]
        if res["v"] in protocol.SIGNED_VERDICTS:
            msg = protocol.signed_message(r["act"], r["to"], r["file"], r["fh"],
                                          r["nonce"], r["exp"], r["taint"])
            try:
                vk.verify(msg, bytes.fromhex(res["sig"]))
            except BadSignatureError:
                ok = False
            tampered = bytearray(msg)
            tampered[-1] ^= 1
            try:
                vk.verify(bytes(tampered), bytes.fromhex(res["sig"]))
                ok = False          # tampered message must NOT verify
            except BadSignatureError:
                pass
        elif res["sig"] != "":
            ok = False              # unsigned verdicts must carry no signature
        failures += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:30} want={want:8} got={res['v']}")

    print(f"\n{len(cases) - failures}/{len(cases)} passed")
    print("Session is now locked by the lie check; press r in the mock to unlock.")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
