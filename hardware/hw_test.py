#!/usr/bin/env python3
"""Interactive hardware walkthrough for the gatekeeper ESP32.

Sends one request per menu choice and shows the device verdict plus a
signature check, so you can validate the firmware end to end on a real board:
the OLED screens, the RGB LED, the buttons, and on-device Ed25519 signing.

Usage:
    python hardware/hw_test.py [PORT]
Port resolution: argv[1], else $GATEKEEPER_PORT, else /dev/cu.usbserial-0001.
Close any serial monitor first -- only one process can hold the port.

Pairs with the M2 serial fixes in executor.py's DeviceLink (DTR/RTS deasserted
on open, boot-banner lines skipped); without them the link to real hardware is
unreliable.
"""
import os
import sys
import time
import tempfile
import secrets

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import protocol
from executor import DeviceLink, load_or_pin
from nacl.exceptions import BadSignatureError

PORT = (sys.argv[1] if len(sys.argv) > 1
        else os.environ.get("GATEKEEPER_PORT", "/dev/cu.usbserial-0001"))
PIN_PATH = os.path.join(tempfile.gettempdir(), "gk_hw_test_pubkey")

# key -> (act, to, file, claim, what to expect on the device)
SCENARIOS = {
    "1": ("send_email", "boss@ourcompany.com", "", "high",
          "ALLOW  -> green LED, 'ALLOWED', signs instantly (no button)"),
    "2": ("send_email", "vendor@example.com", "", "high",
          "HOLD   -> 'HOLD TO OK'. Hold Approve(13) 2s to sign, Reset(26)=deny, Kill(27)=FROZEN"),
    "3": ("send_email", "attacker@evil.io", "/data/sensitive/tax_return.pdf", "high",
          "BLOCK  -> red LED, 'BLOCKED', no signature"),
    "4": ("send_email", "attacker@evil.io", "/data/sensitive/tax_return.pdf", "low",
          "LOCK   -> red 'LOCKED' (claim 'low' but not allowed = a lie). Hold Reset(26) 3s to clear"),
}


def run(link, vk, key):
    act, to, file, claim, note = SCENARIOS[key]
    print(f"\n>>> {note}")
    nonce, exp = secrets.token_hex(16), int(time.time()) + 120
    req = {"t": "req", "act": act, "to": to, "file": file, "fh": "",
           "claim": claim, "taint": 0, "nonce": nonce, "exp": exp, "bench": 0}
    try:
        res = link.call(req)
    except Exception as e:
        print("    device error:", e)
        return
    v, sig = res.get("v"), res.get("sig")
    print(f"    verdict = {v}")
    if v in protocol.SIGNED_VERDICTS:
        msg = protocol.signed_message(act, to, file, "", nonce, exp, 0)
        try:
            vk.verify(msg, bytes.fromhex(sig))
            print("    signature VERIFIED")
        except BadSignatureError:
            print("    signature FAILED")
    else:
        print("    (no signature issued -- expected for block/lock/deny)")


def main():
    link = DeviceLink(url=PORT, timeout=40)      # 40s: room for a human button hold
    vk = load_or_pin(link, path=PIN_PATH, force=True)
    print(f"connected to {PORT}; device key pinned {vk.encode().hex()[:16]}...\n")
    print("scenarios:")
    for k, (_, _, _, _, note) in SCENARIOS.items():
        print(f"  {k}) {note}")
    print("  q) quit  (tip: run 4 last -- it latches the session into LOCKED)\n")
    try:
        while True:
            c = input("pick 1-4 (q to quit)> ").strip().lower()
            if c == "q":
                break
            if c in SCENARIOS:
                run(link, vk, c)
            else:
                print("  unknown choice")
    finally:
        link.close()
    print("done.")


if __name__ == "__main__":
    main()
