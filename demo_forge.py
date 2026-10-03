"""M9 demo: the bank, not the laptop, decides whether a device approval is real.

  NESSIE_API_KEY=... python bank.py   terminal 1 (the bank holds the Nessie key, not the laptop)
  python mock_device.py               terminal 2 (or the board, after F4)
  python demo_forge.py                terminal 3: approve the $750 on the device (hold + card)
  python demo_forge.py --offline      everything in-process, auto-approved; real Nessie if
                                      NESSIE_API_KEY is set, otherwise an in-memory ledger

The laptop gets one genuine device approval: $750.00 to Acme (over $500, so button + card), then:
  1. Legit     the approval exactly as signed            -> bank pays, balances move
  2. Forged    approval signed with the laptop's own key  -> rejected, $0 moves
  3. Tampered  the real approval with amt $750 -> $75,000 -> rejected, $0 moves
  4. Replay    the legit approval sent again              -> rejected, $0 moves
"""
import argparse
import json
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request

from nacl.signing import SigningKey

import bank
import executor
import mock_device
import nessie
import protocol
import verifier
from config import (BANK_HOST, BANK_URL, DEVICE_PORT, NESSIE_ACME_ACCOUNT, NESSIE_COMPANY_ACCOUNT,
                    NESSIE_LOOKALIKE_ACCOUNT, PUBKEY_PATH, REQUEST_TTL_S)

AMOUNT = 75000          # $750.00: over the $500 co-sign line, so it takes the button AND the card


def device_approval(link, payee, cents):
    """Ask the device to sign one payment, as the executor would. None if it won't."""
    req = {"t": "req", "act": "pay_invoice", "to": payee, "file": "", "fh": "", "bh": "",
           "amt": cents, "claim": "high", "taint": 0, "nonce": secrets.token_hex(16),
           "exp": int(time.time()) + REQUEST_TTL_S, "bench": 0}
    res = link.call(req)
    if res.get("v") not in protocol.SIGNED_VERDICTS:
        return None
    return {k: req[k] for k in verifier.FIELDS if k != "sig"} | {"sig": res["sig"], "v": res["v"]}


def forged(payee, cents):
    """What a compromised laptop can make alone: the right format, signed with its own key."""
    a = {"act": "pay_invoice", "to": payee, "file": "", "fh": "", "bh": "", "amt": cents,
         "nonce": secrets.token_hex(16), "exp": int(time.time()) + 60, "taint": 0, "v": "approved"}
    msg = protocol.signed_message(a["act"], a["to"], a["file"], a["fh"], a["nonce"], a["exp"],
                                  a["taint"], a["amt"], a["bh"])
    return a | {"sig": SigningKey.generate().sign(msg).signature.hex()}


def post(url, path, body=None):
    """(status, reply) from the bank. GET when body is None."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url + path, data=data, method="POST" if data else "GET",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")


def balances(url):
    status, out = post(url, "/balances")
    if status != 200:
        sys.exit(f"bank can't read balances: {out.get('reason')}")
    return {b["name"]: b["cents"] for b in out["balances"]}


def run(link, url):
    """Run the four cases. Returns True if only the legit payment moved money."""
    print(f"Ask the device: pay Acme {nessie.dollars(AMOUNT)} "
          "(approve on the device: hold the button and tap the card)")
    good = device_approval(link, NESSIE_ACME_ACCOUNT, AMOUNT)
    if good is None:
        sys.exit("the device didn't sign the payment (denied, locked, or no card tap)")
    tampered = dict(good, amt=AMOUNT * 100)
    cases = [
        ("1. Legit: the approval exactly as signed", NESSIE_ACME_ACCOUNT, AMOUNT, good, True),
        ("2. Forged: signed with the laptop's own key", NESSIE_LOOKALIKE_ACCOUNT, 480000,
         forged(NESSIE_LOOKALIKE_ACCOUNT, 480000), False),
        (f"3. Tampered: amt {nessie.dollars(AMOUNT)} -> {nessie.dollars(AMOUNT * 100)}",
         NESSIE_ACME_ACCOUNT, AMOUNT * 100, tampered, False),
        ("4. Replay: the legit approval again", NESSIE_ACME_ACCOUNT, AMOUNT, good, False),
    ]
    all_ok = True
    print()
    for title, payee, cents, approval, should_pay in cases:
        before = balances(url)
        status, out = post(url, "/pay", {"payee": payee, "amount_cents": cents,
                                         "memo": "INV-2293", "approval": approval})
        after = balances(url)
        moved = {k: after[k] - before[k] for k in after if after[k] != before[k]}
        paid = status == 200
        ok = paid == should_pay and (bool(moved) == should_pay)
        all_ok &= ok
        print(f"{'PASS' if ok else 'FAIL'}  {title}")
        print(f"        {'ACCEPTED' if paid else 'REJECTED'}  {out.get('reason', '')}")
        print("        money moved: " + (", ".join(f"{k} {'+' if v > 0 else ''}{nessie.dollars(v)}"
                                                    for k, v in moved.items()) or "$0"))
    print("\nBalances (Nessie ledger):")
    for name, cents in balances(url).items():
        print(f"  {name:28} {nessie.dollars(cents):>14}")
    return all_ok


class Ledger:
    """In-memory stand-in for Nessie when there's no key (offline demo and tests)."""

    def __init__(self):
        self.cents = {NESSIE_COMPANY_ACCOUNT: 5_000_000, NESSIE_ACME_ACCOUNT: 100_000,
                      NESSIE_LOOKALIKE_ACCOUNT: 0}

    def transfer(self, payee, cents, memo, ref):
        self.cents[NESSIE_COMPANY_ACCOUNT] -= cents
        self.cents[payee] = self.cents.get(payee, 0) + cents
        return {"withdrawal": f"w-{ref}", "deposit": f"d-{ref}"}

    def balances(self):
        return [(name, acct, self.cents.get(acct, 0)) for name, acct in nessie.DEMO]


def start_offline(human="c"):
    """Mock device (auto-approved with `human`) and a bank on a free port, in this process."""
    mock_device.say = bank.say = lambda *a: None
    dev = mock_device.Device()
    dev.wait_for_human = lambda: human
    try:
        client = nessie.Nessie()
        transfer = lambda payee, cents, memo, ref: client.pay(NESSIE_COMPANY_ACCOUNT, payee,
                                                              cents, memo, ref)
        books, label = (lambda: nessie.balances(client)), "real Nessie sandbox"
    except nessie.NessieError:
        ledger = Ledger()
        transfer, books, label = ledger.transfer, ledger.balances, "in-memory ledger (no key)"
    server = bank.serve(bank.Bank(verifier.Verifier(dev.sk.verify_key), transfer, books),
                        host=BANK_HOST, port=0)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()

    class Link:
        def call(self, obj):
            return dev.handle(obj)
    return Link(), f"http://{BANK_HOST}:{server.server_address[1]}", label, server


def main():
    ap = argparse.ArgumentParser(description="Gatekeeper forged-payment demo (M9)")
    ap.add_argument("--offline", action="store_true",
                    help="in-process mock device + bank, auto-approved")
    args = ap.parse_args()
    if args.offline:
        link, url, label, _ = start_offline()
        print(f"(offline: in-process device and bank, {label})\n")
    else:
        try:
            link = executor.DeviceLink(DEVICE_PORT)
            executor.load_or_pin(link, PUBKEY_PATH)     # the bank must trust this same key
        except (executor.DeviceError, executor.PinError) as e:
            sys.exit(f"error: {e}")
        url = BANK_URL
    print("The laptop is assumed hacked: it can forge or edit approvals and talk to the bank "
          "directly.\nIt never holds the device key or the Nessie key.\n")
    try:
        ok = run(link, url)
    except urllib.error.URLError as e:
        sys.exit(f"no bank at {url}: start python bank.py first ({e.reason})")
    print("\n" + ("Only the genuine device approval moved money." if ok
                  else "Something unexpected happened; see FAIL above."))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
