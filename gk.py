"""Send a test request through the executor by hand.

  python gk.py pin [--force]                 save / re-pin the device pubkey
  python gk.py inbox                         read the inbox (sets taint if external mail)
  python gk.py send --to boss@ourcompany.com --file data/public/q3_summary.pdf --claim low
  python gk.py delete --file data/public/q3_summary.pdf --claim medium
  python gk.py pay --to <nessie payee id> --amt 25000 [--memo "INV-2290"]   (cents; claim high)
  python gk.py balances                      Nessie ledger balances (needs NESSIE_API_KEY)
  python gk.py run --code 'print(2+2)'       (or --file script.py)

Common flags: --bench (device returns hold instead of prompting),
              --read-inbox (read the inbox first so taint comes from the real path).
"""
import argparse
import json
import sys

import executor
from config import DEVICE_PORT, PUBKEY_PATH


def connect(args):
    link = executor.DeviceLink(DEVICE_PORT)
    vk = executor.load_or_pin(link, PUBKEY_PATH, force=getattr(args, "force", False))
    return link, vk


def main():
    ap = argparse.ArgumentParser(description="Gatekeeper executor CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pin", help="pin the device pubkey")
    p.add_argument("--force", action="store_true", help="replace an existing pin")

    sub.add_parser("inbox", help="print the inbox and the resulting taint")
    sub.add_parser("balances", help="Nessie ledger balances of the demo accounts")

    for name in ("send", "delete", "pay"):
        p = sub.add_parser(name)
        if name == "send":
            p.add_argument("--to", required=True)
            p.add_argument("--file", default="", help="attachment path (optional)")
            p.add_argument("--subject", default="")
            p.add_argument("--body", default="")
        elif name == "pay":
            p.add_argument("--to", required=True, help="payee's Nessie account id")
            p.add_argument("--amt", required=True, type=int, help="amount in cents")
            p.add_argument("--memo", default="")
        else:
            p.add_argument("--file", required=True)
        p.add_argument("--claim", required=name != "pay", default="high",
                       choices=["low", "medium", "high"])
        p.add_argument("--bench", action="store_true")
        p.add_argument("--read-inbox", action="store_true")

    p = sub.add_parser("run", help="run Python in the no-network sandbox")
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--code")
    g.add_argument("--file")

    args = ap.parse_args()

    if args.cmd == "balances":
        import nessie
        try:
            for name, acct, cents in nessie.balances(nessie.Nessie()):
                print(f"{name:28} {nessie.dollars(cents):>14}   {acct}")
        except nessie.NessieError as e:
            sys.exit(f"error: {e}")
        return

    if args.cmd == "run":
        code = args.code if args.code is not None else open(args.file).read()
        print(json.dumps(executor.run_code(code), indent=2))
        return

    try:
        link, vk = connect(args)
    except (executor.DeviceError, executor.PinError) as e:
        sys.exit(f"error: {e}")

    if args.cmd == "pin":
        print(f"pinned {vk.encode().hex()} -> {PUBKEY_PATH}")
        return

    ex = executor.Executor(link, vk, bench=int(getattr(args, "bench", False)))
    if args.cmd == "inbox" or args.read_inbox:
        msgs = ex.read_inbox()
        if args.cmd == "inbox":
            for m in msgs:
                print(f"{m.get('id')}  {m.get('from')}  |  {m.get('subject')}")
        print(f"taint={ex.taint}")
        if args.cmd == "inbox":
            return

    print("waiting for device..." + ("" if args.bench else " (approve/deny on the device)"))
    if args.cmd == "send":
        res = ex.send_email(args.to, args.file, args.claim, args.subject, args.body)
    elif args.cmd == "pay":
        res = ex.pay_invoice(args.to, args.amt, args.memo, args.claim)
    else:
        res = ex.delete_file(args.file, args.claim)
    print(json.dumps(res, indent=2))
    sys.exit(0 if res["ok"] else 1)


if __name__ == "__main__":
    main()
