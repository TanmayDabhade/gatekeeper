"""M9 bank: the party that moves money checks the device's signature itself, in its own process.

  NESSIE_API_KEY=... python bank.py     terminal 1: listen on 127.0.0.1:8099
  python gk.py pay --to <payee> --amt 25000      the executor asks the bank, never Nessie
  python demo_forge.py                  legit / forged / tampered payments against the bank

The executor (on a laptop we assume can be hacked) never holds the Nessie key or the device key.
It can only POST /pay with the payment and the approval it says the device signed. The bank
runs Verifier.verify() with the pinned device key and its own nonce store, and calls Nessie only
if the device really signed this payee and this amount. GET /balances returns the ledger, so the
laptop can show the proof without the key. In production this is the bank; here it's a local
process standing in for it.
"""
import argparse
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import nessie
import verifier
from config import (BANK_HOST, BANK_NONCES, BANK_PORT, NESSIE_ACME_ACCOUNT, NESSIE_ACME_MERCHANT,
                    NESSIE_COMPANY_ACCOUNT)

MAX_BODY = 64 * 1024

_print_lock = threading.Lock()


def say(*lines):
    with _print_lock:
        for ln in lines:
            print(ln, flush=True)


class Bank:
    """Verify, then pay. `transfer(payee, cents, memo, ref)` moves the money (Nessie)."""

    def __init__(self, verify, transfer, balances=lambda: []):
        self.verifier = verify
        self.transfer = transfer
        self.balances = balances

    def pay(self, body):
        """Return (http status, reply dict) for one POST /pay body."""
        try:
            payee, cents = body["payee"], body["amount_cents"]
            memo, approval = body.get("memo", ""), body["approval"]
        except (KeyError, TypeError):
            return 400, {"ok": False, "reason": "need payee, amount_cents and approval"}
        if not isinstance(memo, str):
            return 400, {"ok": False, "reason": "memo must be text"}
        request = {"act": "pay_invoice", "to": payee, "file": "", "fh": "", "bh": "", "amt": cents}
        ok, reason = self.verifier.verify(request, approval)
        if not ok:
            say(f"[bank] REJECTED  {reason}")
            return 403, {"ok": False, "reason": reason}
        try:
            ids = self.transfer(payee, cents, memo, approval["nonce"][:12])
        except Exception as e:      # noqa: BLE001 -- the nonce stays used: never pay twice
            say(f"[bank] verified but the transfer failed: {e}")
            return 502, {"ok": False, "reason": f"verified, but the transfer failed: {e}"}
        say(f"[bank] PAID      {nessie.dollars(cents)} -> {payee}  ({reason})")
        return 200, {"ok": True, "reason": reason, "transfer": ids}


def handler_for(bank):
    class Handler(BaseHTTPRequestHandler):
        def _reply(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            if self.path != "/pay":
                return self._reply(404, {"ok": False, "reason": "unknown endpoint"})
            n = int(self.headers.get("Content-Length") or 0)
            if not 0 < n <= MAX_BODY:
                return self._reply(413, {"ok": False, "reason": "body missing or too large"})
            try:
                body = json.loads(self.rfile.read(n))
            except ValueError:
                return self._reply(400, {"ok": False, "reason": "body is not JSON"})
            self._reply(*bank.pay(body))

        def do_GET(self):
            if self.path != "/balances":
                return self._reply(404, {"ok": False, "reason": "unknown endpoint"})
            try:
                rows = [{"name": n, "account": a, "cents": c} for n, a, c in bank.balances()]
            except nessie.NessieError as e:
                return self._reply(502, {"ok": False, "reason": str(e)})
            self._reply(200, {"ok": True, "balances": rows})

        def log_message(self, *args):      # the [bank] lines are the log
            pass
    return Handler


def serve(bank, host=BANK_HOST, port=BANK_PORT):
    return ThreadingHTTPServer((host, port), handler_for(bank))


def main():
    ap = argparse.ArgumentParser(description="Gatekeeper bank (M9 payment verifier)")
    ap.add_argument("--pubkey", help="device pubkey hex (default: the pinned key file)")
    ap.add_argument("--port", type=int, default=BANK_PORT)
    args = ap.parse_args()
    vk = verifier.load_key(args.pubkey)
    try:
        client = nessie.Nessie()
    except nessie.NessieError as e:
        sys.exit(f"error: {e}")
    def transfer(payee, cents, memo, ref):
        ids = client.pay(NESSIE_COMPANY_ACCOUNT, payee, cents, memo, ref)
        if payee == NESSIE_ACME_ACCOUNT and NESSIE_ACME_MERCHANT:
            try:    # record the vendor payment as a Nessie purchase; best-effort audit trail
                ids["purchase"] = client.record_purchase(NESSIE_COMPANY_ACCOUNT,
                                                         NESSIE_ACME_MERCHANT, cents, memo, ref)
            except nessie.NessieError as e:
                say(f"[bank] paid; purchase-record skipped: {e}")
        return ids

    bank = Bank(verifier.Verifier(vk, nonce_path=BANK_NONCES), transfer,
                lambda: nessie.balances(client))
    server = serve(bank, port=args.port)
    say("=" * 52,
        " GATEKEEPER BANK (payment verifier)",
        f" listening on http://{BANK_HOST}:{args.port}  (POST /pay, GET /balances)",
        f" trusts device key {vk.encode().hex()[:16]}...  pays from {NESSIE_COMPANY_ACCOUNT[:8]}...",
        "=" * 52)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        say("\n[bank] shutting down")


if __name__ == "__main__":
    main()
