"""M6: Capital One Nessie sandbox client (stdlib urllib). Only the executor calls pay().

  NESSIE_API_KEY=... python nessie.py balances   ledger balances of the demo accounts
  NESSIE_API_KEY=... python nessie.py setup      create a fresh company / Acme / lookalike set

This Nessie deployment never changes an account's stored balance (transfers, withdrawals and
deposits are recorded but the balance field stays put, and PUT ignores it), and it truncates
amounts to whole dollars. So a payment is a withdrawal from the payer plus a deposit to the
payee, each tagged "[gk <ref> <cents>c]", and balance_cents() is a ledger: the stored balance
plus recorded deposits minus withdrawals, in exact cents. A blocked payment leaves no record,
so the ledger doesn't move.
"""
import datetime
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request

from config import (NESSIE_ACME_ACCOUNT, NESSIE_API_KEY_ENV, NESSIE_BASE_URL,
                    NESSIE_COMPANY_ACCOUNT, NESSIE_LOOKALIKE_ACCOUNT, NESSIE_TIMEOUT_S)

TAG = re.compile(r"^\[gk (\S+) (\d+)c\]")
SYSTEM_CA = "/etc/ssl/cert.pem"


def _tls_context():
    """Python.org builds on macOS ship with no CA certificates until "Install Certificates" is
    run, so HTTPS fails to verify. Fall back to the system bundle; never turn verification off."""
    ctx = ssl.create_default_context()
    if not ctx.cert_store_stats()["x509_ca"] and os.path.exists(SYSTEM_CA):
        ctx.load_verify_locations(SYSTEM_CA)
    return ctx


class NessieError(Exception):
    """Nessie couldn't be reached or refused the request."""


class Nessie:
    def __init__(self, base_url=NESSIE_BASE_URL, api_key=None, opener=urllib.request.urlopen,
                 timeout=NESSIE_TIMEOUT_S):
        self.base = base_url.rstrip("/")
        self.key = os.environ.get(NESSIE_API_KEY_ENV, "") if api_key is None else api_key
        if not self.key:
            raise NessieError(f"no Nessie key: set {NESSIE_API_KEY_ENV}")
        self.opener = opener
        self.timeout = timeout
        self.tls = {"context": _tls_context()} if opener is urllib.request.urlopen else {}

    def _req(self, method, path, body=None):
        url = f"{self.base}{path}?key={self.key}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method,
                                     headers={"Content-Type": "application/json"})
        try:
            with self.opener(req, timeout=self.timeout, **self.tls) as r:
                out = json.loads(r.read() or b"null")
        except urllib.error.HTTPError as e:
            raise NessieError(f"Nessie HTTP {e.code} on {method} {path}: "
                              f"{e.read()[:200].decode('utf-8', 'replace')}") from e
        except (urllib.error.URLError, OSError) as e:
            raise NessieError(f"Nessie unreachable at {self.base}: {e}") from e
        except ValueError as e:
            raise NessieError(f"Nessie sent non-JSON on {method} {path}") from e
        if isinstance(out, str):        # validation errors come back as a bare string
            raise NessieError(f"Nessie refused {method} {path}: {out[:200]}")
        return out

    def account(self, account_id):
        return self._req("GET", f"/accounts/{account_id}")

    def _records(self, account_id, kind):
        out = self._req("GET", f"/accounts/{account_id}/{kind}")
        return out if isinstance(out, list) else []

    def pay(self, payer, payee, cents, memo, ref):
        """Move `cents` from payer to payee. Returns the Nessie record ids."""
        today = datetime.date.today().isoformat()
        rec = {"medium": "balance", "amount": cents // 100, "transaction_date": today,
               "status": "completed", "description": f"[gk {ref} {cents}c] {memo}"[:200]}
        w = self._req("POST", f"/accounts/{payer}/withdrawals", rec)
        d = self._req("POST", f"/accounts/{payee}/deposits", rec)
        return {"withdrawal": w["objectCreated"]["_id"], "deposit": d["objectCreated"]["_id"]}

    def balance_cents(self, account_id):
        """Stored balance plus recorded deposits minus withdrawals, in cents."""
        def cents(r):
            m = TAG.match(str(r.get("description", "")))
            return int(m.group(2)) if m else int(round(float(r.get("amount", 0)) * 100))
        total = int(round(float(self.account(account_id)["balance"]) * 100))
        total += sum(cents(r) for r in self._records(account_id, "deposits"))
        total -= sum(cents(r) for r in self._records(account_id, "withdrawals"))
        return total


def dollars(cents):
    sign = "-" if cents < 0 else ""
    return f"{sign}${abs(cents) // 100:,}.{abs(cents) % 100:02d}"


DEMO = [("OurCompany (payer)", NESSIE_COMPANY_ACCOUNT), ("Acme Supplies", NESSIE_ACME_ACCOUNT),
        ("Acme Supp1ies (lookalike)", NESSIE_LOOKALIKE_ACCOUNT)]


def balances(client):
    return [(name, acct, client.balance_cents(acct)) for name, acct in DEMO]


def setup(client):
    """Create one customer + account per demo party. Prints the env vars to use them."""
    addr = {"street_number": "1", "street_name": "Main St", "city": "Detroit", "state": "MI",
            "zip": "48201"}
    out = []
    for env, first, last, nick, bal in [
            ("NESSIE_COMPANY_ACCOUNT", "OurCompany", "Inc", "OurCompany Payables", 50000),
            ("NESSIE_ACME_ACCOUNT", "Acme", "Supplies", "Acme Supplies", 1000),
            ("NESSIE_LOOKALIKE_ACCOUNT", "Acme", "Supp1ies", "Acme Supp1ies Billing", 0)]:
        c = client._req("POST", "/customers", {"first_name": first, "last_name": last,
                                               "address": addr})
        a = client._req("POST", f"/customers/{c['objectCreated']['_id']}/accounts",
                        {"type": "Checking", "nickname": nick, "rewards": 0, "balance": bal})
        out.append(f"export {env}={a['objectCreated']['_id']}")
    print("\n".join(out))
    print("# also put the new Acme id in mock_device.PAYEES (and the firmware payee list)")


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "balances"
    try:
        client = Nessie()
        if cmd == "setup":
            setup(client)
        elif cmd == "balances":
            for name, acct, c in balances(client):
                print(f"{name:28} {dollars(c):>14}   {acct}")
        else:
            sys.exit("usage: python nessie.py [balances|setup]")
    except NessieError as e:
        sys.exit(f"error: {e}")


if __name__ == "__main__":
    main()
