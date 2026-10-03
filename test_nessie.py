"""M6 tests: the Nessie client builds the right requests and the ledger balance is exact.

Run: .venv/bin/python -m pytest -q test_nessie.py
No network or Nessie key needed (a fake opener stands in for the API).
"""
import io
import json
import urllib.error

import pytest

import nessie


class FakeNessie:
    """Stands in for urlopen: answers like the sandbox and records what was sent."""

    def __init__(self, balance=50000):
        self.balance = balance
        self.records = {"withdrawals": [], "deposits": []}
        self.sent = []

    def __call__(self, req, timeout=None):
        body = json.loads(req.data) if req.data else None
        self.sent.append((req.get_method(), req.full_url, body))
        path = req.full_url.split("?")[0].split(".com")[1]
        if req.get_method() == "POST":
            kind = path.rsplit("/", 1)[1]
            rec = dict(body, _id=f"{kind[0]}{len(self.records[kind]) + 1}")
            self.records[kind].append(rec)
            out = {"code": 201, "objectCreated": rec}
        elif path.endswith("withdrawals") or path.endswith("deposits"):
            out = self.records[path.rsplit("/", 1)[1]]
        else:
            out = {"_id": "acct", "balance": self.balance}
        return io.BytesIO(json.dumps(out).encode())


def client(fake):
    return nessie.Nessie("https://api.example.com", api_key="k", opener=fake)


def test_pay_records_a_withdrawal_and_a_deposit():
    fake = FakeNessie()
    ids = client(fake).pay("payer", "payee", 25050, "INV-2290", "abc123")
    assert ids == {"withdrawal": "w1", "deposit": "d1"}
    (m1, u1, b1), (m2, u2, b2) = fake.sent
    assert (m1, m2) == ("POST", "POST")
    assert "/accounts/payer/withdrawals?key=k" in u1 and "/accounts/payee/deposits?key=k" in u2
    assert b1 == b2 and b1["amount"] == 250 and b1["status"] == "completed"
    assert b1["description"] == "[gk abc123 25050c] INV-2290"


def test_ledger_balance_is_exact_in_cents():
    fake = FakeNessie(balance=50000)
    c = client(fake)
    assert c.balance_cents("payer") == 5_000_000
    c.pay("payer", "payee", 25050, "x", "r1")
    fake.records["withdrawals"].append({"amount": 3, "description": "untagged"})
    assert c.balance_cents("payer") == 5_000_000 + 25050 - 25050 - 300   # fake shares records


def test_missing_key_is_an_error(monkeypatch):
    monkeypatch.delenv("NESSIE_API_KEY", raising=False)
    with pytest.raises(nessie.NessieError, match="NESSIE_API_KEY"):
        nessie.Nessie("https://x")


def test_validation_string_is_an_error():
    def opener(req, timeout=None):
        return io.BytesIO(json.dumps("1 validation error for DepositCreate").encode())
    with pytest.raises(nessie.NessieError, match="refused"):
        client(opener).pay("a", "b", 100, "", "r")


def test_http_error_is_an_error():
    def opener(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 404, "nf", None, io.BytesIO(b"no account"))
    with pytest.raises(nessie.NessieError, match="404"):
        client(opener).account("nope")


def test_dollars():
    assert nessie.dollars(25050) == "$250.50" and nessie.dollars(-5) == "-$0.05"
