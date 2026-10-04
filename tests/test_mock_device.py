"""The mock must give exactly the verdicts the firmware gives: same CASES as smoke_device.py.

Run: .venv/bin/python -m pytest -q tests/test_mock_device.py
"""
from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

import mock_device
import protocol
import smoke_device


def test_mock_matches_device_contract(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)    # keep the fake OLED quiet
    dev = mock_device.Device()
    vk = VerifyKey(bytes.fromhex(dev.pk_hex))
    failed = [(name, want, res.get("v"))
              for name, r, want in smoke_device.cases() + smoke_device.v2_cases()
              for res in [dev.handle(r)]
              if not smoke_device.check(r, res, want, vk)]
    assert failed == []
    assert not dev.locked                   # bench never changes locked state


def test_real_lie_locks_session(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)
    dev = mock_device.Device()
    r = smoke_device.req("send_email", smoke_device.ATTACKER, smoke_device.TAX, "low", bench=0)
    assert dev.handle(r)["v"] == "locked"
    assert dev.locked
    r = smoke_device.req("send_email", smoke_device.BOSS, smoke_device.Q3, "low", bench=0)
    assert dev.handle(r)["v"] == "locked"


def _pay(dev, amt, human, to=smoke_device.ACME):
    dev.wait_for_human = lambda: human
    return dev.handle(smoke_device.pay(to, amt, bench=0))


def test_payment_up_to_500_needs_one_button(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)
    dev = mock_device.Device()
    assert _pay(dev, 50000, "a")["v"] == "approved"
    assert _pay(dev, 25000, "d")["v"] == "denied"


def test_payment_over_500_needs_the_card_co_sign(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)
    dev = mock_device.Device()
    assert _pay(dev, 50001, "a")["v"] == "denied"        # button alone isn't enough
    res = _pay(dev, 50001, "c")
    assert res["v"] == "approved" and res["sig"]


def test_lookalike_payee_blocked_even_with_card(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)
    dev = mock_device.Device()
    assert _pay(dev, 25000, "c", to=smoke_device.LOOKALIKE)["v"] == "blocked"


def test_payment_signature_covers_the_amount(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)
    dev = mock_device.Device()
    dev.wait_for_human = lambda: "a"
    r = smoke_device.pay(smoke_device.ACME, 25000, bench=0)
    sig = bytes.fromhex(dev.handle(r)["sig"])
    vk = VerifyKey(bytes.fromhex(dev.pk_hex))
    args = (r["act"], r["to"], r["file"], r["fh"], r["nonce"], r["exp"], r["taint"])
    vk.verify(protocol.signed_message(*args, 25000, ""), sig)
    for amt, bh in ((250000, ""), (25000, "0" * 64)):
        try:
            vk.verify(protocol.signed_message(*args, amt, bh), sig)
            raise AssertionError("signature verified for a different amount or memo")
        except BadSignatureError:
            pass
