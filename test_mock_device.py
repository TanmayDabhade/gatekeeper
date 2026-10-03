"""The mock must give exactly the verdicts the firmware gives: same CASES as smoke_device.py.

Run: .venv/bin/python -m pytest -q test_mock_device.py
"""
from nacl.signing import VerifyKey

import mock_device
import smoke_device


def test_mock_matches_device_contract(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)    # keep the fake OLED quiet
    dev = mock_device.Device()
    vk = VerifyKey(bytes.fromhex(dev.pk_hex))
    failed = [(name, want, res.get("v"))
              for name, r, want in smoke_device.cases()
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
