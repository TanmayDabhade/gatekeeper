"""M9 tests: the verifier gateway accepts exactly what the device signed, over real SMTP.

Run: .venv/bin/python -m pytest -q test_verifier.py
No mock server, Mailpit, Docker or key needed (gateway and device run in-process).
"""
import json
import smtplib
import threading
import time

import pytest

import executor
import forge
import mock_device
import protocol
import verifier
from config import GATEWAY_HOST


@pytest.fixture(autouse=True)
def quiet(monkeypatch):
    monkeypatch.setattr(mock_device, "say", lambda *a: None)
    monkeypatch.setattr(verifier, "say", lambda *a: None)


class Link:
    def __init__(self):
        self.dev = mock_device.Device()

    def call(self, obj):
        return self.dev.handle(obj)


@pytest.fixture
def gateway():
    """(device link, Verifier, delivered list, (host, port)) with the gateway on a free port."""
    link = Link()
    v = verifier.Verifier(link.dev.sk.verify_key)
    delivered = []
    gw = verifier.Gateway((GATEWAY_HOST, 0), v, relay=lambda f, r, raw: delivered.append((r, raw)))
    threading.Thread(target=gw.serve_forever, args=(0.05,), daemon=True).start()
    yield link, v, delivered, gw.server_address
    gw.shutdown()
    gw.server_close()


@pytest.fixture
def ex(tmp_path, gateway):
    """A real executor whose mail goes into a list, plus that list."""
    link, v, delivered, addr = gateway
    data = tmp_path / "data"
    (data / "public").mkdir(parents=True)
    (data / "public" / "q3.pdf").write_bytes(b"%PDF public q3")
    (tmp_path / "inbox.json").write_text(json.dumps([]))
    sent = []
    e = executor.Executor(link, link.dev.sk.verify_key, data_dir=str(data),
                          inbox_path=str(tmp_path / "inbox.json"), smtp_send=sent.append)
    return e, sent, str(data / "public" / "q3.pdf")


def good(link, to=forge.BOSS, exp=None):
    return forge.get_approval(link, forge.Q3, to, exp or int(time.time()) + 60)


# ---------------------------------------------------------------- executor -> gateway

@pytest.mark.parametrize("with_file", [True, False])
def test_executor_mail_passes_the_gateway(ex, gateway, with_file):
    e, sent, q3 = ex
    _, v, _, _ = gateway
    res = e.send_email("boss@ourcompany.com", q3 if with_file else "", "low", "Q3", "hi")
    assert res["ok"]
    ok, reason, nonce = v.check(sent[0].as_bytes(), ["boss@ourcompany.com"])
    assert ok, reason
    assert nonce == res["nonce"]


def test_executor_mail_fails_if_sent_anywhere_else(ex, gateway):
    e, sent, q3 = ex
    _, v, _, _ = gateway
    e.send_email("boss@ourcompany.com", q3, "low")
    ok, reason, _ = v.check(sent[0].as_bytes(), [forge.ATTACKER])
    assert not ok and "addressed to" in reason


# ---------------------------------------------------------------- forged-request demo

def test_forge_demo_rejects_every_forgery(gateway, capsys):
    link, _, delivered, (host, port) = gateway
    assert forge.run(link, host, port)
    out = capsys.readouterr().out
    assert "FAIL" not in out
    assert len(delivered) == 1                     # only the control got through
    rcpts, raw = delivered[0]
    assert rcpts == [forge.BOSS] and b"tax_return" not in raw


# ---------------------------------------------------------------- individual checks

def check(v, msg, rcpts):
    return v.check(msg.as_bytes(), rcpts)


def test_rejected_forgery_does_not_burn_the_real_approval(gateway):
    link, v, _, _ = gateway
    a = good(link)
    assert not check(v, forge.build(forge.ATTACKER, forge.Q3, a), [forge.ATTACKER])[0]
    assert check(v, forge.build(forge.BOSS, forge.Q3, a), [forge.BOSS])[0]


def test_recipient_match_ignores_case(gateway):
    link, v, _, _ = gateway
    a = good(link)
    assert check(v, forge.build("Boss@OurCompany.com", forge.Q3, a), ["BOSS@ourcompany.com"])[0]


def test_cc_header_rejected(gateway):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    msg["Cc"] = forge.ATTACKER
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok and "headers" in reason


def test_to_header_must_match(gateway):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    msg.replace_header("To", forge.ATTACKER)
    assert not check(v, msg, [forge.BOSS])[0]


def test_second_attachment_rejected(gateway):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    msg.add_attachment(b"x", maintype="application", subtype="octet-stream", filename="x.bin")
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok and "one attachment" in reason


# Parts a mail client would show but a "count the attachments" check would miss.
def _html_alternative(msg):
    import base64
    with open(forge.TAX, "rb") as f:
        b64 = base64.b64encode(f.read()).decode()
    msg.get_body(("plain",)).add_alternative(f"<pre>{b64}</pre>", subtype="html")


def _nested_related(msg):
    from email.mime.application import MIMEApplication
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    rel = MIMEMultipart("related")
    rel.attach(MIMEText("<p>hi</p>", "html"))
    with open(forge.TAX, "rb") as f:
        rel.attach(MIMEApplication(f.read(), "pdf"))
    msg.attach(rel)


def _inline_extra(msg):
    with open(forge.TAX, "rb") as f:
        msg.add_attachment(f.read(), maintype="application", subtype="pdf",
                           filename="tax_return.pdf", disposition="inline")


@pytest.mark.parametrize("smuggle", [_html_alternative, _nested_related, _inline_extra])
def test_hidden_parts_are_rejected(gateway, smuggle):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    smuggle(msg)
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok, reason


def test_no_file_approval_must_be_plain_text(gateway):
    from email.message import EmailMessage
    link, v, _, _ = gateway
    req = {"t": "req", "act": "send_email", "to": forge.BOSS, "file": "", "fh": "",
           "claim": "low", "taint": 0, "nonce": "ab" * 16, "exp": int(time.time()) + 60,
           "bench": 0, "amt": 0, "bh": protocol.body_hash("", "status: fine\n")}
    a = {k: req[k] for k in verifier.FIELDS if k != "sig"} | {"sig": link.call(req)["sig"]}
    def text(html=False):
        msg = EmailMessage()
        msg["To"] = forge.BOSS
        verifier.add_approval(msg, a)
        msg.set_content("status: fine")
        if html:
            msg.add_alternative("<p>status: fine</p>", subtype="html")
        return msg
    ok, reason, _ = check(v, text(html=True), [forge.BOSS])
    assert not ok and "plain text" in reason
    assert check(v, text(), [forge.BOSS])[0]       # the rejection didn't use up the approval


def test_replay_after_gateway_restart_rejected(gateway, tmp_path):
    link, _, _, _ = gateway
    path = str(tmp_path / "nonces")
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    assert verifier.Verifier(link.dev.sk.verify_key, nonce_path=path).check(
        msg.as_bytes(), [forge.BOSS])[0]
    restarted = verifier.Verifier(link.dev.sk.verify_key, nonce_path=path)
    ok, reason, _ = restarted.check(msg.as_bytes(), [forge.BOSS])
    assert not ok and "replayed" in reason


def test_expired_nonces_are_pruned_on_start(gateway, tmp_path):
    link, _, _, _ = gateway
    path = tmp_path / "nonces"
    live = int(time.time()) + 60
    path.write_text(f"{'aa' * 16} {int(time.time()) - 10}\n{'bb' * 16} {live}\n")
    v = verifier.Verifier(link.dev.sk.verify_key, nonce_path=str(path))
    assert path.read_text() == f"{'bb' * 16} {live}\n"
    assert "bb" * 16 in v.used and "aa" * 16 not in v.used


def test_unwritable_nonce_store_fails_closed(gateway, tmp_path):
    link, _, _, _ = gateway
    v = verifier.Verifier(link.dev.sk.verify_key, nonce_path=str(tmp_path / "nonces"))
    v.used.path = str(tmp_path / "missing-dir" / "nonces")
    ok, reason, _ = check(v, forge.build(forge.BOSS, forge.Q3, good(link)), [forge.BOSS])
    assert not ok and "can't record the nonce" in reason


def test_renamed_attachment_rejected(gateway):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link), name="invoice.pdf")
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok and "name" in reason


@pytest.mark.parametrize("field, value, why", [
    ("Sig", "zz", "malformed signature"),
    ("Exp", "soon", "not an integer"),
    ("Act", "delete_file", "not send_email"),
])
def test_malformed_approval_rejected(gateway, field, value, why):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    msg.replace_header(verifier.HEADER + field, value)
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok and why in reason


def test_duplicate_approval_header_rejected(gateway):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link))
    msg[verifier.HEADER + "To"] = forge.ATTACKER
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok and "duplicate" in reason


def test_gateway_trusts_only_its_pinned_key(gateway):
    link, _, _, _ = gateway
    other = verifier.Verifier(mock_device.Device().sk.verify_key)    # a different device
    ok, reason, _ = check(other, forge.build(forge.BOSS, forge.Q3, good(link)), [forge.BOSS])
    assert not ok and "pinned device key" in reason


# ---------------------------------------------------------------- SMTP plumbing

def test_relay_failure_is_451_and_the_approval_stays_used(gateway):
    link, v, _, _ = gateway
    def down(*a):
        raise OSError("connection refused")
    gw = verifier.Gateway((GATEWAY_HOST, 0), v, relay=down)
    threading.Thread(target=gw.serve_forever, args=(0.05,), daemon=True).start()
    try:
        msg = forge.build(forge.BOSS, forge.Q3, good(link))
        assert forge.submit(*gw.server_address, [forge.BOSS], msg)[0] == 451
        # Never given back: the upstream might have taken the message before failing.
        ok, reason, _ = check(v, msg, [forge.BOSS])
        assert not ok and "replayed" in reason
    finally:
        gw.shutdown()
        gw.server_close()


def test_dot_stuffed_body_survives(gateway):
    link, _, delivered, (host, port) = gateway
    body = ".leading dot\n..two dots\n"
    a = forge.get_approval(link, forge.Q3, forge.BOSS, int(time.time()) + 60, body=body)
    msg = forge.build(forge.BOSS, forge.Q3, a, body=body)
    assert forge.submit(host, port, [forge.BOSS], msg)[0] == 250
    assert b"\n.leading dot" in delivered[0][1] and b"\n..two dots" in delivered[0][1]


def test_smtp_command_order_enforced(gateway):
    _, _, _, (host, port) = gateway
    with smtplib.SMTP(host, port, timeout=5) as s:
        assert s.docmd("DATA")[0] == 503
        assert s.docmd("RCPT TO:<a@b.co>")[0] == 503
        assert s.docmd("VRFY root")[0] == 502
        assert s.docmd("RSET")[0] == 250


@pytest.mark.parametrize("field, value", [("Subject", "Wire $9,000 today"), ("body", "new text\n")])
def test_changed_subject_or_body_rejected(gateway, field, value):
    link, v, _, _ = gateway
    msg = forge.build(forge.BOSS, forge.Q3, good(link),
                      body=value if field == "body" else forge.BODY)
    if field == "Subject":
        msg.replace_header("Subject", value)
    ok, reason, _ = check(v, msg, [forge.BOSS])
    assert not ok and "subject or body" in reason


@pytest.mark.parametrize("anchor, extra", [
    (b"Subject: Requested records\n", b"Subject: Wire $9,000 today\n"),   # top level
    (b"To: boss@ourcompany.com\n", b"To: records@compliance-archive.io\n"),
    (b"Content-Type: text/plain", b"Content-Type: text/html\n"),           # inside a part
    (b"Content-Transfer-Encoding: 7bit", b"Content-Transfer-Encoding: base64\n"),
])
def test_duplicate_headers_rejected(gateway, anchor, extra):
    link, v, _, _ = gateway
    raw = forge.build(forge.BOSS, forge.Q3, good(link)).as_bytes()
    i = raw.index(anchor)
    raw = raw[:i] + extra + raw[i:]
    ok, reason, _ = v.check(raw, [forge.BOSS])
    assert not ok and "duplicate" in reason


# ---------------------------------------------------------------- M9 bank: verify(request, approval)

import bank
import demo_forge
from config import NESSIE_ACME_ACCOUNT as ACME_ID, NESSIE_LOOKALIKE_ACCOUNT as EVIL_ID


def pay_approval(link, cents=25000, payee=ACME_ID):
    link.dev.wait_for_human = lambda: "c" if cents > 50000 else "a"     # card over $500
    a = demo_forge.device_approval(link, payee, cents)
    assert a is not None, "device didn't sign"
    return a


def pay_request(cents=25000, payee=ACME_ID):
    return {"act": "pay_invoice", "to": payee, "file": "", "fh": "", "bh": "", "amt": cents}


def test_verify_accepts_a_genuine_approval(gateway):
    link, v, _, _ = gateway
    ok, reason = v.verify(pay_request(), pay_approval(link))
    assert ok, reason


def test_verify_rejects_another_key(gateway):
    link, _, _, _ = gateway
    other = verifier.Verifier(mock_device.Device().sk.verify_key)
    ok, reason = other.verify(pay_request(), pay_approval(link))
    assert not ok and "pinned device key" in reason


def test_verify_rejects_a_forgery(gateway):
    _, v, _, _ = gateway
    ok, reason = v.verify(pay_request(480000, EVIL_ID), demo_forge.forged(EVIL_ID, 480000))
    assert not ok and "signature" in reason


@pytest.mark.parametrize("field, value", [("amt", 2500000), ("to", EVIL_ID), ("bh", "0" * 64),
                                          ("taint", 1), ("exp", 9999999999)])
def test_verify_rejects_a_tampered_approval(gateway, field, value):
    link, v, _, _ = gateway
    a = dict(pay_approval(link), **{field: value})
    req = dict(pay_request(), **({field: value} if field in ("amt", "to", "bh") else {}))
    ok, reason = v.verify(req, a)
    assert not ok and "signature" in reason


@pytest.mark.parametrize("field, value", [("amt", 2500000), ("to", EVIL_ID)])
def test_verify_rejects_an_action_that_differs_from_the_approval(gateway, field, value):
    link, v, _, _ = gateway
    ok, reason = v.verify(dict(pay_request(), **{field: value}), pay_approval(link))
    assert not ok and f"device signed {field}=" in reason


def test_verify_rejects_a_replay(gateway):
    link, v, _, _ = gateway
    a = pay_approval(link)
    assert v.verify(pay_request(), a)[0]
    ok, reason = v.verify(pay_request(), a)
    assert not ok and "replayed" in reason


def test_verify_rejects_an_expired_approval(gateway):
    link, _, _, _ = gateway
    a = pay_approval(link)
    later = verifier.Verifier(link.dev.sk.verify_key, clock=lambda: a["exp"] + 1)
    ok, reason = later.verify(pay_request(), a)
    assert not ok and "expired" in reason


@pytest.mark.parametrize("v_", [None, "hold", "denied", "blocked"])
def test_verify_rejects_a_non_signing_verdict(gateway, v_):
    link, v, _, _ = gateway
    ok, reason = v.verify(pay_request(), dict(pay_approval(link), v=v_))
    assert not ok and "verdict" in reason


@pytest.mark.parametrize("approval", [{}, None, {"sig": "x"}])
def test_verify_rejects_garbage(gateway, approval):
    _, v, _, _ = gateway
    assert not v.verify(pay_request(), approval)[0]


def test_failed_forgeries_do_not_burn_the_real_approval(gateway):
    link, v, _, _ = gateway
    a = pay_approval(link)
    assert not v.verify(pay_request(2500000), dict(a, amt=2500000))[0]
    assert v.verify(pay_request(), a)[0]


# ---------------------------------------------------------------- bank over HTTP

def test_demo_moves_money_only_for_the_genuine_approval(capsys):
    link, url, label, server = demo_forge.start_offline()
    try:
        if "real Nessie" in label:
            pytest.skip("NESSIE_API_KEY is set; this test must not touch the sandbox")
        assert demo_forge.run(link, url)
        assert "FAIL" not in capsys.readouterr().out
        books = demo_forge.balances(url)
        assert books["Acme Supplies"] == 100_000 + demo_forge.AMOUNT    # moved exactly once
        assert books["Acme Supp1ies (lookalike)"] == 0
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def live_bank(gateway, monkeypatch):
    """A bank on a free port with an in-memory ledger; the executor's BANK_URL points at it."""
    link, _, _, _ = gateway
    ledger = demo_forge.Ledger()
    monkeypatch.setattr(bank, "say", lambda *a: None)
    server = bank.serve(bank.Bank(verifier.Verifier(link.dev.sk.verify_key), ledger.transfer,
                                  ledger.balances), port=0)
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    monkeypatch.setattr(executor, "BANK_URL", f"http://{GATEWAY_HOST}:{server.server_address[1]}")
    yield link, ledger
    server.shutdown()
    server.server_close()


def test_executor_pays_only_through_the_bank(live_bank, tmp_path):
    link, ledger = live_bank
    link.dev.wait_for_human = lambda: "a"
    (tmp_path / "inbox.json").write_text("[]")
    ex = executor.Executor(link, link.dev.sk.verify_key, data_dir=str(tmp_path),
                           inbox_path=str(tmp_path / "inbox.json"))    # default pay = the bank
    res = ex.pay_invoice(ACME_ID, 25000, "INV-2290")
    assert res["ok"] and ledger.cents[ACME_ID] == 100_000 + 25000


def test_bank_refusal_reaches_the_executor(live_bank):
    link, ledger = live_bank
    with pytest.raises(executor.BankRefused, match="403.*signature"):
        executor._bank_pay(EVIL_ID, 480000, "", demo_forge.forged(EVIL_ID, 480000))
    assert ledger.cents[EVIL_ID] == 0


def test_bank_never_pays_twice_when_the_transfer_fails(gateway):
    link, v, _, _ = gateway
    calls = []
    def flaky(*a):
        calls.append(a)
        raise OSError("Nessie down")
    b = bank.Bank(v, flaky)
    body = {"payee": ACME_ID, "amount_cents": 25000, "approval": pay_approval(link)}
    assert b.pay(body)[0] == 502
    status, out = b.pay(body)
    assert status == 403 and "replayed" in out["reason"] and len(calls) == 1


@pytest.mark.parametrize("body", [{}, {"payee": ACME_ID}, {"payee": ACME_ID, "amount_cents": 1,
                                                             "approval": {}, "memo": 5}])
def test_bank_rejects_malformed_bodies(gateway, body):
    _, v, _, _ = gateway
    status, _ = bank.Bank(v, lambda *a: pytest.fail("paid")).pay(body)
    assert status in (400, 403)
