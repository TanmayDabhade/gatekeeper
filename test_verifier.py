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
