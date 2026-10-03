"""M2 unit tests: every executor check, against an in-process fake device.

Run: .venv/bin/python -m pytest -q test_executor.py
No mock, Mailpit or Docker needed.
"""
import hashlib
import json
import os
import subprocess

import pytest
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

import executor
import protocol


# ---------------------------------------------------------------- fixtures

class FakeDevice:
    """Speaks the wire contract. `decide(req)` returns a verdict; the reply is
    signed for allow/approved unless a test overrides `reply`."""

    def __init__(self):
        self.sk = SigningKey.generate()
        self.pk_hex = self.sk.verify_key.encode(encoder=HexEncoder).decode()
        self.requests = []
        self.decide = lambda req: "allow"
        self.reply = None           # optional hook: reply(req, default_res) -> res
        self.on_request = None      # optional hook run before replying

    def sign(self, req, sk=None):
        msg = protocol.signed_message(req["act"], req["to"], req["file"], req["fh"],
                                      req["nonce"], req["exp"], req["taint"],
                                      req["amt"], req["bh"])
        return (sk or self.sk).sign(msg).signature.hex()

    def call(self, obj):
        if obj.get("t") == "pubkey":
            return {"t": "pubkey", "pk": self.pk_hex}
        self.requests.append(obj)
        if self.on_request:
            self.on_request(obj)
        v = self.decide(obj)
        sig = self.sign(obj) if v in protocol.SIGNED_VERDICTS else ""
        res = {"t": "res", "nonce": obj["nonce"], "v": v, "sig": sig}
        return self.reply(obj, res) if self.reply else res


@pytest.fixture
def env(tmp_path):
    data = tmp_path / "data"
    (data / "public").mkdir(parents=True)
    (data / "sensitive").mkdir()
    (data / "public" / "q3.pdf").write_bytes(b"%PDF public q3")
    (data / "sensitive" / "tax.pdf").write_bytes(b"%PDF secret tax")
    inbox = tmp_path / "inbox.json"
    inbox.write_text(json.dumps([
        {"id": "1", "from": "Dana <boss@ourcompany.com>", "subject": "hi", "body": "x"},
    ]))
    dev = FakeDevice()
    sent, paid = [], []
    def pay(payee, cents, memo, ref):
        paid.append((payee, cents, memo, ref))
        return {"withdrawal": "w1", "deposit": "d1"}
    ex = executor.Executor(dev, dev.sk.verify_key, data_dir=str(data),
                           inbox_path=str(inbox), smtp_send=sent.append, pay=pay)
    return {"tmp": tmp_path, "data": data, "inbox": inbox, "dev": dev, "sent": sent, "ex": ex,
            "paid": paid,
            "q3": str(data / "public" / "q3.pdf"), "tax": str(data / "sensitive" / "tax.pdf")}


# ---------------------------------------------------------------- pinning

def test_pin_first_run_saves_key(env, tmp_path):
    pin = tmp_path / "pk"
    vk = executor.load_or_pin(env["dev"], str(pin))
    assert pin.read_text().strip() == env["dev"].pk_hex
    assert vk == env["dev"].sk.verify_key


def test_pin_mismatch_refuses(env, tmp_path):
    pin = tmp_path / "pk"
    pin.write_text(SigningKey.generate().verify_key.encode(encoder=HexEncoder).decode())
    with pytest.raises(executor.PinError):
        executor.load_or_pin(env["dev"], str(pin))


def test_pin_force_repins(env, tmp_path):
    pin = tmp_path / "pk"
    pin.write_text("00" * 32)
    executor.load_or_pin(env["dev"], str(pin), force=True)
    assert pin.read_text().strip() == env["dev"].pk_hex


def test_pin_rejects_garbage_device_key(env, tmp_path):
    env["dev"].pk_hex = "zz"
    with pytest.raises(executor.PinError):
        executor.load_or_pin(env["dev"], str(tmp_path / "pk"))


# ---------------------------------------------------------------- happy paths

def test_send_allowed_attaches_exact_bytes(env):
    r = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    assert r["ok"] and r["verdict"] == "allow"
    req = env["dev"].requests[0]
    assert req["file"] == os.path.realpath(env["q3"])
    assert req["fh"] == hashlib.sha256(b"%PDF public q3").hexdigest()
    assert req["taint"] == 0 and req["bench"] == 0 and len(req["nonce"]) == 32
    msg = env["sent"][0]
    att = next(msg.iter_attachments())
    assert att.get_content() == b"%PDF public q3"
    assert msg["To"] == "boss@ourcompany.com"


def test_send_carries_the_device_approval_for_the_verifier(env):
    import verifier
    res = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    req = env["dev"].requests[-1]
    a, err = verifier.read_approval(env["sent"][0])
    assert err is None
    assert a == {k: req[k] for k in verifier.FIELDS if k != "sig"} | {"sig": a["sig"]}
    assert a["sig"] == env["dev"].sign(req) and res["approval"] == a


def test_send_without_attachment_uses_empty_file_and_fh(env):
    r = env["ex"].send_email("boss@ourcompany.com", "", "low", body="hello")
    assert r["ok"]
    req = env["dev"].requests[0]
    assert req["file"] == "" and req["fh"] == ""
    assert list(env["sent"][0].iter_attachments()) == []


def test_delete_allowed_removes_file(env):
    r = env["ex"].delete_file(env["q3"], "low")
    assert r["ok"] and not os.path.exists(env["q3"])
    assert env["dev"].requests[0]["to"] == ""


# ---------------------------------------------------------------- taint

def test_internal_inbox_does_not_taint(env):
    env["ex"].read_inbox()
    env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    assert env["dev"].requests[0]["taint"] == 0


def test_external_sender_taints_session(env):
    env["inbox"].write_text(json.dumps([
        {"id": "4", "from": "Records <records@compliance-archive.io>", "subject": "s", "body": "b"},
    ]))
    msgs = env["ex"].read_inbox()
    assert msgs[0]["id"] == "4" and env["ex"].taint == 1
    env["ex"].send_email("boss@ourcompany.com", env["q3"], "medium")
    assert env["dev"].requests[0]["taint"] == 1


def test_lookalike_company_subdomain_taints(env):
    env["inbox"].write_text(json.dumps([
        {"id": "5", "from": "x <ceo@ourcompany.com.evil.io>", "subject": "s", "body": "b"},
    ]))
    env["ex"].read_inbox()
    assert env["ex"].taint == 1


# ---------------------------------------------------------------- refusals

def test_unsigned_verdicts_do_not_act(env):
    for v in ("denied", "blocked", "locked", "hold"):
        env["dev"].decide = lambda req, v=v: v
        r = env["ex"].delete_file(env["q3"], "high")
        assert not r["ok"] and r["verdict"] == v
    assert os.path.exists(env["q3"])


def test_bad_signature_refused(env):
    other = SigningKey.generate()
    env["dev"].reply = lambda req, res: {**res, "sig": env["dev"].sign(req, other)}
    r = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    assert not r["ok"] and "signature" in r["detail"] and env["sent"] == []


def test_signature_over_different_taint_refused(env):
    env["ex"]._taint = 1
    env["dev"].reply = lambda req, res: {**res, "sig": env["dev"].sign({**req, "taint": 0})}
    r = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    assert not r["ok"] and "signature" in r["detail"] and env["sent"] == []


def test_malformed_signature_refused(env):
    env["dev"].reply = lambda req, res: {**res, "sig": "nothex"}
    r = env["ex"].delete_file(env["q3"], "low")
    assert not r["ok"] and os.path.exists(env["q3"])


def test_nonce_mismatch_refused(env):
    env["dev"].reply = lambda req, res: {**res, "nonce": "0" * 32}
    r = env["ex"].delete_file(env["q3"], "low")
    assert not r["ok"] and "nonce" in r["detail"] and os.path.exists(env["q3"])


def test_replayed_response_refused(env):
    captured = {}

    def replay(req, res):
        if "first" not in captured:
            captured["first"] = res
            return res
        return captured["first"]
    env["dev"].reply = replay
    assert env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")["ok"]
    r = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    assert not r["ok"] and "replay" in r["detail"] and len(env["sent"]) == 1


def test_expired_approval_refused(env):
    now = [1_000_000.0]
    env["ex"].clock = lambda: now[0]
    env["dev"].on_request = lambda req: now.__setitem__(0, req["exp"] + 1)
    r = env["ex"].delete_file(env["q3"], "low")
    assert not r["ok"] and "expired" in r["detail"] and os.path.exists(env["q3"])


def test_file_changed_after_approval_not_sent(env):
    def swap(req):
        with open(env["q3"], "wb") as f:
            f.write(b"%PDF swapped")
    env["dev"].on_request = swap
    r = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low")
    assert not r["ok"] and "changed" in r["detail"] and env["sent"] == []


def test_file_changed_after_approval_not_deleted(env):
    env["dev"].on_request = lambda req: open(env["q3"], "ab").write(b"x")
    r = env["ex"].delete_file(env["q3"], "low")
    assert not r["ok"] and os.path.exists(env["q3"])


def test_device_error_refused(env):
    def boom(req):
        raise executor.DeviceError("no reply from device")
    env["dev"].on_request = boom
    r = env["ex"].delete_file(env["q3"], "low")
    assert not r["ok"] and os.path.exists(env["q3"])


def test_bad_reply_shape_refused(env):
    env["dev"].reply = lambda req, res: {**res, "v": "yes please"}
    r = env["ex"].delete_file(env["q3"], "low")
    assert not r["ok"] and os.path.exists(env["q3"])


# ---------------------------------------------------------------- local validation

def test_path_outside_data_dir_rejected_before_device(env):
    outside = env["tmp"] / "outside.pdf"
    outside.write_bytes(b"x")
    r = env["ex"].send_email("boss@ourcompany.com", str(outside), "low")
    assert not r["ok"] and env["dev"].requests == []


def test_symlink_escape_rejected(env):
    outside = env["tmp"] / "outside.pdf"
    outside.write_bytes(b"x")
    link = env["data"] / "public" / "innocent.pdf"
    link.symlink_to(outside)
    r = env["ex"].delete_file(str(link), "low")
    assert not r["ok"] and env["dev"].requests == [] and outside.exists()


def test_symlink_to_sensitive_resolves_to_real_path(env):
    link = env["data"] / "public" / "notes.pdf"
    link.symlink_to(env["tax"])
    env["ex"].send_email("accountant@trustedcpa.com", str(link), "high")
    assert "/data/sensitive/" in env["dev"].requests[0]["file"]


def test_dotdot_path_resolved(env):
    sneaky = os.path.join(str(env["data"]), "public", "..", "sensitive", "tax.pdf")
    env["ex"].send_email("accountant@trustedcpa.com", sneaky, "high")
    assert env["dev"].requests[0]["file"] == os.path.realpath(env["tax"])


def test_missing_file_rejected(env):
    r = env["ex"].delete_file(str(env["data"] / "public" / "nope.pdf"), "low")
    assert not r["ok"] and env["dev"].requests == []


def test_directory_rejected(env):
    r = env["ex"].delete_file(str(env["data"] / "public"), "low")
    assert not r["ok"] and env["dev"].requests == []


@pytest.mark.parametrize("to", ["a|b@x.io", "boss@ourcompany.com\n", " boss@ourcompany.com",
                                "boss", "", "a@b@c.io", "boss@ourcompany.com,x@evil.io"])
def test_bad_recipient_rejected(env, to):
    r = env["ex"].send_email(to, env["q3"], "low")
    assert not r["ok"] and env["dev"].requests == []


def test_bad_claim_rejected(env):
    r = env["ex"].delete_file(env["q3"], "none")
    assert not r["ok"] and env["dev"].requests == []


def test_bench_flag_forwarded(env):
    env["ex"].bench = 1
    env["ex"].delete_file(env["q3"], "low")
    assert env["dev"].requests[0]["bench"] == 1


# ---------------------------------------------------------------- run_code

def fake_docker(run_result=None, info_rc=0, calls=None):
    """Stand-in for subprocess.run: answers `docker info`, then `docker run`."""
    calls = [] if calls is None else calls

    def runner(cmd, **kw):
        calls.append((cmd, kw))
        if cmd[1] == "info":
            return subprocess.CompletedProcess(cmd, info_rc, "27.0\n" if info_rc == 0 else "",
                                               "" if info_rc == 0 else "daemon not running")
        if cmd[1] == "run":
            if isinstance(run_result, Exception):
                raise run_result
            return run_result
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return runner


def run_call(calls):
    return next((cmd, kw) for cmd, kw in calls if cmd[1] == "run")


def test_run_code_uses_isolated_docker():
    calls = []
    ok = subprocess.CompletedProcess([], 0, stdout="4\n", stderr="")
    r = executor.run_code("print(2+2)", runner=fake_docker(ok, calls=calls))
    cmd, kw = run_call(calls)
    assert r["ok"] and r["verdict"] == "ran" and r["stdout"] == "4\n"
    assert cmd[:3] == ["docker", "run", "--rm"]
    assert cmd[cmd.index("--pull") + 1] == "never"   # a pull must not eat the run timeout
    i = cmd.index("--network")
    assert cmd[i + 1] == "none"
    for flag in ("--read-only", "--cap-drop", "--pids-limit", "--memory", "--user"):
        assert flag in cmd
    assert kw["input"] == "print(2+2)" and kw["timeout"] > 0


def test_run_code_user_error_is_ran_not_error():
    bad = subprocess.CompletedProcess([], 1, stdout="", stderr="Traceback ... OSError")
    r = executor.run_code("raise OSError", runner=fake_docker(bad))
    assert not r["ok"] and r["verdict"] == "ran" and r["exit"] == 1


def test_run_code_daemon_down_is_error_and_never_runs():
    calls = []
    r = executor.run_code("print(1)", runner=fake_docker(info_rc=1, calls=calls))
    assert not r["ok"] and r["verdict"] == "error" and "daemon" in r["detail"]
    assert all(cmd[1] != "run" for cmd, _ in calls)


@pytest.mark.parametrize("rc", [125, 126, 127])
def test_run_code_container_start_failure_is_error(rc):
    fail = subprocess.CompletedProcess([], rc, stdout="", stderr="Unable to find image")
    r = executor.run_code("print(1)", runner=fake_docker(fail))
    assert not r["ok"] and r["verdict"] == "error" and "sandbox" in r["detail"]


def test_run_code_timeout_kills_container():
    calls = []
    r = executor.run_code("while True: pass",
                          runner=fake_docker(subprocess.TimeoutExpired("docker", 20), calls=calls))
    assert not r["ok"] and "timeout" in r["detail"]
    cmd, _ = run_call(calls)
    name = cmd[cmd.index("--name") + 1]
    assert calls[-1][0] == ["docker", "kill", name]


def test_run_code_without_docker():
    def runner(cmd, **kw):
        raise FileNotFoundError("docker")
    r = executor.run_code("print(1)", runner=runner)
    assert not r["ok"] and r["verdict"] == "error" and "docker" in r["detail"]


# ---------------------------------------------------------------- device link (real-board quirks)

class FakePort:
    """Stands in for a pyserial port: replays scripted lines, records writes."""

    def __init__(self, lines):
        self.lines = list(lines)
        self.written = []

    def reset_input_buffer(self):
        pass

    def write(self, data):
        self.written.append(data)

    def readline(self, size=-1):
        return self.lines.pop(0) if self.lines else b""     # b"" = timeout


def test_link_skips_boot_noise_before_json():
    port = FakePort([b"ets Jun  8 2016 00:22:57\r\n", b"rst:0x1 (POWERON_RESET)\r\n", b"\r\n",
                     b'{"t":"pong"}\r\n'])
    link = executor.DeviceLink(port=port, timeout=5)
    assert link.call({"t": "ping"}) == {"t": "pong"}
    assert port.written == [b'{"t":"ping"}\n']


def test_link_only_noise_is_timeout():
    link = executor.DeviceLink(port=FakePort([b"boot noise\r\n"]), timeout=5)
    with pytest.raises(executor.DeviceError, match="timeout"):
        link.call({"t": "ping"})


def test_link_truncated_json_refused():
    link = executor.DeviceLink(port=FakePort([b'{"t":"po']), timeout=5)
    with pytest.raises(executor.DeviceError, match="truncated"):
        link.call({"t": "ping"})


def test_link_opens_with_dtr_rts_low(monkeypatch):
    seen = {}

    class Port:
        dtr = rts = None

        def open(self):
            seen["dtr"], seen["rts"] = self.dtr, self.rts

        def reset_input_buffer(self):
            pass

    monkeypatch.setattr(executor.serial, "serial_for_url",
                        lambda url, **kw: (seen.update(kw), Port())[1])
    executor.DeviceLink("/dev/cu.usbserial-0001", settle_s=0)
    assert seen["dtr"] is False and seen["rts"] is False   # set BEFORE open: no reboot
    assert seen["do_not_open"] is True


# ---------------------------------------------------------------- payments (v2)

ACME = "7083a93b-e422-4fa6-8188-330034f0c237"


def test_pay_signed_moves_exact_amount(env):
    res = env["ex"].pay_invoice(ACME, 25000, "INV-2290")
    req = env["dev"].requests[-1]
    assert (req["act"], req["to"], req["file"], req["fh"], req["amt"]) == \
        ("pay_invoice", ACME, "", "", 25000)
    assert req["bh"] == ""                  # CONTRACT: bh is only for send_email
    assert res["ok"] and res["transfer"] == {"withdrawal": "w1", "deposit": "d1"}
    assert env["paid"] == [(ACME, 25000, "INV-2290", res["nonce"][:12])]
    assert res["approval"]["amt"] == 25000 and res["approval"]["bh"] == req["bh"]


@pytest.mark.parametrize("field, value", [("amt", 2500000), ("bh", "0" * 64), ("to", "evil")])
def test_pay_signature_over_other_values_refused(env, field, value):
    env["dev"].reply = lambda req, res: dict(res, sig=env["dev"].sign(dict(req, **{field: value})))
    res = env["ex"].pay_invoice(ACME, 25000, "INV-2290")
    assert (res["ok"], res["verdict"]) == (False, "refused")
    assert env["paid"] == []


@pytest.mark.parametrize("verdict", ["blocked", "hold", "denied", "locked"])
def test_pay_unsigned_verdict_moves_nothing(env, verdict):
    env["dev"].decide = lambda req: verdict
    res = env["ex"].pay_invoice(ACME, 25000)
    assert (res["ok"], res["verdict"]) == (False, verdict)
    assert env["paid"] == []


def test_pay_v1_signature_refused(env):
    """A retired v1-style signature (no amount) must not authorize a payment."""
    def v1(req, res):
        msg = f"v1|{req['act']}|{req['to']}|||{req['nonce']}|{req['exp']}|{req['taint']}".encode()
        return dict(res, sig=env["dev"].sk.sign(msg).signature.hex())
    env["dev"].reply = v1
    assert not env["ex"].pay_invoice(ACME, 25000)["ok"]
    assert env["paid"] == []


@pytest.mark.parametrize("payee, amt, memo, why", [
    ("acme supplies", 25000, "", "payee"),
    ("a" * 65, 25000, "", "payee"),
    (ACME, 0, "", "amount_cents"),
    (ACME, -5, "", "amount_cents"),
    (ACME, 250.0, "", "amount_cents"),
    (ACME, True, "", "amount_cents"),
    (ACME, 100_000_001, "", "amount_cents"),
    (ACME, 25000, "x" * 501, "memo"),
])
def test_pay_bad_input_rejected_before_device(env, payee, amt, memo, why):
    res = env["ex"].pay_invoice(payee, amt, memo)
    assert res["verdict"] == "rejected" and why in res["detail"]
    assert env["dev"].requests == []


def test_pay_nessie_failure_is_error_not_success(env):
    def down(*a):
        raise OSError("Nessie unreachable")
    env["ex"].pay = down
    res = env["ex"].pay_invoice(ACME, 25000)
    assert (res["ok"], res["verdict"]) == (False, "error") and "unreachable" in res["detail"]


def test_send_signs_the_subject_and_body_hash(env):
    env["ex"].send_email("boss@ourcompany.com", env["q3"], "low", "Q3", "Here it is")
    req = env["dev"].requests[-1]
    assert (req["amt"], req["bh"]) == (0, protocol.body_hash("Q3", "Here it is\n"))
    assert env["sent"][0].get_body(("plain",)).get_content() == "Here it is\n"


def test_signature_over_a_different_body_refused(env):
    env["dev"].reply = lambda req, res: dict(res, sig=env["dev"].sign(dict(req, bh="0" * 64)))
    res = env["ex"].send_email("boss@ourcompany.com", env["q3"], "low", "Q3", "hi")
    assert (res["ok"], res["verdict"]) == (False, "refused") and env["sent"] == []


def test_delete_carries_empty_bh_and_zero_amt(env):
    env["ex"].delete_file(env["q3"], "low")
    req = env["dev"].requests[-1]
    assert (req["amt"], req["bh"]) == (0, "")


def test_signed_message_is_contract_v2():
    assert protocol.signed_message("pay_invoice", "p", "", "", "n", 5, 0, 25000, "") == \
        b"v2|pay_invoice|p||||25000|n|5|0"
    assert protocol.signed_message("send_email", "a@b.co", "/f", "fh", "n", 5, 1, 0, "bh") == \
        b"v2|send_email|a@b.co|/f|fh|bh|0|n|5|1"
