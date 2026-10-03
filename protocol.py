"""Wire contract shared by the mock device and the executor.
The ESP32 firmware must produce byte-identical signed messages."""
import json

VERSION = "v1"
ACTIONS = ("send_email", "delete_file", "pay_invoice")
# pay_invoice is signed with v2, which adds the amount and a hash of the memo. send_email and
# delete_file stay v1 until the firmware moves them at F4 (DECISIONS 2026-10-03 16:30).
V2_ACTIONS = ("pay_invoice",)
MAX_AMOUNT_CENTS = 100_000_000      # $1,000,000: anything bigger is malformed
CLAIMS = ("low", "medium", "high")
VERDICTS = ("allow", "approved", "denied", "blocked", "locked", "hold")
SIGNED_VERDICTS = ("allow", "approved")
MAX_LINE = 4096


def signed_message(act, to, file, fh, nonce, exp, taint, amt=0, bh="") -> bytes:
    """v1|<act>|<to>|<file>|<fh>|<nonce>|<exp>|<taint> as UTF-8 bytes, or for V2_ACTIONS
    v2|<act>|<to>|<file>|<fh>|<amt>|<bh>|<nonce>|<exp>|<taint> (amt in cents, bh = SHA-256 hex
    of the memo). For pay_invoice, to is the payee account id and file/fh are empty."""
    if act in V2_ACTIONS:
        return (f"v2|{act}|{to}|{file}|{fh}|{int(amt)}|{bh}|{nonce}|{int(exp)}|{int(taint)}"
                .encode("utf-8"))
    return f"{VERSION}|{act}|{to}|{file}|{fh}|{nonce}|{int(exp)}|{int(taint)}".encode("utf-8")


def encode(obj: dict) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def decode(line) -> dict:
    if isinstance(line, (bytes, bytearray)):
        line = line.decode("utf-8")
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("message is not a JSON object")
    return obj
