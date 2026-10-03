"""Wire contract shared by the mock device and the executor: docs/CONTRACT.md (v2).
The ESP32 firmware must produce byte-identical signed messages."""
import hashlib
import json

VERSION = "v2"
ACTIONS = ("send_email", "delete_file", "pay_invoice")
MAX_AMOUNT_CENTS = 100_000_000      # $1,000,000: anything bigger is malformed
CLAIMS = ("low", "medium", "high")
VERDICTS = ("allow", "approved", "denied", "blocked", "locked", "hold")
SIGNED_VERDICTS = ("allow", "approved")
MAX_LINE = 4096


def signed_message(act, to, file, fh, nonce, exp, taint, amt=0, bh="") -> bytes:
    """v2|<act>|<to>|<file>|<fh>|<bh>|<amt>|<nonce>|<exp>|<taint> as UTF-8 bytes.
    bh: body_hash() for send_email, "" otherwise. amt: cents for pay_invoice, 0 otherwise.
    For pay_invoice, to is the payee account id and file/fh are empty."""
    return (f"{VERSION}|{act}|{to}|{file}|{fh}|{bh}|{int(amt)}|{nonce}|{int(exp)}|{int(taint)}"
            .encode("utf-8"))


def body_hash(subject, body):
    """bh for send_email: SHA-256 hex of subject + "\n" + body. Host-side only (the device just
    signs it). body is the text/plain part as delivered: LF line endings, ending in "\n"."""
    return hashlib.sha256(f"{subject}\n{body}".encode("utf-8")).hexdigest()


def encode(obj: dict) -> bytes:
    return (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")


def decode(line) -> dict:
    if isinstance(line, (bytes, bytearray)):
        line = line.decode("utf-8")
    obj = json.loads(line)
    if not isinstance(obj, dict):
        raise ValueError("message is not a JSON object")
    return obj
