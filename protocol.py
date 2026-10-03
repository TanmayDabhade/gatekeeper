"""Wire contract shared by the mock device and the executor.
The ESP32 firmware must produce byte-identical signed messages."""
import json

VERSION = "v1"
ACTIONS = ("send_email", "delete_file")
CLAIMS = ("low", "medium", "high")
VERDICTS = ("allow", "approved", "denied", "blocked", "locked", "hold")
SIGNED_VERDICTS = ("allow", "approved")
MAX_LINE = 4096


def signed_message(act, to, file, fh, nonce, exp, taint) -> bytes:
    """v1|<act>|<to>|<file>|<fh>|<nonce>|<exp>|<taint> as UTF-8 bytes."""
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
