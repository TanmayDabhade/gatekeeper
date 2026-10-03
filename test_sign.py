import hashlib, json, secrets, time
import serial
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

PORT = "/dev/cu.usbserial-0001"

ser = serial.Serial()
ser.port = PORT
ser.baudrate = 115200
ser.timeout = 1
ser.dtr = False
ser.rts = False
ser.open()
time.sleep(2)
ser.reset_input_buffer()

def send(obj, wait=5):
    ser.write((json.dumps(obj) + "\n").encode())
    deadline = time.time() + wait
    while time.time() < deadline:
        line = ser.readline().decode(errors="ignore").strip()
        if line.startswith("{"):
            return json.loads(line)
    return None

def canonical(req):
    return "|".join([
        "v1", req["act"], req["to"], req["file"], req["fh"],
        req["nonce"], str(req["exp"]), str(req["taint"]),
    ])

# 1. Get the device's public key
pk = send({"t": "pubkey"})["pk"]
vk = VerifyKey(bytes.fromhex(pk))
print("Device public key:", pk)

# 2. A legitimate request: tax return to the trusted accountant
req = {
    "t": "req", "act": "send_email", "to": "accountant@trustedcpa.com",
    "file": "/data/sensitive/tax_return.pdf",
    "fh": hashlib.sha256(b"demo").hexdigest(),
    "claim": "medium", "taint": 0,
    "nonce": secrets.token_hex(16),
    "exp": int(time.time()) + 60, "bench": 0,
}

print("\n>>> Press APPROVE on the device (or RESET to deny). You have 30 s.")
res = send(req, wait=35)
print("Reply:", res["v"] if res else "no reply")

if res and res["v"] == "approved":
    sig = bytes.fromhex(res["sig"])
    msg = canonical(req)

    # 3. The real request should verify
    try:
        vk.verify(msg.encode(), sig)
        print("PASS: signature is valid for the request the device showed")
    except BadSignatureError:
        print("FAIL: signature did not verify")

    # 4. Tamper test: swap the recipient for the attacker
    tampered = msg.replace("accountant@trustedcpa.com", "x9@proton.me")
    try:
        vk.verify(tampered.encode(), sig)
        print("FAIL: tampered request was accepted")
    except BadSignatureError:
        print("PASS: tampered request rejected (recipient was changed)")