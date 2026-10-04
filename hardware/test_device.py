import hashlib, json, secrets, time
import serial

PORT = "/dev/cu.usbserial-0001"

ser = serial.Serial()
ser.port = PORT
ser.baudrate = 115200
ser.timeout = 3
ser.dtr = False   # stops the ESP32 from rebooting when the port opens
ser.rts = False
ser.open()
time.sleep(2)
ser.reset_input_buffer()

def send(obj):
    ser.write((json.dumps(obj) + "\n").encode())
    deadline = time.time() + 5
    while time.time() < deadline:
        line = ser.readline().decode(errors="ignore").strip()
        if line.startswith("{"):          # skip boot messages and noise
            return json.loads(line)
    return None

print("ping ->", send({"t": "ping"}))

req = {
    "t": "req", "act": "send_email", "to": "x9@proton.me",
    "file": "/data/sensitive/tax_return.pdf",
    "fh": hashlib.sha256(b"demo").hexdigest(),
    "claim": "low", "taint": 1,
    "nonce": secrets.token_hex(16),
    "exp": int(time.time()) + 60, "bench": 0,
}
print("req  ->", send(req))