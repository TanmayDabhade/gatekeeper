"""Host-side configuration (executor, agent, scripts).

Device policy (contacts, limits) deliberately does NOT live here: it belongs to
the device. The mock keeps its own copy in mock_device.py, mirroring firmware.
"""
import os

BASE_DIR = os.path.dirname(os.path.realpath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
SENSITIVE_DIR = os.path.join(DATA_DIR, "sensitive")
PUBLIC_DIR = os.path.join(DATA_DIR, "public")
INBOX_PATH = os.environ.get("GATEKEEPER_INBOX", os.path.join(DATA_DIR, "inbox.json"))

# Device link. Same code path for mock and real hardware.
MOCK_HOST = "127.0.0.1"
MOCK_PORT = 7777
DEVICE_PORT = os.environ.get("GATEKEEPER_PORT", f"socket://localhost:{MOCK_PORT}")
# Real device: GATEKEEPER_PORT=/dev/cu.usbserial-0001
SERIAL_BAUD = 115200
DEVICE_TIMEOUT_S = 120      # max time to wait for a human on the device
REQUEST_TTL_S = 60          # exp = now + REQUEST_TTL_S
# Pinned device pubkey (hex). First run saves it; later runs must match it.
PUBKEY_PATH = os.environ.get("GATEKEEPER_PUBKEY", os.path.join(BASE_DIR, ".device_pubkey"))

# Session taint
COMPANY_DOMAIN = "ourcompany.com"

# Email (Mailpit)
SMTP_HOST = "localhost"
SMTP_PORT = 1025
MAILPIT_UI = "http://localhost:8025"
SENDER = "assistant@ourcompany.com"

# Sandbox for run_code
DOCKER_IMAGE = "python:3.12-slim"
RUN_CODE_TIMEOUT_S = 20

# LLM (filled in at M3)
LLM_PROVIDER = "[PROVIDER]"
LLM_API_KEY_ENV = "[KEY_NAME]"
LLM_TEMPERATURE = 0
COMPROMISED_MODE = os.environ.get("GATEKEEPER_COMPROMISED", "0") == "1"
