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

# Email (Mailpit). The executor sends to SMTP_PORT: Mailpit directly (1025), or the M9
# verifier gateway with GATEKEEPER_SMTP_PORT=1026, which relays to Mailpit only if the
# device's signature checks out.
SMTP_HOST = "localhost"
SMTP_PORT = int(os.environ.get("GATEKEEPER_SMTP_PORT", "1025"))
UPSTREAM_SMTP_PORT = 1025       # where the gateway relays verified mail (Mailpit)
GATEWAY_HOST = "127.0.0.1"
GATEWAY_PORT = 1026
GATEWAY_NONCES = os.path.join(BASE_DIR, ".gateway_nonces")   # used approvals, survives restarts
MAILPIT_UI = "http://localhost:8025"
SENDER = "assistant@ourcompany.com"

# Sandbox for run_code
DOCKER_IMAGE = "python:3.12-slim"
RUN_CODE_TIMEOUT_S = 20

# LLM: any OpenAI-style /chat/completions endpoint (see llm.py). Base URLs:
#   OpenAI https://api.openai.com/v1          Anthropic https://api.anthropic.com/v1
#   Groq   https://api.groq.com/openai/v1     Gemini https://generativelanguage.googleapis.com/v1beta/openai
#   Ollama http://localhost:11434/v1 (no key)
LLM_BASE_URL = os.environ.get("LLM_BASE_URL", "")
LLM_MODEL = os.environ.get("LLM_MODEL", "")
LLM_API_KEY_ENV = "LLM_API_KEY"     # name of the env var that holds the key
LLM_TEMPERATURE = 0
LLM_TIMEOUT_S = 60
AGENT_MAX_STEPS = 10                # tool calls per run, so a confused model can't loop forever
COMPROMISED_MODE = os.environ.get("GATEKEEPER_COMPROMISED", "0") == "1"
