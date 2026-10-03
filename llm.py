"""LLM clients for the agent. Stdlib only, so no provider SDK is a dependency.

ChatLLM talks to any OpenAI-style /chat/completions endpoint (set LLM_BASE_URL, LLM_MODEL
and the LLM_API_KEY env var; see config.py). ScriptedLLM replays fixed turns: it is the
compromised-mode demo backup and what the tests use.
"""
import json
import os
import urllib.error
import urllib.request

from config import LLM_API_KEY_ENV, LLM_BASE_URL, LLM_MODEL, LLM_TEMPERATURE, LLM_TIMEOUT_S


class LLMError(Exception):
    """The model couldn't be reached or sent something unusable."""


class ChatLLM:
    def __init__(self, base_url=LLM_BASE_URL, model=LLM_MODEL, api_key=None,
                 opener=urllib.request.urlopen, timeout=LLM_TIMEOUT_S):
        if not base_url or not model:
            raise LLMError("no LLM configured: set LLM_BASE_URL and LLM_MODEL (and "
                           f"{LLM_API_KEY_ENV}), or run with GATEKEEPER_COMPROMISED=1")
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.model = model
        self.api_key = os.environ.get(LLM_API_KEY_ENV, "") if api_key is None else api_key
        self.opener = opener
        self.timeout = timeout

    def chat(self, messages, tools):
        """Send the conversation and tool list; return the assistant message
        ({"role", "content"} plus "tool_calls" when the model wants tools)."""
        body = {"model": self.model, "messages": messages, "tools": tools,
                "temperature": LLM_TEMPERATURE}
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        req = urllib.request.Request(self.url, data=json.dumps(body).encode(), headers=headers,
                                     method="POST")
        try:
            with self.opener(req, timeout=self.timeout) as r:
                reply = json.loads(r.read())
        except urllib.error.HTTPError as e:
            detail = e.read()[:300].decode("utf-8", "replace")
            raise LLMError(f"LLM returned HTTP {e.code} (check {LLM_API_KEY_ENV}, LLM_MODEL "
                           f"and LLM_BASE_URL): {detail}") from e
        except (urllib.error.URLError, OSError) as e:
            raise LLMError(f"LLM unreachable at {self.url}: {e}") from e
        except ValueError as e:
            raise LLMError(f"unexpected LLM reply (not JSON): {e}") from e
        try:
            msg = reply["choices"][0]["message"]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"unexpected LLM reply: {str(reply)[:300]}") from None
        # Keep only the standard fields: providers differ in extras (refusal, annotations)
        # and some reject them when the message is sent back in the next request.
        out = {"role": "assistant", "content": msg.get("content")}
        if msg.get("tool_calls"):
            out["tool_calls"] = msg["tool_calls"]
        return out


def tool_turn(name, **args):
    """An assistant message that calls one tool, in the same shape ChatLLM returns."""
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": f"call_{name}", "type": "function",
                            "function": {"name": name, "arguments": json.dumps(args)}}]}


class ScriptedLLM:
    """Replays fixed assistant turns in order, whatever it's told. Records what it was sent."""

    def __init__(self, turns):
        self.turns = list(turns)
        self.seen = []

    def chat(self, messages, tools):
        self.seen.append(list(messages))
        if not self.turns:
            return {"role": "assistant", "content": "Done."}
        return self.turns.pop(0)
