"""Provider interface. Canonical messages use the OpenAI chat format:

  {"role": "system"|"user", "content": str}
  {"role": "assistant", "content": str, "tool_calls": [{"id", "type": "function", "function": {"name", "arguments": json-str}}]}
  {"role": "tool", "tool_call_id": str, "content": str}

Tools are given as [{"name", "description", "parameters": <JSON schema>}].
"""
from __future__ import annotations

import json
import logging
import random
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

log = logging.getLogger("warden.llm")


class LLMError(Exception):
    pass


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict
    parse_error: str | None = None


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[ToolCall]
    message: dict  # canonical assistant message to append to history
    usage: dict = field(default_factory=dict)  # {"in": int, "out": int}
    finish_reason: str = ""


class Provider(ABC):
    def __init__(self, cfg):
        self.cfg = cfg

    @property
    def label(self) -> str:
        return f"{self.cfg.provider}/{self.cfg.model}"

    @abstractmethod
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse: ...


def parse_arguments(raw) -> tuple[dict, str | None]:
    if isinstance(raw, dict):
        return raw, None
    if not raw:
        return {}, None
    try:
        val = json.loads(raw)
        return (val, None) if isinstance(val, dict) else ({}, "arguments must be a JSON object")
    except json.JSONDecodeError as exc:
        return {}, f"invalid JSON arguments: {exc}"


RETRY_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


def post_json(url: str, headers: dict, payload: dict, timeout: int, retries: int = 4) -> dict:
    body = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", "User-Agent": "warden-agent/0.1", **headers}
    last = ""
    for attempt in range(retries + 1):
        req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:2000]
            last = f"HTTP {exc.code}: {detail}"
            if exc.code not in RETRY_STATUS or attempt == retries:
                raise LLMError(last) from None
            wait = _retry_after(exc.headers.get("Retry-After")) or min(60, 2 ** attempt * 2 + random.random())
        except (urllib.error.URLError, TimeoutError, ConnectionError, json.JSONDecodeError) as exc:
            last = f"{type(exc).__name__}: {exc}"
            if attempt == retries or "CERTIFICATE_VERIFY_FAILED" in last:
                raise LLMError(last) from None
            wait = min(60, 2 ** attempt * 2 + random.random())
        log.warning("LLM request failed (%s), retry %d/%d in %.0fs", last[:200], attempt + 1, retries, wait)
        time.sleep(wait)
    raise LLMError(last)


def _retry_after(v: str | None) -> float | None:
    try:
        return min(120.0, float(v)) if v else None
    except ValueError:
        return None
