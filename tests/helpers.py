import tempfile
from pathlib import Path

from warden.config import load_settings
from warden.db import Store
from warden.llm.base import LLMResponse, Provider, ToolCall


def make_settings(**overrides):
    tmp = tempfile.mkdtemp(prefix="warden-test-")
    base = {"WARDEN_STATE_DIR": tmp, "LLM_PROVIDER": "deepseek", "DEEPSEEK_API_KEY": "test-key", "EMAIL_TO": "", "SMTP_HOST": ""}
    base.update(overrides)
    s = load_settings(env_file=Path(tmp) / "none.env", overrides=base)
    return s


def make_db():
    return Store(":memory:")


class FakeProvider(Provider):
    """Replays scripted responses: each item is (content, [(tool_name, args), ...])."""

    def __init__(self, script):
        self.script = list(script)
        self.calls = []

        class Cfg:
            provider, model = "fake", "fake-1"

        self.cfg = Cfg()

    def chat(self, messages, tools):
        self.calls.append([dict(m) for m in messages])
        content, calls = self.script.pop(0) if self.script else ("done", [])
        tcs = [ToolCall(id=f"call_{len(self.calls)}_{i}", name=n, arguments=a) for i, (n, a) in enumerate(calls)]
        msg = {"role": "assistant", "content": content}
        if tcs:
            import json

            msg["tool_calls"] = [{"id": t.id, "type": "function", "function": {"name": t.name, "arguments": json.dumps(t.arguments)}} for t in tcs]
        return LLMResponse(content=content, tool_calls=tcs, message=msg, usage={"in": 10, "out": 5})


class FakeFirewall:
    def __init__(self):
        self.ready = True
        self.last_error = ""
        self.banned = {}

    def ban(self, target, seconds):
        self.banned[target] = seconds
        return True, ""

    def unban(self, target):
        self.banned.pop(target, None)
        return True, ""

    def counters(self):
        return {"warden-ban": 3}

    def set_allowlist(self, entries):
        self.allowlist = list(entries)
