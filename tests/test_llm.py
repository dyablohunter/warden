import json
import unittest

from warden.llm.anthropic import AnthropicProvider, to_anthropic
from warden.llm.base import parse_arguments
from warden.llm.openai_compat import OpenAICompatProvider


class LLMTests(unittest.TestCase):
    HISTORY = [
        {"role": "system", "content": "sys"},
        {"role": "user", "content": "task"},
        {"role": "assistant", "content": "thinking", "tool_calls": [
            {"id": "c1", "type": "function", "function": {"name": "run_command", "arguments": '{"command": "id"}'}},
            {"id": "c2", "type": "function", "function": {"name": "read_file", "arguments": '{"path": "/x"}'}},
        ]},
        {"role": "tool", "tool_call_id": "c1", "content": "uid=0"},
        {"role": "tool", "tool_call_id": "c2", "content": "data"},
        {"role": "user", "content": "nudge"},
    ]

    def test_to_anthropic(self):
        system, msgs = to_anthropic(self.HISTORY)
        self.assertEqual(system, "sys")
        self.assertEqual([m["role"] for m in msgs], ["user", "assistant", "user"])
        self.assertEqual(msgs[1]["content"][1], {"type": "tool_use", "id": "c1", "name": "run_command", "input": {"command": "id"}})
        last = msgs[2]["content"]
        self.assertEqual([b["type"] for b in last], ["tool_result", "tool_result", "text"])
        self.assertEqual(last[1]["tool_use_id"], "c2")

    def test_anthropic_parse(self):
        r = AnthropicProvider.parse_response({"content": [{"type": "text", "text": "hi"}, {"type": "tool_use", "id": "t1", "name": "finish", "input": {"a": 1}}],
                                              "usage": {"input_tokens": 3, "output_tokens": 4}, "stop_reason": "tool_use"})
        self.assertEqual(r.tool_calls[0].arguments, {"a": 1})
        self.assertEqual(json.loads(r.message["tool_calls"][0]["function"]["arguments"]), {"a": 1})
        self.assertEqual(r.usage, {"in": 3, "out": 4, "cached": 0})

    def test_openai_parse(self):
        data = {"choices": [{"finish_reason": "tool_calls", "message": {"content": None, "reasoning_content": "hmm", "tool_calls": [
            {"id": "x", "type": "function", "function": {"name": "finish", "arguments": '{"ok": true}'}},
            {"id": "y", "type": "function", "function": {"name": "bad", "arguments": "{not json"}}]}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 2}}
        r = OpenAICompatProvider.parse_response(data)
        self.assertEqual(r.tool_calls[0].arguments, {"ok": True})
        self.assertIsNotNone(r.tool_calls[1].parse_error)
        self.assertEqual(r.message["reasoning_content"], "hmm")
        self.assertEqual(r.message["content"], "")

    def test_openai_payload(self):
        class Cfg:
            model, temperature, max_tokens, api_key, base_url, timeout = "m", 0.1, 100, "k", "u", 5

        p = OpenAICompatProvider(Cfg())
        payload = p.build_payload([{"role": "user", "content": "x"}], [{"name": "t", "description": "d", "parameters": {"type": "object"}}])
        self.assertEqual(payload["tools"][0]["function"]["name"], "t")

    def test_cached_usage(self):
        ds = OpenAICompatProvider.parse_response({"choices": [{"message": {"content": "x"}}], "usage": {"prompt_tokens": 100, "completion_tokens": 5, "prompt_cache_hit_tokens": 80}})
        self.assertEqual(ds.usage, {"in": 100, "out": 5, "cached": 80})
        oa = OpenAICompatProvider.parse_response({"choices": [{"message": {"content": "x"}}], "usage": {"prompt_tokens": 100, "completion_tokens": 5, "prompt_tokens_details": {"cached_tokens": 64}}})
        self.assertEqual(oa.usage["cached"], 64)
        an = AnthropicProvider.parse_response({"content": [], "usage": {"input_tokens": 10, "cache_read_input_tokens": 90, "cache_creation_input_tokens": 5, "output_tokens": 3}})
        self.assertEqual(an.usage, {"in": 105, "out": 3, "cached": 90})

    def test_anthropic_cache_breakpoints(self):
        sent = {}

        class Cfg:
            model, temperature, max_tokens, api_key, base_url, timeout = "m", 0.1, 100, "k", "u", 5

        import warden.llm.anthropic as mod
        orig = mod.post_json
        mod.post_json = lambda url, h, payload, t: sent.setdefault("p", payload) and {"content": [], "usage": {}}
        try:
            AnthropicProvider(Cfg()).chat(self.HISTORY, [{"name": "t", "description": "d", "parameters": {"type": "object"}}])
        finally:
            mod.post_json = orig
        p = sent["p"]
        self.assertEqual(p["system"][0]["cache_control"], {"type": "ephemeral"})
        self.assertEqual(p["messages"][-1]["content"][-1]["cache_control"], {"type": "ephemeral"})
        self.assertNotIn("cache_control", self.HISTORY[-1])  # caller's history untouched

    def test_parse_arguments(self):
        self.assertEqual(parse_arguments(""), ({}, None))
        self.assertEqual(parse_arguments({"a": 1}), ({"a": 1}, None))
        self.assertIsNotNone(parse_arguments("[1]")[1])


if __name__ == "__main__":
    unittest.main()
