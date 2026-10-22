"""Anthropic Messages API (Claude)."""
from __future__ import annotations

import json

from warden.llm.base import LLMError, LLMResponse, Provider, ToolCall, post_json


def to_anthropic(messages: list[dict]) -> tuple[str, list[dict]]:
    """Convert canonical (OpenAI-style) history into (system, messages) for the Messages API."""
    system: list[str] = []
    out: list[dict] = []

    def push(role: str, blocks: list[dict]) -> None:
        if out and out[-1]["role"] == role:
            out[-1]["content"].extend(blocks)
        else:
            out.append({"role": role, "content": list(blocks)})

    for m in messages:
        role = m["role"]
        if role == "system":
            system.append(m.get("content") or "")
        elif role == "tool":
            push("user", [{"type": "tool_result", "tool_use_id": m["tool_call_id"], "content": m.get("content") or ""}])
        elif role == "assistant":
            blocks: list[dict] = []
            if m.get("content"):
                blocks.append({"type": "text", "text": m["content"]})
            for tc in m.get("tool_calls") or []:
                raw = tc["function"].get("arguments") or "{}"
                try:
                    args = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    args = {}
                blocks.append({"type": "tool_use", "id": tc["id"], "name": tc["function"]["name"], "input": args if isinstance(args, dict) else {}})
            push("assistant", blocks or [{"type": "text", "text": "(no content)"}])
        else:
            push("user", [{"type": "text", "text": m.get("content") or ""}])
    return "\n\n".join(system), out


class AnthropicProvider(Provider):
    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        system, msgs = to_anthropic(messages)
        payload: dict = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
            "temperature": self.cfg.temperature,
            "messages": msgs,
        }
        # prompt caching: tools+system are static (breakpoint 1); the growing conversation gets a moving breakpoint
        if system:
            payload["system"] = [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}]
        if msgs and msgs[-1]["content"]:
            last = msgs[-1]["content"][-1]
            msgs[-1]["content"][-1] = {**last, "cache_control": {"type": "ephemeral"}}
        if tools:
            payload["tools"] = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in tools]
        headers = {"x-api-key": self.cfg.api_key, "anthropic-version": "2023-06-01"}
        data = post_json(self.cfg.base_url + "/v1/messages", headers, payload, self.cfg.timeout)
        return self.parse_response(data)

    @staticmethod
    def parse_response(data: dict) -> LLMResponse:
        if "content" not in data:
            raise LLMError(f"unexpected response: {str(data)[:500]}")
        texts, calls, canonical_calls = [], [], []
        for block in data["content"]:
            if block.get("type") == "text":
                texts.append(block.get("text", ""))
            elif block.get("type") == "tool_use":
                args = block.get("input") or {}
                calls.append(ToolCall(id=block["id"], name=block["name"], arguments=args))
                canonical_calls.append({"id": block["id"], "type": "function", "function": {"name": block["name"], "arguments": json.dumps(args)}})
        content = "\n".join(texts)
        canonical: dict = {"role": "assistant", "content": content}
        if canonical_calls:
            canonical["tool_calls"] = canonical_calls
        usage = data.get("usage") or {}
        cached = usage.get("cache_read_input_tokens", 0) or 0
        total_in = (usage.get("input_tokens", 0) or 0) + cached + (usage.get("cache_creation_input_tokens", 0) or 0)
        return LLMResponse(
            content=content,
            tool_calls=calls,
            message=canonical,
            usage={"in": total_in, "out": usage.get("output_tokens", 0) or 0, "cached": cached},
            finish_reason=data.get("stop_reason") or "",
        )
