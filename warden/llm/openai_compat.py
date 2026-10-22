"""OpenAI chat-completions compatible providers: DeepSeek, OpenAI, OpenRouter, Groq, Mistral, Gemini, Ollama, vLLM..."""
from __future__ import annotations

import uuid

from warden.llm.base import LLMError, LLMResponse, Provider, ToolCall, parse_arguments, post_json


class OpenAICompatProvider(Provider):
    def build_payload(self, messages: list[dict], tools: list[dict]) -> dict:
        payload = {
            "model": self.cfg.model,
            "messages": messages,
            "temperature": self.cfg.temperature,
            "max_tokens": self.cfg.max_tokens,
        }
        if tools:
            payload["tools"] = [
                {"type": "function", "function": {"name": t["name"], "description": t["description"], "parameters": t["parameters"]}}
                for t in tools
            ]
            payload["tool_choice"] = "auto"
        return payload

    def chat(self, messages: list[dict], tools: list[dict]) -> LLMResponse:
        headers = {"Authorization": f"Bearer {self.cfg.api_key}"} if self.cfg.api_key else {}
        data = post_json(self.cfg.base_url + "/chat/completions", headers, self.build_payload(messages, tools), self.cfg.timeout)
        return self.parse_response(data)

    @staticmethod
    def parse_response(data: dict) -> LLMResponse:
        try:
            choice = data["choices"][0]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"unexpected response: {str(data)[:500]}") from None
        msg = choice.get("message") or {}
        content = msg.get("content") or ""
        calls: list[ToolCall] = []
        canonical_calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function") or {}
            tc_id = tc.get("id") or f"call_{uuid.uuid4().hex[:12]}"
            raw_args = fn.get("arguments") or "{}"
            args, err = parse_arguments(raw_args)
            calls.append(ToolCall(id=tc_id, name=fn.get("name", ""), arguments=args, parse_error=err))
            canonical_calls.append(
                {"id": tc_id, "type": "function", "function": {"name": fn.get("name", ""), "arguments": raw_args if isinstance(raw_args, str) else str(raw_args)}}
            )
        canonical: dict = {"role": "assistant", "content": content}
        if canonical_calls:
            canonical["tool_calls"] = canonical_calls
        # DeepSeek thinking mode expects its reasoning echoed back within a tool-use turn
        if msg.get("reasoning_content"):
            canonical["reasoning_content"] = msg["reasoning_content"]
        usage = data.get("usage") or {}
        # cached prefix tokens: DeepSeek reports prompt_cache_hit_tokens, OpenAI prompt_tokens_details.cached_tokens
        cached = usage.get("prompt_cache_hit_tokens") or (usage.get("prompt_tokens_details") or {}).get("cached_tokens") or 0
        return LLMResponse(
            content=content,
            tool_calls=calls,
            message=canonical,
            usage={"in": usage.get("prompt_tokens", 0) or 0, "out": usage.get("completion_tokens", 0) or 0, "cached": cached},
            finish_reason=choice.get("finish_reason") or "",
        )
