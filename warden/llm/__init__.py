"""LLM provider factory. Swap providers purely through configuration."""
from __future__ import annotations

import logging

from warden.llm.anthropic import AnthropicProvider
from warden.llm.base import LLMError, LLMResponse, Provider, ToolCall
from warden.llm.openai_compat import OpenAICompatProvider

log = logging.getLogger("warden.llm")

ADAPTERS = {"openai": OpenAICompatProvider, "anthropic": AnthropicProvider}

__all__ = ["LLMError", "LLMResponse", "Provider", "ToolCall", "build_provider"]


class FallbackProvider(Provider):
    def __init__(self, primary: Provider, secondary: Provider):
        self.primary, self.secondary = primary, secondary
        self.cfg = primary.cfg

    @property
    def label(self) -> str:
        return f"{self.primary.label} (fallback {self.secondary.label})"

    def chat(self, messages, tools):
        try:
            return self.primary.chat(messages, tools)
        except LLMError as exc:
            log.warning("primary LLM failed (%s); using fallback %s", str(exc)[:200], self.secondary.label)
            return self.secondary.chat(messages, tools)


def build_provider(settings) -> Provider:
    if settings.llm is None:
        raise LLMError(settings.llm_error or "LLM not configured")
    primary = ADAPTERS[settings.llm.adapter](settings.llm)
    if settings.llm_fallback:
        return FallbackProvider(primary, ADAPTERS[settings.llm_fallback.adapter](settings.llm_fallback))
    return primary
