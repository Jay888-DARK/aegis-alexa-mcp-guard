"""Forwarding module for bedrock_client."""

from aegishome.bedrock_client import (
    BedrockClient,
    FakeModel,
    LLMModel,
    PATH_BEDROCK_VERIFIED,
    PATH_GROQ_VERIFIED,
    PATH_DETERMINISTIC_FALLBACK,
    deterministic_template_summary,
    format_bedrock_prompt,
    generate_home_summary,
)

__all__ = [
    "BedrockClient",
    "FakeModel",
    "LLMModel",
    "PATH_BEDROCK_VERIFIED",
    "PATH_GROQ_VERIFIED",
    "PATH_DETERMINISTIC_FALLBACK",
    "deterministic_template_summary",
    "format_bedrock_prompt",
    "generate_home_summary",
]
