"""Forwarding module for aegishome.agent from apps.aegishome.agent."""

import apps.aegishome.agent as _agent_mod
from apps.aegishome.agent import (
    ALLOWED_TOOLS,
    SYSTEM_PROMPT,
    _build_tool_config,
    _fallback_to_rule_engine,
    evaluate,
    get_mcp_client,
    run_turn,
)

boto3 = _agent_mod.boto3

__all__ = [
    "ALLOWED_TOOLS",
    "SYSTEM_PROMPT",
    "_build_tool_config",
    "_fallback_to_rule_engine",
    "evaluate",
    "get_mcp_client",
    "run_turn",
    "boto3",
]
