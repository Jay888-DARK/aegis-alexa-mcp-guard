"""Offline rule engine intent evaluator."""

from typing import Any
from aegishome.client import get_intent_driver


def evaluate(utterance: str, session_id: str = "web_session") -> dict[str, Any]:
    """Evaluate utterance using offline intent parser rules."""
    driver = get_intent_driver()
    res = driver._process_via_rule_parser(utterance, session_id=session_id)
    return {
        "text": res.reply,
        "reply": res.reply,
        "tool_calls": res.tool_calls,
        "active_proposal_id": res.active_proposal_id,
        "voice_code": res.voice_code,
        "risk_tier": res.risk_tier,
        "is_tainted": res.is_tainted,
    }
