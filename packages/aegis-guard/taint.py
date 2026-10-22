"""Forwarding module for taint."""

from aegis_guard.taint import (
    TaintTracker,
    TaintRecord,
    escalate_tier,
    get_taint_tracker,
    reset_taint_tracker,
)

__all__ = [
    "TaintTracker",
    "TaintRecord",
    "escalate_tier",
    "get_taint_tracker",
    "reset_taint_tracker",
]
