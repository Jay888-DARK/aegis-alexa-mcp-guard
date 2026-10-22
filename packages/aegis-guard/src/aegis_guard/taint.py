"""Per-session Taint Tracking and Dynamic Risk Escalation for Aegis Guard.

Tracks untrusted input sources (such as external visitor notes, unstructured web data,
or courier messages) and automatically escalates action risk tiers for any operations
attempted within a tainted session context.
"""

from dataclasses import dataclass, field
import time
from typing import Any, Callable

from aegis_guard.policy import RiskLevel
from aegis_guard.storage import AegisStorage, get_storage


@dataclass
class TaintRecord:
    """Audit metadata recorded when a session is tainted by untrusted input."""

    session_id: str
    source: str
    reason: str
    timestamp: float
    metadata: dict[str, Any] = field(default_factory=dict)


def escalate_tier(risk: RiskLevel) -> tuple[RiskLevel, str]:
    """Escalate a risk tier by one level due to taint.

    Rules:
    - LOW -> MEDIUM (requires 4-digit voice code)
    - MEDIUM -> HIGH (requires 4-digit voice code AND out-of-band owner approval)
    - HIGH -> HIGH (remains HIGH, flagged tainted, requires code AND owner approval)
    """
    if risk == RiskLevel.LOW:
        return RiskLevel.MEDIUM, "Escalated from LOW to MEDIUM due to tainted session"
    elif risk == RiskLevel.MEDIUM:
        return RiskLevel.HIGH, "Escalated from MEDIUM to HIGH due to tainted session"
    else:  # HIGH
        return RiskLevel.HIGH, "Risk remains HIGH; action flagged as tainted"


class TaintTracker:
    """Manages per-session taint state backed by SQLite persistence."""

    def __init__(
        self,
        time_provider: Callable[[], float] | None = None,
        storage: AegisStorage | None = None,
    ) -> None:
        self._time_provider = time_provider or time.time
        self.storage = storage if storage is not None else get_storage(time_provider=self._time_provider)

    def mark_tainted(
        self,
        session_id: str,
        source: str,
        reason: str = "Accessed untrusted input",
        metadata: dict[str, Any] | None = None,
    ) -> TaintRecord:
        """Mark a session as tainted by an untrusted source in durable storage.

        Args:
            session_id: Identifier of the session to taint.
            source: Name or URI of the untrusted source.
            reason: Optional justification or context for auditing.
            metadata: Optional additional key-value metadata.

        Returns:
            The created TaintRecord.
        """
        return self.storage.set_taint(
            session_id=session_id,
            source=source,
            reason=reason,
            metadata=metadata,
        )

    def is_tainted(self, session_id: str) -> bool:
        """Return True if the given session is currently marked tainted."""
        return self.storage.is_tainted(session_id)

    def get_taint_record(self, session_id: str) -> TaintRecord | None:
        """Retrieve the TaintRecord for a session if tainted."""
        return self.storage.get_taint_record(session_id)

    def wrap_untrusted(
        self,
        content: str,
        source: str,
        session_id: str | None = None,
        reason: str = "External untrusted message read",
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Wrap untrusted text into a standardized dictionary and taint the session.

        Format:
            {"content": content, "untrusted": True, "source": source}

        Args:
            content: Raw string content from the untrusted source.
            source: Source identifier (e.g. 'visitor_note', 'courier_doorbell').
            session_id: Optional session identifier. If provided, marks the session tainted.
            reason: Audit rationale for the taint mark.
            metadata: Additional metadata dictionary.

        Returns:
            Standardized untrusted dictionary wrapper.
        """
        if session_id:
            self.mark_tainted(session_id=session_id, source=source, reason=reason, metadata=metadata)

        return {
            "content": content,
            "untrusted": True,
            "source": source,
        }

    def evaluate_risk(
        self,
        base_risk: RiskLevel,
        session_id: str,
    ) -> tuple[RiskLevel, bool, str | None]:
        """Evaluate effective risk tier applying session taint escalation.

        Returns:
            tuple: (effective_risk_level, is_tainted, escalation_reason)
        """
        if not self.is_tainted(session_id):
            return base_risk, False, None

        record = self.get_taint_record(session_id)
        effective_risk, escalation_desc = escalate_tier(base_risk)
        source_desc = f"source='{record.source}'" if record else "unknown source"
        reason = f"{escalation_desc} ({source_desc})"
        return effective_risk, True, reason

    def reset(self) -> None:
        """Clear all tainted sessions from storage (for tests)."""
        self.storage.clear_taint()


# Global taint tracker singleton
_GLOBAL_TAINT_TRACKER: TaintTracker | None = None


def get_taint_tracker(storage: AegisStorage | None = None) -> TaintTracker:
    """Retrieve or initialize the global TaintTracker singleton."""
    global _GLOBAL_TAINT_TRACKER
    if _GLOBAL_TAINT_TRACKER is None:
        _GLOBAL_TAINT_TRACKER = TaintTracker(storage=storage)
    elif storage is not None and _GLOBAL_TAINT_TRACKER.storage != storage:
        _GLOBAL_TAINT_TRACKER = TaintTracker(storage=storage)
    return _GLOBAL_TAINT_TRACKER


def reset_taint_tracker() -> None:
    """Reset the global TaintTracker instance."""
    global _GLOBAL_TAINT_TRACKER
    tracker = get_taint_tracker()
    tracker.reset()

