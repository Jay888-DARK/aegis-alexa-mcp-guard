"""Append-only audit logging module for Aegis Guard.

Records every action proposal, confirmation, block, and reason to an append-only JSONL log.
Ensures accountability, non-repudiation, and forensics for all agentic actions.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Mapping

from aegis_guard.storage import AegisStorage, ValidChain, BrokenIndex, get_storage

DEFAULT_AUDIT_LOG_PATH = "aegis_audit.jsonl"


@dataclass
class AuditEntry:
    """A single record in the append-only audit trail."""

    timestamp: float
    iso_time: str
    event_type: str  # 'PROPOSAL', 'CONFIRMATION', 'BLOCK', 'APPROVAL'
    proposal_id: str = ""
    device: str = ""
    action: str = ""
    risk_tier: str = ""
    session_id: str = ""
    reason: str = ""
    error_type: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    entry_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert entry to dictionary for JSON serialization."""
        return asdict(self)


class AuditLogger:
    """Append-only hash-chained SQLite and JSONL logger for proposals, confirmations, and security blocks."""

    def __init__(
        self,
        log_path: str | Path | None = None,
        storage: AegisStorage | None = None,
    ) -> None:
        raw_path = log_path or os.getenv("AEGIS_AUDIT_LOG_PATH", DEFAULT_AUDIT_LOG_PATH)
        self.log_path = Path(raw_path).resolve()
        self._lock = threading.Lock()
        self.storage = storage if storage is not None else get_storage()

        # Ensure directory exists
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def _append_entry(self, entry: AuditEntry) -> AuditEntry:
        """Atomically append a single audit entry to SQLite hash chain and JSONL."""
        db_record = self.storage.log_audit(
            event=entry.event_type,
            detail_json=entry.to_dict(),
            ts=entry.timestamp,
        )
        entry.prev_hash = db_record.get("prev_hash", "")
        entry.entry_hash = db_record.get("entry_hash", "")

        line = json.dumps(entry.to_dict(), default=str)
        try:
            with self._lock:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
                    f.flush()
        except Exception:
            pass
        return entry


    def log_event(
        self,
        event_type: str,
        proposal_id: str = "",
        device: str = "",
        action: str = "",
        risk_tier: str = "",
        session_id: str = "",
        reason: str = "",
        error_type: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Create and write an audit entry to the log."""
        now = time.time()
        iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        entry = AuditEntry(
            timestamp=now,
            iso_time=iso,
            event_type=event_type.upper(),
            proposal_id=proposal_id,
            device=device,
            action=action,
            risk_tier=risk_tier,
            session_id=session_id,
            reason=reason,
            error_type=error_type,
            details=dict(details or {}),
        )
        return self._append_entry(entry)

    def log_proposal(
        self,
        proposal: Any,
        reason: str = "Action proposed",
        details: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Record an action proposal event."""
        extra: dict[str, Any] = dict(details or {})
        if hasattr(proposal, "params"):
            extra["params"] = proposal.params
        if hasattr(proposal, "is_tainted"):
            extra["is_tainted"] = proposal.is_tainted

        risk = ""
        if hasattr(proposal, "risk_tier"):
            risk = getattr(proposal.risk_tier, "value", str(proposal.risk_tier))

        return self.log_event(
            event_type="PROPOSAL",
            proposal_id=getattr(proposal, "proposal_id", str(proposal)),
            device=getattr(proposal, "device", ""),
            action=getattr(proposal, "action", ""),
            risk_tier=risk,
            session_id=getattr(proposal, "session_id", ""),
            reason=reason,
            details=extra,
        )

    def log_confirmation(
        self,
        proposal: Any,
        approver: str = "",
        reason: str = "Action confirmed and executed",
        details: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Record a successful confirmation and execution event."""
        extra: dict[str, Any] = dict(details or {})
        if approver:
            extra["approver"] = approver
        if hasattr(proposal, "params"):
            extra["params"] = proposal.params

        risk = ""
        if hasattr(proposal, "risk_tier"):
            risk = getattr(proposal.risk_tier, "value", str(proposal.risk_tier))

        return self.log_event(
            event_type="CONFIRMATION",
            proposal_id=getattr(proposal, "proposal_id", str(proposal)),
            device=getattr(proposal, "device", ""),
            action=getattr(proposal, "action", ""),
            risk_tier=risk,
            session_id=getattr(proposal, "session_id", ""),
            reason=reason,
            details=extra,
        )

    def log_block(
        self,
        proposal_id: str = "",
        device: str = "",
        action: str = "",
        risk_tier: str = "",
        session_id: str = "",
        reason: str = "",
        error_type: str = "",
        details: Mapping[str, Any] | None = None,
    ) -> AuditEntry:
        """Record a security block or rejection event."""
        return self.log_event(
            event_type="BLOCK",
            proposal_id=proposal_id,
            device=device,
            action=action,
            risk_tier=risk_tier,
            session_id=session_id,
            reason=reason,
            error_type=error_type,
            details=details,
        )

    def verify_chain(self) -> ValidChain | BrokenIndex:
        """Verify cryptographic hash chain integrity across all audit records."""
        return self.storage.verify_chain()

    def read_entries(self) -> list[dict[str, Any]]:
        """Read all logged entries from SQLite audit storage, falling back to JSONL if empty."""
        db_entries = self.storage.get_audit_entries()
        if db_entries:
            formatted = []
            for item in db_entries:
                detail = item.get("detail", {})
                if isinstance(detail, dict):
                    merged = dict(detail)
                    merged["id"] = item.get("id")
                    merged["prev_hash"] = item.get("prev_hash")
                    merged["entry_hash"] = item.get("entry_hash")
                    formatted.append(merged)
                else:
                    formatted.append(item)
            return formatted

        if not self.log_path.exists():
            return []
        entries: list[dict[str, Any]] = []
        with self._lock:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            pass
        return entries

    def clear(self) -> None:
        """Clear the log file and audit database table (primarily for unit tests)."""
        self.storage.clear_audit()
        with self._lock:
            if self.log_path.exists():
                self.log_path.unlink()


# Global audit logger instance
_GLOBAL_AUDIT_LOGGER: AuditLogger | None = None


def get_audit_logger(
    log_path: str | Path | None = None,
    storage: AegisStorage | None = None,
) -> AuditLogger:
    """Retrieve or initialize the global AuditLogger instance."""
    global _GLOBAL_AUDIT_LOGGER
    if (
        _GLOBAL_AUDIT_LOGGER is None
        or (log_path is not None and str(Path(log_path).resolve()) != str(_GLOBAL_AUDIT_LOGGER.log_path))
        or (storage is not None and _GLOBAL_AUDIT_LOGGER.storage != storage)
    ):
        _GLOBAL_AUDIT_LOGGER = AuditLogger(log_path=log_path, storage=storage)
    return _GLOBAL_AUDIT_LOGGER


def reset_audit_logger(
    log_path: str | Path | None = None,
    storage: AegisStorage | None = None,
) -> AuditLogger:
    """Reset and reinitialize the global audit logger."""
    global _GLOBAL_AUDIT_LOGGER
    _GLOBAL_AUDIT_LOGGER = AuditLogger(log_path=log_path, storage=storage)
    _GLOBAL_AUDIT_LOGGER.clear()
    return _GLOBAL_AUDIT_LOGGER

