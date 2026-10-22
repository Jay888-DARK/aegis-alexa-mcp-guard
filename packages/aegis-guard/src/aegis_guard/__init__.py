"""Aegis Guard: Deterministic safety gateway and guardrails library for MCP servers."""

from aegis_guard.policy import RiskPolicy, RiskLevel, PolicyRule
from aegis_guard.confirm import (
    ConfirmationGateway,
    Proposal,
    ConfirmationError,
    ProposalNotFoundError,
    ProposalExpiredError,
    ProposalLockedError,
    ProposalAlreadyConfirmedError,
    InvalidCodeError,
    MissingOwnerApprovalError,
    ActionTamperedError,
    get_confirmation_gateway,
)
from aegis_guard.taint import (
    TaintTracker,
    TaintRecord,
    escalate_tier,
    get_taint_tracker,
    reset_taint_tracker,
)
from aegis_guard.numeric_guard import (
    verify,
    extract_numbers,
    ExtractedNumber,
    FactsIndex,
)

from aegis_guard.audit import (
    AuditEntry,
    AuditLogger,
    get_audit_logger,
    reset_audit_logger,
)
from aegis_guard.storage import (
    AegisStorage,
    ValidChain,
    BrokenIndex,
    get_storage,
    reset_storage,
)

__version__ = "0.1.0"

__all__ = [
    "RiskPolicy",
    "RiskLevel",
    "PolicyRule",
    "ConfirmationGateway",
    "Proposal",
    "ConfirmationError",
    "ProposalNotFoundError",
    "ProposalExpiredError",
    "ProposalLockedError",
    "ProposalAlreadyConfirmedError",
    "InvalidCodeError",
    "MissingOwnerApprovalError",
    "ActionTamperedError",
    "get_confirmation_gateway",
    "TaintTracker",
    "TaintRecord",
    "escalate_tier",
    "get_taint_tracker",
    "reset_taint_tracker",
    "verify",
    "extract_numbers",
    "ExtractedNumber",
    "FactsIndex",
    "AuditEntry",
    "AuditLogger",
    "get_audit_logger",
    "reset_audit_logger",
    "AegisStorage",
    "ValidChain",
    "BrokenIndex",
    "get_storage",
    "reset_storage",
]

