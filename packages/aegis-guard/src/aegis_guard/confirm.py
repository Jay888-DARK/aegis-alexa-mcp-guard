"""Two-step Human-in-the-Loop Confirmation Gateway for Aegis Guard.

Security Model & Threat Profile:
--------------------------------
What this protects against:
- Voice spoofing & unauthorized ambient smart-speaker commands:
  High/medium impact actions cannot be triggered by ambient room noise, TV audio,
  or unauthenticated visitors without knowing the ephemeral voice confirmation code.
- Prompt injection & tool misuse:
  An attacker manipulating an LLM to call privileged tools (e.g. "unlock the front door")
  is halted at the gateway because the action is bound to a cryptographic proposal.
- Replay attacks:
  Proposals and voice codes are strictly single-use and transition to terminal states upon execution.
- Action parameter tampering:
  The 4-digit code is cryptographically bound via HMAC-SHA256 to the exact canonical
  JSON representation of (device, action, parameters). Any parameter drift invalidates the code.
- Brute-force code guessing:
  Proposals permanently lock after 3 failed verification attempts, mitigating brute-force
  enumeration of the 4-digit (0000-9999) keyspace within the 60-second validity window.
- Unauthorized physical perimeter breach (HIGH tier defense-in-depth):
  HIGH-risk physical security actions require out-of-band "owner" approval (simulated phone/app
  authorization) in addition to voice confirmation, preventing an intruder inside the home
  from confirming perimeter access solely with voice.

What this does NOT protect against:
- An adversary who has fully compromised both channels simultaneously:
  If an adversary can hear the voice code in real-time AND holds the authenticated owner device
  to sign off on out-of-band approval, the action will succeed.
- Physical override of hardware:
  Hardware key tampering, manual latch turning, or physical power cut to smart devices.
"""

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Callable

from aegis_guard.audit import AuditLogger, get_audit_logger
from aegis_guard.policy import RiskLevel, RiskPolicy
from aegis_guard.storage import AegisStorage, get_storage
from aegis_guard.taint import TaintTracker, get_taint_tracker


class ConfirmationError(Exception):
    """Base exception for confirmation gateway errors."""


class ProposalNotFoundError(ConfirmationError):
    """Raised when a proposal ID does not exist."""


class ProposalExpiredError(ConfirmationError):
    """Raised when an action proposal has passed its validity window."""


class ProposalLockedError(ConfirmationError):
    """Raised when a proposal is locked due to excessive failed attempts."""


class ProposalAlreadyConfirmedError(ConfirmationError):
    """Raised when attempting to reuse or replay an already-confirmed proposal."""


class InvalidCodeError(ConfirmationError):
    """Raised when the submitted voice confirmation code is incorrect."""


class MissingOwnerApprovalError(ConfirmationError):
    """Raised when a HIGH-risk action is confirmed before owner out-of-band approval."""


class ActionTamperedError(ConfirmationError):
    """Raised when the action payload does not match the proposal's bound digest."""


def canonicalize_action(device: str, action: str, params: dict[str, Any] | None) -> str:
    """Produce deterministic, canonical JSON for an action payload."""
    payload = {
        "device": device.strip().lower(),
        "action": action.strip().lower(),
        "params": params or {},
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_action_digest(canonical_json: str) -> str:
    """Compute SHA-256 hex digest for canonical action JSON."""
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


def derive_voice_code(
    secret: bytes,
    proposal_id: str,
    action_digest: str,
    nonce: str,
    expires_at: float,
) -> str:
    """Derive a deterministic 4-digit voice confirmation code bound to the exact action.

    Formula:
        HMAC-SHA256(secret, f"{proposal_id}|{action_digest}|{nonce}|{expires_at}")
        truncated to 4 digits (0000-9999).
    """
    message = f"{proposal_id}|{action_digest}|{nonce}|{int(expires_at)}".encode("utf-8")
    mac = hmac.new(secret, message, hashlib.sha256).digest()
    code_int = int.from_bytes(mac[:4], byteorder="big") % 10000
    return f"{code_int:04d}"


@dataclass
class Proposal:
    """State record for a proposed smart-home action."""

    proposal_id: str
    device: str
    action: str
    params: dict[str, Any]
    canonical_action_json: str
    action_digest: str
    risk_tier: RiskLevel
    summary: str
    created_at: float
    expires_at: float
    nonce: str
    voice_code: str | None
    session_id: str = ""
    status: str = "PENDING"  # PENDING, CONFIRMED, REJECTED, LOCKED, EXPIRED
    failed_attempts: int = 0
    max_failed_attempts: int = 3
    owner_approved: bool = False
    approved_by: str | None = None
    executed: bool = False
    is_tainted: bool = False
    base_risk_tier: RiskLevel | None = None
    escalation_reason: str | None = None


class ConfirmationGateway:
    """Cryptographic Human-in-the-Loop Confirmation Gateway backed by SQLite persistence."""

    def __init__(
        self,
        policy: RiskPolicy | None = None,
        server_secret: bytes | None = None,
        default_ttl_seconds: float = 60.0,
        time_provider: Callable[[], float] | None = None,
        taint_tracker: TaintTracker | None = None,
        audit_logger: AuditLogger | None = None,
        storage: AegisStorage | None = None,
    ) -> None:
        self.policy = policy or RiskPolicy.default()
        self.server_secret = server_secret or os.getenv("AEGIS_SECRET_KEY", "aegis-dev-secret-key").encode("utf-8")
        self.default_ttl_seconds = default_ttl_seconds
        self._time_provider = time_provider or time.time
        self.storage = storage if storage is not None else get_storage(time_provider=self._time_provider)
        self.taint_tracker = taint_tracker if taint_tracker is not None else get_taint_tracker(storage=self.storage)
        self.audit_logger = audit_logger if audit_logger is not None else get_audit_logger(storage=self.storage)

    def propose(
        self,
        device: str,
        action: str,
        params: dict[str, Any] | None = None,
        session_id: str = "",
        ttl_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Propose a smart-home action and evaluate risk, escalating if the session is tainted.

        Args:
            device: Target device name (e.g. 'front_door_lock', 'thermostat').
            action: Action being attempted (e.g. 'unlock', 'set_temperature').
            params: Optional dictionary of action parameters.
            session_id: Calling client or MCP session identifier.
            ttl_seconds: Proposal validity lifetime in seconds (defaults to 60s).

        Returns:
            Dictionary with proposal_id, risk_tier, summary, expires_at, and
            for MEDIUM/HIGH risk tiers a 4-digit voice code.
        """
        now = self._time_provider()
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl_seconds
        expires_at = now + ttl

        base_risk = self.policy.get_risk(device, action)
        effective_risk, is_tainted, escalation_reason = self.taint_tracker.evaluate_risk(
            base_risk=base_risk,
            session_id=session_id,
        )

        proposal_id = f"prop-{secrets.token_hex(6)}"
        nonce = secrets.token_hex(4)

        canonical_json = canonicalize_action(device, action, params)
        action_digest = compute_action_digest(canonical_json)

        # Generate 4-digit voice code for MEDIUM and HIGH effective tiers
        if effective_risk in (RiskLevel.MEDIUM, RiskLevel.HIGH):
            voice_code = derive_voice_code(
                self.server_secret,
                proposal_id,
                action_digest,
                nonce,
                expires_at,
            )
        else:
            voice_code = None

        summary = f"Action '{action}' on '{device}' (Risk: {effective_risk.value}"
        if is_tainted:
            summary += f", Base: {base_risk.value} [TAINTED: {escalation_reason}]"
        summary += ")"
        if params:
            summary += f" with parameters {params}"

        proposal = Proposal(
            proposal_id=proposal_id,
            device=device,
            action=action,
            params=params or {},
            canonical_action_json=canonical_json,
            action_digest=action_digest,
            risk_tier=effective_risk,
            summary=summary,
            created_at=now,
            expires_at=expires_at,
            nonce=nonce,
            voice_code=voice_code,
            session_id=session_id,
            status="PENDING",
            failed_attempts=0,
            owner_approved=False,
            executed=False,
            is_tainted=is_tainted,
            base_risk_tier=base_risk,
            escalation_reason=escalation_reason,
        )

        self.storage.save_proposal(proposal)
        self.audit_logger.log_proposal(proposal, reason=summary)

        response: dict[str, Any] = {
            "proposal_id": proposal_id,
            "risk_tier": effective_risk.value,
            "base_risk_tier": base_risk.value,
            "is_tainted": is_tainted,
            "summary": summary,
            "expires_at": expires_at,
            "status": "PENDING",
        }

        if escalation_reason is not None:
            response["escalation_reason"] = escalation_reason

        if voice_code is not None:
            response["voice_code"] = voice_code

        # For LOW risk tier, indicate immediate execution eligibility
        if effective_risk == RiskLevel.LOW:
            response["requires_code"] = False
            response["requires_owner_approval"] = False
        elif effective_risk == RiskLevel.MEDIUM:
            response["requires_code"] = True
            response["requires_owner_approval"] = False
        else:  # HIGH
            response["requires_code"] = True
            response["requires_owner_approval"] = True

        return response

    def approve(self, proposal_id: str, approver_id: str = "caregiver_phone") -> dict[str, Any]:
        """Approve a HIGH-risk proposal via an authenticated out-of-band owner channel."""
        proposal = self.storage.get_proposal(proposal_id)
        if not proposal:
            self.audit_logger.log_block(
                proposal_id=proposal_id,
                reason=f"Proposal '{proposal_id}' was not found.",
                error_type="ProposalNotFoundError",
            )
            raise ProposalNotFoundError(f"Proposal '{proposal_id}' was not found.")

        now = self._time_provider()
        if now >= proposal.expires_at:
            self.storage.update_proposal_status(proposal_id, status="EXPIRED")
            self.audit_logger.log_block(
                proposal_id=proposal_id,
                device=proposal.device,
                action=proposal.action,
                risk_tier=proposal.risk_tier.value,
                session_id=proposal.session_id,
                reason=f"Proposal '{proposal_id}' has expired.",
                error_type="ProposalExpiredError",
            )
            raise ProposalExpiredError(f"Proposal '{proposal_id}' has expired.")

        if proposal.status == "LOCKED":
            self.audit_logger.log_block(
                proposal_id=proposal_id,
                device=proposal.device,
                action=proposal.action,
                risk_tier=proposal.risk_tier.value,
                session_id=proposal.session_id,
                reason=f"Proposal '{proposal_id}' is locked.",
                error_type="ProposalLockedError",
            )
            raise ProposalLockedError(f"Proposal '{proposal_id}' is locked.")

        if proposal.status == "CONFIRMED" or proposal.executed or self.storage.is_code_used(proposal_id):
            self.audit_logger.log_block(
                proposal_id=proposal_id,
                device=proposal.device,
                action=proposal.action,
                risk_tier=proposal.risk_tier.value,
                session_id=proposal.session_id,
                reason=f"Proposal '{proposal_id}' has already been confirmed.",
                error_type="ProposalAlreadyConfirmedError",
            )
            raise ProposalAlreadyConfirmedError(f"Proposal '{proposal_id}' has already been confirmed.")

        self.storage.update_proposal_status(
            proposal_id=proposal_id,
            status=proposal.status,
            approved_by_owner=True,
            approved_by=approver_id,
        )

        self.audit_logger.log_event(
            event_type="APPROVAL",
            proposal_id=proposal_id,
            device=proposal.device,
            action=proposal.action,
            risk_tier=proposal.risk_tier.value,
            session_id=proposal.session_id,
            reason=f"Approved by {approver_id}",
            details={"approved_by": approver_id},
        )

        return {
            "proposal_id": proposal_id,
            "owner_approved": True,
            "approved_by": approver_id,
            "status": proposal.status,
        }

    def confirm(
        self,
        proposal_id: str,
        code: str | None = None,
        expected_device: str | None = None,
        expected_action: str | None = None,
        expected_params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Confirm a proposed action, verifying all security guardrails atomically.

        Args:
            proposal_id: Unique proposal ID.
            code: 4-digit voice confirmation code (required for MEDIUM/HIGH).
            expected_device: Optional expected device for tamper verification.
            expected_action: Optional expected action for tamper verification.
            expected_params: Optional expected parameters for tamper verification.

        Returns:
            Dictionary with confirmation verdict and execution status.
        """
        now = self._time_provider()

        with self.storage._lock:
            conn = self.storage._get_connection()
            try:
                conn.execute("BEGIN IMMEDIATE;")

                # 1. Replay check via used_codes table
                cur = conn.execute("SELECT used_at FROM used_codes WHERE proposal_id = ?;", (proposal_id,))
                if cur.fetchone() is not None:
                    conn.execute("ROLLBACK;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        reason=f"Proposal '{proposal_id}' has already been executed. Replay rejected.",
                        error_type="ProposalAlreadyConfirmedError",
                    )
                    raise ProposalAlreadyConfirmedError(
                        f"Proposal '{proposal_id}' has already been executed. Replay rejected."
                    )

                # 2. Proposal existence check
                cur = conn.execute("SELECT * FROM proposals WHERE id = ?;", (proposal_id,))
                row = cur.fetchone()
                if not row:
                    conn.execute("ROLLBACK;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        reason=f"Proposal '{proposal_id}' was not found.",
                        error_type="ProposalNotFoundError",
                    )
                    raise ProposalNotFoundError(f"Proposal '{proposal_id}' was not found.")

                device = row["device"] or ""
                action = row["action"] or ""
                risk_val = row["risk"]
                session_id = row["session_id"] or ""
                attempts = row["attempts"]
                status = row["status"]
                executed = row["executed"]
                expires_at = row["expires_at"]
                voice_code = row["voice_code"]
                approved_by_owner = bool(row["approved_by_owner"])
                action_hash = row["action_hash"]
                params = json.loads(row["params_json"] or "{}")
                summary = row["summary"] or ""

                # 3. Replay check via proposal status
                if status == "CONFIRMED" or executed == 1:
                    conn.execute("ROLLBACK;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        device=device,
                        action=action,
                        risk_tier=risk_val,
                        session_id=session_id,
                        reason=f"Proposal '{proposal_id}' has already been executed. Replay rejected.",
                        error_type="ProposalAlreadyConfirmedError",
                    )
                    raise ProposalAlreadyConfirmedError(
                        f"Proposal '{proposal_id}' has already been executed. Replay rejected."
                    )

                # 4. Lock check
                if status == "LOCKED" or attempts >= 3:
                    conn.execute("UPDATE proposals SET status = 'LOCKED' WHERE id = ?;", (proposal_id,))
                    conn.execute("COMMIT;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        device=device,
                        action=action,
                        risk_tier=risk_val,
                        session_id=session_id,
                        reason=f"Proposal '{proposal_id}' is locked due to too many failed confirmation attempts.",
                        error_type="ProposalLockedError",
                    )
                    raise ProposalLockedError(
                        f"Proposal '{proposal_id}' is locked due to too many failed confirmation attempts."
                    )

                # 5. Expiry check
                if now >= expires_at:
                    conn.execute("UPDATE proposals SET status = 'EXPIRED' WHERE id = ?;", (proposal_id,))
                    conn.execute("COMMIT;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        device=device,
                        action=action,
                        risk_tier=risk_val,
                        session_id=session_id,
                        reason=f"Proposal '{proposal_id}' has expired.",
                        error_type="ProposalExpiredError",
                    )
                    raise ProposalExpiredError(f"Proposal '{proposal_id}' has expired.")

                # 6. Tamper check
                if expected_device is not None or expected_action is not None or expected_params is not None:
                    chk_device = expected_device if expected_device is not None else device
                    chk_action = expected_action if expected_action is not None else action
                    chk_params = expected_params if expected_params is not None else params
                    current_canonical = canonicalize_action(chk_device, chk_action, chk_params)
                    current_digest = compute_action_digest(current_canonical)
                    if current_digest != action_hash:
                        conn.execute("ROLLBACK;")
                        self.audit_logger.log_block(
                            proposal_id=proposal_id,
                            device=chk_device,
                            action=chk_action,
                            risk_tier=risk_val,
                            session_id=session_id,
                            reason=f"Action mismatch detected for proposal '{proposal_id}'. Payload does not match proposal digest.",
                            error_type="ActionTamperedError",
                        )
                        raise ActionTamperedError(
                            f"Action mismatch detected for proposal '{proposal_id}'. Payload does not match proposal digest."
                        )

                # 7. Code check for MEDIUM and HIGH
                if risk_val in (RiskLevel.MEDIUM.value, RiskLevel.HIGH.value):
                    submitted_code = str(code).strip() if code is not None else ""
                    if not hmac.compare_digest(submitted_code, voice_code or ""):
                        new_attempts = attempts + 1
                        if new_attempts >= 3:
                            conn.execute(
                                "UPDATE proposals SET attempts = ?, status = 'LOCKED' WHERE id = ?;",
                                (new_attempts, proposal_id),
                            )
                            conn.execute("COMMIT;")
                            self.audit_logger.log_block(
                                proposal_id=proposal_id,
                                device=device,
                                action=action,
                                risk_tier=risk_val,
                                session_id=session_id,
                                reason=f"Invalid confirmation code. Maximum attempts (3) exceeded. Proposal is now LOCKED.",
                                error_type="ProposalLockedError",
                                details={"failed_attempts": new_attempts},
                            )
                            raise ProposalLockedError(
                                f"Invalid confirmation code. Maximum attempts (3) exceeded. Proposal is now LOCKED."
                            )
                        else:
                            conn.execute(
                                "UPDATE proposals SET attempts = ? WHERE id = ?;",
                                (new_attempts, proposal_id),
                            )
                            conn.execute("COMMIT;")
                            self.audit_logger.log_block(
                                proposal_id=proposal_id,
                                device=device,
                                action=action,
                                risk_tier=risk_val,
                                session_id=session_id,
                                reason=f"Invalid confirmation code. Attempt {new_attempts} of 3.",
                                error_type="InvalidCodeError",
                                details={"failed_attempts": new_attempts},
                            )
                            raise InvalidCodeError(
                                f"Invalid confirmation code. Attempt {new_attempts} of 3."
                            )

                # 8. Out-of-band owner approval check for HIGH
                if risk_val == RiskLevel.HIGH.value and not approved_by_owner:
                    conn.execute("ROLLBACK;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        device=device,
                        action=action,
                        risk_tier=risk_val,
                        session_id=session_id,
                        reason=f"HIGH risk proposal '{proposal_id}' requires out-of-band owner approval before confirmation.",
                        error_type="MissingOwnerApprovalError",
                    )
                    raise MissingOwnerApprovalError(
                        f"HIGH risk proposal '{proposal_id}' requires out-of-band owner approval before confirmation."
                    )

                # 9. Record used code atomically (PRIMARY KEY constraint prevents race condition)
                try:
                    conn.execute("INSERT INTO used_codes (proposal_id, used_at) VALUES (?, ?);", (proposal_id, now))
                except sqlite3.IntegrityError:
                    conn.execute("ROLLBACK;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        device=device,
                        action=action,
                        risk_tier=risk_val,
                        session_id=session_id,
                        reason=f"Proposal '{proposal_id}' has already been executed. Replay rejected.",
                        error_type="ProposalAlreadyConfirmedError",
                    )
                    raise ProposalAlreadyConfirmedError(
                        f"Proposal '{proposal_id}' has already been executed. Replay rejected."
                    )

                # 10. Update proposal status
                cur_upd = conn.execute(
                    "UPDATE proposals SET status = 'CONFIRMED', executed = 1 WHERE id = ? AND status = 'PENDING';",
                    (proposal_id,),
                )
                if cur_upd.rowcount != 1:
                    conn.execute("ROLLBACK;")
                    self.audit_logger.log_block(
                        proposal_id=proposal_id,
                        device=device,
                        action=action,
                        risk_tier=risk_val,
                        session_id=session_id,
                        reason=f"Proposal '{proposal_id}' has already been executed. Replay rejected.",
                        error_type="ProposalAlreadyConfirmedError",
                    )
                    raise ProposalAlreadyConfirmedError(
                        f"Proposal '{proposal_id}' has already been executed. Replay rejected."
                    )

                conn.execute("COMMIT;")
            except ConfirmationError:
                raise
            except Exception:
                try:
                    conn.execute("ROLLBACK;")
                except Exception:
                    pass
                raise

        # Log confirmation

        prop_record = self.storage.get_proposal(proposal_id)
        self.audit_logger.log_confirmation(prop_record, reason="Action confirmed and executed")

        return {
            "proposal_id": proposal_id,
            "status": "CONFIRMED",
            "executed": True,
            "device": device,
            "action": action,
            "params": params,
            "risk_tier": risk_val,
            "summary": summary,
        }

    def get_proposal(self, proposal_id: str) -> Proposal | None:
        """Retrieve the Proposal record from storage if it exists."""
        return self.storage.get_proposal(proposal_id)

    def get_all_proposals(self) -> list[Proposal]:
        """Retrieve all proposals from storage."""
        return self.storage.get_all_proposals()

    @property
    def _proposals(self) -> dict[str, Proposal]:
        """Backward-compatible mapping of proposals."""
        return {p.proposal_id: p for p in self.storage.get_all_proposals()}

    def reset(self) -> None:
        """Clear all active proposals from storage (for tests)."""
        self.storage.reset()



# Global in-memory gateway singleton
_GLOBAL_GATEWAY: ConfirmationGateway | None = None


def get_confirmation_gateway(storage: AegisStorage | None = None) -> ConfirmationGateway:
    """Retrieve or initialize the global ConfirmationGateway instance."""
    global _GLOBAL_GATEWAY
    if _GLOBAL_GATEWAY is None:
        _GLOBAL_GATEWAY = ConfirmationGateway(storage=storage)
    elif storage is not None and _GLOBAL_GATEWAY.storage != storage:
        _GLOBAL_GATEWAY = ConfirmationGateway(storage=storage)
    return _GLOBAL_GATEWAY


def reset_confirmation_gateway() -> ConfirmationGateway:
    """Reset and reinitialize global confirmation gateway."""
    global _GLOBAL_GATEWAY
    gw = get_confirmation_gateway()
    gw.reset()
    return gw

