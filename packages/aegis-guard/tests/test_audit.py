"""Tests for Aegis Guard Append-Only Audit Logger."""

import json
from pathlib import Path
import tempfile
import pytest

from aegis_guard.audit import AuditLogger, AuditEntry, get_audit_logger, reset_audit_logger
from aegis_guard.confirm import ConfirmationGateway
from aegis_guard.policy import RiskLevel


@pytest.fixture
def temp_audit_file(tmp_path: Path) -> Path:
    """Fixture providing a temporary audit log path."""
    return tmp_path / "test_audit.jsonl"


class TestAuditLogger:
    def test_log_proposal_creates_valid_jsonl(self, temp_audit_file: Path) -> None:
        logger = AuditLogger(temp_audit_file)
        gateway = ConfirmationGateway(audit_logger=logger)

        res = gateway.propose(
            device="front_door_lock",
            action="unlock",
            params={"source": "test"},
            session_id="session-123",
        )

        entries = logger.read_entries()
        assert len(entries) == 1
        entry = entries[0]
        assert entry["event_type"] == "PROPOSAL"
        assert entry["proposal_id"] == res["proposal_id"]
        assert entry["device"] == "front_door_lock"
        assert entry["action"] == "unlock"
        assert entry["risk_tier"] == RiskLevel.HIGH.value
        assert entry["session_id"] == "session-123"
        assert "params" in entry["details"]

    def test_log_confirmation_on_successful_action(self, temp_audit_file: Path) -> None:
        logger = AuditLogger(temp_audit_file)
        gateway = ConfirmationGateway(audit_logger=logger)

        res = gateway.propose(device="thermostat", action="set_temperature", params={"temperature": 70})
        prop_id = res["proposal_id"]

        # LOW risk allows immediate execution
        gateway.confirm(prop_id)

        entries = logger.read_entries()
        assert len(entries) == 2
        assert entries[0]["event_type"] == "PROPOSAL"
        assert entries[1]["event_type"] == "CONFIRMATION"
        assert entries[1]["proposal_id"] == prop_id
        assert entries[1]["action"] == "set_temperature"

    def test_log_block_on_invalid_code(self, temp_audit_file: Path) -> None:
        logger = AuditLogger(temp_audit_file)
        gateway = ConfirmationGateway(audit_logger=logger)

        res = gateway.propose(device="garage_door", action="open")
        prop_id = res["proposal_id"]

        with pytest.raises(Exception):
            gateway.confirm(prop_id, code="9999")  # wrong code

        entries = logger.read_entries()
        # Should have PROPOSAL, then BLOCK
        blocks = [e for e in entries if e["event_type"] == "BLOCK"]
        assert len(blocks) == 1
        assert blocks[0]["proposal_id"] == prop_id
        assert blocks[0]["error_type"] == "InvalidCodeError"
        assert "Invalid confirmation code" in blocks[0]["reason"]

    def test_log_block_on_replay(self, temp_audit_file: Path) -> None:
        logger = AuditLogger(temp_audit_file)
        gateway = ConfirmationGateway(audit_logger=logger)

        res = gateway.propose(device="thermostat", action="set_temperature", params={"temperature": 70})
        prop_id = res["proposal_id"]
        gateway.confirm(prop_id)

        # Attempt replay
        with pytest.raises(Exception):
            gateway.confirm(prop_id)

        entries = logger.read_entries()
        replays = [e for e in entries if e["error_type"] == "ProposalAlreadyConfirmedError"]
        assert len(replays) == 1
        assert "Replay rejected" in replays[0]["reason"]

    def test_log_block_on_action_tampering(self, temp_audit_file: Path) -> None:
        logger = AuditLogger(temp_audit_file)
        gateway = ConfirmationGateway(audit_logger=logger)

        res = gateway.propose(device="thermostat", action="set_temperature", params={"temperature": 70})
        prop_id = res["proposal_id"]

        with pytest.raises(Exception):
            gateway.confirm(prop_id, expected_action="unlock")

        entries = logger.read_entries()
        tampered = [e for e in entries if e["error_type"] == "ActionTamperedError"]
        assert len(tampered) == 1
        assert "Action mismatch detected" in tampered[0]["reason"]

    def test_log_block_on_expired_proposal(self, temp_audit_file: Path) -> None:
        current_time = 1000.0

        def mock_time():
            return current_time

        logger = AuditLogger(temp_audit_file)
        gateway = ConfirmationGateway(audit_logger=logger, time_provider=mock_time, default_ttl_seconds=30.0)

        res = gateway.propose(device="thermostat", action="set_temperature")
        prop_id = res["proposal_id"]

        # Advance time past expiration
        current_time = 1050.0

        with pytest.raises(Exception):
            gateway.confirm(prop_id)

        entries = logger.read_entries()
        expired = [e for e in entries if e["error_type"] == "ProposalExpiredError"]
        assert len(expired) == 1
        assert "expired" in expired[0]["reason"]
