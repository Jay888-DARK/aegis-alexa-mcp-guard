"""Comprehensive tests for Aegis SQLite persistence layer, hash chaining, and concurrency."""

import concurrent.futures
from pathlib import Path
import sqlite3
import pytest

from aegis_guard.confirm import (
    ConfirmationGateway,
    InvalidCodeError,
    ProposalAlreadyConfirmedError,
    ProposalExpiredError,
    ProposalLockedError,
)
from aegis_guard.audit import AuditLogger
from aegis_guard.storage import AegisStorage
from aegis_guard.taint import TaintTracker


def test_confirm_replay_rejected_after_restart(tmp_path: Path) -> None:
    """Test (a): Confirm a proposal, simulate restart by creating a new storage instance

    on the same DB file, replay the code, must be rejected.
    """
    db_file = str(tmp_path / "test_storage_a.db")

    # Instance 1: Propose and confirm
    storage1 = AegisStorage(db_file)
    gw1 = ConfirmationGateway(storage=storage1)
    prop = gw1.propose(device="front_door_lock", action="unlock", session_id="session-a")
    proposal_id = prop["proposal_id"]
    code = prop["voice_code"]
    assert code is not None

    gw1.approve(proposal_id)
    confirm_res = gw1.confirm(proposal_id, code=code)
    assert confirm_res["status"] == "CONFIRMED"
    assert confirm_res["executed"] is True

    # Instance 2 (simulate restart on the same DB file)
    storage2 = AegisStorage(db_file)
    gw2 = ConfirmationGateway(storage=storage2)

    # Verify the proposal record survives restart
    saved_prop = gw2.get_proposal(proposal_id)
    assert saved_prop is not None
    assert saved_prop.status == "CONFIRMED"
    assert saved_prop.executed is True

    # Replay attempt on instance 2 must be rejected
    with pytest.raises(ProposalAlreadyConfirmedError) as exc_info:
        gw2.confirm(proposal_id, code=code)
    assert "already been executed" in str(exc_info.value)


def test_expired_proposals_stay_expired_after_restart(tmp_path: Path) -> None:
    """Test (b): Expired proposals stay expired after restart."""
    db_file = str(tmp_path / "test_storage_b.db")
    simulated_time = 1000.0

    # Instance 1: Propose with 60s TTL
    storage1 = AegisStorage(db_file, time_provider=lambda: simulated_time)
    gw1 = ConfirmationGateway(storage=storage1, time_provider=lambda: simulated_time)
    prop = gw1.propose(device="front_door_lock", action="unlock", ttl_seconds=60.0)
    proposal_id = prop["proposal_id"]
    code = prop["voice_code"]

    # Advance time past TTL (+70s)
    simulated_time = 1070.0

    # Instance 2 (simulate restart on the same DB file)
    storage2 = AegisStorage(db_file, time_provider=lambda: simulated_time)
    gw2 = ConfirmationGateway(storage=storage2, time_provider=lambda: simulated_time)

    # Attempt to confirm after restart must be rejected with ProposalExpiredError
    with pytest.raises(ProposalExpiredError):
        gw2.confirm(proposal_id, code=code)

    # Proposal state must be marked EXPIRED in storage
    saved_prop = gw2.get_proposal(proposal_id)
    assert saved_prop is not None
    assert saved_prop.status == "EXPIRED"


def test_lockout_after_three_failures_survives_restart(tmp_path: Path) -> None:
    """Test (c): Lockout after 3 failures survives restart."""
    db_file = str(tmp_path / "test_storage_c.db")

    # Instance 1: Propose and trigger 3 failed code attempts
    storage1 = AegisStorage(db_file)
    gw1 = ConfirmationGateway(storage=storage1)
    prop = gw1.propose(device="front_door_lock", action="unlock")
    proposal_id = prop["proposal_id"]
    valid_code = prop["voice_code"]
    gw1.approve(proposal_id)

    with pytest.raises(InvalidCodeError):
        gw1.confirm(proposal_id, code="0000")

    with pytest.raises(InvalidCodeError):
        gw1.confirm(proposal_id, code="0001")

    with pytest.raises(ProposalLockedError):
        gw1.confirm(proposal_id, code="0002")

    # Instance 2 (simulate restart on the same DB file)
    storage2 = AegisStorage(db_file)
    gw2 = ConfirmationGateway(storage=storage2)

    saved_prop = gw2.get_proposal(proposal_id)
    assert saved_prop is not None
    assert saved_prop.status == "LOCKED"
    assert saved_prop.failed_attempts >= 3

    # Attempting confirmation even with the VALID code must be rejected
    with pytest.raises(ProposalLockedError) as exc_info:
        gw2.confirm(proposal_id, code=valid_code)
    assert "locked" in str(exc_info.value).lower()


def test_edit_audit_row_detected_by_verify_chain(tmp_path: Path) -> None:
    """Test (d): Edit one audit row directly in SQLite, verify_chain() must detect it."""
    db_file = str(tmp_path / "test_storage_d.db")
    storage = AegisStorage(db_file)
    logger = AuditLogger(storage=storage)

    # Log 4 events
    logger.log_event("PROPOSAL", proposal_id="p-1", reason="Propose action 1")
    logger.log_event("APPROVAL", proposal_id="p-1", reason="Owner approved")
    logger.log_event("CONFIRMATION", proposal_id="p-1", reason="Voice code confirmed")
    logger.log_event("PROPOSAL", proposal_id="p-2", reason="Propose action 2")

    # Verification before tampering must succeed
    initial_verification = storage.verify_chain()
    assert initial_verification == "OK"
    assert initial_verification.is_valid is True

    # Directly edit row id 2 in SQLite (tampering with audit trail)
    conn = sqlite3.connect(db_file)
    conn.execute("UPDATE audit SET event = 'TAMPERED_EVENT' WHERE id = 2;")
    conn.commit()
    conn.close()

    # verify_chain() must detect the break
    corrupted_result = storage.verify_chain()
    assert corrupted_result != "OK"
    assert corrupted_result.is_valid is False
    # The broken index identifies the tampered row (index 1 or row_id 2)
    assert corrupted_result == 1 or corrupted_result == 2
    assert int(corrupted_result) == 1


def test_two_concurrent_confirms_exactly_one_succeeds(tmp_path: Path) -> None:
    """Test (e): Two concurrent confirms of the same code, exactly one succeeds."""
    db_file = str(tmp_path / "test_storage_e.db")
    storage = AegisStorage(db_file)
    gw = ConfirmationGateway(storage=storage)

    prop = gw.propose(device="front_door_lock", action="unlock")
    proposal_id = prop["proposal_id"]
    code = prop["voice_code"]
    gw.approve(proposal_id)

    results = []
    errors = []

    def attempt_confirm() -> None:
        try:
            res = gw.confirm(proposal_id, code=code)
            results.append(res)
        except Exception as err:
            errors.append(err)

    # Execute both confirms simultaneously
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(attempt_confirm)
        f2 = executor.submit(attempt_confirm)
        f1.result()
        f2.result()

    # Exactly one must succeed
    assert len(results) == 1
    assert results[0]["status"] == "CONFIRMED"
    assert results[0]["executed"] is True

    # Exactly one must fail with ProposalAlreadyConfirmedError
    assert len(errors) == 1
    assert isinstance(errors[0], ProposalAlreadyConfirmedError)


def test_taint_persists_across_restart(tmp_path: Path) -> None:
    """Verify session taint tracking persists in SQLite across storage restarts."""
    db_file = str(tmp_path / "test_storage_taint.db")

    storage1 = AegisStorage(db_file)
    tracker1 = TaintTracker(storage=storage1)
    tracker1.mark_tainted(session_id="session-persist", source="visitor_note:delivery", reason="Malicious prompt")
    assert tracker1.is_tainted("session-persist") is True

    # Restart
    storage2 = AegisStorage(db_file)
    tracker2 = TaintTracker(storage=storage2)
    assert tracker2.is_tainted("session-persist") is True
    record = tracker2.get_taint_record("session-persist")
    assert record is not None
    assert record.source == "visitor_note:delivery"
    assert record.reason == "Malicious prompt"
