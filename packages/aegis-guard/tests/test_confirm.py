"""Unit tests for the Aegis Guard Two-Step Confirmation Gateway."""

import pytest
from aegis_guard.confirm import (
    ConfirmationGateway,
    ProposalExpiredError,
    ProposalLockedError,
    ProposalAlreadyConfirmedError,
    InvalidCodeError,
    MissingOwnerApprovalError,
    ActionTamperedError,
    ProposalNotFoundError,
)
from aegis_guard.policy import RiskPolicy


class MockClock:
    """Injectable simulated time provider for deterministic expiry testing."""

    def __init__(self, start_time: float = 1_000_000.0) -> None:
        self.current_time = start_time

    def __call__(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


@pytest.fixture
def clock() -> MockClock:
    return MockClock()


@pytest.fixture
def gateway(clock: MockClock) -> ConfirmationGateway:
    return ConfirmationGateway(
        policy=RiskPolicy.default(),
        server_secret=b"test-secret-key-12345",
        default_ttl_seconds=60.0,
        time_provider=clock,
    )


def test_happy_path_low_tier(gateway: ConfirmationGateway) -> None:
    """Verify LOW-tier action executes immediately without voice code or owner approval."""
    res = gateway.propose(
        device="thermostat",
        action="set",
        params={"temperature": 72.0},
    )
    assert res["risk_tier"] == "LOW"
    assert res["requires_code"] is False
    assert res["requires_owner_approval"] is False
    assert "voice_code" not in res

    confirm_res = gateway.confirm(res["proposal_id"])
    assert confirm_res["status"] == "CONFIRMED"
    assert confirm_res["executed"] is True
    assert confirm_res["risk_tier"] == "LOW"


def test_happy_path_medium_tier(gateway: ConfirmationGateway) -> None:
    """Verify MEDIUM-tier action requires 4-digit voice code but no owner approval."""
    res = gateway.propose(
        device="garage_door",
        action="open",
        params={"target": "main_garage"},
    )
    assert res["risk_tier"] == "MEDIUM"
    assert res["requires_code"] is True
    assert res["requires_owner_approval"] is False
    assert "voice_code" in res
    voice_code = res["voice_code"]
    assert len(voice_code) == 4
    assert voice_code.isdigit()

    confirm_res = gateway.confirm(res["proposal_id"], code=voice_code)
    assert confirm_res["status"] == "CONFIRMED"
    assert confirm_res["executed"] is True
    assert confirm_res["risk_tier"] == "MEDIUM"


def test_happy_path_high_tier_with_owner_approval(gateway: ConfirmationGateway) -> None:
    """Verify HIGH-tier action requires out-of-band owner approval AND 4-digit voice code."""
    res = gateway.propose(
        device="front_door_lock",
        action="unlock",
        params={"temporary_guest": "visiting_nurse"},
    )
    assert res["risk_tier"] == "HIGH"
    assert res["requires_code"] is True
    assert res["requires_owner_approval"] is True
    proposal_id = res["proposal_id"]
    voice_code = res["voice_code"]

    # 1. Out-of-band owner approval (simulated phone channel)
    appr = gateway.approve(proposal_id, approver_id="caregiver_iphone_auth")
    assert appr["owner_approved"] is True

    # 2. Voice code confirmation
    confirm_res = gateway.confirm(proposal_id, code=voice_code)
    assert confirm_res["status"] == "CONFIRMED"
    assert confirm_res["executed"] is True
    assert confirm_res["risk_tier"] == "HIGH"


def test_high_tier_without_owner_approval_rejected(gateway: ConfirmationGateway) -> None:
    """Verify HIGH-tier action is rejected if confirmed without owner approval."""
    res = gateway.propose(
        device="front_door_lock",
        action="unlock",
    )
    proposal_id = res["proposal_id"]
    voice_code = res["voice_code"]

    # Attempt to confirm directly without approval
    with pytest.raises(MissingOwnerApprovalError) as exc_info:
        gateway.confirm(proposal_id, code=voice_code)

    assert "requires out-of-band owner approval" in str(exc_info.value)
    proposal = gateway.get_proposal(proposal_id)
    assert proposal is not None
    assert proposal.executed is False


def test_replay_attack_rejected(gateway: ConfirmationGateway) -> None:
    """Verify confirmed proposals cannot be replayed or reused."""
    res = gateway.propose(device="garage_door", action="open")
    proposal_id = res["proposal_id"]
    voice_code = res["voice_code"]

    # First confirmation succeeds
    gateway.confirm(proposal_id, code=voice_code)

    # Replay attempt
    with pytest.raises(ProposalAlreadyConfirmedError) as exc_info:
        gateway.confirm(proposal_id, code=voice_code)

    assert "already been executed" in str(exc_info.value)


def test_expiry_with_injectable_clock(gateway: ConfirmationGateway, clock: MockClock) -> None:
    """Verify proposal rejection past its 60s validity window."""
    res = gateway.propose(device="garage_door", action="open", ttl_seconds=60.0)
    proposal_id = res["proposal_id"]
    voice_code = res["voice_code"]

    # Advance clock by 59 seconds (still valid)
    clock.advance(59.0)
    proposal = gateway.get_proposal(proposal_id)
    assert proposal is not None
    assert proposal.status == "PENDING"

    # Advance past 60s
    clock.advance(2.0)  # total 61 seconds elapsed

    with pytest.raises(ProposalExpiredError) as exc_info:
        gateway.confirm(proposal_id, code=voice_code)

    assert "has expired" in str(exc_info.value)


def test_tampered_action_rejected(gateway: ConfirmationGateway) -> None:
    """Verify code is bound to exact action payload and rejects tampered arguments."""
    res = gateway.propose(
        device="front_door_lock",
        action="unlock",
        params={"door": "front", "user": "authorized_nurse"},
    )
    proposal_id = res["proposal_id"]
    voice_code = res["voice_code"]
    gateway.approve(proposal_id)

    # Attempt confirmation with tampered params
    with pytest.raises(ActionTamperedError) as exc_info:
        gateway.confirm(
            proposal_id,
            code=voice_code,
            expected_params={"door": "front", "user": "unauthorized_attacker"},
        )

    assert "Action mismatch detected" in str(exc_info.value)


def test_brute_force_lockout_after_three_attempts(gateway: ConfirmationGateway) -> None:
    """Verify proposal locks permanently after 3 consecutive wrong code attempts."""
    res = gateway.propose(device="garage_door", action="open")
    proposal_id = res["proposal_id"]
    real_code = res["voice_code"]
    wrong_code = "9999" if real_code != "9999" else "0000"

    # Attempt 1: wrong code
    with pytest.raises(InvalidCodeError) as e1:
        gateway.confirm(proposal_id, code=wrong_code)
    assert "Attempt 1 of 3" in str(e1.value)

    # Attempt 2: wrong code
    with pytest.raises(InvalidCodeError) as e2:
        gateway.confirm(proposal_id, code=wrong_code)
    assert "Attempt 2 of 3" in str(e2.value)

    # Attempt 3: wrong code -> LOCKOUT
    with pytest.raises(ProposalLockedError) as e3:
        gateway.confirm(proposal_id, code=wrong_code)
    assert "Proposal is now LOCKED" in str(e3.value)

    # Attempt 4: even with the REAL correct code, must reject as LOCKED
    with pytest.raises(ProposalLockedError) as e4:
        gateway.confirm(proposal_id, code=real_code)
    assert "is locked" in str(e4.value).lower()


def test_nonexistent_proposal_raises_not_found(gateway: ConfirmationGateway) -> None:
    """Verify looking up or confirming non-existent proposal raises ProposalNotFoundError."""
    with pytest.raises(ProposalNotFoundError):
        gateway.confirm("prop-does-not-exist", code="1234")

    with pytest.raises(ProposalNotFoundError):
        gateway.approve("prop-does-not-exist")
