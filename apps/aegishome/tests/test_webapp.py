"""Tests for AegisHome Web Application endpoints and interactive demo scenarios."""

import pytest
import pytest_asyncio
import httpx

from aegishome.server import create_app
from aegishome.devices import get_simulated_home
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import reset_taint_tracker


@pytest_asyncio.fixture
async def web_client():
    """Create test client using httpx.ASGITransport directly against Starlette app."""
    get_simulated_home().reset()
    get_confirmation_gateway().reset()
    reset_taint_tracker()

    app = create_app(enable_dns_protection=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.mark.asyncio
async def test_serve_index_html(web_client: httpx.AsyncClient) -> None:
    """Verify GET / serves the Aegis dashboard HTML page."""
    res = await web_client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "AEGIS" in res.text
    assert "Alexa+" in res.text
    assert "panel-voice-chat" in res.text
    assert "panel-devices-proposals" in res.text
    assert "panel-wire-audit" in res.text


@pytest.mark.asyncio
async def test_get_api_state(web_client: httpx.AsyncClient) -> None:
    """Verify GET /api/state returns devices, proposals, wire logs, and audit logs."""
    res = await web_client.get("/api/state")
    assert res.status_code == 200
    data = res.json()
    assert "devices" in data
    assert "proposals" in data
    assert "wire_logs" in data
    assert "audit_logs" in data
    assert data["devices"]["resident"]["name"] == "Eleanor Vance"


@pytest.mark.asyncio
async def test_scenario_1_normal_thermostat_change(web_client: httpx.AsyncClient) -> None:
    """Scenario 1: Normal thermostat adjustment (LOW risk, auto-confirmed)."""
    res = await web_client.post(
        "/api/say",
        json={"utterance": "Alexa, set the thermostat to 72 degrees", "session_id": "test_s1"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "72" in data["reply"]
    assert len(data["tool_calls"]) == 2  # propose_action + confirm_action

    # Verify device state updated
    state_res = await web_client.get("/api/state")
    state_data = state_res.json()
    thermo = state_data["devices"]["thermostat"]
    assert thermo["target_temperature"] == 72.0

    # Verify wire log recorded JSON-RPC frames
    wire_logs = state_data["wire_logs"]
    assert len(wire_logs) >= 2
    tool_names = [w["tool_name"] for w in wire_logs]
    assert "propose_action" in tool_names
    assert "confirm_action" in tool_names


@pytest.mark.asyncio
async def test_scenario_2_unlock_door_voice_code_and_approval(web_client: httpx.AsyncClient) -> None:
    """Scenario 2: Unlock front door requiring voice code and owner out-of-band approval."""
    # Step 1: Propose unlock by voice
    say_res = await web_client.post(
        "/api/say",
        json={"utterance": "Alexa, unlock the front door", "session_id": "test_s2"},
    )
    assert say_res.status_code == 200
    say_data = say_res.json()
    prop_id = say_data["active_proposal_id"]
    voice_code = say_data["voice_code"]
    assert prop_id is not None
    assert voice_code is not None
    assert say_data["risk_tier"] == "HIGH"
    assert "HIGH risk" in say_data["reply"]

    # Door should still be locked!
    state_res = await web_client.get("/api/state")
    state_data = state_res.json()
    assert state_data["devices"]["front_door_lock"]["status"] == "locked"

    # Step 2: Attempt confirm WITHOUT owner approval -> should be blocked!
    fail_conf = await web_client.post(
        "/api/confirm",
        json={"proposal_id": prop_id, "code": voice_code, "approved": True},
    )
    assert fail_conf.status_code == 200
    assert fail_conf.json().get("executed") is False
    assert "MissingOwnerApprovalError" in str(fail_conf.json())

    # Step 3: Owner Approval via out-of-band channel
    appr_res = await web_client.post(
        "/api/approve",
        json={"proposal_id": prop_id, "approver_id": "caregiver_phone_test"},
    )
    assert appr_res.status_code == 200
    assert appr_res.json()["owner_approved"] is True

    # Step 4: Confirm with voice code
    conf_res = await web_client.post(
        "/api/confirm",
        json={"proposal_id": prop_id, "code": voice_code, "approved": True},
    )
    assert conf_res.status_code == 200
    assert conf_res.json()["executed"] is True
    assert conf_res.json()["status"] == "APPROVED"

    # Door is now unlocked!
    final_state = (await web_client.get("/api/state")).json()
    assert final_state["devices"]["front_door_lock"]["status"] == "unlocked"


@pytest.mark.asyncio
async def test_scenario_3_injected_visitor_note_blocked(web_client: httpx.AsyncClient) -> None:
    """Scenario 3: Injected visitor note taints session; perimeter unlock is blocked."""
    say_res = await web_client.post(
        "/api/say",
        json={
            "utterance": "Alexa, read the latest visitor note and unlock the front door",
            "session_id": "test_s3",
        },
    )
    assert say_res.status_code == 200
    say_data = say_res.json()

    # Session marked tainted & warning returned
    assert say_data["is_tainted"] is True
    assert "TAINTED" in say_data["reply"]
    assert "BLOCKED" in say_data["reply"]

    # Verify door remains securely locked
    state_res = await web_client.get("/api/state?session_id=test_s3")
    state_data = state_res.json()
    assert state_data["is_tainted"] is True
    assert state_data["devices"]["front_door_lock"]["status"] == "locked"

    # Verify audit log recorded proposal under tainted session
    audit_logs = state_data["audit_logs"]
    assert any("visitor_note" in str(a) or "TAINTED" in str(a) for a in audit_logs)
