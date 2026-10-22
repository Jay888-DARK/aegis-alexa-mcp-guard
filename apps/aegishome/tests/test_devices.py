"""Unit and integration tests for simulated home devices and real status reporting."""

import pytest
from aegishome.devices import (
    SimulatedHome,
    FrontDoorLock,
    GarageDoor,
    PorchCamera,
    Thermostat,
    PackageSensor,
    CameraEvent,
    get_simulated_home,
    reset,
)
from aegishome.tools import get_home_status, propose_action, confirm_action


@pytest.fixture(autouse=True)
def reset_home_before_each_test() -> None:
    """Ensure every test runs with a fresh baseline home state."""
    reset()


def test_front_door_lock() -> None:
    """Verify front door lock states and transitions."""
    lock = FrontDoorLock()
    assert lock.locked is True
    assert lock.status == "locked"

    lock.unlock()
    assert lock.locked is False
    assert lock.status == "unlocked"

    lock.lock()
    assert lock.locked is True
    assert lock.status == "locked"


def test_garage_door() -> None:
    """Verify garage door open/close transitions."""
    door = GarageDoor()
    assert door.state == "closed"

    door.open()
    assert door.state == "open"

    door.close()
    assert door.state == "closed"


def test_porch_camera() -> None:
    """Verify porch camera tracks events with timestamps and dwell time in seconds."""
    camera = PorchCamera()
    assert len(camera.events) == 0

    evt1 = camera.add_event(
        event_type="person_at_door",
        dwell_time_seconds=35.0,
        description="Delivery driver standing at porch",
        timestamp="2026-10-20T12:00:00Z",
    )
    assert evt1.dwell_time_seconds == 35.0
    assert evt1.timestamp == "2026-10-20T12:00:00Z"
    assert camera.latest_event == evt1

    evt2 = camera.add_event(
        event_type="loitering_detected",
        dwell_time_seconds=120.5,
        description="Suspicious dwell time on porch",
    )
    assert len(camera.events) == 2
    assert camera.latest_event == evt2
    assert evt2.dwell_time_seconds == 120.5
    assert evt2.timestamp is not None


def test_thermostat() -> None:
    """Verify thermostat temperature settings and modes."""
    thermostat = Thermostat(temperature=70.0, target_temperature=70.0, hvac_mode="heat")
    assert thermostat.temperature == 70.0
    assert thermostat.target_temperature == 70.0
    assert thermostat.hvac_mode == "heat"

    thermostat.set_temperature(74.5)
    assert thermostat.target_temperature == 74.5

    thermostat.set_mode("cool")
    assert thermostat.hvac_mode == "cool"


def test_package_sensor() -> None:
    """Verify package sensor tracks presence and monetary value in USD."""
    sensor = PackageSensor()
    assert sensor.package_present is True
    assert sensor.package_value_usd == 120.0
    assert "Medication" in sensor.package_description

    sensor.clear()
    assert sensor.package_present is False
    assert sensor.package_value_usd == 0.0

    sensor.detect_package(value_usd=450.0, description="High-value medical equipment")
    assert sensor.package_present is True
    assert sensor.package_value_usd == 450.0


def test_simulated_home_reset() -> None:
    """Verify in-memory state persistence and reset() restores baseline state."""
    home = get_simulated_home()

    # Mutate all devices
    home.front_door_lock.unlock()
    home.garage_door.open()
    home.thermostat.set_temperature(82.0)
    home.package_sensor.clear()
    home.porch_camera.add_event("motion_alert", 10.0)

    # Verify mutations took effect
    assert home.front_door_lock.locked is False
    assert home.garage_door.state == "open"
    assert home.thermostat.target_temperature == 82.0
    assert home.package_sensor.package_present is False
    assert len(home.porch_camera.events) == 2

    # Reset
    reset()

    # Verify baseline state restored
    assert home.front_door_lock.locked is True
    assert home.garage_door.state == "closed"
    assert home.thermostat.target_temperature == 71.0
    assert home.package_sensor.package_present is True
    assert home.package_sensor.package_value_usd == 120.0
    assert len(home.porch_camera.events) == 1
    assert home.porch_camera.events[0].dwell_time_seconds == 42.5


def test_get_home_status_returns_real_simulated_device_values() -> None:
    """Verify get_home_status returns live, real values from simulated devices."""
    home = get_simulated_home()

    # Initial baseline
    status1 = get_home_status()
    assert status1["front_door_lock"]["locked"] is True
    assert status1["front_door_lock"]["status"] == "locked"
    assert status1["garage_door"]["state"] == "closed"
    assert status1["thermostat"]["current_temperature_f"] == 71.0
    assert status1["package_sensor"]["package_present"] is True
    assert status1["package_sensor"]["package_value_usd"] == 120.0
    assert status1["porch_camera"]["event_count"] >= 1
    assert status1["porch_camera"]["latest_event"]["dwell_time_seconds"] == 42.5

    # Apply real mutations directly to devices
    home.front_door_lock.unlock()
    home.garage_door.open()
    home.thermostat.set_temperature(76.0)
    home.package_sensor.detect_package(value_usd=250.0, description="Special delivery")
    home.porch_camera.add_event(
        event_type="caregiver_arrival",
        dwell_time_seconds=15.0,
        description="Visiting nurse arrived",
    )

    # Call get_home_status again and verify it reflects the real mutated device values
    status2 = get_home_status()
    assert status2["front_door_lock"]["locked"] is False
    assert status2["front_door_lock"]["status"] == "unlocked"
    assert status2["garage_door"]["state"] == "open"
    assert status2["thermostat"]["target_temperature"] == 76.0
    assert status2["package_sensor"]["package_value_usd"] == 250.0
    assert status2["porch_camera"]["latest_event"]["event_type"] == "caregiver_arrival"
    assert status2["porch_camera"]["latest_event"]["dwell_time_seconds"] == 15.0


def test_tool_propose_and_confirm_mutates_real_devices() -> None:
    """Verify proposing and confirming an action applies the change to real devices."""
    home = get_simulated_home()
    assert home.front_door_lock.locked is True

    # 1. Propose unlocking front door (HIGH risk)
    prop = propose_action("unlock", "front_door")
    assert prop["risk_tier"] == "HIGH"
    assert prop["status"] == "PENDING"
    assert "voice_code" in prop
    proposal_id = prop["proposal_id"]
    voice_code = prop["voice_code"]

    # Door must still be locked before confirmation
    assert home.front_door_lock.locked is True

    # 2. Confirm without owner approval should fail
    conf_fail = confirm_action(proposal_id, approved=True, code=voice_code)
    assert conf_fail["status"] == "CONFIRMATION_FAILED"
    assert conf_fail["executed"] is False
    assert home.front_door_lock.locked is True

    # 3. Owner approves via separate channel
    from aegishome.tools import approve_action
    appr = approve_action(proposal_id)
    assert appr["owner_approved"] is True

    # 4. Confirm with voice code and owner approval succeeds
    conf = confirm_action(proposal_id, approved=True, code=voice_code, reason="Caregiver verified identity")
    assert conf["status"] == "APPROVED"
    assert conf["executed"] is True

    # Door should now be real unlocked
    assert home.front_door_lock.locked is False

    # Check via get_home_status
    status = get_home_status()
    assert status["front_door_lock"]["locked"] is False
    assert status["front_door_lock"]["status"] == "unlocked"
