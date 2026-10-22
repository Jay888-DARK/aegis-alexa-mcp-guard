"""Unit tests for RiskPolicy and fail-closed security guarantees."""

import pytest
from aegis_guard.policy import RiskPolicy, RiskLevel


SAMPLE_POLICY_YAML = """
version: "1.0"
default_risk: "HIGH"

rules:
  - device: "thermostat"
    action: "set"
    risk: "LOW"
  - device: "garage"
    action: "open"
    risk: "MEDIUM"
  - device: "front_door"
    action: "unlock"
    risk: "HIGH"
  - device: "front_door_lock"
    action: "unlock"
    risk: "HIGH"
  - device: "front_door_lock"
    action: "lock"
    risk: "LOW"
"""


def test_risk_level_ordering() -> None:
    """Verify RiskLevel comparison hierarchy."""
    assert RiskLevel.HIGH > RiskLevel.MEDIUM
    assert RiskLevel.MEDIUM > RiskLevel.LOW
    assert RiskLevel.HIGH > RiskLevel.LOW
    assert RiskLevel.LOW < RiskLevel.HIGH
    assert RiskLevel.HIGH >= RiskLevel.HIGH
    assert RiskLevel.LOW <= RiskLevel.MEDIUM


def test_policy_lookups_from_yaml_string() -> None:
    """Verify exact policy lookups for mapped rules."""
    policy = RiskPolicy.from_yaml_string(SAMPLE_POLICY_YAML)

    # Required examples from hackathon spec:
    # thermostat set = LOW
    assert policy.get_risk("thermostat", "set") == RiskLevel.LOW
    assert not policy.is_high_risk("thermostat", "set")
    assert not policy.requires_confirmation("thermostat", "set")

    # garage open = MEDIUM
    assert policy.get_risk("garage", "open") == RiskLevel.MEDIUM
    assert policy.requires_confirmation("garage", "open")
    assert not policy.is_high_risk("garage", "open")

    # front door unlock = HIGH
    assert policy.get_risk("front_door", "unlock") == RiskLevel.HIGH
    assert policy.get_risk("front_door_lock", "unlock") == RiskLevel.HIGH
    assert policy.is_high_risk("front_door", "unlock")
    assert policy.requires_confirmation("front_door", "unlock")

    # front door lock = LOW
    assert policy.get_risk("front_door_lock", "lock") == RiskLevel.LOW


def test_unknown_action_defaults_to_high_fail_closed() -> None:
    """Verify unknown action defaults to HIGH (Fail Closed)."""
    policy = RiskPolicy.from_yaml_string(SAMPLE_POLICY_YAML)

    # Unknown actions on known devices
    assert policy.get_risk("thermostat", "disable_safety_limit") == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "firmware_flash") == RiskLevel.HIGH
    assert policy.get_risk("front_door", "remove_pin") == RiskLevel.HIGH
    assert policy.get_risk("garage", "detonate") == RiskLevel.HIGH

    # Unknown devices with known or unknown actions
    assert policy.get_risk("unknown_drone", "fly") == RiskLevel.HIGH
    assert policy.get_risk("smart_oven", "self_clean") == RiskLevel.HIGH
    assert policy.get_risk("medication_dispenser", "dispense_all") == RiskLevel.HIGH

    # Missing or empty strings
    assert policy.get_risk("", "") == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "") == RiskLevel.HIGH
    assert policy.get_risk("", "set") == RiskLevel.HIGH


def test_normalization_and_whitespace_tolerance() -> None:
    """Verify case-insensitivity and hyphen/underscore normalization."""
    policy = RiskPolicy.from_yaml_string(SAMPLE_POLICY_YAML)

    assert policy.get_risk("Thermostat", "SET") == RiskLevel.LOW
    assert policy.get_risk("  thermostat  ", "  set  ") == RiskLevel.LOW
    assert policy.get_risk("front-door", "UNLOCK") == RiskLevel.HIGH
    assert policy.get_risk("Front_Door_Lock", "Lock") == RiskLevel.LOW


def test_default_policy_loads_bundled_yaml() -> None:
    """Verify default() loads the bundled policy.yaml with all smart home devices."""
    policy = RiskPolicy.default()
    assert policy.rule_count > 0

    assert policy.get_risk("thermostat", "set") == RiskLevel.LOW
    assert policy.get_risk("thermostat", "set_temperature") == RiskLevel.LOW
    assert policy.get_risk("garage_door", "open") == RiskLevel.MEDIUM
    assert policy.get_risk("front_door_lock", "unlock") == RiskLevel.HIGH
    assert policy.get_risk("porch_camera", "read") == RiskLevel.LOW
    assert policy.get_risk("package_sensor", "read") == RiskLevel.LOW

    # Unmapped action on bundled policy fails closed to HIGH
    assert policy.get_risk("front_door_lock", "factory_reset") == RiskLevel.HIGH


def test_missing_policy_file_fails_closed(tmp_path: pytest.TempPathFactory) -> None:
    """Verify non-existent policy file fails closed gracefully."""
    non_existent = tmp_path / "does_not_exist.yaml"
    policy = RiskPolicy.from_yaml_file(non_existent)
    assert policy.get_risk("thermostat", "set") == RiskLevel.HIGH
    assert policy.get_risk("anything", "anything") == RiskLevel.HIGH


def test_temperature_safety_cap() -> None:
    """Verify temperature safety caps dynamically elevate extreme climate changes to HIGH risk."""
    policy = RiskPolicy.default()

    # Normal human comfort range [65.0°F, 80.0°F] -> LOW risk
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 70.0}) == RiskLevel.LOW
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 72.0}) == RiskLevel.LOW
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 65.0}) == RiskLevel.LOW
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 80.0}) == RiskLevel.LOW

    # Extreme low temperatures (< 65.0°F) -> Dynamically elevated to HIGH risk
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 64.9}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 55.0}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 40.0}) == RiskLevel.HIGH

    # Extreme high temperatures (> 80.0°F) -> Dynamically elevated to HIGH risk
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 80.1}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 85.0}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": 99.0}) == RiskLevel.HIGH

    # Alternate parameter keys (target_temperature, target_temp_f, temp)
    assert policy.get_risk("thermostat", "set_temperature", {"target_temperature": 88.0}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"target_temp_f": 60.0}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"temp": 95.0}) == RiskLevel.HIGH
    assert policy.get_risk("thermostat", "set_temperature", {"temperature": "invalid"}) == RiskLevel.HIGH

