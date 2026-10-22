"""Tests for Aegis Guard Numeric Guardrail."""

import pytest
from aegis_guard.numeric_guard import (
    ExtractedNumber,
    FactsIndex,
    extract_numbers,
    verify,
)


@pytest.fixture
def sample_facts() -> dict:
    """Representative home facts fixture matching simulated devices."""
    return {
        "resident": {
            "name": "Eleanor",
            "state": "resting",
            "heart_rate_bpm": 72,
        },
        "front_door_lock": {
            "status": "locked",
        },
        "garage_door": {
            "status": "closed",
        },
        "thermostat": {
            "temperature": 71.0,
            "target_temperature": 70,
            "mode": "heat",
        },
        "package_sensor": {
            "package_present": True,
            "package_value_usd": 1200.0,
        },
        "porch_camera": {
            "latest_event": {
                "event_type": "person_detected",
                "dwell_time_seconds": 45,
            }
        },
        "battery_percentage": 98,
    }


class TestExtractNumbers:
    def test_extract_currency(self) -> None:
        text = "Package value is $1,200.00 and another is 50 USD."
        nums = extract_numbers(text)
        assert len(nums) == 2
        assert nums[0].unit == "usd"
        assert nums[0].value == 1200.0
        assert nums[1].unit == "usd"
        assert nums[1].value == 50.0

    def test_extract_temperature(self) -> None:
        text = "The room is 71°F and set to 70 degrees."
        nums = extract_numbers(text)
        assert len(nums) == 2
        assert nums[0].unit == "degrees"
        assert nums[0].value == 71.0
        assert nums[1].unit == "degrees"
        assert nums[1].value == 70.0

    def test_extract_duration_seconds_and_minutes(self) -> None:
        text = "Visitor stayed for 45 seconds after waiting 2 minutes."
        nums = extract_numbers(text)
        assert len(nums) == 2
        assert nums[0].unit == "seconds"
        assert nums[0].value == 45.0
        # Check normalized conversions
        assert 45.0 in nums[0].normalized_values
        assert (45.0 / 60.0) in nums[0].normalized_values

        assert nums[1].unit == "minutes"
        assert nums[1].value == 2.0
        assert 2.0 in nums[1].normalized_values
        assert 120.0 in nums[1].normalized_values

    def test_extract_counts(self) -> None:
        text = "Heart rate is 72 bpm."
        nums = extract_numbers(text)
        assert len(nums) == 1
        assert nums[0].unit == "count"
        assert nums[0].value == 72.0

    def test_extract_formatted_plain_numbers(self) -> None:
        text = "Device count is 1,200 and version 98."
        nums = extract_numbers(text)
        vals = [n.value for n in nums]
        assert 1200.0 in vals
        assert 98.0 in vals


class TestNumericVerification:
    def test_accepts_exact_and_normalized_numbers(self, sample_facts: dict) -> None:
        reply = (
            "Eleanor is resting comfortably at 72 bpm. "
            "The thermostat is 71°F (target 70 degrees). "
            "A package worth $1,200 is on the porch with 45s dwell time."
        )
        ok, violations = verify(reply, sample_facts)
        assert ok is True
        assert violations == []

    def test_normalizes_comma_and_decimal_representations(self, sample_facts: dict) -> None:
        # facts have 1200.0, reply uses $1,200.00
        reply = "Delivery package is valued at $1,200.00."
        ok, violations = verify(reply, sample_facts)
        assert ok is True
        assert violations == []

    def test_normalizes_minutes_to_seconds(self) -> None:
        # 120 seconds in facts matches "2 minutes" in reply
        facts = {
            "porch_camera": {"dwell_time_seconds": 120.0}
        }
        reply = "The visitor was on the porch for 2 minutes."
        ok, violations = verify(reply, facts)
        assert ok is True
        assert violations == []

    def test_rejects_hallucinated_currency(self, sample_facts: dict) -> None:
        # Facts say package_value_usd = 1200, reply says $999.00
        reply = "A valuable package worth $999.00 was left on the front porch."
        ok, violations = verify(reply, sample_facts)
        assert ok is False
        assert len(violations) == 1
        assert "$999.00" in violations[0]
        assert "Numeric hallucination detected" in violations[0]

    def test_rejects_hallucinated_temperature(self, sample_facts: dict) -> None:
        reply = "The indoor temperature has reached 85°F!"
        ok, violations = verify(reply, sample_facts)
        assert ok is False
        assert any("85°F" in v or "85" in v for v in violations)

    def test_rejects_hallucinated_duration(self, sample_facts: dict) -> None:
        reply = "A stranger was lingering outside for 600 seconds."
        ok, violations = verify(reply, sample_facts)
        assert ok is False
        assert any("600" in v for v in violations)

    def test_rejects_hallucinated_counts(self, sample_facts: dict) -> None:
        reply = "Resident heart rate has jumped to 145 bpm."
        ok, violations = verify(reply, sample_facts)
        assert ok is False
        assert any("145" in v for v in violations)

    def test_empty_or_non_numeric_reply_is_ok(self, sample_facts: dict) -> None:
        ok, violations = verify("All systems normal and doors locked.", sample_facts)
        assert ok is True
        assert violations == []

        ok_empty, violations_empty = verify("", sample_facts)
        assert ok_empty is True
        assert violations_empty == []

    def test_multiple_violations_reported(self, sample_facts: dict) -> None:
        reply = "It is 88°F inside and package is worth $5,000."
        ok, violations = verify(reply, sample_facts)
        assert ok is False
        assert len(violations) == 2
