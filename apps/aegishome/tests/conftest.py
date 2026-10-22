"""Pytest fixtures for aegishome tests."""

import pytest
from aegishome.devices import reset
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import reset_taint_tracker


@pytest.fixture(autouse=True)
def reset_home_state() -> None:
    """Reset simulated home state, confirmation gateway, and taint tracker to baseline before every test."""
    reset()
    get_confirmation_gateway().reset()
    reset_taint_tracker()

