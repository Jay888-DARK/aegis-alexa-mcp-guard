"""Pytest fixtures for aegis-guard tests."""

import pytest
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import reset_taint_tracker


@pytest.fixture(autouse=True)
def reset_gateway_and_taint() -> None:
    """Reset confirmation gateway and taint tracker before every test."""
    get_confirmation_gateway().reset()
    reset_taint_tracker()
