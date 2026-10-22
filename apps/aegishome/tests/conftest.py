import os
import pytest
from aegishome.devices import reset
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import reset_taint_tracker


@pytest.fixture(autouse=True)
def reset_home_state(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reset simulated home state, confirmation gateway, and taint tracker to baseline before every test.

    Isolate ambient live API keys so unit tests run deterministically against their mocked backends.
    """
    reset()
    get_confirmation_gateway().reset()
    reset_taint_tracker()
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("GROQ_MODEL_ID", raising=False)

