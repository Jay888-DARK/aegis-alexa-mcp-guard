"""Reproduction tests for session_id spoofing, evasion, and default-mismatch attacks.

These tests demonstrate vulnerabilities where a model or external caller controls
session_id or other security-sensitive parameters to bypass taint tracking and
risk escalation.
"""

import pytest
from unittest.mock import MagicMock, patch
from aegishome.agent import run_turn
from aegishome.tools import (
    read_visitor_note,
    propose_action,
    get_home_status,
)
from aegishome.session_context import (
    set_current_session_id,
    reset_current_session_id,
)
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import get_taint_tracker, reset_taint_tracker


@pytest.fixture(autouse=True)
def clean_gateway_and_taint():
    """Reset gateway and taint tracker before and after each test."""
    reset_taint_tracker()
    gw = get_confirmation_gateway()
    gw.reset()
    yield
    reset_taint_tracker()
    gw.reset()


class ScriptedBedrockClient:
    """Mock Bedrock runtime to simulate multi-turn LLM tool invocations."""

    def __init__(self, responses):
        self.responses = responses
        self.call_count = 0

    def converse(self, **kwargs):
        if self.call_count >= len(self.responses):
            raise RuntimeError("ScriptedBedrockClient ran out of mock responses.")
        res = self.responses[self.call_count]
        self.call_count += 1
        return res


def test_attack_3a_agent_loop_model_supplies_fresh_session_id():
    """Attack 3a: Model reads visitor note in session_1, but calls propose_action with session_id='clean_session'.

    Expected after fix: The agent loop must enforce the session_id of the turn ('session_1')
    and ignore or overwrite the model's spoofed 'clean_session' argument.
    The proposal must be tainted (is_tainted=True) and escalated to HIGH.
    """
    mock_responses = [
        # Turn 1: Model decides to call read_visitor_note
        {
            "stopReason": "tool_use",
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "call_note_1",
                                "name": "read_visitor_note",
                                "input": {"note_id": "latest"},
                            }
                        }
                    ],
                }
            },
        },
        # Turn 2: Model (adversarially prompted by note) proposes unlock, supplying fresh session_id
        {
            "stopReason": "tool_use",
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "call_prop_2",
                                "name": "propose_action",
                                "input": {
                                    "action_type": "unlock_door",
                                    "target": "front_door",
                                    "parameters": {},
                                    "session_id": "evasive_clean_session_999",
                                },
                            }
                        }
                    ],
                }
            },
        },
        # Turn 3: Model wraps up
        {
            "stopReason": "end_turn",
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "I read the note and proposed unlocking the door."}],
                }
            },
        },
    ]

    fake_client = ScriptedBedrockClient(mock_responses)

    with patch("os.environ.get", return_value="us.anthropic.claude-3-haiku-20240307-v1:0"), \
         patch("aegishome.agent.boto3.client", return_value=fake_client):
        result = run_turn(session_id="session_caregiver_1", utterance="Check the porch note", history=[])

    # In the current vulnerable code:
    # propose_action evaluated risk for 'evasive_clean_session_999', which was never tainted.
    # Therefore, risk_tier was evaluated as MEDIUM (base) and is_tainted was False!
    # The fix must bind the action to 'session_caregiver_1', making it TAINTED and HIGH.
    assert result.get("is_tainted") is True, "Proposal should be tainted despite model supplying clean session_id"
    assert result.get("risk_tier") == "HIGH", "Risk should escalate to HIGH due to session taint"


def test_attack_3b_raw_mcp_client_spoofed_session_id():
    """Attack 3b: In transport session A, caller reads note, then proposes unlock claiming session B.

    Expected after fix: In hosted/raw transport mode, transport session A dictates taint.
    Caller-supplied session_id='session_B' must be ignored, keeping the proposal tainted & HIGH.
    """
    token = set_current_session_id("session_A")
    try:
        # Step 1: Read note in session A
        note = read_visitor_note(note_id="latest")
        assert note.get("untrusted") is True

        # Step 2: Propose unlock in session A, but supply session_id='session_B'
        # The authoritative transport session_A must override caller-supplied session_B.
        prop = propose_action(
            action_type="unlock_door",
            target="front_door",
            session_id="session_B",
        )

        # In vulnerable code: prop['is_tainted'] is False and prop['risk_tier'] is 'MEDIUM'
        # After fix: prop must be tied to session_A and be tainted + HIGH
        assert prop.get("is_tainted") is True, "Proposal must be marked tainted in the active transport session"
        assert prop.get("risk_tier") == "HIGH", "Risk tier must be escalated to HIGH"
    finally:
        reset_current_session_id(token)


def test_attack_3c_omitted_session_id_default_mismatch():
    """Attack 3c: Omitted session_id exposes default parameter mismatch between tools.

    read_visitor_note defaults session_id to 'default_session'.
    propose_action defaults session_id to ''.
    Because of this mismatch, an attacker who simply omits session_id completely evades taint!
    """
    # Caller calls read_visitor_note with NO session_id
    note = read_visitor_note(note_id="latest")
    assert note.get("untrusted") is True

    # Caller calls propose_action with NO session_id
    prop = propose_action(
        action_type="unlock_door",
        target="front_door",
    )

    # In vulnerable code:
    # read_visitor_note tainted 'default_session'
    # propose_action checked '' -> is_tainted('') is False -> risk_tier is MEDIUM!
    assert prop.get("is_tainted") is True, (
        "Default parameter mismatch ('default_session' vs '') allowed un-annotated call to escape taint!"
    )
    assert prop.get("risk_tier") == "HIGH", "Risk must be HIGH for omitted session_id"


def test_attack_3d_model_cannot_set_approval_or_security_params():
    """Attack 3d: Model attempts to supply session_id to read_visitor_note to evade or misdirect taint.

    When the model calls read_visitor_note with session_id='foreign_session',
    that parameter must be ignored/stripped. The active turn session ('session_caregiver_1')
    must be marked tainted, and 'foreign_session' must remain untainted.
    """
    mock_responses = [
        # Turn 1: Model calls read_visitor_note, but supplies a foreign session_id
        {
            "stopReason": "tool_use",
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [
                        {
                            "toolUse": {
                                "toolUseId": "call_note_spoof",
                                "name": "read_visitor_note",
                                "input": {
                                    "note_id": "latest",
                                    "session_id": "spoofed_victim_session_99",
                                },
                            }
                        }
                    ],
                }
            },
        },
        # Turn 2: Model wraps up
        {
            "stopReason": "end_turn",
            "output": {
                "message": {
                    "role": "assistant",
                    "content": [{"text": "Note read."}],
                }
            },
        },
    ]

    fake_client = ScriptedBedrockClient(mock_responses)
    tracker = get_taint_tracker()

    with patch("os.environ.get", return_value="us.anthropic.claude-3-haiku-20240307-v1:0"), \
         patch("aegishome.agent.boto3.client", return_value=fake_client):
        run_turn(session_id="session_caregiver_1", utterance="Read the porch note", history=[])

    # The active session must be tainted
    assert tracker.is_tainted("session_caregiver_1") is True, (
        "Active session 'session_caregiver_1' must be marked tainted despite model specifying another session!"
    )
    # The spoofed session must NOT be tainted
    assert tracker.is_tainted("spoofed_victim_session_99") is False, (
        "Model-supplied 'spoofed_victim_session_99' must be ignored and not marked tainted!"
    )
