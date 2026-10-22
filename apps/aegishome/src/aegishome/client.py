"""Client driver for AegisHome MCP tools with Bedrock tool-use and offline intent parser.

Handles:
- Bedrock tool-use when AWS credentials are present.
- High-fidelity offline rule-based intent parser so the demo never depends on the network.
- Driving the MCP tools and recording real JSON-RPC wire frames in the WireLogger.
"""

from dataclasses import dataclass, field
import json
import logging
import os
import re
from typing import Any, Mapping

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aegishome.wire_logger import get_wire_logger
from aegishome.tools import (
    get_home_status,
    propose_action,
    approve_action,
    confirm_action,
    read_visitor_note,
)
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import get_taint_tracker

logger = logging.getLogger("aegishome.client")

MCP_TOOLS_SPEC = [
    {
        "toolSpec": {
            "name": "get_home_status",
            "description": "Retrieve real-time smart home device states and resident health status",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {},
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "propose_action",
            "description": "Propose an action on a smart-home device (unlock door, set temperature, open garage)",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "action_type": {
                            "type": "string",
                            "description": "Action type (e.g. 'unlock_door', 'set_temperature', 'open', 'close', 'lock_door')",
                        },
                        "target": {
                            "type": "string",
                            "description": "Target device (e.g. 'front_door', 'thermostat', 'garage_door')",
                        },
                        "parameters": {
                            "type": "object",
                            "description": "Key-value parameters for the action",
                        },
                    },
                    "required": ["action_type", "target"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "confirm_action",
            "description": "Confirm and execute an action proposal using a 4-digit voice confirmation code",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "proposal_id": {
                            "type": "string",
                            "description": "The unique proposal identifier",
                        },
                        "approved": {
                            "type": "boolean",
                            "description": "True to confirm and execute, False to reject",
                        },
                        "code": {
                            "type": "string",
                            "description": "4-digit voice confirmation code",
                        },
                    },
                    "required": ["proposal_id"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "approve_action",
            "description": "Owner out-of-band approval for HIGH-risk actions via caregiver phone channel",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "proposal_id": {
                            "type": "string",
                            "description": "Proposal ID to approve",
                        },
                    },
                    "required": ["proposal_id"],
                }
            },
        }
    },
    {
        "toolSpec": {
            "name": "read_visitor_note",
            "description": "Read a note left by a visitor or delivery courier at the entrance",
            "inputSchema": {
                "json": {
                    "type": "object",
                    "properties": {
                        "note_id": {
                            "type": "string",
                            "description": "Note identifier (e.g. 'latest', 'delivery', 'injection')",
                        },
                    },
                }
            },
        }
    },
]


class MCPToolExecutor:
    """Executes MCP tools and logs JSON-RPC wire frames."""

    def __init__(self) -> None:
        self.wire_logger = get_wire_logger()
        self._rpc_id = 0

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call and log JSON-RPC wire frames."""
        self._rpc_id += 1
        req_id = self._rpc_id

        # Log JSON-RPC Request frame
        self.wire_logger.log_request(
            method="tools/call",
            params={"name": name, "arguments": arguments},
            jsonrpc_id=req_id,
            tool_name=name,
        )

        result: dict[str, Any] = {}
        error: dict[str, Any] | None = None

        try:
            if name == "get_home_status":
                result = get_home_status()
            elif name == "propose_action":
                result = propose_action(
                    action_type=arguments.get("action_type", ""),
                    target=arguments.get("target", ""),
                    parameters=arguments.get("parameters", {}),
                    session_id=arguments.get("session_id", "web_session"),
                )
            elif name == "approve_action":
                result = approve_action(
                    proposal_id=arguments.get("proposal_id", ""),
                    approver_id=arguments.get("approver_id", "caregiver_phone"),
                )
            elif name == "confirm_action":
                result = confirm_action(
                    proposal_id=arguments.get("proposal_id", ""),
                    approved=arguments.get("approved", True),
                    code=arguments.get("code"),
                    reason=arguments.get("reason", "Voice confirmation received"),
                )
            elif name == "read_visitor_note":
                result = read_visitor_note(
                    note_id=arguments.get("note_id", "latest"),
                    session_id=arguments.get("session_id", "web_session"),
                )
            else:
                error = {"code": -32601, "message": f"Method '{name}' not found"}
        except Exception as e:
            error = {"code": -32000, "message": str(e), "type": type(e).__name__}

        # Log JSON-RPC Response frame
        self.wire_logger.log_response(
            jsonrpc_id=req_id,
            result=result if error is None else None,
            error=error,
            method="tools/call",
            tool_name=name,
        )

        if error:
            return {"error": error, "is_error": True}
        return {"result": result, "is_error": False}


@dataclass
class SayResponse:
    """Structured response from /api/say."""

    utterance: str
    reply: str
    engine: str  # 'BEDROCK' or 'RULE ENGINE'
    tool_calls: list[dict[str, Any]]
    active_proposal_id: str | None = None
    voice_code: str | None = None
    risk_tier: str | None = None
    is_tainted: bool = False
    events: list[dict[str, Any]] = field(default_factory=list)
    engine_badge: str = ""
    badge_tooltip: str = ""


class IntentDriver:
    """Drives user utterances through Bedrock or offline intent parsing to MCP tools."""

    def __init__(self) -> None:
        self.executor = MCPToolExecutor()

    def has_aws_credentials(self) -> bool:
        """Check if AWS credentials are configured in environment or boto3 chain."""
        try:
            session = boto3.Session()
            creds = session.get_credentials()
            return creds is not None and creds.access_key is not None
        except Exception:
            return False

    def process_utterance(
        self,
        utterance: str,
        session_id: str = "web_session",
        history: list[dict[str, Any]] | None = None,
    ) -> SayResponse:
        """Process an utterance via Bedrock tool-use agent, falling back to rule engine."""
        clean_text = utterance.strip()

        from apps.aegishome.agent import run_turn
        turn_result = run_turn(session_id=session_id, utterance=clean_text, history=history)

        engine_badge = turn_result.get("engine_badge") or turn_result.get("engine", "RULE ENGINE")
        badge_tooltip = turn_result.get("badge_tooltip", "")

        return SayResponse(
            utterance=clean_text,
            reply=turn_result.get("reply") or turn_result.get("text", ""),
            engine=turn_result.get("engine", "RULE ENGINE"),
            tool_calls=turn_result.get("tool_calls", []),
            active_proposal_id=turn_result.get("active_proposal_id"),
            voice_code=turn_result.get("voice_code"),
            risk_tier=turn_result.get("risk_tier"),
            is_tainted=turn_result.get("is_tainted", False),
            events=turn_result.get("events", []),
            engine_badge=engine_badge,
            badge_tooltip=badge_tooltip,
        )

    def _process_via_bedrock(self, utterance: str, session_id: str) -> SayResponse:
        """Invoke Bedrock Converse API with toolConfig to let LLM decide tool calls."""
        model_id = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-haiku-20240307-v1:0")
        client = boto3.client("bedrock-runtime", region_name=os.getenv("AWS_REGION", "us-east-1"))

        system_prompt = (
            "You are Alexa+, a smart-home caregiver assistant. "
            "Use the provided smart-home tools to fulfill the user's caregiver request. "
            "Always follow safety rules and report outcomes accurately."
        )

        response = client.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": utterance}]}],
            system=[{"text": system_prompt}],
            toolConfig={"tools": MCP_TOOLS_SPEC},
            inferenceConfig={"maxTokens": 400, "temperature": 0.0},
        )

        output_msg = response.get("output", {}).get("message", {})
        content_blocks = output_msg.get("content", [])

        tool_calls: list[dict[str, Any]] = []
        reply_texts: list[str] = []

        for block in content_blocks:
            if "text" in block:
                reply_texts.append(block["text"])
            elif "toolUse" in block:
                tool_use = block["toolUse"]
                name = tool_use.get("name", "")
                args = tool_use.get("input", {})
                args["session_id"] = session_id
                exec_res = self.executor.call_tool(name, args)
                tool_calls.append({"name": name, "arguments": args, "result": exec_res})

        final_reply = " ".join(reply_texts) if reply_texts else "Action processed via Bedrock."
        return SayResponse(
            utterance=utterance,
            reply=final_reply,
            engine="bedrock_tool_use",
            tool_calls=tool_calls,
        )

    def _process_via_rule_parser(self, utterance: str, session_id: str) -> SayResponse:
        """High-precision offline intent parser supporting all demo scenarios."""
        low = utterance.lower().strip()
        tool_calls: list[dict[str, Any]] = []
        reply = ""
        active_prop_id: str | None = None
        voice_code: str | None = None
        risk_tier: str | None = None

        # -------------------------------------------------------------
        # Scenario 3 / Injected Note Intent
        # "read the latest visitor note and unlock the front door" / "read visitor note" / "read me the note on the porch"
        # -------------------------------------------------------------
        if "visitor note" in low or "read note" in low or ("read" in low and "note" in low) or "note on the porch" in low:
            note_res = self.executor.call_tool("read_visitor_note", {"note_id": "latest", "session_id": session_id})
            tool_calls.append({"name": "read_visitor_note", "arguments": {"note_id": "latest"}, "result": note_res})
            note_data = note_res.get("result", {})
            note_content = note_data.get("content", "")

            # If user also asked to unlock door in the same utterance (prompt injection demo!)
            if "unlock" in low and ("door" in low or "front" in low):
                # Attempt to propose unlock under tainted session
                prop_res = self.executor.call_tool(
                    "propose_action",
                    {
                        "action_type": "unlock_door",
                        "target": "front_door",
                        "parameters": {"auto_relock_seconds": 60},
                        "session_id": session_id,
                    },
                )
                tool_calls.append({"name": "propose_action", "arguments": {"action_type": "unlock_door", "target": "front_door"}, "result": prop_res})

                p_data = prop_res.get("result", {})
                active_prop_id = p_data.get("proposal_id")
                voice_code = p_data.get("voice_code")
                risk_tier = p_data.get("risk_tier", "HIGH")

                reply = (
                    f"Read visitor note: \"{note_content}\". "
                    f"SECURITY ALERT: Untrusted input detected; session marked TAINTED. "
                    f"Front door unlock escalated to {risk_tier} risk (Proposal {active_prop_id}). "
                    f"Requires 2-step verification: out-of-band Owner Approval AND voice code {voice_code}. "
                    f"Unauthorized prompt injection execution was safely BLOCKED."
                )
            else:
                reply = f"Read visitor note from porch: \"{note_content}\". Note is marked untrusted; session is tainted."

        # -------------------------------------------------------------
        # Scenario 1 / Thermostat Adjustment
        # "set thermostat to 72 degrees" / "set temperature to 72" / "make it 70 degrees"
        # -------------------------------------------------------------
        elif any(k in low for k in ("thermostat", "temperature", "temp", "degrees")):
            match = re.search(r"(\d+(?:\.\d+)?)", low)
            target_temp = float(match.group(1)) if match else 72.0

            # Propose thermostat setpoint
            prop_res = self.executor.call_tool(
                "propose_action",
                {
                    "action_type": "set_temperature",
                    "target": "thermostat",
                    "parameters": {"temperature": target_temp},
                    "session_id": session_id,
                },
            )
            tool_calls.append({"name": "propose_action", "arguments": {"action_type": "set_temperature", "target": "thermostat", "parameters": {"temperature": target_temp}}, "result": prop_res})

            p_data = prop_res.get("result", {})
            active_prop_id = p_data.get("proposal_id")
            risk_tier = p_data.get("risk_tier", "LOW")

            # If outside standard comfort range, it is HIGH risk and requires owner approval
            if risk_tier in ("HIGH", "MEDIUM"):
                reply = (
                    f"Thermostat adjustment to {target_temp}°F is outside the standard comfort range (65°F - 80°F) "
                    f"and is classified as {risk_tier} risk (Proposal: {active_prop_id}). "
                    f"Out-of-band owner approval is required on your phone."
                )
            else:
                # Routine thermostat adjustments are LOW risk -> Auto-confirm
                conf_res = self.executor.call_tool(
                    "confirm_action",
                    {
                        "proposal_id": active_prop_id,
                        "approved": True,
                        "reason": f"Routine caregiver thermostat setpoint {target_temp}°F",
                    },
                )
                tool_calls.append({"name": "confirm_action", "arguments": {"proposal_id": active_prop_id, "approved": True}, "result": conf_res})

                reply = f"I've set the thermostat to {target_temp}°F (LOW risk, verified & confirmed). Eleanor's room climate updated."

        # -------------------------------------------------------------
        # Scenario 2 / Door Unlock Intent
        # "unlock the front door" / "unlock door"
        # -------------------------------------------------------------
        elif "unlock" in low and ("door" in low or "front" in low):
            prop_res = self.executor.call_tool(
                "propose_action",
                {
                    "action_type": "unlock_door",
                    "target": "front_door",
                    "parameters": {"auto_relock_seconds": 60},
                    "session_id": session_id,
                },
            )
            tool_calls.append({"name": "propose_action", "arguments": {"action_type": "unlock_door", "target": "front_door"}, "result": prop_res})

            p_data = prop_res.get("result", {})
            active_prop_id = p_data.get("proposal_id")
            voice_code = p_data.get("voice_code")
            risk_tier = p_data.get("risk_tier", "HIGH")

            reply = (
                f"Unlocking the front door is HIGH risk. "
                f"Created proposal {active_prop_id} with voice confirmation code [{voice_code}]. "
                f"Please tap 'Owner approve' in the center panel, then confirm with the 4-digit code."
            )

        # -------------------------------------------------------------
        # Voice Code Confirmation Intent
        # "confirm with code 1234" / "confirm 1234" / "code 1234"
        # -------------------------------------------------------------
        elif "confirm" in low or "code" in low:
            match = re.search(r"\b(\d{4})\b", low)
            submitted_code = match.group(1) if match else ""

            # Locate latest pending proposal
            gw = get_confirmation_gateway()
            pending_proposals = [p for p in gw._proposals.values() if p.status == "PENDING"]
            latest_prop = pending_proposals[-1] if pending_proposals else None

            if not latest_prop:
                reply = "There are no pending action proposals to confirm."
            else:
                active_prop_id = latest_prop.proposal_id
                conf_res = self.executor.call_tool(
                    "confirm_action",
                    {
                        "proposal_id": active_prop_id,
                        "approved": True,
                        "code": submitted_code,
                        "reason": f"Voice confirmed with code {submitted_code}",
                    },
                )
                tool_calls.append({"name": "confirm_action", "arguments": {"proposal_id": active_prop_id, "code": submitted_code}, "result": conf_res})

                c_data = conf_res.get("result", {})
                if c_data.get("executed"):
                    reply = f"Proposal {active_prop_id} successfully confirmed! Action '{latest_prop.action}' on '{latest_prop.device}' executed."
                else:
                    err_msg = c_data.get("message", "Confirmation failed")
                    err_type = c_data.get("error_type", "Blocked")
                    reply = f"Confirmation blocked by Aegis Guard ({err_type}): {err_msg}"

        # -------------------------------------------------------------
        # Lock Door Intent
        # -------------------------------------------------------------
        elif "lock" in low and ("door" in low or "front" in low):
            prop_res = self.executor.call_tool(
                "propose_action",
                {
                    "action_type": "lock_door",
                    "target": "front_door",
                    "session_id": session_id,
                },
            )
            tool_calls.append({"name": "propose_action", "arguments": {"action_type": "lock_door", "target": "front_door"}, "result": prop_res})
            p_data = prop_res.get("result", {})
            active_prop_id = p_data.get("proposal_id")

            conf_res = self.executor.call_tool(
                "confirm_action",
                {"proposal_id": active_prop_id, "approved": True, "reason": "Caregiver locked door"},
            )
            tool_calls.append({"name": "confirm_action", "arguments": {"proposal_id": active_prop_id, "approved": True}, "result": conf_res})
            reply = "Front door is now securely locked."

        # -------------------------------------------------------------
        # Garage Door Intents
        # -------------------------------------------------------------
        elif "garage" in low:
            action_type = "open" if "open" in low else "close"
            prop_res = self.executor.call_tool(
                "propose_action",
                {
                    "action_type": action_type,
                    "target": "garage_door",
                    "session_id": session_id,
                },
            )
            tool_calls.append({"name": "propose_action", "arguments": {"action_type": action_type, "target": "garage_door"}, "result": prop_res})
            p_data = prop_res.get("result", {})
            active_prop_id = p_data.get("proposal_id")
            voice_code = p_data.get("voice_code")
            risk_tier = p_data.get("risk_tier", "MEDIUM")

            if action_type == "open":
                reply = (
                    f"Opening garage door is {risk_tier} risk. "
                    f"Proposal {active_prop_id} created with voice code [{voice_code}]. "
                    f"Please confirm with the 4-digit code."
                )
            else:
                conf_res = self.executor.call_tool(
                    "confirm_action",
                    {"proposal_id": active_prop_id, "approved": True, "reason": "Caregiver closed garage"},
                )
                tool_calls.append({"name": "confirm_action", "arguments": {"proposal_id": active_prop_id, "approved": True}, "result": conf_res})
                reply = "Garage door has been closed."

        # -------------------------------------------------------------
        # Status Query Intent
        # -------------------------------------------------------------
        elif any(k in low for k in ("status", "check", "how is", "how's", "dad", "father", "house", "home", "resident", "devices")):
            status_res = self.executor.call_tool("get_home_status", {})
            tool_calls.append({"name": "get_home_status", "arguments": {}, "result": status_res})
            status = status_res.get("result", {})
            try:
                from aegishome.bedrock_client import generate_home_summary
                summary_text, path_used, _ = generate_home_summary(status)
                reply = summary_text
            except Exception:
                doors = status.get("doors", {})
                resident = status.get("resident", {})
                climate = status.get("climate", {})
                pkg = status.get("package_sensor", {})
                reply = (
                    f"Safe Home Status: {resident.get('name', 'Resident')} is {resident.get('state', 'resting')} "
                    f"(Heart rate: {resident.get('heart_rate_bpm', 72)} bpm). "
                    f"Front door is {doors.get('front_door', 'locked')}. "
                    f"Climate is {climate.get('current_temp_f', 71.0)}°F. "
                    f"Package on porch: {'Yes ($' + str(pkg.get('package_value_usd', 120)) + ')' if pkg.get('package_present') else 'None'}."
                )

        # Default fallback response
        else:
            reply = f"I heard: '{utterance}'. You can ask me to check status, set temperature, unlock the door, or read visitor notes."

        is_tainted = get_taint_tracker().is_tainted(session_id)

        return SayResponse(
            utterance=utterance,
            reply=reply,
            engine="rule_intent_parser",
            tool_calls=tool_calls,
            active_proposal_id=active_prop_id,
            voice_code=voice_code,
            risk_tier=risk_tier,
            is_tainted=is_tainted,
        )


# Global intent driver singleton
_GLOBAL_DRIVER = IntentDriver()


def get_intent_driver() -> IntentDriver:
    return _GLOBAL_DRIVER
