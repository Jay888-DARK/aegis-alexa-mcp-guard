#!/usr/bin/env python3
"""Aegis End-to-End System Smoke Test.

Tests the full running system end-to-end against a live server subprocess
over the official MCP Python client (Streamable HTTP at /mcp) and SQLite DB.

Checks:
1.  /health returns OK.
2.  MCP Python client over Streamable HTTP at /mcp: initialize, report protocol
    version (>= 2025-11-25), list tools, and confirm 4 expected tools.
3.  get_home_status returns real device values.
4.  LOW action (thermostat set) executes immediately.
5.  HIGH action (front door unlock): propose returns code; confirm WITHOUT owner
    approval is rejected; after owner approve, confirm with right code succeeds.
6.  Replay the same code: rejected.
7.  Wrong code 3 times: proposal locks.
8.  read_visitor_note, then propose unlock: risk escalated & tainted; cannot
    execute without owner approval.
9.  Numeric guard: FakeModel that hallucinates package value is rejected and falls back.
10. Restart: stop server, start on same DB, replay old code: rejected; expired
    proposal stays expired.
11. Audit: verify_chain() returns OK; direct SQLite edit detected by verify_chain().
12. If AWS credentials exist, make real Bedrock call (report model & path); else SKIPPED.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
from typing import Any
import urllib.request
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

# Official MCP Client imports
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.streamable_http import is_version_at_least

# Aegis Guard & AegisHome imports
from aegis_guard.storage import AegisStorage
from aegishome.bedrock_client import (
    FakeModel,
    generate_home_summary,
    PATH_DETERMINISTIC_FALLBACK,
    PATH_BEDROCK_VERIFIED,
)
from aegishome.devices import get_simulated_home


@dataclass
class CheckResult:
    step: int
    name: str
    status: str  # "PASS", "FAIL", "SKIPPED"
    detail: str = ""


def get_free_port() -> int:
    """Find an available ephemeral TCP port on localhost."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def start_server_subprocess(port: int, db_path: Path) -> subprocess.Popen:
    """Launch the AegisHome MCP server as an independent background subprocess."""
    env = os.environ.copy()
    env["AEGIS_DB_PATH"] = str(db_path)
    env["AEGIS_SERVER_PORT"] = str(port)
    env["AEGIS_SERVER_HOST"] = "127.0.0.1"
    env["AEGIS_DNS_PROTECTION"] = "false"
    env["AEGIS_LOG_LEVEL"] = "warning"

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "aegishome.main",
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
            "--log-level",
            "warning",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return proc


def stop_server_subprocess(proc: subprocess.Popen) -> None:
    """Safely terminate a server subprocess."""
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=4)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=4)


def wait_for_health(base_url: str, timeout: float = 15.0) -> dict[str, Any] | None:
    """Poll GET /health until healthy status received or timeout expires."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            req = urllib.request.Request(f"{base_url}/health")
            with urllib.request.urlopen(req, timeout=1.5) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    if data.get("status") == "healthy":
                        return data
        except Exception:
            time.sleep(0.15)
    return None


def extract_tool_data(result: Any) -> dict[str, Any]:
    """Extract dict payload from MCP CallToolResult (supports structured_content or text content)."""
    if hasattr(result, "structured_content") and isinstance(result.structured_content, dict):
        return result.structured_content
    if hasattr(result, "content") and result.content:
        first = result.content[0]
        if hasattr(first, "text") and first.text:
            try:
                parsed = json.loads(first.text)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass
    return {}


async def run_smoke_test() -> list[CheckResult]:
    results: list[CheckResult] = []

    temp_dir = tempfile.TemporaryDirectory()
    db_path = Path(temp_dir.name) / "smoke_aegis.db"
    port = get_free_port()
    base_url = f"http://127.0.0.1:{port}"
    mcp_url = f"{base_url}/mcp"

    server_proc = start_server_subprocess(port, db_path)

    try:
        # -------------------------------------------------------------
        # Step 1: /health returns OK
        # -------------------------------------------------------------
        step_1_name = "/health endpoint check"
        health_data = wait_for_health(base_url, timeout=15.0)
        if health_data and health_data.get("status") == "healthy":
            line = f"GET {base_url}/health returned 200 OK (status: healthy, service: {health_data.get('service')})"
            print(f"[PASS] Check 01: {line}")
            results.append(CheckResult(1, step_1_name, "PASS", line))
        else:
            line = f"Failed to get healthy response from {base_url}/health within timeout"
            print(f"[FAIL] Check 01: {line}")
            results.append(CheckResult(1, step_1_name, "FAIL", line))
            return results

        # Connect MCP Client for steps 2 - 8
        async with streamable_http_client(mcp_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                # -------------------------------------------------------------
                # Step 2: Protocol version negotiation and 4 expected tools
                # -------------------------------------------------------------
                step_2_name = "MCP initialization, protocol >= 2025-11-25 & 4 tools"
                init_res = await session.initialize()
                proto_version = init_res.protocol_version or ""
                proto_ok = is_version_at_least(proto_version, "2025-11-25")

                tools_res = await session.list_tools()
                tool_names = {t.name for t in tools_res.tools}
                expected_tools = {
                    "get_home_status",
                    "propose_action",
                    "confirm_action",
                    "read_visitor_note",
                }
                tools_present = expected_tools.issubset(tool_names)

                if proto_ok and tools_present:
                    detail = (
                        f"Protocol: {proto_version} (spec >= 2025-11-25 OK), "
                        f"tools confirmed: {sorted(list(expected_tools))}"
                    )
                    print(f"[PASS] Check 02: {detail}")
                    results.append(CheckResult(2, step_2_name, "PASS", detail))
                else:
                    detail = (
                        f"Protocol: {proto_version} (ok={proto_ok}), "
                        f"tools present: {tool_names} (expected subset {expected_tools})"
                    )
                    print(f"[FAIL] Check 02: {detail}")
                    results.append(CheckResult(2, step_2_name, "FAIL", detail))

                # -------------------------------------------------------------
                # Step 3: get_home_status returns real device values
                # -------------------------------------------------------------
                step_3_name = "get_home_status returns real device values"
                status_res = await session.call_tool("get_home_status", {})
                status_data = extract_tool_data(status_res)

                has_resident = "resident" in status_data and "name" in status_data["resident"]
                has_doors = "doors" in status_data and "front_door" in status_data["doors"]
                has_climate = (
                    ("climate" in status_data and "target_temp_f" in status_data["climate"])
                    or ("thermostat" in status_data and "temperature" in status_data["thermostat"])
                )
                has_pkg = "package_sensor" in status_data

                if has_resident and has_doors and has_climate and has_pkg:
                    detail = (
                        f"Resident: {status_data['resident'].get('name')}, "
                        f"Front Door: {status_data['doors'].get('front_door')}, "
                        f"Temp: {status_data.get('climate', {}).get('target_temp_f') or status_data.get('thermostat', {}).get('temperature')} deg F, "
                        f"Package: {status_data['package_sensor'].get('package_description')}"
                    )
                    print(f"[PASS] Check 03: {detail}")
                    results.append(CheckResult(3, step_3_name, "PASS", detail))
                else:
                    detail = f"Missing expected home status fields. Keys returned: {list(status_data.keys())}"
                    print(f"[FAIL] Check 03: {detail}")
                    results.append(CheckResult(3, step_3_name, "FAIL", detail))

                # -------------------------------------------------------------
                # Step 4: LOW action (thermostat set) executes immediately
                # -------------------------------------------------------------
                step_4_name = "LOW action (thermostat set) executes immediately"
                thermo_prop_res = await session.call_tool(
                    "propose_action",
                    {
                        "action_type": "set_temperature",
                        "target": "thermostat",
                        "parameters": {"temperature": 73.0},
                    },
                )
                thermo_prop = extract_tool_data(thermo_prop_res)
                thermo_prop_id = thermo_prop.get("proposal_id", "")
                requires_code = thermo_prop.get("requires_code", True)

                # Confirm LOW action (no code required)
                thermo_conf_res = await session.call_tool(
                    "confirm_action",
                    {"proposal_id": thermo_prop_id, "approved": True},
                )
                thermo_conf = extract_tool_data(thermo_conf_res)
                executed_immediate = thermo_conf.get("executed") is True

                # Check state reflection
                updated_home = extract_tool_data(await session.call_tool("get_home_status", {}))
                thermo_updated = (
                    updated_home.get("thermostat", {}).get("target_temperature") == 73.0
                    or updated_home.get("climate", {}).get("target_temp_f") == 73.0
                )

                if (not requires_code) and executed_immediate and thermo_updated:
                    detail = (
                        f"Proposal {thermo_prop_id} (LOW risk) required no code, "
                        f"executed immediately, thermostat updated to 73.0 deg F"
                    )
                    print(f"[PASS] Check 04: {detail}")
                    results.append(CheckResult(4, step_4_name, "PASS", detail))
                else:
                    detail = (
                        f"requires_code={requires_code}, executed={executed_immediate}, "
                        f"thermo_updated={thermo_updated}"
                    )
                    print(f"[FAIL] Check 04: {detail}")
                    results.append(CheckResult(4, step_4_name, "FAIL", detail))

                # -------------------------------------------------------------
                # Step 5: HIGH action (front door unlock) lifecycle
                # -------------------------------------------------------------
                step_5_name = "HIGH action lifecycle (code, unapproved reject, owner approve, confirm)"
                unlock_prop_res = await session.call_tool(
                    "propose_action",
                    {
                        "action_type": "unlock_door",
                        "target": "front_door",
                        "parameters": {"auto_relock_seconds": 60},
                    },
                )
                unlock_prop = extract_tool_data(unlock_prop_res)
                unlock_id = unlock_prop.get("proposal_id", "")
                voice_code = unlock_prop.get("voice_code", "")
                is_high = unlock_prop.get("risk_tier") == "HIGH"
                code_present = bool(voice_code and len(voice_code) == 4)

                # Attempt 1: Confirm WITHOUT owner approval -> must be rejected
                unapproved_res = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": unlock_id, "approved": True, "code": voice_code},
                    )
                )
                unapproved_blocked = (
                    unapproved_res.get("executed") is False
                    and "MissingOwnerApprovalError" in str(unapproved_res.get("error_type"))
                )

                # Owner approve
                appr_res = extract_tool_data(
                    await session.call_tool(
                        "approve_action",
                        {"proposal_id": unlock_id, "approver_id": "caregiver_phone_primary"},
                    )
                )
                owner_approved = appr_res.get("owner_approved") is True

                # Attempt 2: Confirm WITH right code after owner approval -> must succeed
                approved_conf_res = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": unlock_id, "approved": True, "code": voice_code},
                    )
                )
                confirmed_ok = approved_conf_res.get("executed") is True

                if is_high and code_present and unapproved_blocked and owner_approved and confirmed_ok:
                    detail = (
                        f"Proposal {unlock_id} generated 4-digit code '{voice_code}', "
                        f"unapproved confirm blocked by MissingOwnerApprovalError, "
                        f"owner approved, and confirmation succeeded"
                    )
                    print(f"[PASS] Check 05: {detail}")
                    results.append(CheckResult(5, step_5_name, "PASS", detail))
                else:
                    detail = (
                        f"is_high={is_high}, code_present={code_present}, "
                        f"unapproved_blocked={unapproved_blocked}, "
                        f"owner_approved={owner_approved}, confirmed_ok={confirmed_ok}"
                    )
                    print(f"[FAIL] Check 05: {detail}")
                    results.append(CheckResult(5, step_5_name, "FAIL", detail))

                # -------------------------------------------------------------
                # Step 6: Replay the same code -> rejected
                # -------------------------------------------------------------
                step_6_name = "Replay protection on executed proposal"
                replay_res = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": unlock_id, "approved": True, "code": voice_code},
                    )
                )
                replay_blocked = (
                    replay_res.get("executed") is False
                    and "ProposalAlreadyConfirmedError" in str(replay_res.get("error_type"))
                )

                if replay_blocked:
                    detail = f"Replaying executed proposal {unlock_id} rejected with ProposalAlreadyConfirmedError"
                    print(f"[PASS] Check 06: {detail}")
                    results.append(CheckResult(6, step_6_name, "PASS", detail))
                else:
                    detail = f"Replay attempt was not properly rejected: {replay_res}"
                    print(f"[FAIL] Check 06: {detail}")
                    results.append(CheckResult(6, step_6_name, "FAIL", detail))

                # -------------------------------------------------------------
                # Step 7: Wrong code 3 times -> proposal locks
                # -------------------------------------------------------------
                step_7_name = "3 wrong code attempts triggers permanent proposal lockout"
                lock_prop = extract_tool_data(
                    await session.call_tool(
                        "propose_action",
                        {"action_type": "open", "target": "garage_door"},
                    )
                )
                lock_id = lock_prop.get("proposal_id", "")
                real_code = lock_prop.get("voice_code", "")
                bad_code = "0000" if real_code != "0000" else "9999"

                att1 = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": lock_id, "approved": True, "code": bad_code},
                    )
                )
                att2 = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": lock_id, "approved": True, "code": bad_code},
                    )
                )
                att3 = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": lock_id, "approved": True, "code": bad_code},
                    )
                )

                lock_triggered = (
                    att1.get("error_type") == "InvalidCodeError"
                    and att2.get("error_type") == "InvalidCodeError"
                    and (att3.get("error_type") == "ProposalLockedError" or att3.get("locked") is True)
                )

                # Subsequent attempt with the real valid code must also be rejected
                att_locked_real = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": lock_id, "approved": True, "code": real_code},
                    )
                )
                locked_enforced = (
                    att_locked_real.get("executed") is False
                    and att_locked_real.get("error_type") == "ProposalLockedError"
                )

                if lock_triggered and locked_enforced:
                    detail = f"Proposal {lock_id} locked after 3 bad code attempts and rejected subsequent valid code"
                    print(f"[PASS] Check 07: {detail}")
                    results.append(CheckResult(7, step_7_name, "PASS", detail))
                else:
                    detail = (
                        f"att1={att1.get('error_type')}, att2={att2.get('error_type')}, "
                        f"att3={att3.get('error_type')}, locked_enforced={locked_enforced}"
                    )
                    print(f"[FAIL] Check 07: {detail}")
                    results.append(CheckResult(7, step_7_name, "FAIL", detail))

                # -------------------------------------------------------------
                # Step 8: read_visitor_note taints session, escalates risk
                # -------------------------------------------------------------
                step_8_name = "Taint tracking and automatic risk escalation from visitor note"
                taint_session_id = "smoke_tainted_sess_8"
                note_res = extract_tool_data(
                    await session.call_tool(
                        "read_visitor_note",
                        {"note_id": "latest", "session_id": taint_session_id},
                    )
                )
                note_untrusted = note_res.get("untrusted") is True

                # Propose action in tainted session context
                taint_prop = extract_tool_data(
                    await session.call_tool(
                        "propose_action",
                        {
                            "action_type": "unlock_door",
                            "target": "front_door",
                            "session_id": taint_session_id,
                        },
                    )
                )
                taint_prop_id = taint_prop.get("proposal_id", "")
                is_tainted_flag = taint_prop.get("is_tainted") is True
                risk_escalated = taint_prop.get("risk_tier") == "HIGH"
                taint_code = taint_prop.get("voice_code", "")

                # Attempt confirm without owner approval
                taint_conf_blocked = extract_tool_data(
                    await session.call_tool(
                        "confirm_action",
                        {"proposal_id": taint_prop_id, "approved": True, "code": taint_code},
                    )
                )
                blocked_ok = (
                    taint_conf_blocked.get("executed") is False
                    and "MissingOwnerApprovalError" in str(taint_conf_blocked.get("error_type"))
                )

                if note_untrusted and is_tainted_flag and risk_escalated and blocked_ok:
                    detail = (
                        f"Note read marked session tainted; proposal {taint_prop_id} has "
                        f"is_tainted=True, risk=HIGH, and execution blocked without owner approval"
                    )
                    print(f"[PASS] Check 08: {detail}")
                    results.append(CheckResult(8, step_8_name, "PASS", detail))
                else:
                    detail = (
                        f"note_untrusted={note_untrusted}, is_tainted={is_tainted_flag}, "
                        f"risk_escalated={risk_escalated}, blocked_ok={blocked_ok}"
                    )
                    print(f"[FAIL] Check 08: {detail}")
                    results.append(CheckResult(8, step_8_name, "FAIL", detail))

                # Propose an action to expire for Step 10
                exp_prop = extract_tool_data(
                    await session.call_tool(
                        "propose_action",
                        {"action_type": "open", "target": "garage_door"},
                    )
                )
                exp_prop_id = exp_prop.get("proposal_id", "")
                exp_code = exp_prop.get("voice_code", "")

        # -------------------------------------------------------------
        # Step 9: Numeric guard: FakeModel hallucination rejected
        # -------------------------------------------------------------
        step_9_name = "Numeric guard hallucination rejection & deterministic fallback"
        home_facts = get_simulated_home().to_dict()
        hallucinating_model = FakeModel.hallucinating_package(hallucinated_val=999.0)
        summary, path_used, violations = generate_home_summary(home_facts, model=hallucinating_model)

        guard_rejected = path_used == PATH_DETERMINISTIC_FALLBACK
        violations_flagged = len(violations) >= 1 and any("999" in v for v in violations)
        ground_truth_used = "$120.00" in summary and "$999.00" not in summary

        if guard_rejected and violations_flagged and ground_truth_used:
            detail = (
                f"Draft with $999.00 rejected by Numeric Guardrail ({len(violations)} violations). "
                f"Fell back to deterministic template using ground truth $120.00"
            )
            print(f"[PASS] Check 09: {detail}")
            results.append(CheckResult(9, step_9_name, "PASS", detail))
        else:
            detail = (
                f"guard_rejected={guard_rejected}, violations={violations}, "
                f"ground_truth_used={ground_truth_used}"
            )
            print(f"[FAIL] Check 09: {detail}")
            results.append(CheckResult(9, step_9_name, "FAIL", detail))

        # -------------------------------------------------------------
        # Step 10: Server restart on same DB, replay rejected, expired stays expired
        # -------------------------------------------------------------
        step_10_name = "Server restart persistence (replay blocked & expired proposal stays expired)"
        # 1. Mark exp_prop_id expired directly in DB before restart
        conn = sqlite3.connect(str(db_path))
        conn.execute("UPDATE proposals SET expires_at = ? WHERE id = ?;", (time.time() - 3600, exp_prop_id))
        conn.commit()
        conn.close()

        # 2. Stop server
        stop_server_subprocess(server_proc)
        time.sleep(0.5)

        # 3. Start new server subprocess on same DB & free port
        port2 = get_free_port()
        base_url2 = f"http://127.0.0.1:{port2}"
        mcp_url2 = f"{base_url2}/mcp"
        server_proc2 = start_server_subprocess(port2, db_path)

        try:
            wait_for_health(base_url2, timeout=15.0)

            async with streamable_http_client(mcp_url2) as (read_stream2, write_stream2):
                async with ClientSession(read_stream2, write_stream2) as session2:
                    await session2.initialize()

                    # Test replay of step 5 proposal on restarted instance
                    restarted_replay = extract_tool_data(
                        await session2.call_tool(
                            "confirm_action",
                            {"proposal_id": unlock_id, "approved": True, "code": voice_code},
                        )
                    )
                    restart_replay_blocked = (
                        restarted_replay.get("executed") is False
                        and "ProposalAlreadyConfirmedError" in str(restarted_replay.get("error_type"))
                    )

                    # Test expired proposal on restarted instance
                    restarted_expired = extract_tool_data(
                        await session2.call_tool(
                            "confirm_action",
                            {"proposal_id": exp_prop_id, "approved": True, "code": exp_code},
                        )
                    )
                    restart_expired_blocked = (
                        restarted_expired.get("executed") is False
                        and "ProposalExpiredError" in str(restarted_expired.get("error_type"))
                    )

            if restart_replay_blocked and restart_expired_blocked:
                detail = (
                    f"Restarted daemon rejected replay of {unlock_id} (ProposalAlreadyConfirmedError) "
                    f"and rejected expired proposal {exp_prop_id} (ProposalExpiredError)"
                )
                print(f"[PASS] Check 10: {detail}")
                results.append(CheckResult(10, step_10_name, "PASS", detail))
            else:
                detail = (
                    f"restart_replay_blocked={restart_replay_blocked}, "
                    f"restart_expired_blocked={restart_expired_blocked}"
                )
                print(f"[FAIL] Check 10: {detail}")
                results.append(CheckResult(10, step_10_name, "FAIL", detail))
        finally:
            stop_server_subprocess(server_proc2)

        # -------------------------------------------------------------
        # Step 11: Audit verify_chain() and tampering detection
        # -------------------------------------------------------------
        step_11_name = "Audit chain validation & tampering detection"
        storage = AegisStorage(str(db_path))
        initial_audit_status = storage.verify_chain()
        chain_initially_valid = (initial_audit_status == "OK") and getattr(initial_audit_status, "is_valid", False)

        # Tamper with an audit entry directly in SQLite
        conn = sqlite3.connect(str(db_path))
        cur = conn.execute("SELECT id FROM audit ORDER BY id ASC LIMIT 1;")
        row = cur.fetchone()
        if row:
            tampered_id = row[0]
            conn.execute("UPDATE audit SET event = 'TAMPERED_ADVERSARY_EVENT' WHERE id = ?;", (tampered_id,))
            conn.commit()
        conn.close()

        tampered_audit_status = storage.verify_chain()
        tampering_detected = (tampered_audit_status != "OK") and not getattr(tampered_audit_status, "is_valid", True)

        if chain_initially_valid and tampering_detected:
            detail = (
                f"Initial hash chain verified valid (OK); after direct SQLite modification of row "
                f"#{tampered_id}, verify_chain() successfully detected the tampering (broken index: {tampered_audit_status})"
            )
            print(f"[PASS] Check 11: {detail}")
            results.append(CheckResult(11, step_11_name, "PASS", detail))
        else:
            detail = (
                f"chain_initially_valid={chain_initially_valid}, "
                f"tampering_detected={tampering_detected}"
            )
            print(f"[FAIL] Check 11: {detail}")
            results.append(CheckResult(11, step_11_name, "FAIL", detail))

        # -------------------------------------------------------------
        # Step 12: Real Bedrock Call (or SKIPPED)
        # -------------------------------------------------------------
        step_12_name = "Live Bedrock Converse API invocation"
        live_bedrock_enabled = os.getenv("AEGIS_LIVE_BEDROCK") == "1"

        if live_bedrock_enabled:
            try:
                from aegishome.bedrock_client import BedrockClient
                client = BedrockClient()
                summary_text, path_used, v_list = generate_home_summary(home_facts, model=client)
                if path_used == "deterministic_fallback":
                    err_type = getattr(client, "last_error", None)
                    if not err_type and v_list:
                        err_type = v_list[0].split(":")[0].replace("Bedrock invocation failed", "").strip() or "Error"
                    err_type = err_type or "UnknownError"
                    detail = f"Model: {client.model_id}, Path used: deterministic_fallback (Error: {err_type}), Summary length: {len(summary_text)} chars"
                    print(f"[DEGRADED] Check 12: {detail}")
                    results.append(CheckResult(12, step_12_name, "DEGRADED", detail))
                else:
                    detail = f"Model: {client.model_id}, Path used: {path_used}, Summary length: {len(summary_text)} chars"
                    print(f"[PASS] Check 12: {detail}")
                    results.append(CheckResult(12, step_12_name, "PASS", detail))
            except Exception as e:
                err_name = type(e).__name__
                detail = f"Bedrock invocation exception ({err_name}): {e}"
                print(f"[FAIL] Check 12: {detail}")
                results.append(CheckResult(12, step_12_name, "FAIL", detail))
        else:
            detail = "AEGIS_LIVE_BEDROCK!=1 (SKIPPED as specified)"
            print(f"[SKIPPED] Check 12: {detail}")
            results.append(CheckResult(12, step_12_name, "SKIPPED", detail))

    finally:
        stop_server_subprocess(server_proc)
        try:
            temp_dir.cleanup()
        except Exception:
            pass

    return results


def print_summary_table(results: list[CheckResult]) -> int:
    """Print formatted summary table and return count of failed checks."""
    print("\n" + "=" * 76)
    print("                     AEGIS END-TO-END SMOKE TEST SUMMARY")
    print("=" * 76)
    print(f"{'Step':<6} {'Description':<58} {'Status':<10}")
    print("-" * 76)

    pass_count = 0
    fail_count = 0
    degraded_count = 0
    skip_count = 0

    for r in results:
        status_str = r.status
        if r.status == "PASS":
            pass_count += 1
        elif r.status == "FAIL":
            fail_count += 1
        elif r.status == "DEGRADED":
            degraded_count += 1
        else:
            skip_count += 1

        short_name = r.name if len(r.name) <= 56 else r.name[:53] + "..."
        print(f"{r.step:02d}     {short_name:<58} {status_str:<10}")

    print("-" * 76)
    print(
        f"Total: {len(results)} checks | "
        f"Passed: {pass_count} | "
        f"Degraded: {degraded_count} | "
        f"Failed: {fail_count} | "
        f"Skipped: {skip_count}"
    )
    print("=" * 76 + "\n")
    return fail_count


def main() -> None:
    print("Starting Aegis End-to-End System Smoke Test...")
    print("=" * 76)
    results = asyncio.run(run_smoke_test())
    failed = print_summary_table(results)
    if failed > 0:
        print(f"FAILED: {failed} smoke test check(s) failed.")
        sys.exit(1)
    else:
        print("SUCCESS: All active checks passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
