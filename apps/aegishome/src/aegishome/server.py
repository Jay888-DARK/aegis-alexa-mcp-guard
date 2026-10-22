"""AegisHome MCP Server with Streamable HTTP transport, Starlette integration, and Web App."""

import contextlib
import os
from pathlib import Path
from typing import Any, AsyncIterator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import LATEST_PROTOCOL_VERSION

from aegishome.client import get_intent_driver, MCPToolExecutor
from aegishome.devices import get_simulated_home
from aegishome.tools import (
    get_home_status,
    propose_action,
    confirm_action,
    approve_action,
    read_visitor_note,
)
from aegishome.wire_logger import get_wire_logger
from aegis_guard.audit import get_audit_logger
from aegis_guard.confirm import get_confirmation_gateway
from aegis_guard.taint import get_taint_tracker, reset_taint_tracker

SERVER_NAME = "aegishome"
SERVER_VERSION = "0.1.0"
MINIMUM_SUPPORTED_PROTOCOL_VERSION = "2025-11-25"
STATIC_DIR = Path(__file__).resolve().parent / "static"


def create_mcp_server() -> MCPServer:
    """Create and configure the AegisHome MCPServer instance with registered tools."""
    server = MCPServer(
        name=SERVER_NAME,
        version=SERVER_VERSION,
        instructions=(
            "Aegis Smart-Home Caregiver safety gateway MCP server. "
            "Controls smart-home caregiver devices with deterministic guardrails."
        ),
    )

    # Register tool stubs
    server.tool(name="get_home_status")(get_home_status)
    server.tool(name="propose_action")(propose_action)
    server.tool(name="approve_action")(approve_action)
    server.tool(name="confirm_action")(confirm_action)
    server.tool(name="read_visitor_note")(read_visitor_note)

    return server


async def health_check(request: Request) -> JSONResponse:
    """Health check endpoint exposing server status and MCP protocol compatibility."""
    return JSONResponse(
        {
            "status": "healthy",
            "service": SERVER_NAME,
            "version": SERVER_VERSION,
            "mcp_endpoint": "/mcp",
            "minimum_protocol_version": MINIMUM_SUPPORTED_PROTOCOL_VERSION,
            "latest_protocol_version": LATEST_PROTOCOL_VERSION,
        }
    )


async def serve_index(request: Request) -> HTMLResponse:
    """Serve the single-page dashboard application."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        content = index_file.read_text(encoding="utf-8")
        return HTMLResponse(content=content, status_code=200)
    return HTMLResponse("<h1>AegisHome Web Dashboard</h1><p>Static index.html not found.</p>", status_code=200)


async def api_say(request: Request) -> JSONResponse:
    """Handle caregiver utterance, driving MCP tools via Bedrock or offline intent parser."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    utterance = body.get("utterance", "")
    session_id = body.get("session_id", "web_session")
    history = body.get("history", [])

    driver = get_intent_driver()
    response = driver.process_utterance(utterance, session_id=session_id, history=history)

    return JSONResponse(
        {
            "utterance": response.utterance,
            "reply": response.reply,
            "engine": response.engine,
            "engine_badge": getattr(response, "engine_badge", response.engine),
            "badge_tooltip": getattr(response, "badge_tooltip", ""),
            "tool_calls": response.tool_calls,
            "active_proposal_id": response.active_proposal_id,
            "voice_code": response.voice_code,
            "risk_tier": response.risk_tier,
            "is_tainted": response.is_tainted,
            "events": getattr(response, "events", []),
        }
    )


async def api_state(request: Request) -> JSONResponse:
    """Return live device status, pending proposals, wire logs, and audit trail."""
    session_id = request.query_params.get("session_id", "web_session")
    gw = get_confirmation_gateway()
    taint_tracker = get_taint_tracker()
    wire_logger = get_wire_logger()
    audit_logger = get_audit_logger()

    proposals_data = []
    for p in gw._proposals.values():
        proposals_data.append(
            {
                "proposal_id": p.proposal_id,
                "device": p.device,
                "action": p.action,
                "params": p.params,
                "risk_tier": p.risk_tier.value,
                "summary": p.summary,
                "expires_at": p.expires_at,
                "voice_code": p.voice_code,
                "status": p.status,
                "owner_approved": p.owner_approved,
                "is_tainted": p.is_tainted,
            }
        )

    return JSONResponse(
        {
            "devices": get_home_status(),
            "proposals": proposals_data,
            "wire_logs": wire_logger.get_entries(limit=50),
            "audit_logs": audit_logger.read_entries()[-50:],
            "is_tainted": taint_tracker.is_tainted(session_id),
        }
    )


async def api_approve(request: Request) -> JSONResponse:
    """Approve a HIGH-risk proposal via the out-of-band owner channel."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    proposal_id = body.get("proposal_id", "")
    approver_id = body.get("approver_id", "caregiver_phone_primary")

    executor = MCPToolExecutor()
    res = executor.call_tool("approve_action", {"proposal_id": proposal_id, "approver_id": approver_id})
    return JSONResponse(res.get("result", res))


async def api_confirm(request: Request) -> JSONResponse:
    """Confirm an action proposal with voice confirmation code."""
    try:
        body = await request.json()
    except Exception:
        body = {}

    proposal_id = body.get("proposal_id", "")
    approved = body.get("approved", True)
    code = body.get("code")
    reason = body.get("reason", "Caregiver voice confirmation")

    executor = MCPToolExecutor()
    res = executor.call_tool(
        "confirm_action",
        {
            "proposal_id": proposal_id,
            "approved": approved,
            "code": code,
            "reason": reason,
        },
    )
    return JSONResponse(res.get("result", res))


async def api_reset(request: Request) -> JSONResponse:
    """Reset simulated devices, proposals, and taint records to baseline."""
    get_simulated_home().reset()
    get_confirmation_gateway().reset()
    reset_taint_tracker()
    get_wire_logger().clear()
    return JSONResponse({"status": "reset_complete"})


async def api_wire_log(request: Request) -> JSONResponse:
    """Return captured JSON-RPC wire frames."""
    return JSONResponse(get_wire_logger().get_entries(limit=100))


async def api_audit(request: Request) -> JSONResponse:
    """Return append-only audit log records."""
    return JSONResponse(get_audit_logger().read_entries()[-100:])


def create_app(
    mcp_server: MCPServer | None = None,
    streamable_http_path: str = "/mcp",
    enable_dns_protection: bool | None = None,
) -> Starlette:
    """Create the Starlette application with Web UI, API endpoints, and /mcp Streamable HTTP.

    Args:
        mcp_server: Optional pre-configured MCPServer instance.
        streamable_http_path: Route path for MCP Streamable HTTP transport (default '/mcp').
        enable_dns_protection: Whether to enforce DNS rebinding protection. Defaults to env var
            or True for localhost/127.0.0.1.
    """
    if mcp_server is None:
        mcp_server = create_mcp_server()

    if enable_dns_protection is None:
        dns_env = os.getenv("AEGIS_DNS_PROTECTION", "true").lower()
        enable_dns_protection = dns_env in ("true", "1", "yes")

    transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=enable_dns_protection,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", "0.0.0.0:*"],
        allowed_origins=[
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
            "vscode-webview://*",
        ],
    )

    mcp_app = mcp_server.streamable_http_app(
        streamable_http_path=streamable_http_path,
        transport_security=transport_security,
    )

    @contextlib.asynccontextmanager
    async def app_lifespan(app: Starlette) -> AsyncIterator[None]:
        # Explicitly forward Starlette lifespan into the mounted MCP Streamable HTTP session manager
        async with mcp_app.router.lifespan_context(mcp_app):
            yield

    routes = [
        Route("/", serve_index, methods=["GET"]),
        Route("/health", health_check, methods=["GET"]),
        Route("/api/say", api_say, methods=["POST"]),
        Route("/api/state", api_state, methods=["GET"]),
        Route("/api/approve", api_approve, methods=["POST"]),
        Route("/api/confirm", api_confirm, methods=["POST"]),
        Route("/api/reset", api_reset, methods=["POST"]),
        Route("/api/wire_log", api_wire_log, methods=["GET"]),
        Route("/api/audit", api_audit, methods=["GET"]),
        Mount("/static", app=StaticFiles(directory=STATIC_DIR), name="static"),
        Mount("", app=mcp_app),
    ]

    return Starlette(routes=routes, lifespan=app_lifespan)
