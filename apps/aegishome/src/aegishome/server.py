"""AegisHome MCP Server with Streamable HTTP transport, Starlette integration, and Web App."""

from pathlib import Path
from dotenv import load_dotenv, find_dotenv

# Ensure .env is loaded at the very top of server.py before importing server or agent components
load_dotenv(override=True)
load_dotenv(find_dotenv(usecwd=True), override=True)
_curr = Path(__file__).resolve().parent
for _ in range(6):
    if (_curr / ".env").exists():
        load_dotenv(_curr / ".env", override=True)
        break
    _curr = _curr.parent

import contextlib
import os
from typing import Any, AsyncIterator
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse
from starlette.routing import Route, Mount
from starlette.staticfiles import StaticFiles
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import LATEST_PROTOCOL_VERSION

from starlette.middleware import Middleware
from starlette.types import ASGIApp, Scope, Receive, Send

from aegishome.client import get_intent_driver, MCPToolExecutor
from aegishome.devices import get_simulated_home
from aegishome.session_context import set_current_session_id, reset_current_session_id
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


class SessionBindingMiddleware:
    """Extracts Mcp-Session-Id from incoming HTTP transport headers and binds to ContextVar."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            mcp_sid = headers.get(b"mcp-session-id")
            if mcp_sid:
                session_str = mcp_sid.decode("utf-8", errors="ignore").strip()
                token = set_current_session_id(session_str)
                try:
                    await self.app(scope, receive, send)
                finally:
                    reset_current_session_id(token)
                return
        await self.app(scope, receive, send)


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

    # Strip session_id from tool schemas exposed to MCP clients
    for tool_name in ("propose_action", "read_visitor_note"):
        tool_obj = server._tool_manager.get_tool(tool_name)
        if tool_obj and hasattr(tool_obj, "parameters") and isinstance(tool_obj.parameters, dict):
            props = tool_obj.parameters.get("properties", {})
            if "session_id" in props:
                del props["session_id"]
            req = tool_obj.parameters.get("required", [])
            if "session_id" in req:
                tool_obj.parameters["required"] = [r for r in req if r != "session_id"]

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
    token = set_current_session_id(session_id)
    try:
        response = driver.process_utterance(utterance, session_id=session_id, history=history)
    finally:
        reset_current_session_id(token)

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

    engine = "RULE ENGINE"
    engine_badge = "RULE ENGINE"
    badge_tooltip = "Deterministic safety gateway active"
    groq_api_key = os.environ.get("GROQ_API_KEY")
    if groq_api_key and groq_api_key.strip():
        model_id = os.environ.get("GROQ_MODEL_ID", "llama-3.1-70b-versatile")
        try:
            from aegishome.groq_client import get_groq_short_model_name
            engine = "GROQ"
            engine_badge = f"GROQ · {get_groq_short_model_name(model_id)}"
            badge_tooltip = f"Active Groq LLM: {model_id}"
        except Exception:
            engine = "GROQ"
            engine_badge = "GROQ"
            badge_tooltip = f"Active Groq LLM: {model_id}"
    elif os.environ.get("BEDROCK_MODEL_ID"):
        try:
            from apps.aegishome.agent import _get_short_model_name
            mid = os.environ.get("BEDROCK_MODEL_ID", "")
            engine = "BEDROCK"
            engine_badge = f"BEDROCK · {_get_short_model_name(mid)}"
            badge_tooltip = f"Active AWS Bedrock: {mid}"
        except Exception:
            pass

    return JSONResponse(
        {
            "devices": get_home_status(),
            "proposals": proposals_data,
            "wire_logs": wire_logger.get_entries(limit=50),
            "audit_logs": audit_logger.read_entries()[-50:],
            "is_tainted": taint_tracker.is_tainted(session_id),
            "engine": engine,
            "engine_badge": engine_badge,
            "badge_tooltip": badge_tooltip,
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
    print("GROQ API KEY DETECTED:", bool(os.environ.get("GROQ_API_KEY")), flush=True)
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

    return Starlette(
        routes=routes,
        lifespan=app_lifespan,
        middleware=[Middleware(SessionBindingMiddleware)],
    )
