"""Session context management and server-side session resolution for AegisHome.

Enforces transport-level and agent-level session binding. Ensures the model or
external caller cannot choose, spoof, or evade its session_id.
"""

from contextvars import ContextVar, Token
import logging
from typing import Any

logger = logging.getLogger("aegishome.session")

_CURRENT_SESSION_ID: ContextVar[str | None] = ContextVar("current_session_id", default=None)
FAIL_CLOSED_ANONYMOUS_SESSION = "__untrusted_anonymous_session__"


def set_current_session_id(session_id: str | None) -> Token:
    """Bind a verified session ID to the current asynchronous execution context."""
    return _CURRENT_SESSION_ID.set(session_id)


def reset_current_session_id(token: Token) -> None:
    """Reset the bound session ID using the context token."""
    _CURRENT_SESSION_ID.reset(token)


def resolve_active_session(explicit_session_id: str | None = None) -> tuple[str, bool]:
    """Resolve the authoritative session ID for the active execution context.

    Resolution hierarchy:
    1. ContextVar bound by ASGI middleware (Mcp-Session-Id header) or agent turn runner.
    2. MCP request context headers if available via mcp.server.mcpserver.context().
    3. If no ambient context is bound, but caller provided an explicit session (e.g. direct unit test):
       use the explicit session ID.
    4. Fail closed: if no session can be determined at all, returns FAIL_CLOSED_ANONYMOUS_SESSION
       and marks it tainted in the taint tracker so that any proposal is escalated to
       HIGH risk and requires owner approval.

    Returns:
        tuple[str, bool]: (resolved_session_id, was_spoofing_attempt)
    """
    sid = _CURRENT_SESSION_ID.get()
    if sid is None or not str(sid).strip():
        # Attempt to extract Mcp-Session-Id from MCP lowlevel server request_ctx
        try:
            from mcp.server.lowlevel.server import request_ctx
            mcp_req_ctx = request_ctx.get()
            if mcp_req_ctx is not None:
                starlette_req = getattr(mcp_req_ctx, "request", None)
                if starlette_req is not None and hasattr(starlette_req, "headers"):
                    val = starlette_req.headers.get("mcp-session-id")
                    if val and str(val).strip():
                        sid = str(val).strip()
        except Exception:
            pass

    if sid is None or not str(sid).strip():
        # Attempt to extract Mcp-Session-Id from legacy MCP server request context
        try:
            from mcp.server.mcpserver import context
            ctx = context()
            headers = getattr(ctx, "headers", None)
            if headers:
                for k, v in headers.items():
                    if k.lower() == "mcp-session-id" and v and str(v).strip():
                        sid = str(v).strip()
                        break
        except Exception:
            pass

    # If ambient/transport context is bound:
    if sid is not None and str(sid).strip():
        authoritative_sid = str(sid).strip()
        was_spoof = (
            explicit_session_id is not None
            and str(explicit_session_id).strip() != ""
            and str(explicit_session_id).strip() != authoritative_sid
        )
        return authoritative_sid, was_spoof

    # If no ambient context is bound (e.g. direct Python test without HTTP/agent):
    if explicit_session_id is not None and str(explicit_session_id).strip():
        return str(explicit_session_id).strip(), False

    # Fail closed: treat as untrusted anonymous session and taint it
    try:
        from aegis_guard.taint import get_taint_tracker
        tracker = get_taint_tracker()
        tracker.mark_tainted(
            session_id=FAIL_CLOSED_ANONYMOUS_SESSION,
            source="fail_closed_unspecified_session",
            reason="No session ID could be determined from transport or agent context; failing closed to tainted.",
        )
    except Exception as e:
        logger.error(f"Failed to mark anonymous session tainted: {e}")

    return FAIL_CLOSED_ANONYMOUS_SESSION, False
