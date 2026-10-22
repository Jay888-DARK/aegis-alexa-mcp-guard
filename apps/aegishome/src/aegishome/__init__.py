"""AegisHome: Smart-home caregiver MCP server for Alexa+."""

import sys
import types
from typing import Any

# Ensure backwards-compatibility for MCP SDK 1.28.0
try:
    import mcp.server.streamable_http as _sh
    if not hasattr(_sh, "is_version_at_least"):
        def _is_version_at_least(v: str, min_v: str) -> bool:
            return str(v) >= str(min_v)
        _sh.is_version_at_least = _is_version_at_least
except Exception:
    pass

try:
    from mcp.types import CallToolResult, InitializeResult

    if not hasattr(CallToolResult, "is_error"):
        CallToolResult.is_error = property(lambda self: getattr(self, "isError", False))
    if not hasattr(CallToolResult, "structured_content"):
        CallToolResult.structured_content = property(lambda self: getattr(self, "structuredContent", None))
    if not hasattr(InitializeResult, "protocol_version"):
        InitializeResult.protocol_version = property(lambda self: getattr(self, "protocolVersion", None))
    if not hasattr(InitializeResult, "server_info"):
        InitializeResult.server_info = property(lambda self: getattr(self, "serverInfo", None))
except Exception:
    pass

try:
    import mcp.server.mcpserver
except ImportError:
    import mcp.server
    from mcp.server.fastmcp import FastMCP

    class MCPServer(FastMCP):
        """Adapter bridging FastMCP with legacy MCPServer interface."""

        def __init__(self, name: str | None = None, version: str | None = None, **kwargs: Any) -> None:
            super().__init__(name=name, **kwargs)
            if version:
                self.version = version

        def streamable_http_app(self, streamable_http_path: str = "/mcp", transport_security: Any = None) -> Any:
            if transport_security is not None:
                self.transport_security = transport_security
            if streamable_http_path:
                self.streamable_http_path = streamable_http_path
            return super().streamable_http_app()

    mod = types.ModuleType("mcp.server.mcpserver")
    mod.MCPServer = MCPServer
    mod.context = getattr(mcp.server, "context", lambda: None)
    sys.modules["mcp.server.mcpserver"] = mod
    setattr(mcp.server, "mcpserver", mod)

__version__ = "0.1.0"
