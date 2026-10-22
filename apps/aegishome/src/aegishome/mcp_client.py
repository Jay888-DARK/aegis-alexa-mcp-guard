"""MCP Client adapter for Bedrock tool-use."""

from typing import Any
from aegishome.client import MCPToolExecutor, MCP_TOOLS_SPEC


class ToolDescriptor:
    """Wrapper describing an MCP tool schema for Bedrock Converse."""

    def __init__(self, name: str, description: str, input_schema: dict[str, Any]) -> None:
        self.name = name
        self.description = description
        self.inputSchema = input_schema


class MCPClient:
    """Synchronous adapter to list and invoke AegisHome MCP tools."""

    def __init__(self, executor: MCPToolExecutor | None = None) -> None:
        self.executor = executor or MCPToolExecutor()

    def list_tools(self) -> list[ToolDescriptor]:
        """Fetch registered tool specifications matching MCPToolExecutor capabilities."""
        tools = []
        for spec in MCP_TOOLS_SPEC:
            ts = spec.get("toolSpec", {})
            name = ts.get("name", "")
            description = ts.get("description", "")
            input_schema = ts.get("inputSchema", {}).get("json", {})
            tools.append(ToolDescriptor(name, description, input_schema))
        return tools

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch tool call through the real executor and return unwrapped dictionary."""
        res = self.executor.call_tool(name, arguments)
        if isinstance(res, dict) and "result" in res and not res.get("is_error"):
            return res["result"]
        return res


_GLOBAL_MCP_CLIENT = MCPClient()


def get_mcp_client() -> MCPClient:
    """Return global or mockable MCP client instance."""
    return _GLOBAL_MCP_CLIENT
