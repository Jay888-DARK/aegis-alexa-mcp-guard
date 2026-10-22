"""Integration tests for AegisHome MCP server over Streamable HTTP transport."""

import asyncio
import socket
from typing import AsyncGenerator
import httpx
import pytest
import pytest_asyncio
import uvicorn
from mcp.server.streamable_http import is_version_at_least

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from aegishome.server import create_app, MINIMUM_SUPPORTED_PROTOCOL_VERSION


def get_free_port() -> int:
    """Find an available ephemeral port on localhost."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest_asyncio.fixture
async def running_server() -> AsyncGenerator[str, None]:
    """Start the AegisHome Starlette/uvicorn server in-process on an ephemeral port."""
    port = get_free_port()
    app = create_app(enable_dns_protection=False)
    config = uvicorn.Config(app=app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    server_task = asyncio.create_task(server.serve())

    # Wait for server startup
    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(f"{base_url}/health")
                if res.status_code == 200:
                    break
        except Exception:
            await asyncio.sleep(0.05)
    else:
        server.should_exit = True
        await server_task
        raise RuntimeError("Server failed to start within timeout.")

    try:
        yield base_url
    finally:
        server.should_exit = True
        await server_task


@pytest.mark.asyncio
async def test_health_endpoint(running_server: str) -> None:
    """Verify GET /health returns 200 OK and protocol metadata."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{running_server}/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["service"] == "aegishome"
        assert data["mcp_endpoint"] == "/mcp"
        assert "minimum_protocol_version" in data
        assert "latest_protocol_version" in data


@pytest.mark.asyncio
async def test_protocol_version_negotiation(running_server: str) -> None:
    """Verify MCP protocol version negotiation satisfies spec 2025-11-25 or later."""
    mcp_url = f"{running_server}/mcp"
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            negotiated_version = init_result.protocol_version
            assert negotiated_version is not None
            # MCP spec constraint: 2025-11-25 or later
            assert is_version_at_least(negotiated_version, MINIMUM_SUPPORTED_PROTOCOL_VERSION)
            assert negotiated_version >= MINIMUM_SUPPORTED_PROTOCOL_VERSION
            assert init_result.server_info.name == "aegishome"


@pytest.mark.asyncio
async def test_list_tools(running_server: str) -> None:
    """Verify that all 4 smart-home caregiver tools are exposed over Streamable HTTP."""
    mcp_url = f"{running_server}/mcp"
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_response = await session.list_tools()
            tool_names = {t.name for t in tools_response.tools}
            expected_tools = {
                "get_home_status",
                "propose_action",
                "confirm_action",
                "read_visitor_note",
            }
            assert expected_tools.issubset(tool_names)


@pytest.mark.asyncio
async def test_call_tool_get_home_status(running_server: str) -> None:
    """Verify get_home_status returns resident and device states."""
    mcp_url = f"{running_server}/mcp"
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool("get_home_status", {})
            assert not result.is_error
            content = result.structured_content
            assert content is not None
            assert "resident" in content
            assert content["resident"]["name"] == "Eleanor Vance"
            assert "doors" in content
            assert content["doors"]["front_door"] == "locked"
            assert "climate" in content
            assert content["climate"]["target_temp_f"] == 71.0
            assert "medication_drawer" in content


@pytest.mark.asyncio
async def test_call_tool_propose_and_confirm_action(running_server: str) -> None:
    """Verify the propose_action -> confirm_action lifecycle through MCP client."""
    mcp_url = f"{running_server}/mcp"
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            # 1. Propose action (HIGH tier: front door unlock)
            propose_res = await session.call_tool(
                "propose_action",
                {
                    "action_type": "unlock_door",
                    "target": "front_door",
                    "parameters": {"auto_relock_seconds": 60},
                },
            )
            assert not propose_res.is_error
            prop_data = propose_res.structured_content
            assert prop_data is not None
            assert prop_data["status"] == "PENDING"
            assert prop_data["action_type"] == "unlock_door"
            assert prop_data["risk_tier"] == "HIGH"
            assert "voice_code" in prop_data
            proposal_id = prop_data["proposal_id"]
            voice_code = prop_data["voice_code"]

            # 2. Approve via owner channel
            appr_res = await session.call_tool(
                "approve_action",
                {"proposal_id": proposal_id},
            )
            assert not appr_res.is_error
            assert appr_res.structured_content["owner_approved"] is True

            # 3. Confirm action with voice code
            confirm_res = await session.call_tool(
                "confirm_action",
                {
                    "proposal_id": proposal_id,
                    "approved": True,
                    "code": voice_code,
                    "reason": "Caregiver verified nurse scheduled arrival",
                },
            )
            assert not confirm_res.is_error
            conf_data = confirm_res.structured_content
            assert conf_data is not None
            assert conf_data["status"] == "APPROVED"
            assert conf_data["executed"] is True
            assert conf_data["proposal_id"] == proposal_id


@pytest.mark.asyncio
async def test_call_tool_confirm_action_invalid_id(running_server: str) -> None:
    """Verify confirm_action returns NOT_FOUND for non-existent proposals."""
    mcp_url = f"{running_server}/mcp"
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            confirm_res = await session.call_tool(
                "confirm_action",
                {
                    "proposal_id": "non_existent_prop_999",
                    "approved": True,
                },
            )
            assert not confirm_res.is_error
            conf_data = confirm_res.structured_content
            assert conf_data is not None
            assert conf_data["status"] == "NOT_FOUND"
            assert conf_data["executed"] is False


@pytest.mark.asyncio
async def test_call_tool_read_visitor_note(running_server: str) -> None:
    """Verify read_visitor_note returns untrusted visitor note with taint label."""
    mcp_url = f"{running_server}/mcp"
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            # Latest note
            note_res = await session.call_tool("read_visitor_note", {"note_id": "latest"})
            assert not note_res.is_error
            note_data = note_res.structured_content
            assert note_data is not None
            assert "porch" in note_data["content"].lower()
            assert note_data["taint_source"] == "external_untrusted"

            # Unknown note
            unknown_res = await session.call_tool("read_visitor_note", {"note_id": "unknown_404"})
            assert not unknown_res.is_error
            unknown_data = unknown_res.structured_content
            assert unknown_data is not None
            assert "No note found" in unknown_data["content"]
