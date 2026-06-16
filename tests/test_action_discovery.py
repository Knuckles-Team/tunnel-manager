"""Action-discovery standardization checks for tunnel-manager MCP tools.

Verifies the shared agent_utilities.mcp_utilities.resolve_action wiring:
list_actions discovery payloads and rich did-you-mean errors on bad actions.
"""

import asyncio

import pytest
from fastmcp import FastMCP

from tunnel_manager.mcp_server import (
    register_file_tools,
    register_host_tools,
    register_inventory_tools,
    register_operations_tools,
    register_remote_tools,
    register_security_tools,
    register_system_tools,
)

REGISTRARS = {
    "tm_hosts": register_host_tools,
    "tm_remote": register_remote_tools,
    "tm_inventory": register_inventory_tools,
    "tm_operations": register_operations_tools,
    "tm_system": register_system_tools,
    "tm_files": register_file_tools,
    "tm_security": register_security_tools,
}


async def _get_fn(tool_name):
    mcp = FastMCP("test")
    REGISTRARS[tool_name](mcp)
    tool = await mcp.get_tool(tool_name)
    return tool.fn


@pytest.mark.parametrize("tool_name", list(REGISTRARS))
def test_list_actions_returns_names(tool_name):
    fn = asyncio.run(_get_fn(tool_name))
    result = asyncio.run(fn(action="list_actions"))
    assert isinstance(result, dict)
    assert result["service"] == "tunnel-manager"
    assert isinstance(result["actions"], list)
    assert len(result["actions"]) >= 1


@pytest.mark.parametrize("tool_name", list(REGISTRARS))
def test_bogus_action_raises_with_list_actions_hint(tool_name):
    fn = asyncio.run(_get_fn(tool_name))
    with pytest.raises(ValueError) as exc:
        asyncio.run(fn(action="definitely_not_a_real_action"))
    assert "list_actions" in str(exc.value)
