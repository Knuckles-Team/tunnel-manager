"""No tunnel-manager tool routes an action: every operation is its own tool."""

import asyncio

from scion_sdk.connector import build_server

OPERATIONS = {
    "tm_remote": (
        "run_command", "send_file", "receive_file", "check_ssh", "test_key_auth",
        "setup_passwordless", "copy_ssh_config", "rotate_key", "remove_host_key",
    ),
    "tm_inventory": (
        "run_command", "configure_key_auth", "mesh_bootstrap", "copy_ssh_config",
        "rotate_key", "send_file", "receive_file",
    ),
}  # fmt: skip


def _served():
    mcp = build_server("tunnel_manager", command_args=[])[1]
    return {t.name: t for t in asyncio.run(mcp.list_tools())}


def test_no_served_tool_takes_an_action():
    for name, tool in _served().items():
        assert "action" not in tool.parameters.get("properties", {}), name


def test_each_remote_and_inventory_operation_is_a_tool():
    served = set(_served())
    for prefix, actions in OPERATIONS.items():
        for action in actions:
            assert f"{prefix}_{action}" in served
