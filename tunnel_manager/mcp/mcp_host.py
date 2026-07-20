"""MCP tools for host operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import logging

from agent_utilities.mcp.concurrency import run_blocking
from agent_utilities.mcp.context_helpers import (
    ctx_confirm_destructive,
    ctx_progress,
)
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.mcp_server import ResponseBuilder, host_manager

logger = logging.getLogger("tunnel-manager-mcp")


def register_host_tools(mcp: FastMCP):
    """Register host inventory management tool."""

    @mcp.tool(
        annotations={
            "title": "Host Management",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"host_management"},
    )
    async def tm_hosts(
        action: str = Field(description="Action: 'list', 'add', 'remove'"),
        alias: str = Field(default="", description="Host alias."),
        hostname: str = Field(default="", description="Real hostname or IP."),
        user: str = Field(default="", description="Username."),
        port: int = Field(default=22, description="SSH port."),
        identity_file: str = Field(default="", description="Path to private key."),
        password_ref: str = Field(
            default="", description="Secret-manager reference for an SSH password."
        ),
        known_hosts_file: str = Field(
            default="", description="Verified SSH server-key trust store path."
        ),
        proxy_command: str = Field(default="", description="Proxy command."),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Manage the local host alias inventory."""
        if action == "list":
            return {"hosts": await run_blocking(host_manager.list_hosts)}
        elif action == "add":
            if not alias or not hostname or not user:
                return ResponseBuilder.build(
                    400,
                    "Need alias, hostname, user",
                    {"action": action},
                    errors=["Need alias, hostname, user"],
                )
            await run_blocking(
                host_manager.add_host,
                alias=alias,
                hostname=hostname,
                user=user,
                port=port,
                identity_file=identity_file or None,
                password_ref=password_ref or None,
                known_hosts_file=known_hosts_file or None,
                proxy_command=proxy_command or None,
            )
            return {"status": "success", "message": "Host added."}
        elif action == "remove":
            if not alias:
                return ResponseBuilder.build(
                    400, "Need alias", {"action": action}, errors=["Need alias"]
                )
            if not await ctx_confirm_destructive(ctx, "remove host"):
                return {"status": "cancelled", "message": "Operation cancelled by user"}
            await ctx_progress(ctx, 0, 100)
            await run_blocking(host_manager.remove_host, alias)
            return {"status": "success", "message": "Host removed."}
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=["Valid: list, add, remove"],
            )
