"""MCP tools for system operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import logging

from agent_utilities.mcp_utilities import ctx_log
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.mcp_server import ResponseBuilder
from tunnel_manager.system_intelligence import SystemIntelligence
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger("tunnel-manager-mcp")


def register_system_tools(mcp: FastMCP):
    """Register remote system intelligence tool."""

    @mcp.tool(
        annotations={
            "title": "System Intelligence",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"system_intelligence"},
    )
    async def tm_system(
        action: str = Field(
            description="Action: 'get_info', 'discover_services', 'analyze_logs', 'network_topology'"
        ),
        remote_host: str = Field(description="Remote host."),
        username: str = Field(default="", description="SSH username."),
        password: str = Field(default="", description="SSH password."),
        identity_file: str = Field(default="", description="SSH identity file path."),
        log_paths: list[str] = Field(
            default=[], description="Log file paths (analyze_logs)."
        ),
        patterns: list[str] = Field(
            default=[], description="Search patterns (analyze_logs)."
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Remote system intelligence via SSH."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            intelligence = SystemIntelligence(tunnel)

            if action == "get_info":
                result = intelligence.get_system_info()
                return ResponseBuilder.build(
                    200,
                    "System information retrieved",
                    {"host": remote_host, "system_info": result},
                )

            elif action == "discover_services":
                result = intelligence.discover_services()
                return ResponseBuilder.build(
                    200,
                    "Services discovered",
                    {"host": remote_host, "services": result},
                )

            elif action == "analyze_logs":
                if not log_paths or not patterns:
                    return ResponseBuilder.build(
                        400,
                        "Need log_paths and patterns",
                        {"host": remote_host},
                        errors=["Need log_paths and patterns"],
                    )
                result = intelligence.analyze_logs(log_paths, patterns)
                return ResponseBuilder.build(
                    200,
                    "Log analysis completed",
                    {"host": remote_host, "analysis": result},
                )

            elif action == "network_topology":
                result = intelligence.network_topology()
                return ResponseBuilder.build(
                    200,
                    "Network topology mapped",
                    {"host": remote_host, "topology": result},
                )
            else:
                return ResponseBuilder.build(
                    400,
                    f"Unknown action: {action}",
                    {"action": action},
                    errors=[
                        "Valid: get_info, discover_services, analyze_logs, network_topology"
                    ],
                )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"System intelligence fail ({action}): {e}")
            return ResponseBuilder.build(
                500,
                f"System intelligence fail ({action})",
                {"host": remote_host},
                str(e),
            )
