"""MCP tool registration modules for tunnel-manager.

Auto-generated during ecosystem standardization.
Each domain has its own module with a register_*_tools function.
"""

from tunnel_manager.mcp.mcp_file import register_file_tools
from tunnel_manager.mcp.mcp_host import register_host_tools
from tunnel_manager.mcp.mcp_inventory import register_inventory_tools
from tunnel_manager.mcp.mcp_operations import register_operations_tools
from tunnel_manager.mcp.mcp_remote import register_remote_tools
from tunnel_manager.mcp.mcp_security import register_security_tools
from tunnel_manager.mcp.mcp_system import register_system_tools

__all__ = [
    "register_file_tools",
    "register_host_tools",
    "register_inventory_tools",
    "register_operations_tools",
    "register_remote_tools",
    "register_security_tools",
    "register_system_tools",
]
