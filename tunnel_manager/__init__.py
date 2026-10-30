#!/usr/bin/env python

import importlib
import inspect
from typing import Any

__all__: list[str] = []

CORE_MODULES: list[str] = ["tunnel_manager.tunnel_manager"]

OPTIONAL_MODULES = {
    "tunnel_manager.mcp_server": "mcp",
}


def _expose_members(module):
    """Expose public classes and functions from a module into globals and __all__."""
    for name, obj in inspect.getmembers(module):
        if (inspect.isclass(obj) or inspect.isfunction(obj)) and not name.startswith(
            "_"
        ):
            globals()[name] = obj
            if name not in __all__:
                __all__.append(name)


# Eagerly import core modules (keeps API wrappers fast & light)
for module_name in CORE_MODULES:
    if module_name:
        module = importlib.import_module(module_name)
        _expose_members(module)

# Stable structured remote-execution seam.  Keep the export list explicit so
# importing the package does not expose HostConfig/transport implementation
# details from this adapter.
from .remote_execution import (  # noqa: E402
    AuthorizedTarget,
    ExecutionOutcome,
    FailureClass,
    HostInventory,
    RemoteArtifactReference,
    RemoteCommandRequest,
    RemoteExecutionContext,
    RemoteExecutionError,
    RemoteExecutionResult,
    RemoteLogReference,
    RemoteRequestError,
    RemoteTargetError,
    RemoteTransportError,
    TunnelCommandExecutor,
    TunnelTransport,
    create_tunnel_executor,
    render_remote_command,
)

__all__ += [
    "AuthorizedTarget",
    "ExecutionOutcome",
    "FailureClass",
    "HostInventory",
    "RemoteArtifactReference",
    "RemoteCommandRequest",
    "RemoteExecutionError",
    "RemoteExecutionContext",
    "RemoteExecutionResult",
    "RemoteLogReference",
    "RemoteRequestError",
    "RemoteTargetError",
    "RemoteTransportError",
    "TunnelCommandExecutor",
    "TunnelTransport",
    "create_tunnel_executor",
    "render_remote_command",
]

# Dynamic/lazy loading of optional modules (mcp_server)
_loaded_optional_modules: dict[str, Any] = {}


def _import_module_safely(module_name: str):
    """Try to import a module and return it, or None if not available."""
    try:
        return importlib.import_module(module_name)
    except ImportError:
        return None


def __getattr__(name: str) -> Any:
    # Handle availability flags dynamically without eager imports
    if name == "_MCP_AVAILABLE":
        mcp_key = next((k for k in OPTIONAL_MODULES if "mcp_server" in k), None)
        if mcp_key:
            return _import_module_safely(mcp_key) is not None
        return False

    # Check optional modules
    for module_name in OPTIONAL_MODULES:
        if module_name not in _loaded_optional_modules:
            module = _import_module_safely(module_name)
            if module is not None:
                _loaded_optional_modules[module_name] = module
                _expose_members(module)

        module = _loaded_optional_modules.get(module_name)
        if module is not None and hasattr(module, name):
            return getattr(module, name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + __all__)


from scion_sdk.connector import Connector

from tunnel_manager.mcp_server import (
    get_client,
    register_file_tools,
    register_ingest_tools,
    register_inventory_tools,
    register_operations_tools,
    register_remote_tools,
    register_security_tools,
    register_system_tools,
)
from tunnel_manager.tunnel_manager import HostManager

connector = Connector(
    api=HostManager,
    get_client=get_client,
    instructions="Tunnel Manager MCP Utility — Manage SSH tunnels, managed hosts, and remote execution.",
    action_tools=(
        ("remote", "REMOTETOOL", register_remote_tools),
        ("inventory", "INVENTORYTOOL", register_inventory_tools),
        ("operations", "OPERATIONSTOOL", register_operations_tools),
        ("system", "SYSTEMTOOL", register_system_tools),
        ("files", "FILETOOL", register_file_tools),
        ("security", "SECURITYTOOL", register_security_tools),
        ("ingest", "INGESTTOOL", register_ingest_tools),
    ),
    action_prefixes={
        "tm_remote": "tm_remote",
        "tm_inventory": "tm_inventory",
        "tm_operations": "tm_operation",
        "tm_system": "tm_system",
        "tm_files": "tm_file",
        "tm_security": "tm_security",
    },
)

__all__ = ["connector"]
