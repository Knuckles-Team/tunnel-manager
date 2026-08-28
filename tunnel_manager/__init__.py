#!/usr/bin/env python

import importlib
import inspect
from typing import Any

__all__: list[str] = []

CORE_MODULES: list[str] = ["tunnel_manager.tunnel_manager"]

OPTIONAL_MODULES = {
    "tunnel_manager.agent_server": "agent_server",
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

# Dynamic/lazy loading of optional modules (agent_server, mcp_server)
_loaded_optional_modules: dict[str, Any] = {}


def _import_module_safely(module_name: str):
    """Try to import a module and return it, or None if not available."""
    try:
        return importlib.import_module(module_name)
    except ImportError:
        return None


_AVAILABILITY_FLAG_MARKERS = {
    "_MCP_AVAILABLE": "mcp_server",
    "_AGENT_AVAILABLE": "agent_server",
}


def _availability_flag(name: str) -> bool:
    """Resolve an `_*_AVAILABLE` flag without eagerly importing the module."""
    marker = _AVAILABILITY_FLAG_MARKERS[name]
    module_key = next((k for k in OPTIONAL_MODULES if marker in k), None)
    if module_key is None:
        return False
    return _import_module_safely(module_key) is not None


def _load_optional_module(module_name: str):
    """Import and cache one optional module, exposing its public members."""
    if module_name in _loaded_optional_modules:
        return _loaded_optional_modules[module_name]
    module = _import_module_safely(module_name)
    if module is not None:
        _loaded_optional_modules[module_name] = module
        _expose_members(module)
    return module


def _find_in_optional_modules(name: str) -> Any:
    for module_name in OPTIONAL_MODULES:
        module = _load_optional_module(module_name)
        if module is not None and hasattr(module, name):
            return getattr(module, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __getattr__(name: str) -> Any:
    if name in _AVAILABILITY_FLAG_MARKERS:
        return _availability_flag(name)
    return _find_in_optional_modules(name)


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + __all__)
