#!/usr/bin/env python
import warnings

from fastmcp import Context, FastMCP
from fastmcp.utilities.logging import get_logger
from pydantic import Field

# Filter RequestsDependencyWarning early to prevent log spam
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    try:
        from requests.exceptions import RequestsDependencyWarning

        warnings.filterwarnings("ignore", category=RequestsDependencyWarning)
    except ImportError:
        pass

# General urllib3/chardet mismatch warnings
warnings.filterwarnings("ignore", message=".*urllib3.*or chardet.*")
warnings.filterwarnings("ignore", message=".*urllib3.*or charset_normalizer.*")

import asyncio
import concurrent.futures
import logging
import os
import shlex
import subprocess
import sys
from typing import Any

import yaml
from agent_utilities.core.config import load_config, setting
from agent_utilities.mcp.action_dispatch import resolve_action
from agent_utilities.mcp.concurrency import run_blocking
from agent_utilities.mcp.context_helpers import (
    ctx_confirm_destructive,
    ctx_log,
    ctx_progress,
)
from agent_utilities.mcp.server_factory import create_mcp_server
from agent_utilities.mcp.verbose_tools import register_tool_surface
from agent_utilities.security.persistence_privacy import sanitize_for_persistence

from tunnel_manager.advanced_file_manager import AdvancedFileManager
from tunnel_manager.connection_security import (
    max_concurrency,
    max_fleet_hosts,
    max_transfer_bytes,
    resolve_secret_ref,
    validate_public_key,
    validate_secret_ref,
    validate_timeout,
)
from tunnel_manager.models import HostConfig
from tunnel_manager.operation_manager import operation_manager
from tunnel_manager.security_auditor import SecurityAuditor
from tunnel_manager.system_intelligence import SystemIntelligence
from tunnel_manager.tunnel_manager import (
    HostManager,
    Tunnel,
    _known_hosts_file,
    default_inventory_path,
)

__version__ = "3.1.0"

# XDG-compliant default paths. The inventory is shared across the ecosystem
# (the HostManager library, container-manager-mcp, and the ssh-bootstrap skill all
# read $XDG_CONFIG_HOME/agent-utilities/inventory.yml), so the MCP server defaults
# to the SAME file — one inventory, one location. The resolver prefers the new
# `inventory.yml` and falls back to a legacy `inventory.yaml`. Override with
# $TUNNEL_INVENTORY.
_XDG_CONFIG_HOME = setting("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
_TM_CONFIG_DIR = os.path.join(_XDG_CONFIG_HOME, "agent-utilities")
_DEFAULT_INVENTORY_PATH = default_inventory_path()

# Ensure config directory exists on import
os.makedirs(_TM_CONFIG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = get_logger("TunnelManager")
# D-CDX-88: HostManager (the alias store tm_remote/tm_hosts authorize
# against) must resolve the SAME inventory file tm_inventory defaults to —
# previously it always used default_inventory_path() and silently ignored
# a $TUNNEL_INVENTORY override, so a deployment pointing tm_inventory at a
# mounted inventory left the alias store reading a different (often empty)
# default file. This is the bridge: one env var, one resolution order, for
# both surfaces.
host_manager = HostManager(
    config_file=setting("TUNNEL_INVENTORY") or _DEFAULT_INVENTORY_PATH
)


def get_client() -> HostManager:
    """Return the process-wide :class:`HostManager` (verbose-surface dependency)."""
    return host_manager


class ResponseBuilder:
    @staticmethod
    def build(
        status: int,
        msg: str,
        details: dict,
        error: str = "",
        stdout: str = "",
        files: list | None = None,
        locations: list | None = None,
        errors: list | None = None,
    ) -> dict:
        safe_payload, _ = sanitize_for_persistence(
            {
                "status_code": status,
                "message": msg,
                "stdout": stdout,
                "stderr": error,
                "files_copied": files or [],
                "locations_copied_to": locations or [],
                "details": details,
                "errors": errors or ([error] if error else []),
            }
        )
        return safe_payload


def _inventory_password_ref(*sources: dict) -> str | None:
    """Return a validated reference and reject plaintext inventory secrets."""

    reference = None
    for source in sources:
        if not isinstance(source, dict):
            continue
        if "ansible_ssh_pass" in source or "password" in source:
            raise ValueError(
                "plaintext inventory passwords are unsupported; configure password_ref"
            )
        reference = (
            reference
            or source.get("ansible_ssh_pass_ref")
            or source.get("password_ref")
        )
    if not reference:
        return None
    return validate_secret_ref(str(reference))


def _first_value(sources: tuple[dict, ...], *keys: str) -> Any:
    """First truthy ``source[key]`` scanning sources in order, keys within each.

    Preserves the source-major/key-minor precedence of the ``or``-chains this
    replaces (host vars beat group vars beat ``all`` vars) AND their fallback:
    ``a or b or c`` yields ``c`` when nothing is truthy, so with no truthy hit
    this returns the LAST lookup -- ``""`` for a present-but-empty final key,
    not ``None``. Returning ``None`` there changed ``key_path: ""`` into
    ``key_path: None``, which an OLD-vs-NEW inventory sweep caught.
    """
    value = None
    for source in sources:
        for key in keys:
            value = source.get(key)
            if value:
                return value
    return value


def _group_host_pairs(data: Any) -> dict:
    """``alias -> (hvars, g_vars)`` for one Ansible group mapping."""
    if not isinstance(data, dict):
        return {}
    g_vars = data.get("vars", {}) or {}
    g_hosts = data.get("hosts", {}) or {}
    return {alias: (hvars or {}, g_vars) for alias, hvars in g_hosts.items()}


def _ansible_all_group_pairs(all_group: dict) -> dict:
    """``alias -> (hvars, g_vars)`` for the ``all`` group and every child."""
    all_hosts = all_group.get("hosts", {}) or {}
    pairs: dict = {alias: (hvars or {}, {}) for alias, hvars in all_hosts.items()}
    for child_data in (all_group.get("children", {}) or {}).values():
        pairs.update(_group_host_pairs(child_data))
    return pairs


def _ansible_toplevel_group_pairs(inv: dict, group: str) -> dict | None:
    """Pairs for a group defined as a top-level key outside ``all.children``."""
    entry = inv.get(group)
    if not isinstance(entry, dict) or "hosts" not in entry:
        return None
    return _group_host_pairs(entry)


def _ansible_hosts_to_parse(
    inv: dict, all_group: dict, group: str, inventory: str
) -> tuple[dict, dict | None]:
    """Collect the (hvars, g_vars) pairs an Ansible-style group resolves to."""
    children = all_group.get("children", {}) or {}
    if group == "all":
        return _ansible_all_group_pairs(all_group), None
    if group in children:
        return _group_host_pairs(children[group]), None
    pairs = _ansible_toplevel_group_pairs(inv, group)
    if pairs is None:
        return {}, ResponseBuilder.build(
            400,
            "Configured inventory group is invalid",
            {"inventory": inventory, "group": group},
            errors=["Configured inventory group is invalid"],
        )
    return pairs, None


_KEY_PATH_KEYS = ("key_path", "identity_file", "ansible_ssh_private_key_file")


def _build_ansible_entry(alias: str, hvars: dict, g_vars: dict, all_vars: dict) -> dict:
    """One host entry from an Ansible-style (host, group, all) var cascade."""
    sources = (hvars, g_vars, all_vars)
    username = _first_value(sources, "ansible_user", "user") or ""
    port = _first_value(sources, "ansible_port", "port") or 22
    return {
        "hostname": hvars.get("ansible_host") or hvars.get("hostname") or alias,
        "username": username,
        "password_ref": _inventory_password_ref(hvars, g_vars, all_vars),
        "known_hosts_file": _known_hosts_file(hvars, g_vars, all_vars),
        "key_path": _first_value(sources, *_KEY_PATH_KEYS),
        "port": int(port) if port else 22,
    }


def _build_ansible_entries(
    hosts_to_parse: dict, all_vars: dict, logger: logging.Logger
) -> list[dict]:
    hosts = []
    for alias, (hvars, g_vars) in hosts_to_parse.items():
        entry = _build_ansible_entry(alias, hvars, g_vars, all_vars)
        if not entry["username"]:
            logger.error("Skipping inventory host without a username")
            continue
        hosts.append(entry)
    return hosts


def _load_ansible_style_hosts(
    inv: dict, group: str, inventory: str, logger: logging.Logger
) -> tuple[list[dict], dict | None]:
    all_group = inv["all"]
    all_vars = all_group.get("vars", {}) or {}
    hosts_to_parse, error = _ansible_hosts_to_parse(inv, all_group, group, inventory)
    if error is not None:
        return [], error
    return _build_ansible_entries(hosts_to_parse, all_vars, logger), None


def _build_legacy_flat_entry(alias: str, hvars: dict) -> dict:
    """One host entry from a flat (non-Ansible) inventory mapping."""
    sources = (hvars,)
    username = _first_value(sources, "user", "username", "ansible_user") or ""
    port = _first_value(sources, "port", "ansible_port") or 22
    return {
        "hostname": hvars.get("hostname") or hvars.get("ansible_host") or alias,
        "username": username,
        "password_ref": _inventory_password_ref(hvars),
        "known_hosts_file": _known_hosts_file(hvars),
        "key_path": _first_value(sources, *_KEY_PATH_KEYS),
        "port": int(port) if port else 22,
    }


def _load_legacy_flat_hosts(inv: dict, logger: logging.Logger) -> list[dict]:
    # Treat the entire inv as flat hosts
    hosts = []
    for alias, hvars in inv.items():
        if not isinstance(hvars, dict):
            continue
        entry = _build_legacy_flat_entry(alias, hvars)
        if not entry["username"]:
            logger.error("Skipping inventory host without a username")
            continue
        hosts.append(entry)
    return hosts


def _build_legacy_group_entry(host: str, hvars: dict) -> dict:
    """One host entry from a legacy top-level ``<group>.hosts`` mapping."""
    sources = (hvars,)
    username = _first_value(sources, "ansible_user", "user", "username")
    return {
        "hostname": hvars.get("ansible_host") or hvars.get("hostname") or host,
        "username": username,
        "password_ref": _inventory_password_ref(hvars),
        "known_hosts_file": _known_hosts_file(hvars),
        "key_path": _first_value(
            sources, "ansible_ssh_private_key_file", "key_path", "identity_file"
        ),
        "port": int(_first_value(sources, "ansible_port", "port") or 22),
    }


def _load_legacy_group_hosts(
    inv: dict, group: str, logger: logging.Logger
) -> list[dict]:
    # Legacy style with group as a top-level key containing 'hosts'
    hosts = []
    for host, vars in inv[group]["hosts"].items():
        entry = _build_legacy_group_entry(host, vars or {})
        if not entry["username"]:
            logger.error("Skipping inventory host without a username")
            continue
        hosts.append(entry)
    return hosts


def _load_legacy_style_hosts(
    inv: dict, group: str, inventory: str, logger: logging.Logger
) -> tuple[list[dict], dict | None]:
    # Legacy non-Ansible flat inventory (or key-value flat structure)
    if group == "all":
        return _load_legacy_flat_hosts(inv, logger), None
    if (
        group in inv
        and isinstance(inv[group], dict)
        and "hosts" in inv[group]
        and isinstance(inv[group]["hosts"], dict)
    ):
        return _load_legacy_group_hosts(inv, group, logger), None
    return [], ResponseBuilder.build(
        400,
        "Configured inventory group is invalid",
        {"inventory": inventory, "group": group},
        errors=["Configured inventory group is invalid"],
    )


def load_inventory(
    inventory: str, group: str, logger: logging.Logger
) -> tuple[list[dict], dict]:
    try:
        with open(inventory) as f:
            inv = yaml.safe_load(f) or {}

        # Check if it's an Ansible-style inventory
        if "all" in inv and isinstance(inv["all"], dict):
            hosts, error = _load_ansible_style_hosts(inv, group, inventory, logger)
        else:
            hosts, error = _load_legacy_style_hosts(inv, group, inventory, logger)
        if error is not None:
            return [], error

        if not hosts:
            return [], ResponseBuilder.build(
                400,
                "No hosts in configured inventory group",
                {"inventory": inventory, "group": group},
                errors=["No hosts in configured inventory group"],
            )
        if len(hosts) > max_fleet_hosts():
            return [], ResponseBuilder.build(
                400,
                "Configured inventory exceeds the fleet limit",
                {"host_count": len(hosts)},
                errors=["Configured inventory exceeds the fleet limit"],
            )
        return hosts, {}
    except Exception as e:
        logger.error("Load inv fail")
        return [], ResponseBuilder.build(
            500,
            "Load inv fail",
            {"inventory": inventory, "group": group},
            type(e).__name__,
        )


def resolve_single_host(
    inventory: str, host: str, logger: logging.Logger
) -> tuple[list[dict], dict]:
    """Resolve exactly ONE host for a single-host inventory selector.

    D-CDX-88: bridges ``tm_inventory``'s YAML-group fan-out (``load_inventory``
    above) to the SAME entitlement-checked alias store ``tm_remote``/
    ``tm_hosts`` authorize against (:data:`host_manager`), instead of a second,
    divergent notion of "known host". An unknown alias returns a 400 and a
    caller not entitled to a known alias gets the identical ``PermissionError``
    denial ``tm_remote`` would give them — never a silent no-op, matching this
    codebase's fail-loudly convention.

    Returns a one-item ``hosts`` list shaped like ``load_inventory``'s entries
    (safe to feed straight into the same per-host execution loop) plus an
    error-response dict (empty on success).
    """
    try:
        host_config = host_manager.get_host(host)
    except PermissionError as e:
        return [], ResponseBuilder.build(
            403,
            f"Not entitled to host alias: {host}",
            {"inventory": inventory, "host": host},
            errors=[str(e)],
        )
    if host_config is None:
        return [], ResponseBuilder.build(
            400,
            f"Unknown host alias: {host}",
            {"inventory": inventory, "host": host},
            errors=[f"Unknown host alias: {host}"],
        )
    if not host_config.user:
        return [], ResponseBuilder.build(
            400,
            f"Host alias '{host}' has no configured username",
            {"inventory": inventory, "host": host},
            errors=[f"Host alias '{host}' has no configured username"],
        )
    entry = {
        "hostname": host_config.hostname,
        "username": host_config.user,
        "password_ref": host_config.password_ref,
        "known_hosts_file": host_config.known_hosts_file,
        "key_path": host_config.identity_file or host_config.key_path,
        "port": host_config.port or 22,
    }
    return [entry], {}


def _resolve_host(
    host_alias: str,
    user: str | None = None,
    password: str | None = None,
    port: int | None = None,
    identity_file: str | None = None,
    certificate_file: str | None = None,
    proxy_command: str | None = None,
    ssh_config_file: str | None = None,
) -> tuple[dict, str | None]:
    """
    Resolve host details from HostManager if alias exists,
    otherwise return provided parameters as a config dict.
    """
    host_config = host_manager.get_host(host_alias)
    if host_config:
        logger.debug("Resolved configured host alias")

        final_config = host_config.model_dump()
        final_config["password"] = host_config.resolved_password()
        final_config.pop("password_ref", None)
        if user:
            final_config["user"] = user
        if password:
            final_config["password"] = password
        if port:
            final_config["port"] = port
        if identity_file:
            final_config["identity_file"] = identity_file
        if certificate_file:
            final_config["certificate_file"] = certificate_file
        if proxy_command:
            final_config["proxy_command"] = proxy_command

    else:
        logger.debug("Configured host alias was not found; using request parameters")
        final_config = {
            "hostname": host_alias,
            "user": user,
            "password": password,
            "port": port or 22,
            "identity_file": identity_file,
            "certificate_file": certificate_file,
            "proxy_command": proxy_command,
        }

    return final_config, ssh_config_file


async def _tm_hosts_list() -> dict:
    """``tm_hosts`` ``list``: return the alias inventory, best-effort KG ingest."""
    hosts = await run_blocking(host_manager.list_hosts)
    # Native KG ingestion — default-on, best-effort, never fatal.
    if setting("TUNNEL_KG_INGEST", "true").lower() not in ("false", "0", "no"):
        try:
            from tunnel_manager.kg_ingest import ingest_hosts

            await run_blocking(ingest_hosts, hosts, group="all")
        except Exception as e:  # noqa: BLE001 — ingestion must not break list
            logger.debug("Operation failed: error_type=%s", type(e).__name__)
    return {"hosts": hosts}


async def _tm_hosts_add(
    action: str,
    alias: str,
    hostname: str,
    user: str,
    port: int,
    optional: dict,
) -> dict:
    """``tm_hosts`` ``add``. ``optional`` carries the blank-means-unset fields."""
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
        identity_file=optional.get("identity_file") or None,
        password_ref=optional.get("password_ref") or None,
        known_hosts_file=optional.get("known_hosts_file") or None,
        proxy_command=optional.get("proxy_command") or None,
    )
    return {"status": "success", "message": "Host added."}


async def _tm_hosts_remove(action: str, alias: str, ctx) -> dict:
    """``tm_hosts`` ``remove``, with the destructive-operation confirmation."""
    if not alias:
        return ResponseBuilder.build(
            400, "Need alias", {"action": action}, errors=["Need alias"]
        )
    if not await ctx_confirm_destructive(ctx, "remove host"):
        return {"status": "cancelled", "message": "Operation cancelled by user"}
    await ctx_progress(ctx, 0, 100)
    await run_blocking(host_manager.remove_host, alias)
    return {"status": "success", "message": "Host removed."}


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
        resolved = resolve_action(
            action, ["list", "add", "remove"], service="tunnel-manager"
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        if action == "list":
            return await _tm_hosts_list()
        if action == "add":
            return await _tm_hosts_add(
                action,
                alias,
                hostname,
                user,
                port,
                {
                    "identity_file": identity_file,
                    "password_ref": password_ref,
                    "known_hosts_file": known_hosts_file,
                    "proxy_command": proxy_command,
                },
            )
        if action == "remove":
            return await _tm_hosts_remove(action, alias, ctx)
        return ResponseBuilder.build(
            400,
            f"Unknown action: {action}",
            {"action": action},
            errors=["Valid: list, add, remove"],
        )


async def _tm_remote_run_command(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    if not host or not cmd:
        return ResponseBuilder.build(
            400,
            "Need host, cmd",
            {"host": host, "cmd": cmd},
            errors=["Need host, cmd"],
        )
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            identity_file=id_file,
            certificate_file=certificate,
            proxy_command=proxy,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            identity_file=conf["identity_file"],
            certificate_file=conf.get("certificate_file"),
            proxy_command=conf.get("proxy_command"),
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        await run_blocking(t.connect)
        out, error = await run_blocking(t.run_command, cmd, timeout=timeout)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200,
            f"Cmd '{cmd}' done on {host} ({conf['hostname']})",
            {"host": host, "real_host": conf["hostname"], "cmd": cmd},
            error,
            stdout=out,
            files=[],
            locations=[],
            errors=[],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Cmd fail")
        await ctx_progress(ctx, 100, 100)
        return ResponseBuilder.build(
            500, "Cmd fail", {"host": host, "cmd": cmd}, type(e).__name__
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


def _validate_upload_request(host: str, lpath: str, rpath: str) -> dict | None:
    """Reject an unusable ``send_file`` request; ``None`` means "go ahead".

    Checks run in the order of the inline block this replaces: presence, then
    file-ness, then the managed transfer-size limit.
    """
    if not host or not lpath or not rpath:
        return ResponseBuilder.build(
            400,
            "Need host, lpath, rpath",
            {"host": host, "lpath": lpath, "rpath": rpath},
            errors=["Need host, lpath, rpath"],
        )
    if not os.path.exists(lpath) or not os.path.isfile(lpath):
        return ResponseBuilder.build(
            400,
            f"Invalid file: {lpath}",
            {"host": host, "lpath": lpath, "rpath": rpath},
            errors=[f"Invalid file: {lpath}"],
        )
    if os.path.getsize(lpath) > max_transfer_bytes():
        return ResponseBuilder.build(
            400,
            "Managed file transfer limit exceeded",
            {},
            errors=["Managed file transfer limit exceeded"],
        )
    return None


async def _tm_remote_send_file(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    _logger = logging.getLogger("TunnelServer")
    _lpath = os.path.abspath(os.path.expanduser(lpath))
    _rpath = os.path.expanduser(rpath)
    invalid = _validate_upload_request(host, _lpath, _rpath)
    if invalid is not None:
        return invalid
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            identity_file=id_file,
            certificate_file=certificate,
            proxy_command=proxy,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            identity_file=conf["identity_file"],
            certificate_file=conf.get("certificate_file"),
            proxy_command=conf.get("proxy_command"),
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        await run_blocking(t.send_file, _lpath, _rpath)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200,
            f"Uploaded to {_rpath}",
            {"host": host, "lpath": _lpath, "rpath": _rpath},
            files=[_lpath],
            locations=[_rpath],
            errors=[],
        )
    except Exception as e:
        ctx_log(ctx, _logger, "error", "Upload fail")
        return ResponseBuilder.build(
            500,
            "Upload fail",
            {"host": host, "lpath": _lpath, "rpath": _rpath},
            type(e).__name__,
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


async def _tm_remote_receive_file(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    _lpath = os.path.abspath(os.path.expanduser(lpath))
    if not host or not rpath or not _lpath:
        return ResponseBuilder.build(
            400,
            "Need host, rpath, lpath",
            {"host": host, "rpath": rpath, "lpath": _lpath},
            errors=["Need host, rpath, lpath"],
        )
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            identity_file=id_file,
            certificate_file=certificate,
            proxy_command=proxy,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            identity_file=conf["identity_file"],
            certificate_file=conf.get("certificate_file"),
            proxy_command=conf.get("proxy_command"),
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        await run_blocking(t.receive_file, rpath, _lpath)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200,
            f"Downloaded to {_lpath}",
            {"host": host, "rpath": rpath, "lpath": _lpath},
            files=[rpath],
            locations=[_lpath],
            errors=[],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Download fail")
        return ResponseBuilder.build(
            500,
            "Download fail",
            {"host": host, "rpath": rpath, "lpath": _lpath},
            type(e).__name__,
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


async def _tm_remote_check_ssh(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    if not host:
        return ResponseBuilder.build(
            400, "Need host", {"host": host}, errors=["Need host"]
        )
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            identity_file=id_file,
            certificate_file=certificate,
            proxy_command=proxy,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            identity_file=conf["identity_file"],
            certificate_file=conf.get("certificate_file"),
            proxy_command=conf.get("proxy_command"),
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        success, msg = await run_blocking(t.check_ssh_server)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200 if success else 400,
            f"SSH check: {msg}",
            {"host": host, "success": success},
            files=[],
            locations=[],
            errors=[] if success else [msg],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Check fail")
        return ResponseBuilder.build(
            500, "Check fail", {"host": host}, type(e).__name__
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


async def _tm_remote_test_key_auth(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    _key = key or setting("TUNNEL_IDENTITY_FILE", "")
    if not host or not _key:
        return ResponseBuilder.build(
            400,
            "Need host, key",
            {"host": host, "key": _key},
            errors=["Need host, key"],
        )
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host, user=user, port=port, ssh_config_file=cfg
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            port=conf["port"],
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        success, msg = await run_blocking(t.test_key_auth, _key)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200 if success else 400,
            f"Key test: {msg}",
            {"host": host, "key": _key, "success": success},
            files=[],
            locations=[],
            errors=[] if success else [msg],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Key test fail")
        return ResponseBuilder.build(
            500, "Key test fail", {"host": host, "key": _key}, type(e).__name__
        )


def _validate_passwordless_request(
    host: str, password: str, key_type: str
) -> dict | None:
    """Reject an unusable ``setup_passwordless`` request; ``None`` means proceed."""
    if not host or not password:
        return ResponseBuilder.build(
            400,
            "Need host, password_ref",
            {"host": host},
            errors=["Need host, password_ref"],
        )
    if key_type not in ["rsa", "ed25519"]:
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"host": host},
            errors=["key_type must be 'rsa' or 'ed25519'"],
        )
    return None


async def _ensure_ssh_keypair(
    key_path: str, key_type: str, probe: str | None = None
) -> None:
    """Generate ``key_path`` with ssh-keygen when ``probe`` is missing.

    ``probe`` defaults to ``key_path + ".pub"`` (what ``tm_remote
    setup_passwordless`` checked); the bulk ``configure_key_auth`` path checks
    the private key itself and passes ``probe=key_path``.
    """
    if os.path.exists(probe or key_path + ".pub"):
        return
    type_args = ["-t", "rsa", "-b", "4096"] if key_type == "rsa" else ["-t", "ed25519"]
    await run_blocking(
        subprocess.run,
        ["/usr/bin/ssh-keygen", *type_args, "-f", key_path, "-N", ""],
        check=True,
        timeout=30,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


async def _tm_remote_setup_passwordless(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    _key = key or os.path.expanduser("~/.ssh/id_rsa")
    invalid = _validate_passwordless_request(host, password, key_type)
    if invalid is not None:
        return invalid
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        _key = os.path.expanduser(_key)
        pub_key = _key + ".pub"
        await _ensure_ssh_keypair(_key, key_type)
        await run_blocking(
            t.setup_passwordless_ssh, local_key_path=_key, key_type=key_type
        )
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200,
            f"SSH setup for {user}@{host}",
            {"host": host, "key": _key, "user": user, "key_type": key_type},
            files=[pub_key],
            locations=[f"~/.ssh/authorized_keys on {host}"],
            errors=[],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "SSH setup fail")
        return ResponseBuilder.build(
            500,
            "SSH setup fail",
            {"host": host, "key_type": key_type},
            type(e).__name__,
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


async def _tm_remote_copy_ssh_config(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    if not host or not lcfg:
        return ResponseBuilder.build(
            400,
            "Need host, lcfg",
            {"host": host, "lcfg": lcfg, "rcfg": rcfg},
            errors=["Need host, lcfg"],
        )
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            identity_file=id_file,
            certificate_file=certificate,
            proxy_command=proxy,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            identity_file=conf["identity_file"],
            certificate_file=conf.get("certificate_file"),
            proxy_command=conf.get("proxy_command"),
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        await run_blocking(t.copy_ssh_config, lcfg, rcfg)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200,
            f"Copied cfg to {rcfg} on {host}",
            {"host": host, "lcfg": lcfg, "rcfg": rcfg},
            files=[lcfg],
            locations=[rcfg],
            errors=[],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Copy cfg fail")
        return ResponseBuilder.build(
            500,
            "Copy cfg fail",
            {"host": host, "lcfg": lcfg, "rcfg": rcfg},
            type(e).__name__,
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


async def _tm_remote_rotate_key(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    if not host or not new_key:
        return ResponseBuilder.build(
            400,
            "Need host, new_key",
            {"host": host, "new_key": new_key},
            errors=["Need host, new_key"],
        )
    if key_type not in ["rsa", "ed25519"]:
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"host": host},
            errors=["key_type must be 'rsa' or 'ed25519'"],
        )
    try:
        conf, final_cfg = _resolve_host(
            host_alias=host,
            user=user,
            password=password,
            port=port,
            identity_file=id_file,
            certificate_file=certificate,
            proxy_command=proxy,
            ssh_config_file=cfg,
        )
        t = Tunnel(
            remote_host=conf["hostname"],
            username=conf["user"],
            password=conf["password"],
            port=conf["port"],
            identity_file=conf["identity_file"],
            certificate_file=conf.get("certificate_file"),
            proxy_command=conf.get("proxy_command"),
            known_hosts_file=conf.get("known_hosts_file"),
            ssh_config_file=final_cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        _new_key = os.path.expanduser(new_key)
        new_public_key = _new_key + ".pub"
        if not os.path.exists(_new_key):
            if key_type == "rsa":
                await run_blocking(
                    subprocess.run,
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        _new_key,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                await run_blocking(
                    subprocess.run,
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        _new_key,
                        "-N",
                        "",
                    ],
                    check=True,
                    timeout=30,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
        await run_blocking(t.rotate_ssh_key, _new_key, key_type=key_type)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200,
            f"Rotated {key_type} key to {_new_key} on {host}",
            {
                "host": host,
                "new_key": _new_key,
                "old_key": id_file,
                "key_type": key_type,
            },
            files=[new_public_key],
            locations=[f"~/.ssh/authorized_keys on {host}"],
            errors=[],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Rotate fail")
        return ResponseBuilder.build(
            500,
            "Rotate fail",
            {"host": host, "new_key": new_key, "key_type": key_type},
            type(e).__name__,
        )
    finally:
        if "t" in locals():
            await run_blocking(t.close)


async def _tm_remote_remove_host_key(
    action,
    host,
    user,
    password_ref,
    password,
    port,
    id_file,
    certificate,
    proxy,
    cfg,
    cmd,
    lpath,
    rpath,
    key,
    key_type,
    new_key,
    lcfg,
    rcfg,
    known_hosts,
    timeout,
    ctx,
) -> dict:
    if not host:
        return ResponseBuilder.build(
            400, "Need host", {"host": host}, errors=["Need host"]
        )
    if not await ctx_confirm_destructive(ctx, "remove host key"):
        return {"status": "cancelled", "message": "Operation cancelled by user"}
    try:
        conf, _ = _resolve_host(host_alias=host)
        t = Tunnel(remote_host=conf["hostname"])
        if ctx:
            await ctx.report_progress(progress=0, total=100)
        _known_hosts = os.path.expanduser(known_hosts)
        msg = await run_blocking(t.remove_host_key, known_hosts_path=_known_hosts)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
        return ResponseBuilder.build(
            200 if "Removed" in msg else 400,
            msg,
            {"host": host, "known_hosts": _known_hosts},
            files=[],
            locations=[],
            errors=[] if "Removed" in msg else [msg],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Remove fail")
        return ResponseBuilder.build(
            500,
            "Remove fail",
            {"host": host, "known_hosts": known_hosts},
            type(e).__name__,
        )


async def _tm_remote_unknown_action(action) -> dict:
    return ResponseBuilder.build(
        400,
        f"Unknown action: {action}",
        {"action": action},
        errors=[
            "Valid: run_command, send_file, receive_file, check_ssh, test_key_auth, setup_passwordless, copy_ssh_config, rotate_key, remove_host_key"
        ],
    )


_TM_REMOTE_ACTIONS = {
    "run_command": _tm_remote_run_command,
    "send_file": _tm_remote_send_file,
    "receive_file": _tm_remote_receive_file,
    "check_ssh": _tm_remote_check_ssh,
    "test_key_auth": _tm_remote_test_key_auth,
    "setup_passwordless": _tm_remote_setup_passwordless,
    "copy_ssh_config": _tm_remote_copy_ssh_config,
    "rotate_key": _tm_remote_rotate_key,
    "remove_host_key": _tm_remote_remove_host_key,
}


def register_remote_tools(mcp: FastMCP):
    """Register single-host SSH operations tool."""

    @mcp.tool(
        annotations={
            "title": "Remote SSH Operations",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def tm_remote(
        action: str = Field(
            description="Action: 'run_command', 'send_file', 'receive_file', 'check_ssh', 'test_key_auth', 'setup_passwordless', 'copy_ssh_config', 'rotate_key', 'remove_host_key'"
        ),
        host: str = Field(
            default=setting("TUNNEL_REMOTE_HOST", ""), description="Remote host."
        ),
        user: str | None = Field(
            default=setting("TUNNEL_USERNAME", ""), description="Username."
        ),
        password_ref: str | None = Field(
            default=setting("TUNNEL_PASSWORD_REF", ""),
            description="Runtime secret reference for the SSH password.",
        ),
        port: int = Field(
            default=int(setting("TUNNEL_REMOTE_PORT", 22)),
            description="Port.",
        ),
        id_file: str | None = Field(
            default=setting("TUNNEL_IDENTITY_FILE", ""),
            description="Private key path.",
        ),
        certificate: str | None = Field(
            default=setting("TUNNEL_CERTIFICATE", ""),
            description="Teleport certificate.",
        ),
        proxy: str | None = Field(
            default=setting("TUNNEL_PROXY_COMMAND", ""),
            description="Teleport proxy.",
        ),
        cfg: str = Field(
            default=os.path.expanduser("~/.ssh/config"), description="SSH config path."
        ),
        cmd: str = Field(default="", description="Shell command (run_command)."),
        lpath: str = Field(
            default="", description="Local file path (send_file/receive_file)."
        ),
        rpath: str = Field(
            default="", description="Remote file path (send_file/receive_file)."
        ),
        key: str = Field(
            default="", description="Key path (test_key_auth/setup_passwordless)."
        ),
        key_type: str = Field(
            default="ed25519",
            description="Key type: rsa or ed25519 (setup_passwordless/rotate_key).",
        ),
        new_key: str = Field(
            default="", description="New private key path (rotate_key)."
        ),
        lcfg: str = Field(
            default="", description="Local SSH config (copy_ssh_config)."
        ),
        rcfg: str = Field(
            default=os.path.expanduser("~/.ssh/config"),
            description="Remote SSH config (copy_ssh_config).",
        ),
        known_hosts: str = Field(
            default=os.path.expanduser("~/.ssh/known_hosts"),
            description="Known hosts path (remove_host_key).",
        ),
        timeout: int = Field(default=60, description="Command timeout in seconds."),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Single-host SSH operations with shared connection params."""
        resolved = resolve_action(
            action,
            [
                "run_command",
                "send_file",
                "receive_file",
                "check_ssh",
                "test_key_auth",
                "setup_passwordless",
                "copy_ssh_config",
                "rotate_key",
                "remove_host_key",
            ],
            service="tunnel-manager",
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        try:
            password = resolve_secret_ref(password_ref)
        except ValueError:
            return ResponseBuilder.build(
                400,
                "Invalid SSH credential configuration",
                {"credential_ref_configured": bool(password_ref)},
                errors=["A supported runtime secret reference is required"],
            )
        try:
            timeout = validate_timeout(timeout, default=60)
        except ValueError:
            return ResponseBuilder.build(
                400, "Invalid SSH timeout", {}, errors=["Invalid SSH timeout"]
            )
        handler = _TM_REMOTE_ACTIONS.get(action)
        if handler is None:
            return await _tm_remote_unknown_action(action)
        return await handler(
            action,
            host,
            user,
            password_ref,
            password,
            port,
            id_file,
            certificate,
            proxy,
            cfg,
            cmd,
            lpath,
            rpath,
            key,
            key_type,
            new_key,
            lcfg,
            rcfg,
            known_hosts,
            timeout,
            ctx,
        )


def _parallel_error_result(exc: Exception, **extra: Any) -> dict:
    """The per-host result recorded when a pooled future itself raised."""
    return {
        "hostname": "unknown",
        "status": "failed",
        "message": "Parallel error",
        "errors": [type(exc).__name__],
        **extra,
    }


class _HostResults:
    """Accumulate one bulk ``tm_inventory`` action's per-host worker results.

    ``on_success(acc, result)`` records the artefacts a successful host
    produced. When it is ``None`` every result's ``errors`` are collected
    regardless of status -- which is what ``run_command``'s original loop did.
    ``error_extra(exc)`` supplies the action-specific keys of the synthetic
    result recorded for a pooled future that raised.
    """

    def __init__(self, on_success=None, error_extra=None, seed=None) -> None:
        self.results: list = list(seed) if seed else []
        self.files: list = []
        self.locations: list = []
        self.errors: list = []
        self._on_success = on_success
        self._error_extra = error_extra

    def record(self, result: dict) -> None:
        self.results.append(result)
        if self._on_success is not None and result["status"] == "success":
            self._on_success(self, result)
        else:
            self.errors.extend(result["errors"])

    def parallel_error(self, exc: Exception) -> None:
        extra = self._error_extra(exc) if self._error_extra else {}
        self.results.append(_parallel_error_result(exc, **extra))
        self.errors.append(type(exc).__name__)


async def _fan_out_serial(hosts: list, worker, ctx, results: _HostResults) -> None:
    """Await ``worker`` once per host, in order, reporting progress as it goes."""
    total = len(hosts)
    for i, h in enumerate(hosts, 1):
        results.record(await worker(h))
        if ctx:
            await ctx.report_progress(progress=i, total=total)


async def _fan_out_parallel(
    hosts: list, worker, ctx, max_threads: int, results: _HostResults
) -> None:
    """Run ``worker`` for every host in a thread pool, each in its own loop.

    A future that itself raised is recorded through ``results.parallel_error``
    and reports no progress -- exactly as the inline loops this replaces did.
    """
    total = len(hosts)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
        futures = [ex.submit(lambda h: asyncio.run(worker(h)), h) for h in hosts]
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            try:
                results.record(future.result())
                if ctx:
                    await ctx.report_progress(progress=i, total=total)
            except Exception as e:
                results.parallel_error(e)


async def _fan_out_over_hosts(
    hosts: list, worker, ctx, parallel: bool, max_threads: int, results: _HostResults
) -> None:
    """Fan ``worker`` out over ``hosts`` -- pooled or serial -- into ``results``."""
    if parallel:
        await _fan_out_parallel(hosts, worker, ctx, max_threads, results)
    else:
        await _fan_out_serial(hosts, worker, ctx, results)


def _run_command_preview(target: dict, resolved_hosts: list) -> dict:
    """The ``preview=True`` response for ``tm_inventory run_command``."""
    scope = (
        f" (host={target['host']})" if target["host"] else f" (group={target['group']})"
    )
    return ResponseBuilder.build(
        200,
        f"Preview: '{target['cmd']}' would run on {len(resolved_hosts)} host(s)"
        + scope,
        {**target, "resolved_hosts": resolved_hosts, "preview": True},
        errors=[],
    )


def _run_command_response(
    target: dict, resolved_hosts: list, collected: _HostResults
) -> dict:
    """The completed-run response for ``tm_inventory run_command``."""
    label = f"host={target['host']}" if target["host"] else f"group={target['group']}"
    cmd = target["cmd"]
    msg = (
        f"Cmd '{cmd}' done on {label}"
        if not collected.errors
        else f"Cmd '{cmd}' failed for some in {label}"
    )
    return ResponseBuilder.build(
        200 if not collected.errors else 500,
        msg,
        {
            **target,
            "resolved_hosts": resolved_hosts,
            "host_results": collected.results,
        },
        error="; ".join(collected.errors),
        files=[],
        locations=[],
        errors=collected.errors,
    )


def _validate_inventory_upload(action: str, lpath: str, rpath: str) -> dict | None:
    """Reject an unusable bulk ``send_file`` request; ``None`` means proceed.

    Same order as the inline block it replaces: presence, file-ness, size limit.
    """
    if not lpath or not rpath:
        return ResponseBuilder.build(
            400,
            "Need lpath, rpath",
            {"action": action},
            errors=["Need lpath, rpath"],
        )
    if not os.path.exists(lpath) or not os.path.isfile(lpath):
        return ResponseBuilder.build(
            400,
            f"Invalid file: {lpath}",
            {"action": action},
            errors=[f"Invalid file: {lpath}"],
        )
    if os.path.getsize(lpath) > max_transfer_bytes():
        return ResponseBuilder.build(
            400,
            "Managed file transfer limit exceeded",
            {},
            errors=["Managed file transfer limit exceeded"],
        )
    return None


async def _tm_inventory_configure_key_auth(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    if key_type not in ["rsa", "ed25519"]:
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"action": action},
            errors=["key_type must be 'rsa' or 'ed25519'"],
        )
    try:
        _key = os.path.expanduser(key)
        pub_key = _key + ".pub"
        await _ensure_ssh_keypair(_key, key_type, probe=_key)
        with open(pub_key) as f:
            pub = validate_public_key(f.read())
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def setup_host(h: dict) -> dict:
            host, _user = h["hostname"], h["username"]
            kpath = h.get("key_path", _key)
            try:
                t = Tunnel(
                    config=HostConfig(
                        hostname=host,
                        user=_user,
                        port=h.get("port", 22),
                        password_ref=h.get("password_ref"),
                        known_hosts_file=h.get("known_hosts_file"),
                    )
                )
                await run_blocking(
                    t.setup_passwordless_ssh,
                    local_key_path=kpath,
                    key_type=key_type,
                )
                await run_blocking(t.connect)
                await run_blocking(
                    t.run_command,
                    f"printf '%s\\n' {shlex.quote(pub)} >> ~/.ssh/authorized_keys",
                )
                await run_blocking(t.run_command, "chmod 600 ~/.ssh/authorized_keys")
                res, msg = await run_blocking(t.test_key_auth, kpath)
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"SSH setup for {_user}@{host} with {key_type} key",
                    "errors": [] if res else [msg],
                }
            except Exception as e:
                return {
                    "hostname": host,
                    "status": "failed",
                    "message": "Setup fail",
                    "errors": [type(e).__name__],
                }
            finally:
                if "t" in locals():
                    await run_blocking(t.close)

        def on_success(acc: _HostResults, r: dict) -> None:
            acc.files.append(pub_key)
            acc.locations.append(f"~/.ssh/authorized_keys on {r['hostname']}")

        collected = _HostResults(on_success)
        await _fan_out_over_hosts(
            hosts, setup_host, ctx, parallel, max_threads, collected
        )
        msg = (
            f"SSH setup done for {group}"
            if not collected.errors
            else f"SSH setup failed for some in {group}"
        )
        return ResponseBuilder.build(
            200 if not collected.errors else 500,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "key_type": key_type,
                "host_results": collected.results,
            },
            stdout="; ".join(collected.errors),
            files=collected.files,
            locations=collected.locations,
            errors=collected.errors,
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Setup all fail")
        return ResponseBuilder.build(
            500,
            "Setup all fail",
            {"inventory": inventory, "group": group, "key_type": key_type},
            type(e).__name__,
        )


async def _tm_inventory_mesh_bootstrap(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    if key_type not in ["rsa", "ed25519"]:
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"action": action},
            errors=["key_type must be 'rsa' or 'ed25519'"],
        )
    try:
        res = await asyncio.to_thread(
            Tunnel.setup_full_mesh_ssh,
            inventory=inventory,
            key_path=key,
            key_type=key_type,
            group=group,
            parallel=parallel,
            max_threads=max_threads,
        )

        status_code = 200 if res["status"] == "success" else 500
        msg = (
            "Full-mesh SSH bootstrap completed successfully"
            if status_code == 200
            else "Full-mesh SSH bootstrap failed for some hosts"
        )

        return ResponseBuilder.build(
            status_code,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "key_type": key_type,
                "host_results": res["host_results"],
            },
            stdout="; ".join(res["errors"]),
            errors=res["errors"],
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Mesh bootstrap fail")
        return ResponseBuilder.build(
            500,
            "Mesh bootstrap fail",
            {"inventory": inventory, "group": group, "key_type": key_type},
            type(e).__name__,
        )


async def _tm_inventory_run_command(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    if not cmd:
        return ResponseBuilder.build(
            400, "Need cmd", {"action": action, "cmd": cmd}, errors=["Need cmd"]
        )
    try:
        if host:
            hosts, error = resolve_single_host(inventory, host, logger)
        else:
            hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        resolved_hosts = [h["hostname"] for h in hosts]
        total = len(hosts)
        if preview:
            return _run_command_preview(
                {"inventory": inventory, "group": group, "host": host, "cmd": cmd},
                resolved_hosts,
            )
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def run_host(h: dict) -> dict:
            await ctx_progress(ctx, 0, 100)
            host = h["hostname"]
            try:
                t = Tunnel(
                    config=HostConfig(
                        hostname=host,
                        user=h["username"],
                        port=h.get("port", 22),
                        password_ref=h.get("password_ref"),
                        identity_file=h.get("key_path"),
                        known_hosts_file=h.get("known_hosts_file"),
                    )
                )
                out, error = await run_blocking(t.run_command, cmd, timeout=timeout)
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Cmd '{cmd}' done on {host}",
                    "stdout": out,
                    "stderr": error,
                    "errors": [],
                }
            except Exception as e:
                return {
                    "hostname": host,
                    "status": "failed",
                    "message": "Cmd fail",
                    "stdout": "",
                    "stderr": type(e).__name__,
                    "errors": [type(e).__name__],
                }
            finally:
                if "t" in locals():
                    await run_blocking(t.close)

        collected = _HostResults(
            error_extra=lambda e: {"stdout": "", "stderr": type(e).__name__}
        )
        await _fan_out_over_hosts(
            hosts, run_host, ctx, parallel, max_threads, collected
        )
        return _run_command_response(
            {"inventory": inventory, "group": group, "host": host, "cmd": cmd},
            resolved_hosts,
            collected,
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Cmd all fail")
        await ctx_progress(ctx, 100, 100)
        return ResponseBuilder.build(
            500,
            "Cmd all fail",
            {"inventory": inventory, "group": group, "host": host, "cmd": cmd},
            type(e).__name__,
        )


async def _tm_inventory_copy_ssh_config(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    if not cfg:
        return ResponseBuilder.build(
            400, "Need cfg", {"action": action}, errors=["Need cfg"]
        )
    if not os.path.exists(cfg):
        return ResponseBuilder.build(
            400,
            f"No cfg file: {cfg}",
            {"action": action},
            errors=[f"No cfg file: {cfg}"],
        )
    try:
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def copy_host(h: dict) -> dict:
            try:
                t = Tunnel(
                    config=HostConfig(
                        hostname=h["hostname"],
                        user=h["username"],
                        port=h.get("port", 22),
                        password_ref=h.get("password_ref"),
                        identity_file=h.get("key_path"),
                        known_hosts_file=h.get("known_hosts_file"),
                    )
                )
                await run_blocking(t.copy_ssh_config, cfg, rmt_cfg)
                return {
                    "hostname": h["hostname"],
                    "status": "success",
                    "message": f"Copied cfg to {rmt_cfg}",
                    "errors": [],
                }
            except Exception as e:
                return {
                    "hostname": h["hostname"],
                    "status": "failed",
                    "message": "Copy fail",
                    "errors": [type(e).__name__],
                }
            finally:
                if "t" in locals():
                    await run_blocking(t.close)

        def on_success(acc: _HostResults, r: dict) -> None:
            acc.files.append(cfg)
            acc.locations.append(f"{rmt_cfg} on {r['hostname']}")

        collected = _HostResults(on_success)
        await _fan_out_over_hosts(
            hosts, copy_host, ctx, parallel, max_threads, collected
        )
        msg = (
            f"Copied cfg to {group}"
            if not collected.errors
            else f"Copy failed for some in {group}"
        )
        return ResponseBuilder.build(
            200 if not collected.errors else 500,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "cfg": cfg,
                "rmt_cfg": rmt_cfg,
                "host_results": collected.results,
            },
            error="; ".join(collected.errors),
            files=collected.files,
            locations=collected.locations,
            errors=collected.errors,
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Copy all fail")
        return ResponseBuilder.build(
            500,
            "Copy all fail",
            {
                "inventory": inventory,
                "group": group,
                "cfg": cfg,
                "rmt_cfg": rmt_cfg,
            },
            type(e).__name__,
        )


async def _tm_inventory_rotate_key(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    if key_type not in ["rsa", "ed25519"]:
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"action": action},
            errors=["key_type must be 'rsa' or 'ed25519'"],
        )
    try:
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def rotate_host(h: dict) -> dict:
            _key = os.path.expanduser(key_pfx + h["hostname"])
            try:
                t = Tunnel(
                    config=HostConfig(
                        hostname=h["hostname"],
                        user=h["username"],
                        port=h.get("port", 22),
                        password_ref=h.get("password_ref"),
                        identity_file=h.get("key_path"),
                        known_hosts_file=h.get("known_hosts_file"),
                    )
                )
                await run_blocking(t.rotate_ssh_key, _key, key_type=key_type)
                return {
                    "hostname": h["hostname"],
                    "status": "success",
                    "message": f"Rotated {key_type} key to {_key}",
                    "errors": [],
                    "new_key_path": _key,
                }
            except Exception as e:
                return {
                    "hostname": h["hostname"],
                    "status": "failed",
                    "message": "Rotate fail",
                    "errors": [type(e).__name__],
                    "new_key_path": _key,
                }
            finally:
                if "t" in locals():
                    await run_blocking(t.close)

        def on_success(acc: _HostResults, r: dict) -> None:
            acc.files.append(r["new_key_path"] + ".pub")
            acc.locations.append(f"~/.ssh/authorized_keys on {r['hostname']}")

        collected = _HostResults(
            on_success, error_extra=lambda _e: {"new_key_path": None}
        )
        await _fan_out_over_hosts(
            hosts, rotate_host, ctx, parallel, max_threads, collected
        )
        msg = (
            f"Rotated {key_type} keys for {group}"
            if not collected.errors
            else f"Rotate failed for some in {group}"
        )
        return ResponseBuilder.build(
            200 if not collected.errors else 500,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "key_prefix": key_pfx,
                "key_type": key_type,
                "host_results": collected.results,
            },
            error="; ".join(collected.errors),
            files=collected.files,
            locations=collected.locations,
            errors=collected.errors,
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Rotate all fail")
        return ResponseBuilder.build(
            500,
            "Rotate all fail",
            {
                "inventory": inventory,
                "group": group,
                "key_pfx": key_pfx,
                "key_type": key_type,
            },
            error=type(e).__name__,
        )


async def _tm_inventory_send_file(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    _lpath = os.path.abspath(os.path.expanduser(lpath))
    _rpath = os.path.expanduser(rpath)
    invalid = _validate_inventory_upload(action, _lpath, _rpath)
    if invalid is not None:
        return invalid
    try:
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def send_host(h: dict) -> dict:
            host = h["hostname"]
            try:
                t = Tunnel(
                    config=HostConfig(
                        hostname=host,
                        user=h["username"],
                        port=h.get("port", 22),
                        password_ref=h.get("password_ref"),
                        identity_file=h.get("key_path"),
                        known_hosts_file=h.get("known_hosts_file"),
                    )
                )
                await run_blocking(t.send_file, _lpath, _rpath)
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Uploaded {_lpath} to {_rpath}",
                    "errors": [],
                }
            except Exception as e:
                return {
                    "hostname": host,
                    "status": "failed",
                    "message": "Upload fail",
                    "errors": [type(e).__name__],
                }
            finally:
                if "t" in locals():
                    await run_blocking(t.close)

        def on_success(acc: _HostResults, r: dict) -> None:
            acc.locations.append(f"{_rpath} on {r['hostname']}")

        collected = _HostResults(on_success, seed=[_lpath])
        await _fan_out_over_hosts(
            hosts, send_host, ctx, parallel, max_threads, collected
        )
        msg = (
            f"Uploaded {_lpath} to {group}"
            if not collected.errors
            else f"Upload failed for some in {group}"
        )
        return ResponseBuilder.build(
            200 if not collected.errors else 500,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "local_path": _lpath,
                "remote_path": _rpath,
                "host_results": collected.results,
            },
            error="; ".join(collected.errors),
            files=collected.files,
            locations=collected.locations,
            errors=collected.errors,
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Upload all fail")
        return ResponseBuilder.build(
            500,
            "Upload all fail",
            {
                "inventory": inventory,
                "group": group,
                "lpath": _lpath,
                "rpath": _rpath,
            },
            type(e).__name__,
        )


async def _tm_inventory_receive_file(
    action,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
    key,
    key_type,
    key_pfx,
    cfg,
    rmt_cfg,
    lpath,
    rpath,
    lpath_prefix,
    timeout,
    ctx,
) -> dict:
    if not rpath or not lpath_prefix:
        return ResponseBuilder.build(
            400,
            "Need rpath, lpath_prefix",
            {"action": action},
            errors=["Need rpath, lpath_prefix"],
        )
    try:
        os.makedirs(lpath_prefix, exist_ok=True)
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def receive_host(h: dict) -> dict:
            host = h["hostname"]
            _lpath = os.path.join(lpath_prefix, host, os.path.basename(rpath))
            os.makedirs(os.path.dirname(_lpath), exist_ok=True)
            try:
                t = Tunnel(
                    config=HostConfig(
                        hostname=host,
                        user=h["username"],
                        port=h.get("port", 22),
                        password_ref=h.get("password_ref"),
                        identity_file=h.get("key_path"),
                        known_hosts_file=h.get("known_hosts_file"),
                    )
                )
                await run_blocking(t.receive_file, rpath, _lpath)
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Downloaded {rpath} to {_lpath}",
                    "errors": [],
                    "local_path": _lpath,
                }
            except Exception as e:
                return {
                    "hostname": host,
                    "status": "failed",
                    "message": "Download fail",
                    "errors": [type(e).__name__],
                    "local_path": _lpath,
                }
            finally:
                if "t" in locals():
                    await run_blocking(t.close)

        def on_success(acc: _HostResults, r: dict) -> None:
            acc.files.append(rpath)
            acc.locations.append(r["local_path"])

        collected = _HostResults(
            on_success, error_extra=lambda _e: {"local_path": None}
        )
        await _fan_out_over_hosts(
            hosts, receive_host, ctx, parallel, max_threads, collected
        )
        msg = (
            f"Downloaded {rpath} from {group}"
            if not collected.errors
            else f"Download failed for some in {group}"
        )
        return ResponseBuilder.build(
            200 if not collected.errors else 500,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "rpath": rpath,
                "lpath_prefix": lpath_prefix,
                "host_results": collected.results,
            },
            error="; ".join(collected.errors),
            files=collected.files,
            locations=collected.locations,
            errors=collected.errors,
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Download all fail")
        return ResponseBuilder.build(
            500,
            "Download all fail",
            {
                "inventory": inventory,
                "group": group,
                "rpath": rpath,
                "lpath_prefix": lpath_prefix,
            },
            type(e).__name__,
        )


async def _tm_inventory_unknown_action(action) -> dict:
    return ResponseBuilder.build(
        400,
        f"Unknown action: {action}",
        {"action": action},
        errors=[
            "Valid: configure_key_auth, run_command, copy_ssh_config, rotate_key, send_file, receive_file"
        ],
    )


_TM_INVENTORY_ACTIONS = {
    "configure_key_auth": _tm_inventory_configure_key_auth,
    "mesh_bootstrap": _tm_inventory_mesh_bootstrap,
    "run_command": _tm_inventory_run_command,
    "copy_ssh_config": _tm_inventory_copy_ssh_config,
    "rotate_key": _tm_inventory_rotate_key,
    "send_file": _tm_inventory_send_file,
    "receive_file": _tm_inventory_receive_file,
}


def register_inventory_tools(mcp: FastMCP):
    """Register bulk inventory operations tool."""

    @mcp.tool(
        annotations={
            "title": "Inventory Operations",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"inventory_ops"},
    )
    async def tm_inventory(
        action: str = Field(
            description="Action: 'configure_key_auth', 'mesh_bootstrap', 'run_command', 'copy_ssh_config', 'rotate_key', 'send_file', 'receive_file'"
        ),
        inventory: str = Field(
            default=setting("TUNNEL_INVENTORY", _DEFAULT_INVENTORY_PATH),
            description="YAML inventory path (default: $XDG_CONFIG_HOME/agent-utilities/inventory.yaml).",
        ),
        group: str = Field(
            default=setting("TUNNEL_INVENTORY_GROUP", "all"),
            description="Target group.",
        ),
        host: str = Field(
            default="",
            description=(
                "run_command only. Optional single-host alias to target instead of "
                "the whole 'group' fan-out — the safe way to reach ONE inventory "
                "host (e.g. 'gb10') without running against 'homelab'. Resolved and "
                "authorized through the same alias store tm_remote/tm_hosts use, so "
                "the two are one source of truth: an unknown or unauthorized alias "
                "is rejected outright, never silently skipped. Takes precedence over "
                "'group' when set."
            ),
        ),
        preview: bool = Field(
            default=False,
            description=(
                "run_command only. If true, resolve the exact target host(s) for "
                "'host'/'group' and return them in 'resolved_hosts' WITHOUT running "
                "'cmd' — lets a caller verify scope before executing for real (no "
                "surprise fan-out). The real (non-preview) response also always "
                "includes 'resolved_hosts' for the same reason."
            ),
        ),
        parallel: bool = Field(
            default=bool(setting("TUNNEL_PARALLEL", False)),
            description="Run parallel.",
        ),
        max_threads: int = Field(
            default=int(setting("TUNNEL_MAX_THREADS", 6)),
            description="Max threads.",
        ),
        cmd: str = Field(default="", description="Shell command (run_command)."),
        key: str = Field(
            default=setting(
                "TUNNEL_IDENTITY_FILE", os.path.expanduser("~/.ssh/id_shared")
            ),
            description="Shared key path (configure_key_auth).",
        ),
        key_type: str = Field(
            default="ed25519", description="Key type: rsa or ed25519."
        ),
        key_pfx: str = Field(
            default=os.path.expanduser("~/.ssh/id_"),
            description="Prefix for new keys (rotate_key).",
        ),
        cfg: str = Field(
            default="", description="Local SSH config path (copy_ssh_config)."
        ),
        rmt_cfg: str = Field(
            default=os.path.expanduser("~/.ssh/config"),
            description="Remote config path (copy_ssh_config).",
        ),
        lpath: str = Field(default="", description="Local file path (send_file)."),
        rpath: str = Field(
            default="", description="Remote file path (send_file/receive_file)."
        ),
        lpath_prefix: str = Field(
            default="", description="Local dir prefix (receive_file)."
        ),
        timeout: int = Field(default=60, description="Command timeout in seconds."),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Bulk inventory operations against YAML host groups."""
        resolved = resolve_action(
            action,
            [
                "configure_key_auth",
                "mesh_bootstrap",
                "run_command",
                "copy_ssh_config",
                "rotate_key",
                "send_file",
                "receive_file",
            ],
            service="tunnel-manager",
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        if isinstance(max_threads, bool):
            return ResponseBuilder.build(
                400,
                "Invalid fleet concurrency",
                {},
                errors=["Invalid fleet concurrency"],
            )
        max_threads = max(1, min(int(max_threads), max_concurrency()))
        try:
            timeout = validate_timeout(timeout, default=60)
        except ValueError:
            return ResponseBuilder.build(
                400, "Invalid SSH timeout", {}, errors=["Invalid SSH timeout"]
            )
        if not inventory:
            return ResponseBuilder.build(
                400, "Need inventory", {"action": action}, errors=["Need inventory"]
            )

        handler = _TM_INVENTORY_ACTIONS.get(action)
        if handler is None:
            return await _tm_inventory_unknown_action(action)
        return await handler(
            action,
            inventory,
            group,
            host,
            preview,
            parallel,
            max_threads,
            cmd,
            key,
            key_type,
            key_pfx,
            cfg,
            rmt_cfg,
            lpath,
            rpath,
            lpath_prefix,
            timeout,
            ctx,
        )


async def _tm_operations_start(
    action: str,
    operation_id: str,
    operation_type: str,
    total_steps: int,
    details: dict,
    ctx,
) -> dict:
    """``tm_operations`` ``start``."""
    if not operation_type:
        return ResponseBuilder.build(
            400,
            "Need operation_type",
            {"action": action},
            errors=["Need operation_type"],
        )
    try:
        op_id = await run_blocking(
            operation_manager.create_operation,
            operation_type=operation_type,
            total_steps=total_steps,
            details=details,
        )
        return ResponseBuilder.build(
            200,
            "Operation started",
            {"operation_id": op_id, "operation_type": operation_type},
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Failed to start operation")
        return ResponseBuilder.build(
            500,
            "Failed to start operation",
            {"operation_type": operation_type},
            type(e).__name__,
        )


async def _tm_operations_get_progress(
    action: str,
    operation_id: str,
    operation_type: str,
    total_steps: int,
    details: dict,
    ctx,
) -> dict:
    """``tm_operations`` ``get_progress``."""
    if not operation_id:
        return ResponseBuilder.build(
            400,
            "Need operation_id",
            {"action": action},
            errors=["Need operation_id"],
        )
    try:
        status = await run_blocking(
            operation_manager.get_operation_status, operation_id
        )
        if status is None:
            return ResponseBuilder.build(
                404,
                "Operation not found",
                {"operation_id": operation_id},
                errors=["Operation not found"],
            )
        return ResponseBuilder.build(
            200,
            "Operation progress retrieved",
            {"operation_id": operation_id, "status": status},
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Failed to get operation progress")
        return ResponseBuilder.build(
            500,
            "Failed to get operation progress",
            {"operation_id": operation_id},
            type(e).__name__,
        )


async def _tm_operations_cancel(
    action: str,
    operation_id: str,
    operation_type: str,
    total_steps: int,
    details: dict,
    ctx,
) -> dict:
    """``tm_operations`` ``cancel``, with the destructive-operation confirmation."""
    if not operation_id:
        return ResponseBuilder.build(
            400,
            "Need operation_id",
            {"action": action},
            errors=["Need operation_id"],
        )
    if not await ctx_confirm_destructive(ctx, "cancel operation"):
        return {"status": "cancelled", "message": "Operation cancelled by user"}
    await ctx_progress(ctx, 0, 100)
    try:
        success = await run_blocking(
            operation_manager.request_cancellation, operation_id
        )
        if success:
            return ResponseBuilder.build(
                200,
                "Operation cancellation requested",
                {"operation_id": operation_id},
            )
        else:
            return ResponseBuilder.build(
                400,
                "Failed to cancel",
                {"operation_id": operation_id},
                errors=["Operation not found or already completed"],
            )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Failed to cancel operation")
        return ResponseBuilder.build(
            500,
            "Failed to cancel operation",
            {"operation_id": operation_id},
            type(e).__name__,
        )


async def _tm_operations_get_metrics(
    action: str,
    operation_id: str,
    operation_type: str,
    total_steps: int,
    details: dict,
    ctx,
) -> dict:
    """``tm_operations`` ``get_metrics``."""
    if not operation_id:
        return ResponseBuilder.build(
            400,
            "Need operation_id",
            {"action": action},
            errors=["Need operation_id"],
        )
    try:
        metrics = await run_blocking(
            operation_manager.get_resource_metrics, operation_id
        )
        return ResponseBuilder.build(
            200,
            "Resource metrics retrieved",
            {
                "operation_id": operation_id,
                "metrics": metrics,
                "metric_count": len(metrics),
            },
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Failed to get resource metrics")
        return ResponseBuilder.build(
            500,
            "Failed to get resource metrics",
            {"operation_id": operation_id},
            type(e).__name__,
        )


async def _tm_operations_list_sessions(
    action: str,
    operation_id: str,
    operation_type: str,
    total_steps: int,
    details: dict,
    ctx,
) -> dict:
    """``tm_operations`` ``list_sessions``."""
    try:
        sessions = await run_blocking(operation_manager.list_active_sessions)
        return ResponseBuilder.build(
            200,
            "Active sessions listed",
            {
                "sessions": sessions["sessions"],
                "total_sessions": sessions["total_sessions"],
            },
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Failed to list active sessions")
        return ResponseBuilder.build(
            500, "Failed to list active sessions", {}, type(e).__name__
        )


_TM_OPERATIONS_ACTIONS = {
    "start": _tm_operations_start,
    "get_progress": _tm_operations_get_progress,
    "cancel": _tm_operations_cancel,
    "get_metrics": _tm_operations_get_metrics,
    "list_sessions": _tm_operations_list_sessions,
}


def register_operations_tools(mcp: FastMCP):
    """Register operation lifecycle and session management tool."""

    @mcp.tool(
        annotations={
            "title": "Operation Management",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"operation_management"},
    )
    async def tm_operations(
        action: str = Field(
            description="Action: 'start', 'get_progress', 'cancel', 'get_metrics', 'list_sessions'"
        ),
        operation_id: str = Field(
            default="", description="Operation ID (get_progress/cancel/get_metrics)."
        ),
        operation_type: str = Field(
            default="", description="Type of operation (start)."
        ),
        total_steps: int = Field(default=0, description="Total steps (start)."),
        details: dict = Field(
            description="Additional details (start).", default_factory=dict
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Operation lifecycle and session management."""
        resolved = resolve_action(
            action,
            ["start", "get_progress", "cancel", "get_metrics", "list_sessions"],
            service="tunnel-manager",
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        handler = _TM_OPERATIONS_ACTIONS.get(action)
        if handler is None:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: start, get_progress, cancel, get_metrics, list_sessions"
                ],
            )
        return await handler(
            action, operation_id, operation_type, total_steps, details, ctx
        )


async def _tm_system_get_info(
    intelligence, remote_host: str, log_paths: list, patterns: list
) -> dict:
    """``tm_system`` ``get_info``."""
    result = await run_blocking(intelligence.get_system_info)
    return ResponseBuilder.build(
        200,
        "System information retrieved",
        {"host": remote_host, "system_info": result},
    )


async def _tm_system_discover_services(
    intelligence, remote_host: str, log_paths: list, patterns: list
) -> dict:
    """``tm_system`` ``discover_services``."""
    result = await run_blocking(intelligence.discover_services)
    return ResponseBuilder.build(
        200,
        "Services discovered",
        {"host": remote_host, "services": result},
    )


async def _tm_system_analyze_logs(
    intelligence, remote_host: str, log_paths: list, patterns: list
) -> dict:
    """``tm_system`` ``analyze_logs``."""
    if not log_paths or not patterns:
        return ResponseBuilder.build(
            400,
            "Need log_paths and patterns",
            {"host": remote_host},
            errors=["Need log_paths and patterns"],
        )
    result = await run_blocking(intelligence.analyze_logs, log_paths, patterns)
    return ResponseBuilder.build(
        200,
        "Log analysis completed",
        {"host": remote_host, "analysis": result},
    )


async def _tm_system_network_topology(
    intelligence, remote_host: str, log_paths: list, patterns: list
) -> dict:
    """``tm_system`` ``network_topology``."""
    result = await run_blocking(intelligence.network_topology)
    return ResponseBuilder.build(
        200,
        "Network topology mapped",
        {"host": remote_host, "topology": result},
    )


_TM_SYSTEM_ACTIONS = {
    "get_info": _tm_system_get_info,
    "discover_services": _tm_system_discover_services,
    "analyze_logs": _tm_system_analyze_logs,
    "network_topology": _tm_system_network_topology,
}


async def _tm_system_dispatch(
    action: str, intelligence, remote_host: str, log_paths: list, patterns: list
) -> dict:
    """Route one ``tm_system`` action onto an already-built SystemIntelligence."""
    handler = _TM_SYSTEM_ACTIONS.get(action)
    if handler is None:
        return ResponseBuilder.build(
            400,
            f"Unknown action: {action}",
            {"action": action},
            errors=[
                "Valid: get_info, discover_services, analyze_logs, network_topology"
            ],
        )
    return await handler(intelligence, remote_host, log_paths, patterns)


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
        password_ref: str = Field(
            default="", description="Runtime secret reference for the SSH password."
        ),
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
        resolved = resolve_action(
            action,
            ["get_info", "discover_services", "analyze_logs", "network_topology"],
            service="tunnel-manager",
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        try:
            password = resolve_secret_ref(password_ref)
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            intelligence = SystemIntelligence(tunnel)

            return await _tm_system_dispatch(
                action, intelligence, remote_host, log_paths, patterns
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", "System intelligence fail ({action})")
            return ResponseBuilder.build(
                500,
                f"System intelligence fail ({action})",
                {"host": remote_host},
                type(e).__name__,
            )


def _file_manager(conn: dict) -> AdvancedFileManager:
    """Build the AdvancedFileManager every ``tm_files`` action works through.

    ``conn`` carries remote_host/username/password/identity_file; blank strings
    mean "unset" and are normalised to ``None`` exactly as the inline
    ``Tunnel(...)`` constructions this replaces did.
    """
    return AdvancedFileManager(
        Tunnel(
            remote_host=conn["remote_host"],
            username=conn["username"] or None,
            password=conn["password"] or None,
            identity_file=conn["identity_file"] or None,
        )
    )


def _recursive_ops_options(operation: str, params: dict) -> dict:
    """Per-operation option bag for ``recursive_ops``."""
    if operation == "chmod":
        return {"mode": params["mode"]}
    if operation == "chown":
        return {"owner": params["owner"], "group": params["group"]}
    return {}


async def _tm_files_recursive_ops(action: str, conn: dict, params: dict, ctx) -> dict:
    """``tm_files`` ``recursive_ops``."""
    remote_host = conn["remote_host"]
    operation = params["operation"]
    source = params["source"]
    if not remote_host or not operation or not source:
        return ResponseBuilder.build(
            400,
            "Need remote_host, operation, source",
            {"action": action},
            errors=["Need remote_host, operation, source"],
        )
    try:
        fm = _file_manager(conn)
        options = _recursive_ops_options(operation, params)
        result = await run_blocking(
            fm.recursive_file_operations,
            operation,
            source,
            params["destination"],
            options,
        )
        return ResponseBuilder.build(
            200 if result["success"] else 500,
            f"Recursive {operation} completed",
            {"host": remote_host, "operation": operation, "result": result},
            error=result.get("error", ""),
            errors=result.get("errors", []),
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Recursive file ops fail")
        return ResponseBuilder.build(
            500,
            "Recursive file ops fail",
            {"host": remote_host, "operation": operation},
            type(e).__name__,
        )


async def _tm_files_content_search(action: str, conn: dict, params: dict, ctx) -> dict:
    """``tm_files`` ``content_search``."""
    remote_host = conn["remote_host"]
    search_paths = params["search_paths"]
    pattern = params["pattern"]
    if not remote_host or not search_paths or not pattern:
        return ResponseBuilder.build(
            400,
            "Need remote_host, search_paths, pattern",
            {"action": action},
            errors=["Need remote_host, search_paths, pattern"],
        )
    try:
        fm = _file_manager(conn)
        options = {
            "case_sensitive": params["case_sensitive"],
            "recursive": params["recursive"],
            "max_results": params["max_results"],
        }
        result = await run_blocking(
            fm.file_content_search, search_paths, pattern, options
        )
        return ResponseBuilder.build(
            200 if result["success"] else 500,
            "File content search completed",
            {"host": remote_host, "pattern": pattern, "result": result},
            error=result.get("error", ""),
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "File content search fail")
        return ResponseBuilder.build(
            500,
            "File content search fail",
            {"host": remote_host, "pattern": pattern},
            type(e).__name__,
        )


async def _tm_files_watch(action: str, conn: dict, params: dict, ctx) -> dict:
    """``tm_files`` ``watch``."""
    remote_host = conn["remote_host"]
    watch_paths = params["watch_paths"]
    if not remote_host or not watch_paths:
        return ResponseBuilder.build(
            400,
            "Need remote_host, watch_paths",
            {"action": action},
            errors=["Need remote_host, watch_paths"],
        )
    try:
        fm = _file_manager(conn)
        result = await run_blocking(
            fm.file_watch_monitor, watch_paths, params["duration"]
        )
        return ResponseBuilder.build(
            200 if result["success"] else 500,
            "File monitoring completed",
            {"host": remote_host, "watch_paths": watch_paths, "result": result},
            error=result.get("error", ""),
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "File watch fail")
        return ResponseBuilder.build(
            500,
            "File watch fail",
            {"host": remote_host, "watch_paths": watch_paths},
            type(e).__name__,
        )


async def _tm_files_diff_compare(action: str, conn: dict, params: dict, ctx) -> dict:
    """``tm_files`` ``diff_compare`` (connects to ``host1``, not remote_host)."""
    file_path = params["file_path"]
    host1 = params["host1"]
    host2 = params["host2"]
    if not file_path or not host1 or not host2:
        return ResponseBuilder.build(
            400,
            "Need file_path, host1, host2",
            {"action": action},
            errors=["Need file_path, host1, host2"],
        )
    try:
        fm = _file_manager({**conn, "remote_host": host1})
        result = await run_blocking(fm.file_diff_compare, host1, host2, file_path)
        return ResponseBuilder.build(
            200 if result["success"] else 500,
            "File comparison completed",
            {
                "file": file_path,
                "host1": host1,
                "host2": host2,
                "result": result,
            },
            error=result.get("error", ""),
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "File diff fail")
        return ResponseBuilder.build(
            500,
            "File diff fail",
            {"file": file_path, "host1": host1, "host2": host2},
            type(e).__name__,
        )


async def _tm_files_backup(action: str, conn: dict, params: dict, ctx) -> dict:
    """``tm_files`` ``backup``."""
    remote_host = conn["remote_host"]
    backup_paths = params["backup_paths"]
    backup_dest = params["backup_dest"]
    if not remote_host or not backup_paths or not backup_dest:
        return ResponseBuilder.build(
            400,
            "Need remote_host, backup_paths, backup_dest",
            {"action": action},
            errors=["Need remote_host, backup_paths, backup_dest"],
        )
    try:
        fm = _file_manager(conn)
        options = {
            "compression": params["compression"],
            "incremental": params["incremental"],
        }
        result = await run_blocking(fm.smart_backup, backup_paths, backup_dest, options)
        return ResponseBuilder.build(
            200 if result["success"] else 500,
            "Backup completed",
            {
                "host": remote_host,
                "backup_paths": backup_paths,
                "result": result,
            },
            error=result.get("error", ""),
        )
    except Exception as e:
        ctx_log(ctx, logger, "error", "Backup fail")
        return ResponseBuilder.build(
            500,
            "Backup fail",
            {"host": remote_host, "backup_paths": backup_paths},
            type(e).__name__,
        )


_TM_FILES_ACTIONS = {
    "recursive_ops": _tm_files_recursive_ops,
    "content_search": _tm_files_content_search,
    "watch": _tm_files_watch,
    "diff_compare": _tm_files_diff_compare,
    "backup": _tm_files_backup,
}


def register_file_tools(mcp: FastMCP):
    """Register advanced file operations tool."""

    @mcp.tool(
        annotations={
            "title": "Advanced File Operations",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"advanced_file_operations"},
    )
    async def tm_files(
        action: str = Field(
            description="Action: 'recursive_ops', 'content_search', 'watch', 'diff_compare', 'backup'"
        ),
        remote_host: str = Field(default="", description="Remote host."),
        username: str = Field(default="", description="SSH username."),
        password_ref: str = Field(
            default="", description="Runtime secret reference for the SSH password."
        ),
        identity_file: str = Field(default="", description="SSH identity file path."),
        operation: str = Field(
            default="",
            description="Operation type: copy, move, delete, list, chmod, chown (recursive_ops).",
        ),
        source: str = Field(default="", description="Source path (recursive_ops)."),
        destination: str = Field(
            default="", description="Destination path (recursive_ops/copy/move)."
        ),
        mode: str = Field(
            default="755", description="Permission mode (recursive_ops/chmod)."
        ),
        owner: str = Field(default="", description="Owner (recursive_ops/chown)."),
        group: str = Field(default="", description="Group (recursive_ops/chown)."),
        search_paths: list[str] = Field(
            default=[], description="Directories to search (content_search)."
        ),
        pattern: str = Field(
            default="", description="Search pattern (content_search)."
        ),
        case_sensitive: bool = Field(
            default=False, description="Case-sensitive (content_search)."
        ),
        recursive: bool = Field(
            default=True, description="Recursive search (content_search)."
        ),
        max_results: int = Field(
            default=1000, description="Max results (content_search)."
        ),
        watch_paths: list[str] = Field(
            default=[], description="Paths to monitor (watch)."
        ),
        duration: int = Field(default=60, description="Monitor duration secs (watch)."),
        file_path: str = Field(
            default="", description="File path to compare (diff_compare)."
        ),
        host1: str = Field(default="", description="First host (diff_compare)."),
        host2: str = Field(default="", description="Second host (diff_compare)."),
        backup_paths: list[str] = Field(
            default=[], description="Paths to backup (backup)."
        ),
        backup_dest: str = Field(
            default="", description="Backup destination (backup)."
        ),
        compression: bool = Field(
            default=True, description="Enable compression (backup)."
        ),
        incremental: bool = Field(
            default=False, description="Incremental backup (backup)."
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Advanced file operations on remote hosts."""
        resolved = resolve_action(
            action,
            ["recursive_ops", "content_search", "watch", "diff_compare", "backup"],
            service="tunnel-manager",
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        try:
            password = resolve_secret_ref(password_ref)
        except ValueError:
            return ResponseBuilder.build(
                400,
                "Invalid SSH credential configuration",
                {"credential_ref_configured": bool(password_ref)},
                errors=["A supported runtime secret reference is required"],
            )
        handler = _TM_FILES_ACTIONS.get(action)
        if handler is None:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: recursive_ops, content_search, watch, diff_compare, backup"
                ],
            )
        return await handler(
            action,
            {
                "remote_host": remote_host,
                "username": username,
                "password": password,
                "identity_file": identity_file,
            },
            {
                "operation": operation,
                "source": source,
                "destination": destination,
                "mode": mode,
                "owner": owner,
                "group": group,
                "search_paths": search_paths,
                "pattern": pattern,
                "case_sensitive": case_sensitive,
                "recursive": recursive,
                "max_results": max_results,
                "watch_paths": watch_paths,
                "duration": duration,
                "file_path": file_path,
                "host1": host1,
                "host2": host2,
                "backup_paths": backup_paths,
                "backup_dest": backup_dest,
                "compression": compression,
                "incremental": incremental,
            },
            ctx,
        )


async def _tm_security_audit(
    auditor, remote_host: str, scope: list, standard: str, scan_type: str
) -> dict:
    """``tm_security`` ``security_audit``."""
    result = await run_blocking(auditor.security_audit, scope if scope else None)
    return ResponseBuilder.build(
        200 if result["success"] else 500,
        f"Security audit completed with score: {result['score']}/100",
        {"host": remote_host, "audit_result": result},
        error=result.get("error", ""),
        errors=result.get("audit_errors", []),
    )


async def _tm_security_compliance_check(
    auditor, remote_host: str, scope: list, standard: str, scan_type: str
) -> dict:
    """``tm_security`` ``compliance_check``."""
    result = await run_blocking(auditor.compliance_check, standard)
    return ResponseBuilder.build(
        200 if result["success"] else 500,
        f"Compliance check completed: {result['compliance_percentage']:.1f}% compliant",
        {
            "host": remote_host,
            "standard": standard,
            "compliance_result": result,
        },
        error=result.get("error", ""),
        errors=result.get("check_errors", []),
    )


async def _tm_security_vulnerability_scan(
    auditor, remote_host: str, scope: list, standard: str, scan_type: str
) -> dict:
    """``tm_security`` ``vulnerability_scan``."""
    result = await run_blocking(auditor.vulnerability_scan, scan_type)
    return ResponseBuilder.build(
        200 if result["success"] else 500,
        f"Vulnerability scan completed: {len(result['vulnerabilities'])} vulnerabilities found",
        {
            "host": remote_host,
            "scan_type": scan_type,
            "scan_result": result,
        },
        error=result.get("error", ""),
        errors=result.get("scan_errors", []),
    )


async def _tm_security_access_control_audit(
    auditor, remote_host: str, scope: list, standard: str, scan_type: str
) -> dict:
    """``tm_security`` ``access_control_audit``."""
    result = await run_blocking(auditor.access_control_audit)
    return ResponseBuilder.build(
        200 if result["success"] else 500,
        f"Access control audit completed: {result['users_audited']} users audited",
        {"host": remote_host, "audit_result": result},
        error=result.get("error", ""),
        errors=result.get("audit_errors", []),
    )


_TM_SECURITY_ACTIONS = {
    "security_audit": _tm_security_audit,
    "compliance_check": _tm_security_compliance_check,
    "vulnerability_scan": _tm_security_vulnerability_scan,
    "access_control_audit": _tm_security_access_control_audit,
}


async def _tm_security_dispatch(
    action: str, auditor, remote_host: str, scope: list, standard: str, scan_type: str
) -> dict:
    """Route one ``tm_security`` action onto an already-built SecurityAuditor."""
    handler = _TM_SECURITY_ACTIONS.get(action)
    if handler is None:
        return ResponseBuilder.build(
            400,
            f"Unknown action: {action}",
            {"action": action},
            errors=[
                "Valid: security_audit, compliance_check, vulnerability_scan, access_control_audit"
            ],
        )
    return await handler(auditor, remote_host, scope, standard, scan_type)


def register_security_tools(mcp: FastMCP):
    """Register security scanning and compliance tool."""

    @mcp.tool(
        annotations={
            "title": "Security Auditing",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"security_auditing"},
    )
    async def tm_security(
        action: str = Field(
            description="Action: 'security_audit', 'compliance_check', 'vulnerability_scan', 'access_control_audit'"
        ),
        remote_host: str = Field(description="Remote host to audit."),
        username: str = Field(default="", description="SSH username."),
        password_ref: str = Field(
            default="", description="Runtime secret reference for the SSH password."
        ),
        identity_file: str = Field(default="", description="SSH identity file path."),
        scope: list[str] = Field(
            default=[], description="Security areas to audit (security_audit)."
        ),
        standard: str = Field(
            default="cis_benchmark",
            description="Compliance standard: cis_benchmark, pci_dss, hipaa (compliance_check).",
        ),
        scan_type: str = Field(
            default="basic",
            description="Scan type: basic, package, config (vulnerability_scan).",
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Security scanning and compliance."""
        resolved = resolve_action(
            action,
            [
                "security_audit",
                "compliance_check",
                "vulnerability_scan",
                "access_control_audit",
            ],
            service="tunnel-manager",
        )
        if isinstance(resolved, dict):
            return resolved
        action = resolved
        try:
            password = resolve_secret_ref(password_ref)
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

            return await _tm_security_dispatch(
                action, auditor, remote_host, scope, standard, scan_type
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", "Security audit fail ({action})")
            return ResponseBuilder.build(
                500,
                f"Security audit fail ({action})",
                {"host": remote_host},
                type(e).__name__,
            )


def register_ingest_tools(mcp: FastMCP):
    """Register the Wire-First native KG ingestion tool."""

    @mcp.tool(
        annotations={
            "title": "Ingest Hosts to Knowledge Graph",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"kg_ingest"},
    )
    async def tunnel_ingest_hosts(
        group: str = Field(
            default="all",
            description="HostGroup name to attach the ingested hosts to.",
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """List the managed SSH inventory and push it into the epistemic-graph KG.

        Maps each alias → a typed ``:Host`` node (+ ``:HostGroup`` / ``:SshKey`` and
        their ``:inGroup`` / ``:usesKey`` links). Best-effort: no-ops cleanly when no
        KG engine is reachable.
        """
        from tunnel_manager.kg_ingest import ingest_hosts

        hosts = await run_blocking(host_manager.list_hosts)
        result = await run_blocking(ingest_hosts, hosts, group=group or "all")
        if result is None:
            return {
                "status": "skipped",
                "message": "No KG engine reachable (or empty inventory).",
                "hosts": len(hosts),
            }
        return {"status": "success", "hosts": len(hosts), **result}


def get_mcp_instance() -> tuple[Any, Any, Any, Any]:
    """Initialize and return the MCP instance, args, and middlewares."""
    load_config()

    args, mcp, middlewares = create_mcp_server(
        name="TunnelManagerMCP",
        version=__version__,
        instructions="Tunnel Manager MCP Utility — Manage SSH tunnels, managed hosts, and remote execution.",
    )

    registered_tags = register_tool_surface(
        mcp,
        client_cls=HostManager,
        get_client=get_client,
        service="tunnel-manager",
        tool_registry=[
            ("hosts", "HOSTTOOL", register_host_tools),
            ("remote", "REMOTETOOL", register_remote_tools),
            ("inventory", "INVENTORYTOOL", register_inventory_tools),
            ("operations", "OPERATIONSTOOL", register_operations_tools),
            ("system", "SYSTEMTOOL", register_system_tools),
            ("files", "FILETOOL", register_file_tools),
            ("security", "SECURITYTOOL", register_security_tools),
            ("ingest", "INGESTTOOL", register_ingest_tools),
        ],
    )

    for mw in middlewares:
        mcp.add_middleware(mw)
    return mcp, args, middlewares, registered_tags


def mcp_server() -> None:
    mcp, args, middlewares, registered_tags = get_mcp_instance()
    print(f"{'tunnel-manager'} MCP v{__version__}", file=sys.stderr)
    print("\nStarting MCP Server", file=sys.stderr)
    print(f"  Transport: {args.transport.upper()}", file=sys.stderr)
    print(f"  Auth: {args.auth_type}", file=sys.stderr)
    print(f"  Dynamic Tags Loaded: {len(set(registered_tags))}", file=sys.stderr)

    from agent_utilities.mcp.server_factory import (
        mcp_network_run_kwargs,
    )
    from agent_utilities.security.request_identity import (
        apply_served_security_profile,
    )

    apply_served_security_profile(
        args.transport,
        transport_auth_configured=(
            str(getattr(args, "auth_type", "none") or "none").lower() != "none"
        ),
    )

    if args.transport == "stdio":
        # Stdout purity is owned fd-level by the MCP SDK's own stdio_server()
        # (agent-utilities B-19): it claims fd 1 exclusively and dup2()s stderr
        # over it for every other writer, so no process-wide patch is needed.
        mcp.run(transport="stdio")
    elif args.transport == "streamable-http":
        mcp.run(
            transport="streamable-http",
            host=args.host,
            port=args.port,
            **mcp_network_run_kwargs(args),
        )
    elif args.transport == "sse":
        mcp.run(
            transport="sse",
            host=args.host,
            port=args.port,
            **mcp_network_run_kwargs(args),
        )
    else:
        logger.error("Invalid transport", extra={"transport": args.transport})
        sys.exit(1)


if __name__ == "__main__":
    mcp_server()
