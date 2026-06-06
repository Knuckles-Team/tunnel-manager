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
import subprocess
import sys
from typing import Any

import yaml
from agent_utilities.base_utilities import to_boolean, to_integer
from agent_utilities.mcp_utilities import (
    create_mcp_server,
    ctx_confirm_destructive,
    ctx_log,
    ctx_progress,
)
from dotenv import find_dotenv, load_dotenv

from tunnel_manager.advanced_file_manager import AdvancedFileManager
from tunnel_manager.operation_manager import operation_manager
from tunnel_manager.security_auditor import SecurityAuditor
from tunnel_manager.system_intelligence import SystemIntelligence
from tunnel_manager.tunnel_manager import HostManager, Tunnel

__version__ = "1.28.0"

# XDG-compliant default paths for tunnel-manager data
_XDG_CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
_TM_CONFIG_DIR = os.path.join(_XDG_CONFIG_HOME, "tunnel-manager")
_DEFAULT_INVENTORY_PATH = os.path.join(_TM_CONFIG_DIR, "inventory.yml")

# Ensure config directory exists on import
os.makedirs(_TM_CONFIG_DIR, exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = get_logger("TunnelManager")
host_manager = HostManager()


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
        return {
            "status_code": status,
            "message": msg,
            "stdout": stdout,
            "stderr": error,
            "files_copied": files or [],
            "locations_copied_to": locations or [],
            "details": details,
            "errors": errors or ([error] if error else []),
        }


def load_inventory(
    inventory: str, group: str, logger: logging.Logger
) -> tuple[list[dict], dict]:
    try:
        with open(inventory) as f:
            inv = yaml.safe_load(f) or {}
        hosts = []

        # Check if it's an Ansible-style inventory
        if "all" in inv and isinstance(inv["all"], dict):
            all_group = inv["all"]
            all_vars = all_group.get("vars", {}) or {}
            all_hosts = all_group.get("hosts", {}) or {}
            children = all_group.get("children", {}) or {}

            # We need to collect hosts belonging to the target group
            hosts_to_parse = {}  # alias -> (hvars, g_vars)

            if group == "all":
                # Add direct hosts from 'all'
                for alias, hvars in all_hosts.items():
                    hosts_to_parse[alias] = (hvars or {}, {})
                # Add hosts from all children
                for child_data in children.values():
                    if isinstance(child_data, dict):
                        g_hosts = child_data.get("hosts", {}) or {}
                        g_vars = child_data.get("vars", {}) or {}
                        for alias, hvars in g_hosts.items():
                            hosts_to_parse[alias] = (hvars or {}, g_vars)
            elif group in children:
                child_data = children[group]
                if isinstance(child_data, dict):
                    g_hosts = child_data.get("hosts", {}) or {}
                    g_vars = child_data.get("vars", {}) or {}
                    for alias, hvars in g_hosts.items():
                        hosts_to_parse[alias] = (hvars or {}, g_vars)
            else:
                # Group not found in children. Check if defined as a top-level key outside children
                if (
                    group in inv
                    and isinstance(inv[group], dict)
                    and "hosts" in inv[group]
                ):
                    legacy_hosts = inv[group]["hosts"] or {}
                    legacy_vars = inv[group].get("vars", {}) or {}
                    for alias, hvars in legacy_hosts.items():
                        hosts_to_parse[alias] = (hvars or {}, legacy_vars)
                else:
                    return [], ResponseBuilder.build(
                        400,
                        f"Group '{group}' invalid",
                        {"inventory": inventory, "group": group},
                        errors=[f"Group '{group}' invalid"],
                    )

            # Now build the host entries
            for alias, (hvars, g_vars) in hosts_to_parse.items():
                username = (
                    hvars.get("ansible_user")
                    or hvars.get("user")
                    or g_vars.get("ansible_user")
                    or g_vars.get("user")
                    or all_vars.get("ansible_user")
                    or all_vars.get("user")
                    or ""
                )
                password = (
                    hvars.get("ansible_ssh_pass")
                    or hvars.get("password")
                    or g_vars.get("ansible_ssh_pass")
                    or g_vars.get("password")
                    or all_vars.get("ansible_ssh_pass")
                    or all_vars.get("password")
                )
                key_path = (
                    hvars.get("key_path")
                    or hvars.get("identity_file")
                    or hvars.get("ansible_ssh_private_key_file")
                    or g_vars.get("key_path")
                    or g_vars.get("identity_file")
                    or g_vars.get("ansible_ssh_private_key_file")
                    or all_vars.get("key_path")
                    or all_vars.get("identity_file")
                    or all_vars.get("ansible_ssh_private_key_file")
                )
                port = (
                    hvars.get("ansible_port")
                    or hvars.get("port")
                    or g_vars.get("ansible_port")
                    or g_vars.get("port")
                    or all_vars.get("ansible_port")
                    or all_vars.get("port")
                    or 22
                )

                entry = {
                    "hostname": hvars.get("ansible_host")
                    or hvars.get("hostname")
                    or alias,
                    "username": username,
                    "password": password,
                    "key_path": key_path,
                    "port": int(port) if port else 22,
                }
                if not entry["username"]:
                    logger.error(f"Skip {entry['hostname']}: no username")
                    continue
                hosts.append(entry)

        else:
            # Legacy non-Ansible flat inventory (or key-value flat structure)
            if group == "all":
                # Treat the entire inv as flat hosts
                for alias, hvars in inv.items():
                    if isinstance(hvars, dict):
                        username = (
                            hvars.get("user")
                            or hvars.get("username")
                            or hvars.get("ansible_user")
                            or ""
                        )
                        password = hvars.get("password") or hvars.get(
                            "ansible_ssh_pass"
                        )
                        key_path = (
                            hvars.get("key_path")
                            or hvars.get("identity_file")
                            or hvars.get("ansible_ssh_private_key_file")
                        )
                        port = hvars.get("port") or hvars.get("ansible_port") or 22
                        entry = {
                            "hostname": hvars.get("hostname")
                            or hvars.get("ansible_host")
                            or alias,
                            "username": username,
                            "password": password,
                            "key_path": key_path,
                            "port": int(port) if port else 22,
                        }
                        if not entry["username"]:
                            logger.error(f"Skip {entry['hostname']}: no username")
                            continue
                        hosts.append(entry)
            elif (
                group in inv
                and isinstance(inv[group], dict)
                and "hosts" in inv[group]
                and isinstance(inv[group]["hosts"], dict)
            ):
                # Legacy style with group as a top-level key containing 'hosts'
                for host, vars in inv[group]["hosts"].items():
                    hvars = vars or {}
                    entry = {
                        "hostname": hvars.get("ansible_host")
                        or hvars.get("hostname")
                        or host,
                        "username": hvars.get("ansible_user")
                        or hvars.get("user")
                        or hvars.get("username"),
                        "password": hvars.get("ansible_ssh_pass")
                        or hvars.get("password"),
                        "key_path": hvars.get("ansible_ssh_private_key_file")
                        or hvars.get("key_path")
                        or hvars.get("identity_file"),
                        "port": int(
                            hvars.get("ansible_port") or hvars.get("port") or 22
                        ),
                    }
                    if not entry["username"]:
                        logger.error(f"Skip {entry['hostname']}: no username")
                        continue
                    hosts.append(entry)
            else:
                return [], ResponseBuilder.build(
                    400,
                    f"Group '{group}' invalid",
                    {"inventory": inventory, "group": group},
                    errors=[f"Group '{group}' invalid"],
                )

        if not hosts:
            return [], ResponseBuilder.build(
                400,
                f"No hosts in group '{group}'",
                {"inventory": inventory, "group": group},
                errors=[f"No hosts in group '{group}'"],
            )
        return hosts, {}
    except Exception as e:
        logger.error(f"Load inv fail: {e}")
        return [], ResponseBuilder.build(
            500,
            f"Load inv fail: {e}",
            {"inventory": inventory, "group": group},
            str(e),
        )


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
        logger.debug(f"Resolved host alias '{host_alias}' to config: {host_config}")

        final_config = host_config.model_dump()
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
        logger.debug(f"Host alias '{host_alias}' not found, using provided params.")
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
        password: str = Field(default="", description="Password (if no key)."),
        proxy_command: str = Field(default="", description="Proxy command."),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Manage the local host alias inventory."""
        if action == "list":
            return {"hosts": host_manager.list_hosts()}
        elif action == "add":
            if not alias or not hostname or not user:
                return ResponseBuilder.build(
                    400,
                    "Need alias, hostname, user",
                    {"action": action},
                    errors=["Need alias, hostname, user"],
                )
            host_manager.add_host(
                alias=alias,
                hostname=hostname,
                user=user,
                port=port,
                identity_file=identity_file or None,
                password=password or None,
                proxy_command=proxy_command or None,
            )
            return {"status": "success", "message": f"Host '{alias}' added."}
        elif action == "remove":
            if not alias:
                return ResponseBuilder.build(
                    400, "Need alias", {"action": action}, errors=["Need alias"]
                )
            if not await ctx_confirm_destructive(ctx, "remove host"):
                return {"status": "cancelled", "message": "Operation cancelled by user"}
            await ctx_progress(ctx, 0, 100)
            host_manager.remove_host(alias)
            return {"status": "success", "message": f"Host '{alias}' removed."}
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=["Valid: list, add, remove"],
            )


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
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""), description="Remote host."
        ),
        user: str | None = Field(
            default=os.environ.get("TUNNEL_USERNAME", ""), description="Username."
        ),
        password: str | None = Field(
            default=os.environ.get("TUNNEL_PASSWORD", ""), description="Password."
        ),
        port: int = Field(
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
            description="Port.",
        ),
        id_file: str | None = Field(
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
            description="Private key path.",
        ),
        certificate: str | None = Field(
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
            description="Teleport certificate.",
        ),
        proxy: str | None = Field(
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
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
        if action == "run_command":
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
                    ssh_config_file=final_cfg,
                )
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                t.connect()
                out, error = t.run_command(cmd, timeout=timeout)
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
                ctx_log(ctx, logger, "error", f"Cmd fail: {e}")
                await ctx_progress(ctx, 100, 100)
                return ResponseBuilder.build(
                    500, f"Cmd fail: {e}", {"host": host, "cmd": cmd}, str(e)
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "send_file":
            _logger = logging.getLogger("TunnelServer")
            _lpath = os.path.abspath(os.path.expanduser(lpath))
            _rpath = os.path.expanduser(rpath)
            if not host or not _lpath or not _rpath:
                return ResponseBuilder.build(
                    400,
                    "Need host, lpath, rpath",
                    {"host": host, "lpath": _lpath, "rpath": _rpath},
                    errors=["Need host, lpath, rpath"],
                )
            if not os.path.exists(_lpath) or not os.path.isfile(_lpath):
                return ResponseBuilder.build(
                    400,
                    f"Invalid file: {_lpath}",
                    {"host": host, "lpath": _lpath, "rpath": _rpath},
                    errors=[f"Invalid file: {_lpath}"],
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
                    ssh_config_file=final_cfg,
                )
                t.connect()
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                assert t.ssh_client is not None
                sftp = t.ssh_client.open_sftp()
                transferred = 0

                def progress_callback(transf, total):
                    nonlocal transferred
                    transferred = transf
                    if ctx:
                        asyncio.ensure_future(
                            ctx.report_progress(progress=transf, total=total)
                        )

                sftp.put(_lpath, _rpath, callback=progress_callback)
                sftp.close()
                return ResponseBuilder.build(
                    200,
                    f"Uploaded to {_rpath}",
                    {"host": host, "lpath": _lpath, "rpath": _rpath},
                    files=[_lpath],
                    locations=[_rpath],
                    errors=[],
                )
            except Exception as e:
                ctx_log(ctx, _logger, "error", f"Upload fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Upload fail: {e}",
                    {"host": host, "lpath": _lpath, "rpath": _rpath},
                    str(e),
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "receive_file":
            _lpath = os.path.abspath(os.path.expanduser(lpath))
            if not host or not rpath or not _lpath:
                return ResponseBuilder.build(
                    400,
                    "Need host, rpath, lpath",
                    {"host": host, "rpath": rpath, "lpath": _lpath},
                    errors=["Need host, rpath, lpath"],
                )
            try:
                t = Tunnel(
                    remote_host=host,
                    username=user,
                    password=password,
                    port=port,
                    identity_file=id_file,
                    certificate_file=certificate,
                    proxy_command=proxy,
                    ssh_config_file=cfg,
                )
                t.connect()
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                assert t.ssh_client is not None
                sftp = t.ssh_client.open_sftp()
                sftp.stat(rpath)
                transferred = 0

                def progress_callback(transf, total):
                    nonlocal transferred
                    transferred = transf
                    if ctx:
                        asyncio.ensure_future(
                            ctx.report_progress(progress=transf, total=total)
                        )

                sftp.get(rpath, _lpath, callback=progress_callback)
                if ctx:
                    await ctx.report_progress(progress=100, total=100)
                sftp.close()
                return ResponseBuilder.build(
                    200,
                    f"Downloaded to {_lpath}",
                    {"host": host, "rpath": rpath, "lpath": _lpath},
                    files=[rpath],
                    locations=[_lpath],
                    errors=[],
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Download fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Download fail: {e}",
                    {"host": host, "rpath": rpath, "lpath": _lpath},
                    str(e),
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "check_ssh":
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
                    ssh_config_file=final_cfg,
                )
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                success, msg = t.check_ssh_server()
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
                ctx_log(ctx, logger, "error", f"Check fail: {e}")
                return ResponseBuilder.build(
                    500, f"Check fail: {e}", {"host": host}, str(e)
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "test_key_auth":
            _key = key or os.environ.get("TUNNEL_IDENTITY_FILE", "")
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
                    ssh_config_file=final_cfg,
                )
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                success, msg = t.test_key_auth(_key)
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
                ctx_log(ctx, logger, "error", f"Key test fail: {e}")
                return ResponseBuilder.build(
                    500, f"Key test fail: {e}", {"host": host, "key": _key}, str(e)
                )

        elif action == "setup_passwordless":
            _key = key or os.path.expanduser("~/.ssh/id_rsa")
            if not host or not password:
                return ResponseBuilder.build(
                    400,
                    "Need host, password",
                    {"host": host},
                    errors=["Need host, password"],
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
                    ssh_config_file=cfg,
                )
                t = Tunnel(
                    remote_host=conf["hostname"],
                    username=conf["user"],
                    password=conf["password"],
                    port=conf["port"],
                    ssh_config_file=final_cfg,
                )
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                _key = os.path.expanduser(_key)
                pub_key = _key + ".pub"
                if not os.path.exists(pub_key):
                    if key_type == "rsa":
                        subprocess.run(
                            [
                                "/usr/bin/ssh-keygen",
                                "-t",
                                "rsa",
                                "-b",
                                "4096",
                                "-f",
                                _key,
                                "-N",
                                "",
                            ],
                            check=True,
                        )
                    else:
                        subprocess.run(
                            [
                                "/usr/bin/ssh-keygen",
                                "-t",
                                "ed25519",
                                "-f",
                                _key,
                                "-N",
                                "",
                            ],
                            check=True,
                        )
                t.setup_passwordless_ssh(local_key_path=_key, key_type=key_type)
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
                ctx_log(ctx, logger, "error", f"SSH setup fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"SSH setup fail: {e}",
                    {"host": host, "key_type": key_type},
                    str(e),
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "copy_ssh_config":
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
                    ssh_config_file=final_cfg,
                )
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                t.copy_ssh_config(lcfg, rcfg)
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
                ctx_log(ctx, logger, "error", f"Copy cfg fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Copy cfg fail: {e}",
                    {"host": host, "lcfg": lcfg, "rcfg": rcfg},
                    str(e),
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "rotate_key":
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
                    ssh_config_file=final_cfg,
                )
                if ctx:
                    await ctx.report_progress(progress=0, total=100)
                _new_key = os.path.expanduser(new_key)
                new_public_key = _new_key + ".pub"
                if not os.path.exists(_new_key):
                    if key_type == "rsa":
                        subprocess.run(
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
                        )
                    else:
                        subprocess.run(
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
                        )
                t.rotate_ssh_key(_new_key, key_type=key_type)
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
                ctx_log(ctx, logger, "error", f"Rotate fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Rotate fail: {e}",
                    {"host": host, "new_key": new_key, "key_type": key_type},
                    str(e),
                )
            finally:
                if "t" in locals():
                    t.close()

        elif action == "remove_host_key":
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
                msg = t.remove_host_key(known_hosts_path=_known_hosts)
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
                ctx_log(ctx, logger, "error", f"Remove fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Remove fail: {e}",
                    {"host": host, "known_hosts": known_hosts},
                    str(e),
                )
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: run_command, send_file, receive_file, check_ssh, test_key_auth, setup_passwordless, copy_ssh_config, rotate_key, remove_host_key"
                ],
            )


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
            default=os.environ.get("TUNNEL_INVENTORY", _DEFAULT_INVENTORY_PATH),
            description="YAML inventory path (default: $XDG_CONFIG_HOME/tunnel-manager/inventory.yml).",
        ),
        group: str = Field(
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
            description="Target group.",
        ),
        parallel: bool = Field(
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
            description="Run parallel.",
        ),
        max_threads: int = Field(
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "6")),
            description="Max threads.",
        ),
        cmd: str = Field(default="", description="Shell command (run_command)."),
        key: str = Field(
            default=os.environ.get(
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
        if not inventory:
            return ResponseBuilder.build(
                400, "Need inventory", {"action": action}, errors=["Need inventory"]
            )

        if action == "configure_key_auth":
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
                if not os.path.exists(_key):
                    if key_type == "rsa":
                        subprocess.run(
                            [
                                "/usr/bin/ssh-keygen",
                                "-t",
                                "rsa",
                                "-b",
                                "4096",
                                "-f",
                                _key,
                                "-N",
                                "",
                            ],
                            check=True,
                        )
                    else:
                        subprocess.run(
                            [
                                "/usr/bin/ssh-keygen",
                                "-t",
                                "ed25519",
                                "-f",
                                _key,
                                "-N",
                                "",
                            ],
                            check=True,
                        )
                with open(pub_key) as f:
                    pub = f.read().strip()
                hosts, error = load_inventory(inventory, group, logger)
                if error:
                    return error
                total = len(hosts)
                if ctx:
                    await ctx.report_progress(progress=0, total=total)

                async def setup_host(h: dict, ctx: Context) -> dict:
                    host, _user, _password = h["hostname"], h["username"], h["password"]
                    kpath = h.get("key_path", _key)
                    try:
                        t = Tunnel(remote_host=host, username=_user, password=_password)
                        t.remove_host_key()
                        t.setup_passwordless_ssh(
                            local_key_path=kpath, key_type=key_type
                        )
                        t.connect()
                        t.run_command(f"echo '{pub}' >> ~/.ssh/authorized_keys")
                        t.run_command("chmod 600 ~/.ssh/authorized_keys")
                        res, msg = t.test_key_auth(kpath)
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
                            "message": f"Setup fail: {e}",
                            "errors": [str(e)],
                        }
                    finally:
                        if "t" in locals():
                            t.close()

                results, files, locations, errors = [], [], [], []
                if parallel:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max_threads
                    ) as ex:
                        futures = [
                            ex.submit(lambda h: asyncio.run(setup_host(h, ctx)), h)
                            for h in hosts
                        ]
                        for i, future in enumerate(
                            concurrent.futures.as_completed(futures), 1
                        ):
                            try:
                                r = future.result()
                                results.append(r)
                                if r["status"] == "success":
                                    files.append(pub_key)
                                    locations.append(
                                        f"~/.ssh/authorized_keys on {r['hostname']}"
                                    )
                                else:
                                    errors.extend(r["errors"])
                                if ctx:
                                    await ctx.report_progress(progress=i, total=total)
                            except Exception as e:
                                results.append(
                                    {
                                        "hostname": "unknown",
                                        "status": "failed",
                                        "message": f"Parallel error: {e}",
                                        "errors": [str(e)],
                                    }
                                )
                                errors.append(str(e))
                else:
                    for i, h in enumerate(hosts, 1):
                        r = await setup_host(h, ctx)
                        results.append(r)
                        if r["status"] == "success":
                            files.append(pub_key)
                            locations.append(
                                f"~/.ssh/authorized_keys on {r['hostname']}"
                            )
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                msg = (
                    f"SSH setup done for {group}"
                    if not errors
                    else f"SSH setup failed for some in {group}"
                )
                return ResponseBuilder.build(
                    200 if not errors else 500,
                    msg,
                    {
                        "inventory": inventory,
                        "group": group,
                        "key_type": key_type,
                        "host_results": results,
                    },
                    stdout="; ".join(errors),
                    files=files,
                    locations=locations,
                    errors=errors,
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Setup all fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Setup all fail: {e}",
                    {"inventory": inventory, "group": group, "key_type": key_type},
                    str(e),
                )

        elif action == "mesh_bootstrap":
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
                ctx_log(ctx, logger, "error", f"Mesh bootstrap fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Mesh bootstrap fail: {e}",
                    {"inventory": inventory, "group": group, "key_type": key_type},
                    str(e),
                )

        elif action == "run_command":
            if not cmd:
                return ResponseBuilder.build(
                    400, "Need cmd", {"action": action, "cmd": cmd}, errors=["Need cmd"]
                )
            try:
                hosts, error = load_inventory(inventory, group, logger)
                if error:
                    return error
                total = len(hosts)
                if ctx:
                    await ctx.report_progress(progress=0, total=total)

                async def run_host(h: dict, ctx: Context) -> dict:
                    await ctx_progress(ctx, 0, 100)
                    host = h["hostname"]
                    try:
                        t = Tunnel(
                            remote_host=host,
                            username=h["username"],
                            password=h.get("password"),
                            identity_file=h.get("key_path"),
                        )
                        out, error = t.run_command(cmd, timeout=timeout)
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
                            "message": f"Cmd fail: {e}",
                            "stdout": "",
                            "stderr": str(e),
                            "errors": [str(e)],
                        }
                    finally:
                        if "t" in locals():
                            t.close()

                results, errors = [], []
                if parallel:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max_threads
                    ) as ex:
                        futures = [
                            ex.submit(lambda h: asyncio.run(run_host(h, ctx)), h)
                            for h in hosts
                        ]
                        for i, future in enumerate(
                            concurrent.futures.as_completed(futures), 1
                        ):
                            try:
                                r = future.result()
                                results.append(r)
                                errors.extend(r["errors"])
                                if ctx:
                                    await ctx.report_progress(progress=i, total=total)
                            except Exception as e:
                                results.append(
                                    {
                                        "hostname": "unknown",
                                        "status": "failed",
                                        "message": f"Parallel error: {e}",
                                        "stdout": "",
                                        "stderr": str(e),
                                        "errors": [str(e)],
                                    }
                                )
                                errors.append(str(e))
                else:
                    for i, h in enumerate(hosts, 1):
                        r = await run_host(h, ctx)
                        results.append(r)
                        errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                msg = (
                    f"Cmd '{cmd}' done on {group}"
                    if not errors
                    else f"Cmd '{cmd}' failed for some in {group}"
                )
                return ResponseBuilder.build(
                    200 if not errors else 500,
                    msg,
                    {
                        "inventory": inventory,
                        "group": group,
                        "cmd": cmd,
                        "host_results": results,
                    },
                    error="; ".join(errors),
                    files=[],
                    locations=[],
                    errors=errors,
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Cmd all fail: {e}")
                await ctx_progress(ctx, 100, 100)
                return ResponseBuilder.build(
                    500,
                    f"Cmd all fail: {e}",
                    {"inventory": inventory, "group": group, "cmd": cmd},
                    str(e),
                )

        elif action == "copy_ssh_config":
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
                results, files, locations, errors = [], [], [], []

                async def copy_host(h: dict) -> dict:
                    try:
                        t = Tunnel(
                            remote_host=h["hostname"],
                            username=h["username"],
                            password=h.get("password"),
                            identity_file=h.get("key_path"),
                        )
                        t.copy_ssh_config(cfg, rmt_cfg)
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
                            "message": f"Copy fail: {e}",
                            "errors": [str(e)],
                        }
                    finally:
                        if "t" in locals():
                            t.close()

                if parallel:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max_threads
                    ) as ex:
                        futures = [
                            ex.submit(lambda h: asyncio.run(copy_host(h)), h)
                            for h in hosts
                        ]
                        for i, future in enumerate(
                            concurrent.futures.as_completed(futures), 1
                        ):
                            try:
                                r = future.result()
                                results.append(r)
                                if r["status"] == "success":
                                    files.append(cfg)
                                    locations.append(f"{rmt_cfg} on {r['hostname']}")
                                else:
                                    errors.extend(r["errors"])
                                if ctx:
                                    await ctx.report_progress(progress=i, total=total)
                            except Exception as e:
                                results.append(
                                    {
                                        "hostname": "unknown",
                                        "status": "failed",
                                        "message": f"Parallel error: {e}",
                                        "errors": [str(e)],
                                    }
                                )
                                errors.append(str(e))
                else:
                    for i, h in enumerate(hosts, 1):
                        r = await copy_host(h)
                        results.append(r)
                        if r["status"] == "success":
                            files.append(cfg)
                            locations.append(f"{rmt_cfg} on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                msg = (
                    f"Copied cfg to {group}"
                    if not errors
                    else f"Copy failed for some in {group}"
                )
                return ResponseBuilder.build(
                    200 if not errors else 500,
                    msg,
                    {
                        "inventory": inventory,
                        "group": group,
                        "cfg": cfg,
                        "rmt_cfg": rmt_cfg,
                        "host_results": results,
                    },
                    error="; ".join(errors),
                    files=files,
                    locations=locations,
                    errors=errors,
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Copy all fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Copy all fail: {e}",
                    {
                        "inventory": inventory,
                        "group": group,
                        "cfg": cfg,
                        "rmt_cfg": rmt_cfg,
                    },
                    str(e),
                )

        elif action == "rotate_key":
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
                results, files, locations, errors = [], [], [], []

                async def rotate_host(h: dict) -> dict:
                    _key = os.path.expanduser(key_pfx + h["hostname"])
                    try:
                        t = Tunnel(
                            remote_host=h["hostname"],
                            username=h["username"],
                            password=h.get("password"),
                            identity_file=h.get("key_path"),
                        )
                        t.rotate_ssh_key(_key, key_type=key_type)
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
                            "message": f"Rotate fail: {e}",
                            "errors": [str(e)],
                            "new_key_path": _key,
                        }
                    finally:
                        if "t" in locals():
                            t.close()

                if parallel:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max_threads
                    ) as ex:
                        futures = [
                            ex.submit(lambda h: asyncio.run(rotate_host(h)), h)
                            for h in hosts
                        ]
                        for i, future in enumerate(
                            concurrent.futures.as_completed(futures), 1
                        ):
                            try:
                                r = future.result()
                                results.append(r)
                                if r["status"] == "success":
                                    files.append(r["new_key_path"] + ".pub")
                                    locations.append(
                                        f"~/.ssh/authorized_keys on {r['hostname']}"
                                    )
                                else:
                                    errors.extend(r["errors"])
                                if ctx:
                                    await ctx.report_progress(progress=i, total=total)
                            except Exception as e:
                                results.append(
                                    {
                                        "hostname": "unknown",
                                        "status": "failed",
                                        "message": f"Parallel error: {e}",
                                        "errors": [str(e)],
                                        "new_key_path": None,
                                    }
                                )
                                errors.append(str(e))
                else:
                    for i, h in enumerate(hosts, 1):
                        r = await rotate_host(h)
                        results.append(r)
                        if r["status"] == "success":
                            files.append(r["new_key_path"] + ".pub")
                            locations.append(
                                f"~/.ssh/authorized_keys on {r['hostname']}"
                            )
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                msg = (
                    f"Rotated {key_type} keys for {group}"
                    if not errors
                    else f"Rotate failed for some in {group}"
                )
                return ResponseBuilder.build(
                    200 if not errors else 500,
                    msg,
                    {
                        "inventory": inventory,
                        "group": group,
                        "key_prefix": key_pfx,
                        "key_type": key_type,
                        "host_results": results,
                    },
                    error="; ".join(errors),
                    files=files,
                    locations=locations,
                    errors=errors,
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Rotate all fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Rotate all fail: {e}",
                    {
                        "inventory": inventory,
                        "group": group,
                        "key_pfx": key_pfx,
                        "key_type": key_type,
                    },
                    error=str(e),
                )

        elif action == "send_file":
            _lpath = os.path.abspath(os.path.expanduser(lpath))
            _rpath = os.path.expanduser(rpath)
            if not _lpath or not _rpath:
                return ResponseBuilder.build(
                    400,
                    "Need lpath, rpath",
                    {"action": action},
                    errors=["Need lpath, rpath"],
                )
            if not os.path.exists(_lpath) or not os.path.isfile(_lpath):
                return ResponseBuilder.build(
                    400,
                    f"Invalid file: {_lpath}",
                    {"action": action},
                    errors=[f"Invalid file: {_lpath}"],
                )
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
                            remote_host=host,
                            username=h["username"],
                            password=h.get("password"),
                            identity_file=h.get("key_path"),
                        )
                        t.connect()
                        assert t.ssh_client is not None
                        sftp = t.ssh_client.open_sftp()
                        transferred = 0

                        def progress_callback(transf, total):
                            nonlocal transferred
                            transferred = transf
                            if ctx:
                                asyncio.ensure_future(
                                    ctx.report_progress(progress=transf, total=total)
                                )

                        sftp.put(_lpath, _rpath, callback=progress_callback)
                        sftp.close()
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
                            "message": f"Upload fail: {e}",
                            "errors": [str(e)],
                        }
                    finally:
                        if "t" in locals():
                            t.close()

                results, files, locations, errors = [_lpath], [], [], []
                if parallel:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max_threads
                    ) as ex:
                        futures = [
                            ex.submit(lambda h: asyncio.run(send_host(h)), h)
                            for h in hosts
                        ]
                        for i, future in enumerate(
                            concurrent.futures.as_completed(futures), 1
                        ):
                            try:
                                r = future.result()
                                results.append(r)
                                if r["status"] == "success":
                                    locations.append(f"{_rpath} on {r['hostname']}")
                                else:
                                    errors.extend(r["errors"])
                                if ctx:
                                    await ctx.report_progress(progress=i, total=total)
                            except Exception as e:
                                results.append(
                                    {
                                        "hostname": "unknown",
                                        "status": "failed",
                                        "message": f"Parallel error: {e}",
                                        "errors": [str(e)],
                                    }
                                )
                                errors.append(str(e))
                else:
                    for i, h in enumerate(hosts, 1):
                        r = await send_host(h)
                        results.append(r)
                        if r["status"] == "success":
                            locations.append(f"{_rpath} on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                msg = (
                    f"Uploaded {_lpath} to {group}"
                    if not errors
                    else f"Upload failed for some in {group}"
                )
                return ResponseBuilder.build(
                    200 if not errors else 500,
                    msg,
                    {
                        "inventory": inventory,
                        "group": group,
                        "local_path": _lpath,
                        "remote_path": _rpath,
                        "host_results": results,
                    },
                    error="; ".join(errors),
                    files=files,
                    locations=locations,
                    errors=errors,
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Upload all fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Upload all fail: {e}",
                    {
                        "inventory": inventory,
                        "group": group,
                        "lpath": _lpath,
                        "rpath": _rpath,
                    },
                    str(e),
                )

        elif action == "receive_file":
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
                            remote_host=host,
                            username=h["username"],
                            password=h.get("password"),
                            identity_file=h.get("key_path"),
                        )
                        t.connect()
                        assert t.ssh_client is not None
                        sftp = t.ssh_client.open_sftp()
                        sftp.stat(rpath)
                        transferred = 0

                        def progress_callback(transf, total):
                            nonlocal transferred
                            transferred = transf
                            if ctx:
                                asyncio.ensure_future(
                                    ctx.report_progress(progress=transf, total=total)
                                )

                        sftp.get(rpath, _lpath, callback=progress_callback)
                        sftp.close()
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
                            "message": f"Download fail: {e}",
                            "errors": [str(e)],
                            "local_path": _lpath,
                        }
                    finally:
                        if "t" in locals():
                            t.close()

                results, files, locations, errors = [], [], [], []
                if parallel:
                    with concurrent.futures.ThreadPoolExecutor(
                        max_workers=max_threads
                    ) as ex:
                        futures = [
                            ex.submit(lambda h: asyncio.run(receive_host(h)), h)
                            for h in hosts
                        ]
                        for i, future in enumerate(
                            concurrent.futures.as_completed(futures), 1
                        ):
                            try:
                                r = future.result()
                                results.append(r)
                                if r["status"] == "success":
                                    files.append(rpath)
                                    locations.append(r["local_path"])
                                else:
                                    errors.extend(r["errors"])
                                if ctx:
                                    await ctx.report_progress(progress=i, total=total)
                            except Exception as e:
                                results.append(
                                    {
                                        "hostname": "unknown",
                                        "status": "failed",
                                        "message": f"Parallel error: {e}",
                                        "errors": [str(e)],
                                        "local_path": None,
                                    }
                                )
                                errors.append(str(e))
                else:
                    for i, h in enumerate(hosts, 1):
                        r = await receive_host(h)
                        results.append(r)
                        if r["status"] == "success":
                            files.append(rpath)
                            locations.append(r["local_path"])
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                msg = (
                    f"Downloaded {rpath} from {group}"
                    if not errors
                    else f"Download failed for some in {group}"
                )
                return ResponseBuilder.build(
                    200 if not errors else 500,
                    msg,
                    {
                        "inventory": inventory,
                        "group": group,
                        "rpath": rpath,
                        "lpath_prefix": lpath_prefix,
                        "host_results": results,
                    },
                    error="; ".join(errors),
                    files=files,
                    locations=locations,
                    errors=errors,
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Download all fail: {e}")
                return ResponseBuilder.build(
                    500,
                    f"Download all fail: {e}",
                    {
                        "inventory": inventory,
                        "group": group,
                        "rpath": rpath,
                        "lpath_prefix": lpath_prefix,
                    },
                    str(e),
                )
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: configure_key_auth, run_command, copy_ssh_config, rotate_key, send_file, receive_file"
                ],
            )


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
        if action == "start":
            if not operation_type:
                return ResponseBuilder.build(
                    400,
                    "Need operation_type",
                    {"action": action},
                    errors=["Need operation_type"],
                )
            try:
                op_id = operation_manager.create_operation(
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
                ctx_log(ctx, logger, "error", f"Failed to start operation: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to start operation",
                    {"operation_type": operation_type},
                    str(e),
                )

        elif action == "get_progress":
            if not operation_id:
                return ResponseBuilder.build(
                    400,
                    "Need operation_id",
                    {"action": action},
                    errors=["Need operation_id"],
                )
            try:
                status = operation_manager.get_operation_status(operation_id)
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
                ctx_log(ctx, logger, "error", f"Failed to get operation progress: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to get operation progress",
                    {"operation_id": operation_id},
                    str(e),
                )

        elif action == "cancel":
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
                success = operation_manager.request_cancellation(operation_id)
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
                ctx_log(ctx, logger, "error", f"Failed to cancel operation: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to cancel operation",
                    {"operation_id": operation_id},
                    str(e),
                )

        elif action == "get_metrics":
            if not operation_id:
                return ResponseBuilder.build(
                    400,
                    "Need operation_id",
                    {"action": action},
                    errors=["Need operation_id"],
                )
            try:
                metrics = operation_manager.get_resource_metrics(operation_id)
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
                ctx_log(ctx, logger, "error", f"Failed to get resource metrics: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to get resource metrics",
                    {"operation_id": operation_id},
                    str(e),
                )

        elif action == "list_sessions":
            try:
                sessions = operation_manager.list_active_sessions()
                return ResponseBuilder.build(
                    200,
                    "Active sessions listed",
                    {
                        "sessions": sessions["sessions"],
                        "total_sessions": sessions["total_sessions"],
                    },
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Failed to list active sessions: {e}")
                return ResponseBuilder.build(
                    500, "Failed to list active sessions", {}, str(e)
                )
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: start, get_progress, cancel, get_metrics, list_sessions"
                ],
            )


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
        password: str = Field(default="", description="SSH password."),
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
        if action == "recursive_ops":
            if not remote_host or not operation or not source:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, operation, source",
                    {"action": action},
                    errors=["Need remote_host, operation, source"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                options = {}
                if operation == "chmod":
                    options["mode"] = mode
                elif operation == "chown":
                    options["owner"] = owner
                    options["group"] = group
                result = fm.recursive_file_operations(
                    operation, source, destination, options
                )
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Recursive {operation} completed",
                    {"host": remote_host, "operation": operation, "result": result},
                    error=result.get("error", ""),
                    errors=result.get("errors", []),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Recursive file ops fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "Recursive file ops fail",
                    {"host": remote_host, "operation": operation},
                    str(e),
                )

        elif action == "content_search":
            if not remote_host or not search_paths or not pattern:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, search_paths, pattern",
                    {"action": action},
                    errors=["Need remote_host, search_paths, pattern"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                options = {
                    "case_sensitive": case_sensitive,
                    "recursive": recursive,
                    "max_results": max_results,
                }
                result = fm.file_content_search(search_paths, pattern, options)
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    "File content search completed",
                    {"host": remote_host, "pattern": pattern, "result": result},
                    error=result.get("error", ""),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"File content search fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "File content search fail",
                    {"host": remote_host, "pattern": pattern},
                    str(e),
                )

        elif action == "watch":
            if not remote_host or not watch_paths:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, watch_paths",
                    {"action": action},
                    errors=["Need remote_host, watch_paths"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                result = fm.file_watch_monitor(watch_paths, duration)
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    "File monitoring completed",
                    {"host": remote_host, "watch_paths": watch_paths, "result": result},
                    error=result.get("error", ""),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"File watch fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "File watch fail",
                    {"host": remote_host, "watch_paths": watch_paths},
                    str(e),
                )

        elif action == "diff_compare":
            if not file_path or not host1 or not host2:
                return ResponseBuilder.build(
                    400,
                    "Need file_path, host1, host2",
                    {"action": action},
                    errors=["Need file_path, host1, host2"],
                )
            try:
                tunnel1 = Tunnel(
                    remote_host=host1,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel1)
                result = fm.file_diff_compare(host1, host2, file_path)
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
                ctx_log(ctx, logger, "error", f"File diff fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "File diff fail",
                    {"file": file_path, "host1": host1, "host2": host2},
                    str(e),
                )

        elif action == "backup":
            if not remote_host or not backup_paths or not backup_dest:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, backup_paths, backup_dest",
                    {"action": action},
                    errors=["Need remote_host, backup_paths, backup_dest"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                options = {"compression": compression, "incremental": incremental}
                result = fm.smart_backup(backup_paths, backup_dest, options)
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
                ctx_log(ctx, logger, "error", f"Backup fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "Backup fail",
                    {"host": remote_host, "backup_paths": backup_paths},
                    str(e),
                )
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: recursive_ops, content_search, watch, diff_compare, backup"
                ],
            )


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
        password: str = Field(default="", description="SSH password."),
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
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

            if action == "security_audit":
                result = auditor.security_audit(scope if scope else None)
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Security audit completed with score: {result['score']}/100",
                    {"host": remote_host, "audit_result": result},
                    error=result.get("error", ""),
                    errors=result.get("audit_errors", []),
                )

            elif action == "compliance_check":
                result = auditor.compliance_check(standard)
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

            elif action == "vulnerability_scan":
                result = auditor.vulnerability_scan(scan_type)
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

            elif action == "access_control_audit":
                result = auditor.access_control_audit()
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Access control audit completed: {result['users_audited']} users audited",
                    {"host": remote_host, "audit_result": result},
                    error=result.get("error", ""),
                    errors=result.get("audit_errors", []),
                )
            else:
                return ResponseBuilder.build(
                    400,
                    f"Unknown action: {action}",
                    {"action": action},
                    errors=[
                        "Valid: security_audit, compliance_check, vulnerability_scan, access_control_audit"
                    ],
                )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Security audit fail ({action}): {e}")
            return ResponseBuilder.build(
                500, f"Security audit fail ({action})", {"host": remote_host}, str(e)
            )


def get_mcp_instance() -> tuple[Any, Any, Any, Any]:
    """Initialize and return the MCP instance, args, and middlewares."""
    load_dotenv(find_dotenv())

    args, mcp, middlewares = create_mcp_server(
        name="TunnelManagerMCP",
        version=__version__,
        instructions="Tunnel Manager MCP Utility — Manage SSH tunnels, managed hosts, and remote execution.",
    )

    if to_boolean(os.getenv("TM_HOSTS_TOOL", "True")):
        register_host_tools(mcp)
    if to_boolean(os.getenv("TM_REMOTE_TOOL", "True")):
        register_remote_tools(mcp)
    if to_boolean(os.getenv("TM_INVENTORY_TOOL", "True")):
        register_inventory_tools(mcp)
    if to_boolean(os.getenv("TM_OPERATIONS_TOOL", "True")):
        register_operations_tools(mcp)
    if to_boolean(os.getenv("TM_SYSTEM_TOOL", "True")):
        register_system_tools(mcp)
    if to_boolean(os.getenv("TM_FILES_TOOL", "True")):
        register_file_tools(mcp)
    if to_boolean(os.getenv("TM_SECURITY_TOOL", "True")):
        register_security_tools(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)
    registered_tags: list[str] = []
    return mcp, args, middlewares, registered_tags


def mcp_server() -> None:
    mcp, args, middlewares, registered_tags = get_mcp_instance()
    print(f"{'tunnel-manager'} MCP v{__version__}", file=sys.stderr)
    print("\nStarting MCP Server", file=sys.stderr)
    print(f"  Transport: {args.transport.upper()}", file=sys.stderr)
    print(f"  Auth: {args.auth_type}", file=sys.stderr)
    print(f"  Dynamic Tags Loaded: {len(set(registered_tags))}", file=sys.stderr)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        logger.error("Invalid transport", extra={"transport": args.transport})
        sys.exit(1)


if __name__ == "__main__":
    mcp_server()
