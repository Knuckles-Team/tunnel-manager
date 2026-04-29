#!/usr/bin/env python
import warnings

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
<<<<<<< HEAD
=======
import subprocess
>>>>>>> d85c5b4 (chore: manual fixes)
import sys
from typing import Any

import yaml
from agent_utilities.base_utilities import to_boolean, to_integer
from agent_utilities.mcp_utilities import (
    create_mcp_server,
    ctx_confirm_destructive,
    ctx_progress,
    ctx_log,
)
from dotenv import find_dotenv, load_dotenv
from fastmcp import Context, FastMCP
from fastmcp.utilities.logging import get_logger
from pydantic import Field
<<<<<<< HEAD
=======

from tunnel_manager.advanced_file_manager import AdvancedFileManager
from tunnel_manager.operation_manager import operation_manager
from tunnel_manager.security_auditor import SecurityAuditor
from tunnel_manager.system_intelligence import SystemIntelligence
from tunnel_manager.tunnel_manager import HostManager, Tunnel
>>>>>>> d85c5b4 (chore: manual fixes)

from tunnel_manager.tunnel_manager import HostManager, Tunnel

__version__ = "1.1.54"

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
            inv = yaml.safe_load(f)
        hosts = []
        if group in inv and isinstance(inv[group], dict) and "hosts" in inv[group]:
            for host, vars in inv[group]["hosts"].items():
                entry = {
                    "hostname": vars.get("ansible_host", host),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file"),
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

        final_config = host_config.copy()
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


def register_misc_tools(mcp: FastMCP):
    pass
    pass


def register_host_management_tools(mcp: FastMCP):
    @mcp.tool(
        annotations={
            "title": "List Managed Hosts",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"host_management"},
    )
<<<<<<< HEAD
    async def list_hosts() -> dict:
=======
    async def list_hosts(
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
>>>>>>> d85c5b4 (chore: manual fixes)
        """List all managed hosts in the inventory."""
        return {"hosts": host_manager.list_hosts()}

    @mcp.tool(
        annotations={
            "title": "Add Managed Host",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
        tags={"host_management"},
    )
    async def add_host(
        alias: str = Field(description="Alias for the host."),
        hostname: str = Field(description="Real hostname or IP."),
        user: str = Field(description="Username."),
        port: int = Field(description="SSH Port.", default=22),
        identity_file: str | None = Field(
            description="Path to private key.", default=""
        ),
        password: str | None = Field(description="Password (if no key).", default=""),
        proxy_command: str | None = Field(description="Proxy command.", default=""),
<<<<<<< HEAD
=======
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
>>>>>>> d85c5b4 (chore: manual fixes)
    ) -> dict:
        """Add a new host to the managed inventory."""
        host_manager.add_host(
            alias=alias,
            hostname=hostname,
            user=user,
            port=port,
            identity_file=identity_file,
            password=password,
            proxy_command=proxy_command,
        )
        return {"status": "success", "message": f"Host '{alias}' added."}

    @mcp.tool(
        annotations={
            "title": "Remove Managed Host",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"host_management"},
    )
    async def remove_host(
        alias: str = Field(description="Alias of the host to remove."),
<<<<<<< HEAD
=======
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
>>>>>>> d85c5b4 (chore: manual fixes)
    ) -> dict:
        """Remove a host from the managed inventory."""
        if not await ctx_confirm_destructive(ctx, "remove host"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        await ctx_progress(ctx, 0, 100)
        host_manager.remove_host(alias)
        return {"status": "success", "message": f"Host '{alias}' removed."}


def register_remote_access_tools(mcp: FastMCP):
    @mcp.tool(
        annotations={
            "title": "Run Command on Remote Host",
            "readOnlyHint": True,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def run_command_on_remote_host(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        cmd: str = Field(description="Shell command.", default=""),
        id_file: str | None = Field(
            description="Private key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        certificate: str | None = Field(
            description="Teleport certificate.",
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
        ),
        proxy: str | None = Field(
            description="Teleport proxy.",
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Run shell command on remote host. Expected return object type: dict"""
        ctx_log(ctx, logger, "debug", f"Run cmd: host={host}, cmd={cmd}")
        if not host or not cmd:
            ctx_log(ctx, logger, "error", "Need host, cmd")
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
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            t.connect()
            out, error = t.run_command(cmd)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(ctx, logger, "debug", f"Cmd out: {out}, error: {error}")
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

    @mcp.tool(
        annotations={
            "title": "Send File from Remote Host",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def send_file_to_remote_host(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        lpath: str = Field(description="Local file path.", default=""),
        rpath: str = Field(description="Remote path.", default=""),
        id_file: str | None = Field(
            description="Private key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        certificate: str | None = Field(
            description="Teleport certificate.",
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
        ),
        proxy: str | None = Field(
            description="Teleport proxy.",
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Upload file to remote host. Expected return object type: dict"""
        logger = logging.getLogger("TunnelServer")
        ctx_log(
            ctx, logger, "debug", f"Upload: host={host}, local={lpath}, remote={rpath}"
        )
        lpath = os.path.abspath(os.path.expanduser(lpath))
        rpath = os.path.expanduser(rpath)
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Normalized: lpath={lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)}), rpath={rpath}, CWD={os.getcwd()}",
        )
        ctx_log(
            ctx, logger, "debug", f"Upload: host={host}, local={lpath}, remote={rpath}"
        )
        if not host or not lpath or not rpath:
            ctx_log(ctx, logger, "error", "Need host, lpath, rpath")
            return ResponseBuilder.build(
                400,
                "Need host, lpath, rpath",
                {"host": host, "lpath": lpath, "rpath": rpath},
                errors=["Need host, lpath, rpath"],
            )
        if not os.path.exists(lpath) or not os.path.isfile(lpath):
            ctx_log(
                ctx,
                logger,
                "error",
                f"Invalid file: {lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)})",
            )
            return ResponseBuilder.build(
                400,
                f"Invalid file: {lpath}",
                {"host": host, "lpath": lpath, "rpath": rpath},
                errors=[f"Invalid file: {lpath}"],
            )
        lpath = os.path.abspath(os.path.expanduser(lpath))
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
<<<<<<< HEAD
                logger.debug("Progress: 0/100")
=======
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
>>>>>>> d85c5b4 (chore: manual fixes)
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

            sftp.put(lpath, rpath, callback=progress_callback)
            sftp.close()
            ctx_log(ctx, logger, "debug", f"Uploaded: {lpath} -> {rpath}")
            return ResponseBuilder.build(
                200,
                f"Uploaded to {rpath}",
                {"host": host, "lpath": lpath, "rpath": rpath},
                files=[lpath],
                locations=[rpath],
                errors=[],
            )
        except Exception as e:
            ctx_log(
                ctx, logger, "error", f"Unexpected error during file transfer: {str(e)}"
            )
            return ResponseBuilder.build(
                500,
                f"Upload fail: {str(e)}",
                {"host": host, "lpath": lpath, "rpath": rpath},
                str(e),
                errors=[f"Unexpected error: {str(e)}"],
            )
        finally:
            if "t" in locals():
                t.close()

    @mcp.tool(
        annotations={
            "title": "Receive File from Remote Host",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"remote_access"},
    )
    async def receive_file_from_remote_host(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        rpath: str = Field(description="Remote file path.", default=""),
        lpath: str = Field(description="Local file path.", default=""),
        id_file: str | None = Field(
            description="Private key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        certificate: str | None = Field(
            description="Teleport certificate.",
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
        ),
        proxy: str | None = Field(
            description="Teleport proxy.",
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Download file from remote host. Expected return object type: dict"""
        lpath = os.path.abspath(os.path.expanduser(lpath))
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Download: host={host}, remote={rpath}, local={lpath}",
        )
        if not host or not rpath or not lpath:
            ctx_log(ctx, logger, "error", "Need host, rpath, lpath")
            return ResponseBuilder.build(
                400,
                "Need host, rpath, lpath",
                {"host": host, "rpath": rpath, "lpath": lpath},
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
<<<<<<< HEAD
                logger.debug("Progress: 0/100")
=======
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
>>>>>>> d85c5b4 (chore: manual fixes)
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

            sftp.get(rpath, lpath, callback=progress_callback)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            sftp.close()
            ctx_log(ctx, logger, "debug", f"Downloaded: {rpath} -> {lpath}")
            return ResponseBuilder.build(
                200,
                f"Downloaded to {lpath}",
                {"host": host, "rpath": rpath, "lpath": lpath},
                files=[rpath],
                locations=[lpath],
                errors=[],
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Download fail: {e}")
            return ResponseBuilder.build(
                500,
                f"Download fail: {e}",
                {"host": host, "rpath": rpath, "lpath": lpath},
                str(e),
            )
        finally:
            if "t" in locals():
                t.close()

    @mcp.tool(
        annotations={
            "title": "Check SSH Server",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"remote_access"},
    )
    async def check_ssh_server(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        id_file: str | None = Field(
            description="Private key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        certificate: str | None = Field(
            description="Teleport certificate.",
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
        ),
        proxy: str | None = Field(
            description="Teleport proxy.",
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Check SSH server status. Expected return object type: dict"""
        ctx_log(ctx, logger, "debug", f"Check SSH: host={host}")
        if not host:
            ctx_log(ctx, logger, "error", "Need host")
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
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            success, msg = t.check_ssh_server()
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(ctx, logger, "debug", f"SSH check: {msg}")
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

    @mcp.tool(
        annotations={
            "title": "Test Key Authentication",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"remote_access"},
    )
    async def test_key_auth(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        key: str = Field(
            description="Private key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Test key-based auth. Expected return object type: dict"""
        ctx_log(ctx, logger, "debug", f"Test key: host={host}, key={key}")
        if not host or not key:
            ctx_log(ctx, logger, "error", "Need host, key")
            return ResponseBuilder.build(
                400,
                "Need host, key",
                {"host": host, "key": key},
                errors=["Need host, key"],
            )
        try:
            conf, final_cfg = _resolve_host(
                host_alias=host,
                user=user,
                port=port,
                ssh_config_file=cfg,
            )
            t = Tunnel(
                remote_host=conf["hostname"],
                username=conf["user"],
                port=conf["port"],
                ssh_config_file=final_cfg,
            )
            if ctx:
                await ctx.report_progress(progress=0, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            success, msg = t.test_key_auth(key)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(ctx, logger, "debug", f"Key test: {msg}")
            return ResponseBuilder.build(
                200 if success else 400,
                f"Key test: {msg}",
                {"host": host, "key": key, "success": success},
                files=[],
                locations=[],
                errors=[] if success else [msg],
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Key test fail: {e}")
            return ResponseBuilder.build(
                500, f"Key test fail: {e}", {"host": host, "key": key}, str(e)
            )

    @mcp.tool(
        annotations={
            "title": "Setup Passwordless SSH",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def setup_passwordless_ssh(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        key: str = Field(
            description="Private key path.", default=os.path.expanduser("~/.ssh/id_rsa")
        ),
        key_type: str = Field(
            description="Key type to generate (rsa or ed25519).", default="ed25519"
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Setup passwordless SSH. Expected return object type: dict"""
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Setup SSH: host={host}, key={key}, key_type={key_type}",
        )
        if not host or not password:
            ctx_log(ctx, logger, "error", "Need host, password")
            return ResponseBuilder.build(
                400,
                "Need host, password",
                {"host": host, "key": key, "key_type": key_type},
                errors=["Need host, password"],
            )
        if key_type not in ["rsa", "ed25519"]:
            ctx_log(ctx, logger, "error", f"Invalid key_type: {key_type}")
            return ResponseBuilder.build(
                400,
                f"Invalid key_type: {key_type}",
                {"host": host, "key": key, "key_type": key_type},
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
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            key = os.path.expanduser(key)
            pub_key = key + ".pub"
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
                            key,
                            "-N",
                            "",
                        ],
                        check=True,
                    )
                else:
                    subprocess.run(
                        ["/usr/bin/ssh-keygen", "-t", "ed25519", "-f", key, "-N", ""],
                        check=True,
                    )
                ctx_log(
                    ctx, logger, "info", f"Generated {key_type} key: {key}, {pub_key}"
                )
            t.setup_passwordless_ssh(local_key_path=key, key_type=key_type)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(ctx, logger, "debug", f"SSH setup for {user}@{host}")
            return ResponseBuilder.build(
                200,
                f"SSH setup for {user}@{host}",
                {"host": host, "key": key, "user": user, "key_type": key_type},
                files=[pub_key],
                locations=[f"~/.ssh/authorized_keys on {host}"],
                errors=[],
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"SSH setup fail: {e}")
            return ResponseBuilder.build(
                500,
                f"SSH setup fail: {e}",
                {"host": host, "key": key, "key_type": key_type},
                str(e),
            )
        finally:
            if "t" in locals():
                t.close()

    @mcp.tool(
        annotations={
            "title": "Copy SSH Config",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def copy_ssh_config(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        lcfg: str = Field(description="Local SSH config.", default=""),
        rcfg: str = Field(
            description="Remote SSH config.",
            default=os.path.expanduser("~/.ssh/config"),
        ),
        id_file: str | None = Field(
            description="Private key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        certificate: str | None = Field(
            description="Teleport certificate.",
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
        ),
        proxy: str | None = Field(
            description="Teleport proxy.",
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Copy SSH config to remote host. Expected return object type: dict"""
        ctx_log(
            ctx, logger, "debug", f"Copy cfg: host={host}, local={lcfg}, remote={rcfg}"
        )
        if not host or not lcfg:
            ctx_log(ctx, logger, "error", "Need host, lcfg")
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
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            t.copy_ssh_config(lcfg, rcfg)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(ctx, logger, "debug", f"Copied cfg to {rcfg} on {host}")
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

    @mcp.tool(
        annotations={
            "title": "Rotate SSH Key",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def rotate_ssh_key(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        user: str | None = Field(
            description="Username.", default=os.environ.get("TUNNEL_USERNAME", "")
        ),
        password: str | None = Field(
            description="Password.", default=os.environ.get("TUNNEL_PASSWORD", "")
        ),
        port: int = Field(
            description="Port.",
            default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
        ),
        new_key: str = Field(description="New private key path.", default=""),
        key_type: str = Field(
            description="Key type to generate (rsa or ed25519).", default="ed25519"
        ),
        id_file: str | None = Field(
            description="Current key path.",
            default=os.environ.get("TUNNEL_IDENTITY_FILE", ""),
        ),
        certificate: str | None = Field(
            description="Teleport certificate.",
            default=os.environ.get("TUNNEL_CERTIFICATE", ""),
        ),
        proxy: str | None = Field(
            description="Teleport proxy.",
            default=os.environ.get("TUNNEL_PROXY_COMMAND", ""),
        ),
        cfg: str = Field(
            description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Rotate SSH key on remote host. Expected return object type: dict"""
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Rotate key: host={host}, new_key={new_key}, key_type={key_type}",
        )
        if not host or not new_key:
            ctx_log(ctx, logger, "error", "Need host, new_key")
            return ResponseBuilder.build(
                400,
                "Need host, new_key",
                {"host": host, "new_key": new_key, "key_type": key_type},
                errors=["Need host, new_key"],
            )
        if key_type not in ["rsa", "ed25519"]:
            ctx_log(ctx, logger, "error", f"Invalid key_type: {key_type}")
            return ResponseBuilder.build(
                400,
                f"Invalid key_type: {key_type}",
                {"host": host, "new_key": new_key, "key_type": key_type},
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
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            new_key = os.path.expanduser(new_key)
            new_public_key = new_key + ".pub"
            if not os.path.exists(new_key):
                if key_type == "rsa":
                    subprocess.run(
                        [
                            "/usr/bin/ssh-keygen",
                            "-t",
                            "rsa",
                            "-b",
                            "4096",
                            "-f",
                            new_key,
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
                            new_key,
                            "-N",
                            "",
                        ],
                        check=True,
                    )
                ctx_log(ctx, logger, "info", f"Generated {key_type} key: {new_key}")
            t.rotate_ssh_key(new_key, key_type=key_type)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(
                ctx, logger, "debug", f"Rotated {key_type} key to {new_key} on {host}"
            )
            return ResponseBuilder.build(
                200,
                f"Rotated {key_type} key to {new_key} on {host}",
                {
                    "host": host,
                    "new_key": new_key,
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

    @mcp.tool(
        annotations={
            "title": "Remove Host Key",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
        },
        tags={"remote_access"},
    )
    async def remove_host_key(
        host: str = Field(
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", ""),
        ),
        known_hosts: str = Field(
            description="Known hosts path.",
            default=os.path.expanduser("~/.ssh/known_hosts"),
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Remove host key from known_hosts. Expected return object type: dict"""
        if not await ctx_confirm_destructive(ctx, "remove host key"):
            return {"status": "cancelled", "message": "Operation cancelled by user"}
        ctx_log(
            ctx, logger, "debug", f"Remove key: host={host}, known_hosts={known_hosts}"
        )
        if not host:
            ctx_log(ctx, logger, "error", "Need host")
            return ResponseBuilder.build(
                400,
                "Need host",
                {"host": host, "known_hosts": known_hosts},
                errors=["Need host"],
            )
        try:
            conf, _ = _resolve_host(host_alias=host)
            t = Tunnel(remote_host=conf["hostname"])
            if ctx:
                await ctx.report_progress(progress=0, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 0/100")
            known_hosts = os.path.expanduser(known_hosts)
            msg = t.remove_host_key(known_hosts_path=known_hosts)
            if ctx:
                await ctx.report_progress(progress=100, total=100)
                ctx_log(ctx, logger, "debug", "Progress: 100/100")
            ctx_log(ctx, logger, "debug", f"Remove result: {msg}")
            return ResponseBuilder.build(
                200 if "Removed" in msg else 400,
                msg,
                {"host": host, "known_hosts": known_hosts},
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

    @mcp.tool(
        annotations={
            "title": "Setup Passwordless SSH for All",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def configure_key_auth_on_inventory(
        inventory: str = Field(
            description="YAML inventory path.",
            default=os.environ.get("TUNNEL_INVENTORY", ""),
        ),
        key: str = Field(
            description="Shared key path.",
            default=os.environ.get(
                "TUNNEL_IDENTITY_FILE", os.path.expanduser("~/.ssh/id_shared")
            ),
        ),
        key_type: str = Field(
            description="Key type to generate (rsa or ed25519).", default="ed25519"
        ),
        group: str = Field(
            description="Target group.",
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
        ),
        parallel: bool = Field(
            description="Run parallel.",
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
        ),
        max_threads: int = Field(
            description="Max threads.",
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "6")),
        ),
        _log_path: str | None = Field(description="Log file.", default=""),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Setup passwordless SSH for all hosts in group. Expected return object type: dict"""
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Setup SSH all: inv={inventory}, group={group}, key_type={key_type}",
        )
        if not inventory:
            ctx_log(ctx, logger, "error", "Need inventory")
            return ResponseBuilder.build(
                400,
                "Need inventory",
                {"inventory": inventory, "group": group, "key_type": key_type},
                errors=["Need inventory"],
            )
        if key_type not in ["rsa", "ed25519"]:
            ctx_log(ctx, logger, "error", f"Invalid key_type: {key_type}")
            return ResponseBuilder.build(
                400,
                f"Invalid key_type: {key_type}",
                {"inventory": inventory, "group": group, "key_type": key_type},
                errors=["key_type must be 'rsa' or 'ed25519'"],
            )
        try:
            key = os.path.expanduser(key)
            pub_key = key + ".pub"
            if not os.path.exists(key):
                if key_type == "rsa":
                    subprocess.run(
                        [
                            "/usr/bin/ssh-keygen",
                            "-t",
                            "rsa",
                            "-b",
                            "4096",
                            "-f",
                            key,
                            "-N",
                            "",
                        ],
                        check=True,
                    )
                else:
<<<<<<< HEAD
                    os.system(f"ssh-keygen -t ed25519 -f {key} -N ''")
                logger.info(f"Generated {key_type} key: {key}, {pub_key}")
=======
                    subprocess.run(
                        ["/usr/bin/ssh-keygen", "-t", "ed25519", "-f", key, "-N", ""],
                        check=True,
                    )
                ctx_log(
                    ctx, logger, "info", f"Generated {key_type} key: {key}, {pub_key}"
                )
>>>>>>> d85c5b4 (chore: manual fixes)
            with open(pub_key) as f:
                pub = f.read().strip()
            hosts, error = load_inventory(inventory, group, logger)
            if error:
                return error
            total = len(hosts)
            if ctx:
                await ctx.report_progress(progress=0, total=total)
                ctx_log(ctx, logger, "debug", f"Progress: 0/{total}")

            async def setup_host(h: dict, ctx: Context) -> dict:
                host, user, password = h["hostname"], h["username"], h["password"]
                kpath = h.get("key_path", key)
                ctx_log(ctx, logger, "info", f"Setup {user}@{host}")
                try:
                    t = Tunnel(remote_host=host, username=user, password=password)
                    t.remove_host_key()
                    t.setup_passwordless_ssh(local_key_path=kpath, key_type=key_type)
                    t.connect()
                    t.run_command(f"echo '{pub}' >> ~/.ssh/authorized_keys")
                    t.run_command("chmod 600 ~/.ssh/authorized_keys")
                    ctx_log(
                        ctx, logger, "info", f"Added {key_type} key to {user}@{host}"
                    )
                    res, msg = t.test_key_auth(kpath)
                    return {
                        "hostname": host,
                        "status": "success",
                        "message": f"SSH setup for {user}@{host} with {key_type} key",
                        "errors": [] if res else [msg],
                    }
                except Exception as e:
                    ctx_log(ctx, logger, "error", f"Setup fail {user}@{host}: {e}")
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
                                ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
                        except Exception as e:
                            ctx_log(ctx, logger, "error", f"Parallel error: {e}")
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
                        locations.append(f"~/.ssh/authorized_keys on {r['hostname']}")
                    else:
                        errors.extend(r["errors"])
                    if ctx:
                        await ctx.report_progress(progress=i, total=total)
                        ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
            ctx_log(ctx, logger, "debug", f"Done SSH setup for {group}")
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

    @mcp.tool(
        annotations={
            "title": "Run Command on All Hosts",
            "readOnlyHint": True,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def run_command_on_inventory(
        inventory: str = Field(
            description="YAML inventory path.",
            default=os.environ.get("TUNNEL_INVENTORY", ""),
        ),
        cmd: str = Field(description="Shell command.", default=""),
        group: str = Field(
            description="Target group.",
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
        ),
        parallel: bool = Field(
            description="Run parallel.",
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
        ),
        max_threads: int = Field(
            description="Max threads.",
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "6")),
        ),
        _log_path: str | None = Field(description="Log file.", default=""),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Run command on all hosts in group. Expected return object type: dict"""
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Run cmd all: inv={inventory}, group={group}, cmd={cmd}",
        )
        if not inventory or not cmd:
            ctx_log(ctx, logger, "error", "Need inventory, cmd")
            return ResponseBuilder.build(
                400,
                "Need inventory, cmd",
                {"inventory": inventory, "group": group, "cmd": cmd},
                errors=["Need inventory, cmd"],
            )
        try:
            hosts, error = load_inventory(inventory, group, logger)
            if error:
                return error
            total = len(hosts)
            if ctx:
                await ctx.report_progress(progress=0, total=total)
                ctx_log(ctx, logger, "debug", f"Progress: 0/{total}")

            async def run_host(h: dict, ctx: Context) -> dict:
<<<<<<< HEAD
=======
                await ctx_progress(ctx, 0, 100)
>>>>>>> d85c5b4 (chore: manual fixes)
                host = h["hostname"]
                try:
                    t = Tunnel(
                        remote_host=host,
                        username=h["username"],
                        password=h.get("password"),
                        identity_file=h.get("key_path"),
                    )
                    out, error = t.run_command(cmd)
                    ctx_log(
                        ctx, logger, "info", f"Host {host}: Out: {out}, Err: {error}"
                    )
                    return {
                        "hostname": host,
                        "status": "success",
                        "message": f"Cmd '{cmd}' done on {host}",
                        "stdout": out,
                        "stderr": error,
                        "errors": [],
                    }
                except Exception as e:
                    ctx_log(ctx, logger, "error", f"Cmd fail {host}: {e}")
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
                                ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
                        except Exception as e:
                            ctx_log(ctx, logger, "error", f"Parallel error: {e}")
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
                        ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
            ctx_log(ctx, logger, "debug", f"Done cmd for {group}")
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

    @mcp.tool(
        annotations={
            "title": "Copy SSH Config to All",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def copy_ssh_config_on_inventory(
        inventory: str = Field(
            description="YAML inventory path.",
            default=os.environ.get("TUNNEL_INVENTORY", ""),
        ),
        cfg: str = Field(description="Local SSH config path.", default=""),
        rmt_cfg: str = Field(
            description="Remote path.", default=os.path.expanduser("~/.ssh/config")
        ),
        group: str = Field(
            description="Target group.",
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
        ),
        parallel: bool = Field(
            description="Run parallel.",
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
        ),
        max_threads: int = Field(
            description="Max threads.",
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "6")),
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Copy SSH config to all hosts in YAML group. Expected return object type: dict"""
        ctx_log(
            ctx, logger, "debug", f"Copy SSH config: inv={inventory}, group={group}"
        )

        if not inventory or not cfg:
            ctx_log(ctx, logger, "error", "Need inventory, cfg")
            return ResponseBuilder.build(
                400,
                "Need inventory, cfg",
                {
                    "inventory": inventory,
                    "group": group,
                    "cfg": cfg,
                    "rmt_cfg": rmt_cfg,
                },
                errors=["Need inventory, cfg"],
            )

        if not os.path.exists(cfg):
            ctx_log(ctx, logger, "error", f"No cfg file: {cfg}")
            return ResponseBuilder.build(
                400,
                f"No cfg file: {cfg}",
                {
                    "inventory": inventory,
                    "group": group,
                    "cfg": cfg,
                    "rmt_cfg": rmt_cfg,
                },
                errors=[f"No cfg file: {cfg}"],
            )

        try:
            hosts, error = load_inventory(inventory, group, logger)
            if error:
                return error

            total = len(hosts)
            if ctx:
                await ctx.report_progress(progress=0, total=total)
                ctx_log(ctx, logger, "debug", f"Progress: 0/{total}")

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
                    ctx_log(
                        ctx,
                        logger,
                        "info",
                        f"Copied cfg to {rmt_cfg} on {h['hostname']}",
                    )
                    return {
                        "hostname": h["hostname"],
                        "status": "success",
                        "message": f"Copied cfg to {rmt_cfg}",
                        "errors": [],
                    }
                except Exception as e:
                    ctx_log(ctx, logger, "error", f"Copy fail {h['hostname']}: {e}")
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
                        ex.submit(lambda h: asyncio.run(copy_host(h)), h) for h in hosts
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
                                ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
                        except Exception as e:
                            ctx_log(ctx, logger, "error", f"Parallel error: {e}")
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
                        ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")

            ctx_log(ctx, logger, "debug", f"Done SSH config copy for {group}")
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

    @mcp.tool(
        annotations={
            "title": "Rotate SSH Keys for All",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def rotate_ssh_key_on_inventory(
        inventory: str = Field(
            description="YAML inventory path.",
            default=os.environ.get("TUNNEL_INVENTORY", ""),
        ),
        key_pfx: str = Field(
            description="Prefix for new keys.", default=os.path.expanduser("~/.ssh/id_")
        ),
        key_type: str = Field(
            description="Key type to generate (rsa or ed25519).", default="ed25519"
        ),
        group: str = Field(
            description="Target group.",
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
        ),
        parallel: bool = Field(
            description="Run parallel.",
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
        ),
        max_threads: int = Field(
            description="Max threads.",
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "6")),
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Rotate SSH keys for all hosts in YAML group. Expected return object type: dict"""
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Rotate SSH keys: inv={inventory}, group={group}, key_type={key_type}",
        )

        if not inventory:
            ctx_log(ctx, logger, "error", "Need inventory")
            return ResponseBuilder.build(
                400,
                "Need inventory",
                {
                    "inventory": inventory,
                    "group": group,
                    "key_pfx": key_pfx,
                    "key_type": key_type,
                },
                errors=["Need inventory"],
            )
        if key_type not in ["rsa", "ed25519"]:
            ctx_log(ctx, logger, "error", f"Invalid key_type: {key_type}")
            return ResponseBuilder.build(
                400,
                f"Invalid key_type: {key_type}",
                {
                    "inventory": inventory,
                    "group": group,
                    "key_pfx": key_pfx,
                    "key_type": key_type,
                },
                errors=["key_type must be 'rsa' or 'ed25519'"],
            )

        try:
            hosts, error = load_inventory(inventory, group, logger)
            if error:
                return error

            total = len(hosts)
            if ctx:
                await ctx.report_progress(progress=0, total=total)
                ctx_log(ctx, logger, "debug", f"Progress: 0/{total}")

            results, files, locations, errors = [], [], [], []

            async def rotate_host(h: dict) -> dict:
                key = os.path.expanduser(key_pfx + h["hostname"])
                try:
                    t = Tunnel(
                        remote_host=h["hostname"],
                        username=h["username"],
                        password=h.get("password"),
                        identity_file=h.get("key_path"),
                    )
                    t.rotate_ssh_key(key, key_type=key_type)
                    ctx_log(
                        ctx,
                        logger,
                        "info",
                        f"Rotated {key_type} key for {h['hostname']}: {key}",
                    )
                    return {
                        "hostname": h["hostname"],
                        "status": "success",
                        "message": f"Rotated {key_type} key to {key}",
                        "errors": [],
                        "new_key_path": key,
                    }
                except Exception as e:
                    ctx_log(ctx, logger, "error", f"Rotate fail {h['hostname']}: {e}")
                    return {
                        "hostname": h["hostname"],
                        "status": "failed",
                        "message": f"Rotate fail: {e}",
                        "errors": [str(e)],
                        "new_key_path": key,
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
                                ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
                        except Exception as e:
                            ctx_log(ctx, logger, "error", f"Parallel error: {e}")
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
                        locations.append(f"~/.ssh/authorized_keys on {r['hostname']}")
                    else:
                        errors.extend(r["errors"])
                    if ctx:
                        await ctx.report_progress(progress=i, total=total)
                        ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")

            ctx_log(ctx, logger, "debug", f"Done SSH key rotate for {group}")
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

    @mcp.tool(
        annotations={
            "title": "Upload File to All Hosts",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"remote_access"},
    )
    async def send_file_to_inventory(
        inventory: str = Field(
            description="YAML inventory path.",
            default=os.environ.get("TUNNEL_INVENTORY", ""),
        ),
        lpath: str = Field(description="Local file path.", default=""),
        rpath: str = Field(description="Remote destination path.", default=""),
        group: str = Field(
            description="Target group.",
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
        ),
        parallel: bool = Field(
            description="Run parallel.",
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
        ),
        max_threads: int = Field(
            description="Max threads.",
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "5")),
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Upload a file to all hosts in the specified inventory group. Expected return object type: dict"""
        lpath = os.path.abspath(os.path.expanduser(lpath))
        rpath = os.path.expanduser(rpath)
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Normalized: lpath={lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)}), rpath={rpath}, CWD={os.getcwd()}",
        )
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Upload file all: inv={inventory}, group={group}, local={lpath}, remote={rpath}",
        )
        if not inventory or not lpath or not rpath:
            ctx_log(ctx, logger, "error", "Need inventory, lpath, rpath")
            return ResponseBuilder.build(
                400,
                "Need inventory, lpath, rpath",
                {
                    "inventory": inventory,
                    "group": group,
                    "lpath": lpath,
                    "rpath": rpath,
                },
                error="Need inventory, lpath, rpath",
            )
        if not os.path.exists(lpath) or not os.path.isfile(lpath):
            ctx_log(ctx, logger, "error", f"Invalid file: {lpath}")
            return ResponseBuilder.build(
                400,
                f"Invalid file: {lpath}",
                {
                    "inventory": inventory,
                    "group": group,
                    "lpath": lpath,
                    "rpath": rpath,
                },
                error=f"Invalid file: {lpath}",
            )
        try:
            hosts, error = load_inventory(inventory, group, logger)
            if error:
                return error
            total = len(hosts)
            if ctx:
                await ctx.report_progress(progress=0, total=total)
                ctx_log(ctx, logger, "debug", f"Progress: 0/{total}")

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

                    sftp.put(lpath, rpath, callback=progress_callback)
                    sftp.close()
                    ctx_log(
                        ctx, logger, "info", f"Host {host}: Uploaded {lpath} to {rpath}"
                    )
                    return {
                        "hostname": host,
                        "status": "success",
                        "message": f"Uploaded {lpath} to {rpath}",
                        "errors": [],
                    }
                except Exception as e:
                    ctx_log(ctx, logger, "error", f"Upload fail {host}: {e}")
                    return {
                        "hostname": host,
                        "status": "failed",
                        "message": f"Upload fail: {e}",
                        "errors": [str(e)],
                    }
                finally:
                    if "t" in locals():
                        t.close()

            results, files, locations, errors = [], [lpath], [], []
            if parallel:
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
                    futures = [
                        ex.submit(lambda h: asyncio.run(send_host(h)), h) for h in hosts
                    ]
                    for i, future in enumerate(
                        concurrent.futures.as_completed(futures), 1
                    ):
                        try:
                            r = future.result()
                            results.append(r)
                            if r["status"] == "success":
                                locations.append(f"{rpath} on {r['hostname']}")
                            else:
                                errors.extend(r["errors"])
                            if ctx:
                                await ctx.report_progress(progress=i, total=total)
                                ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
                        except Exception as e:
                            ctx_log(ctx, logger, "error", f"Parallel error: {e}")
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
                        locations.append(f"{rpath} on {r['hostname']}")
                    else:
                        errors.extend(r["errors"])
                    if ctx:
                        await ctx.report_progress(progress=i, total=total)
                        ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")

            ctx_log(ctx, logger, "debug", f"Done file upload for {group}")
            msg = (
                f"Uploaded {lpath} to {group}"
                if not errors
                else f"Upload failed for some in {group}"
            )
            return ResponseBuilder.build(
                200 if not errors else 500,
                msg,
                {
                    "inventory": inventory,
                    "group": group,
                    "local_path": lpath,
                    "remote_path": rpath,
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
                    "lpath": lpath,
                    "rpath": rpath,
                },
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Download File from All Hosts",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"remote_access"},
    )
    async def receive_file_from_inventory(
        inventory: str = Field(
            description="YAML inventory path.",
            default=os.environ.get("TUNNEL_INVENTORY", ""),
        ),
        rpath: str = Field(description="Remote file path to download.", default=""),
        lpath_prefix: str = Field(
            description="Local directory path prefix to save files.", default=""
        ),
        group: str = Field(
            description="Target group.",
            default=os.environ.get("TUNNEL_INVENTORY_GROUP", "all"),
        ),
        parallel: bool = Field(
            description="Run parallel.",
            default=to_boolean(os.environ.get("TUNNEL_PARALLEL", False)),
        ),
        max_threads: int = Field(
            description="Max threads.",
            default=to_integer(os.environ.get("TUNNEL_MAX_THREADS", "5")),
        ),
        _log_path: str | None = Field(
            description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", "")
        ),
        ctx: Context = Field(description="MCP context.", default=""),
    ) -> dict:
        """Download a file from all hosts in the specified inventory group. Expected return object type: dict"""
        ctx_log(
            ctx,
            logger,
            "debug",
            f"Download file all: inv={inventory}, group={group}, remote={rpath}, local_prefix={lpath_prefix}",
        )
        if not inventory or not rpath or not lpath_prefix:
            ctx_log(ctx, logger, "error", "Need inventory, rpath, lpath_prefix")
            return ResponseBuilder.build(
                400,
                "Need inventory, rpath, lpath_prefix",
                {
                    "inventory": inventory,
                    "group": group,
                    "rpath": rpath,
                    "lpath_prefix": lpath_prefix,
                },
                errors=["Need inventory, rpath, lpath_prefix"],
            )
        try:
            os.makedirs(lpath_prefix, exist_ok=True)
            hosts, error = load_inventory(inventory, group, logger)
            if error:
                return error
            total = len(hosts)
            if ctx:
                await ctx.report_progress(progress=0, total=total)
                ctx_log(ctx, logger, "debug", f"Progress: 0/{total}")

            async def receive_host(h: dict) -> dict:
                host = h["hostname"]
                lpath = os.path.join(lpath_prefix, host, os.path.basename(rpath))
                os.makedirs(os.path.dirname(lpath), exist_ok=True)
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

                    sftp.get(rpath, lpath, callback=progress_callback)
                    sftp.close()
                    ctx_log(
                        ctx,
                        logger,
                        "info",
                        f"Host {host}: Downloaded {rpath} to {lpath}",
                    )
                    return {
                        "hostname": host,
                        "status": "success",
                        "message": f"Downloaded {rpath} to {lpath}",
                        "errors": [],
                        "local_path": lpath,
                    }
                except Exception as e:
                    ctx_log(ctx, logger, "error", f"Download fail {host}: {e}")
                    return {
                        "hostname": host,
                        "status": "failed",
                        "message": f"Download fail: {e}",
                        "errors": [str(e)],
                        "local_path": lpath,
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
                                ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")
                        except Exception as e:
                            ctx_log(ctx, logger, "error", f"Parallel error: {e}")
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
                        ctx_log(ctx, logger, "debug", f"Progress: {i}/{total}")

            ctx_log(ctx, logger, "debug", f"Done file download for {group}")
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


def register_operation_management_tools(mcp: FastMCP):
    """Register operation management tools for enhanced MCP capabilities."""

    @mcp.tool(
        annotations={
            "title": "Start Operation",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
        tags={"operation_management"},
    )
    async def start_operation(
        operation_type: str = Field(description="Type of operation to start"),
        total_steps: int = Field(
            description="Total number of steps in the operation", default=0
        ),
        details: dict = Field(
            description="Additional operation details", default_factory=dict
        ),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Start a new operation with progress tracking."""
        try:
            operation_id = operation_manager.create_operation(
                operation_type=operation_type,
                total_steps=total_steps,
                details=details,
            )
            return ResponseBuilder.build(
                200,
                "Operation started successfully",
                {"operation_id": operation_id, "operation_type": operation_type},
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to start operation: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to start operation",
                {"operation_type": operation_type},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Get Operation Progress",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"operation_management"},
    )
    async def get_operation_progress(
        operation_id: str = Field(description="Operation ID to get progress for"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Get current progress of an ongoing operation."""
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

    @mcp.tool(
        annotations={
            "title": "Cancel Operation",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"operation_management"},
    )
    async def cancel_operation(
        operation_id: str = Field(description="Operation ID to cancel"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Cancel an ongoing operation gracefully."""
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
                    "Failed to cancel operation",
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

    @mcp.tool(
        annotations={
            "title": "Get Resource Metrics",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"operation_management"},
    )
    async def get_resource_metrics(
        operation_id: str = Field(description="Operation ID to get metrics for"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Get resource usage metrics for an operation."""
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

    @mcp.tool(
        annotations={
            "title": "List Active Sessions",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"operation_management"},
    )
    async def list_active_sessions(
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """List all active SSH sessions."""
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
                500,
                "Failed to list active sessions",
                {},
                str(e),
            )


def register_system_intelligence_tools(mcp: FastMCP):
    """Register system intelligence and discovery tools."""

    @mcp.tool(
        annotations={
            "title": "Get System Info",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"system_intelligence"},
    )
    async def get_system_info(
        remote_host: str = Field(description="Remote host to get system info from"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Get comprehensive system information including OS, hardware, and packages."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            intelligence = SystemIntelligence(tunnel)
            system_info = intelligence.get_system_info()

            return ResponseBuilder.build(
                200,
                "System information retrieved successfully",
                {"host": remote_host, "system_info": system_info},
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to get system info: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to get system information",
                {"host": remote_host},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Discover Services",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"system_intelligence"},
    )
    async def discover_services(
        remote_host: str = Field(description="Remote host to discover services on"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Discover running services, open ports, and processes."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            intelligence = SystemIntelligence(tunnel)
            services = intelligence.discover_services()

            return ResponseBuilder.build(
                200,
                "Services discovered successfully",
                {"host": remote_host, "services": services},
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to discover services: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to discover services",
                {"host": remote_host},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Analyze Logs",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"system_intelligence"},
    )
    async def analyze_logs(
        remote_host: str = Field(description="Remote host to analyze logs on"),
        log_paths: list[str] = Field(description="List of log file paths to analyze"),
        patterns: list[str] = Field(description="List of patterns to search for"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Analyze log files for specified patterns and return statistics."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            intelligence = SystemIntelligence(tunnel)
            analysis = intelligence.analyze_logs(log_paths, patterns)

            return ResponseBuilder.build(
                200,
                "Log analysis completed successfully",
                {"host": remote_host, "analysis": analysis},
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to analyze logs: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to analyze logs",
                {"host": remote_host},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Network Topology",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"system_intelligence"},
    )
    async def network_topology(
        remote_host: str = Field(description="Remote host to map network topology for"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Map network interfaces, routes, and active connections."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            intelligence = SystemIntelligence(tunnel)
            topology = intelligence.network_topology()

            return ResponseBuilder.build(
                200,
                "Network topology mapped successfully",
                {"host": remote_host, "topology": topology},
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to map network topology: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to map network topology",
                {"host": remote_host},
                str(e),
            )


def register_advanced_file_operations_tools(mcp: FastMCP):
    """Register advanced file operations tools."""

    @mcp.tool(
        annotations={
            "title": "Recursive File Operations",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"advanced_file_operations"},
    )
    async def recursive_file_operations(
        remote_host: str = Field(description="Remote host to perform operations on"),
        operation: str = Field(
            description="Operation type (copy, move, delete, list, chmod, chown)"
        ),
        source: str = Field(description="Source path"),
        destination: str = Field(
            default="", description="Destination path (for copy/move)"
        ),
        mode: str = Field(default="755", description="Permission mode (for chmod)"),
        owner: str = Field(default="", description="Owner (for chown)"),
        group: str = Field(default="", description="Group (for chown)"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Perform recursive directory-level operations."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            file_manager = AdvancedFileManager(tunnel)

            options = {}
            if operation == "chmod":
                options["mode"] = mode
            elif operation == "chown":
                options["owner"] = owner
                options["group"] = group

            result = file_manager.recursive_file_operations(
                operation, source, destination, options
            )

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                f"Recursive {operation} operation completed",
                {"host": remote_host, "operation": operation, "result": result},
                error=result.get("error", ""),
                errors=result.get("errors", []),
            )
        except Exception as e:
            ctx_log(
                ctx,
                logger,
                "error",
                f"Failed to perform recursive file operations: {e}",
            )
            return ResponseBuilder.build(
                500,
                "Failed to perform recursive file operations",
                {"host": remote_host, "operation": operation},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "File Content Search",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"advanced_file_operations"},
    )
    async def file_content_search(
        remote_host: str = Field(description="Remote host to search on"),
        search_paths: list[str] = Field(description="List of directories to search"),
        pattern: str = Field(description="Pattern to search for"),
        case_sensitive: bool = Field(
            default=False, description="Case-sensitive search"
        ),
        recursive: bool = Field(default=True, description="Recursive search"),
        max_results: int = Field(default=1000, description="Maximum results to return"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Search for file content across directories."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            file_manager = AdvancedFileManager(tunnel)

            options = {
                "case_sensitive": case_sensitive,
                "recursive": recursive,
                "max_results": max_results,
            }

            result = file_manager.file_content_search(search_paths, pattern, options)

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                "File content search completed",
                {"host": remote_host, "pattern": pattern, "result": result},
                error=result.get("error", ""),
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to search file content: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to search file content",
                {"host": remote_host, "pattern": pattern},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "File Watch Monitor",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"advanced_file_operations"},
    )
    async def file_watch_monitor(
        remote_host: str = Field(description="Remote host to monitor files on"),
        watch_paths: list[str] = Field(description="List of paths to monitor"),
        duration: int = Field(default=60, description="Duration to monitor in seconds"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Monitor files/directories for real-time changes."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            file_manager = AdvancedFileManager(tunnel)

            result = file_manager.file_watch_monitor(watch_paths, duration)

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                "File monitoring completed",
                {"host": remote_host, "watch_paths": watch_paths, "result": result},
                error=result.get("error", ""),
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to monitor files: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to monitor files",
                {"host": remote_host, "watch_paths": watch_paths},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "File Diff Compare",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"advanced_file_operations"},
    )
    async def file_diff_compare(
        file_path: str = Field(description="File path to compare"),
        host1: str = Field(description="First host"),
        host2: str = Field(description="Second host"),
        username1: str = Field(default="", description="SSH username for host1"),
        password1: str = Field(default="", description="SSH password for host1"),
        identity_file1: str = Field(
            default="", description="SSH identity file for host1"
        ),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Compare files across two different hosts."""
        try:
            tunnel1 = Tunnel(
                remote_host=host1,
                username=username1 or None,
                password=password1 or None,
                identity_file=identity_file1 or None,
            )
            file_manager = AdvancedFileManager(tunnel1)

            result = file_manager.file_diff_compare(host1, host2, file_path)

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                "File comparison completed",
                {"file": file_path, "host1": host1, "host2": host2, "result": result},
                error=result.get("error", ""),
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to compare files: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to compare files",
                {"file": file_path, "host1": host1, "host2": host2},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Smart Backup",
            "readOnlyHint": False,
            "destructiveHint": False,
            "idempotentHint": False,
        },
        tags={"advanced_file_operations"},
    )
    async def smart_backup(
        remote_host: str = Field(description="Remote host to backup"),
        backup_paths: list[str] = Field(description="List of paths to backup"),
        backup_dest: str = Field(description="Backup destination directory"),
        compression: bool = Field(default=True, description="Enable compression"),
        incremental: bool = Field(
            default=False, description="Enable incremental backup"
        ),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Create automated backups with versioning and compression."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            file_manager = AdvancedFileManager(tunnel)

            options = {
                "compression": compression,
                "incremental": incremental,
            }

            result = file_manager.smart_backup(backup_paths, backup_dest, options)

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                "Backup completed",
                {"host": remote_host, "backup_paths": backup_paths, "result": result},
                error=result.get("error", ""),
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to create backup: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to create backup",
                {"host": remote_host, "backup_paths": backup_paths},
                str(e),
            )


def register_security_auditing_tools(mcp: FastMCP):
    """Register security and compliance auditing tools."""

    @mcp.tool(
        annotations={
            "title": "Security Audit",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"security_auditing"},
    )
    async def security_audit(
        remote_host: str = Field(description="Remote host to audit"),
        scope: list[str] = Field(
            default=[], description="Security areas to audit (default: all)"
        ),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Perform comprehensive security assessment."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

            result = auditor.security_audit(scope if scope else None)

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                f"Security audit completed with score: {result['score']}/100",
                {"host": remote_host, "audit_result": result},
                error=result.get("error", ""),
                errors=result.get("audit_errors", []),
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to perform security audit: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to perform security audit",
                {"host": remote_host},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Compliance Check",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"security_auditing"},
    )
    async def compliance_check(
        remote_host: str = Field(description="Remote host to check compliance on"),
        standard: str = Field(
            default="cis_benchmark",
            description="Compliance standard (cis_benchmark, pci_dss, hipaa)",
        ),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Check compliance against security standards."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

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
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to perform compliance check: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to perform compliance check",
                {"host": remote_host, "standard": standard},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Vulnerability Scan",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"security_auditing"},
    )
    async def vulnerability_scan(
        remote_host: str = Field(description="Remote host to scan"),
        scan_type: str = Field(
            default="basic", description="Scan type (basic, package, config)"
        ),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Scan for known vulnerabilities."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

            result = auditor.vulnerability_scan(scan_type)

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                f"Vulnerability scan completed: {len(result['vulnerabilities'])} vulnerabilities found",
                {"host": remote_host, "scan_type": scan_type, "scan_result": result},
                error=result.get("error", ""),
                errors=result.get("scan_errors", []),
            )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Failed to perform vulnerability scan: {e}")
            return ResponseBuilder.build(
                500,
                "Failed to perform vulnerability scan",
                {"host": remote_host, "scan_type": scan_type},
                str(e),
            )

    @mcp.tool(
        annotations={
            "title": "Access Control Audit",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"security_auditing"},
    )
    async def access_control_audit(
        remote_host: str = Field(description="Remote host to audit"),
        username: str = Field(default="", description="SSH username"),
        password: str = Field(default="", description="SSH password"),
        identity_file: str = Field(default="", description="SSH identity file path"),
        ctx: Context = Field(
            description="MCP context for progress reporting", default=None
        ),
    ) -> dict:
        """Audit access controls and permissions."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

            result = auditor.access_control_audit()

            return ResponseBuilder.build(
                200 if result["success"] else 500,
                f"Access control audit completed: {result['users_audited']} users audited",
                {"host": remote_host, "audit_result": result},
                error=result.get("error", ""),
                errors=result.get("audit_errors", []),
            )
        except Exception as e:
            ctx_log(
                ctx, logger, "error", f"Failed to perform access control audit: {e}"
            )
            return ResponseBuilder.build(
                500,
                "Failed to perform access control audit",
                {"host": remote_host},
                str(e),
            )


def get_mcp_instance() -> tuple[Any, Any, Any, Any]:
    """Initialize and return the MCP instance, args, and middlewares."""
    load_dotenv(find_dotenv())

    args, mcp, middlewares = create_mcp_server(
        name="TunnelManagerMCP",
        version=__version__,
        instructions="Tunnel Manager MCP Utility — Manage SSH tunnels, managed hosts, and remote execution.",
    )

    DEFAULT_MISCTOOL = to_boolean(os.getenv("MISCTOOL", "True"))
    if DEFAULT_MISCTOOL:
        register_misc_tools(mcp)
    DEFAULT_HOST_MANAGEMENTTOOL = to_boolean(os.getenv("HOST_MANAGEMENTTOOL", "True"))
    if DEFAULT_HOST_MANAGEMENTTOOL:
        register_host_management_tools(mcp)
    DEFAULT_REMOTE_ACCESSTOOL = to_boolean(os.getenv("REMOTE_ACCESSTOOL", "True"))
    if DEFAULT_REMOTE_ACCESSTOOL:
        register_remote_access_tools(mcp)
    DEFAULT_OPERATION_MANAGEMENTTOOL = to_boolean(
        os.getenv("OPERATION_MANAGEMENTTOOL", "True")
    )
    if DEFAULT_OPERATION_MANAGEMENTTOOL:
        register_operation_management_tools(mcp)
    DEFAULT_SYSTEM_INTELLIGENCETOOL = to_boolean(
        os.getenv("SYSTEM_INTELLIGENCETOOL", "True")
    )
    if DEFAULT_SYSTEM_INTELLIGENCETOOL:
        register_system_intelligence_tools(mcp)
    DEFAULT_ADVANCED_FILE_OPERATIONSTOOL = to_boolean(
        os.getenv("ADVANCED_FILE_OPERATIONSTOOL", "True")
    )
    if DEFAULT_ADVANCED_FILE_OPERATIONSTOOL:
        register_advanced_file_operations_tools(mcp)
    DEFAULT_SECURITY_AUDITINGTOOL = to_boolean(
        os.getenv("SECURITY_AUDITINGTOOL", "True")
    )
    if DEFAULT_SECURITY_AUDITINGTOOL:
        register_security_auditing_tools(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)

    DEFAULT_MISCTOOL = to_boolean(os.getenv("MISCTOOL", "True"))
    if DEFAULT_MISCTOOL:
        register_misc_tools(mcp)
    DEFAULT_HOST_MANAGEMENTTOOL = to_boolean(os.getenv("HOST_MANAGEMENTTOOL", "True"))
    if DEFAULT_HOST_MANAGEMENTTOOL:
        register_host_management_tools(mcp)
    DEFAULT_REMOTE_ACCESSTOOL = to_boolean(os.getenv("REMOTE_ACCESSTOOL", "True"))
    if DEFAULT_REMOTE_ACCESSTOOL:
        register_remote_access_tools(mcp)
    DEFAULT_OPERATION_MANAGEMENTTOOL = to_boolean(
        os.getenv("OPERATION_MANAGEMENTTOOL", "True")
    )
    if DEFAULT_OPERATION_MANAGEMENTTOOL:
        register_operation_management_tools(mcp)
    DEFAULT_SYSTEM_INTELLIGENCETOOL = to_boolean(
        os.getenv("SYSTEM_INTELLIGENCETOOL", "True")
    )
    if DEFAULT_SYSTEM_INTELLIGENCETOOL:
        register_system_intelligence_tools(mcp)
    DEFAULT_ADVANCED_FILE_OPERATIONSTOOL = to_boolean(
        os.getenv("ADVANCED_FILE_OPERATIONSTOOL", "True")
    )
    if DEFAULT_ADVANCED_FILE_OPERATIONSTOOL:
        register_advanced_file_operations_tools(mcp)
    DEFAULT_SECURITY_AUDITINGTOOL = to_boolean(
        os.getenv("SECURITY_AUDITINGTOOL", "True")
    )
    if DEFAULT_SECURITY_AUDITINGTOOL:
        register_security_auditing_tools(mcp)

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
