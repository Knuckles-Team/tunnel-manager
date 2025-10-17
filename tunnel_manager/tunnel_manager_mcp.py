#!/usr/bin/env python
# coding: utf-8
import os
import sys
import argparse
import logging
import concurrent.futures
import yaml
import asyncio
from typing import Optional, Dict, List, Union
from pydantic import Field
from fastmcp import FastMCP, Context
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth import OAuthProxy, RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from fastmcp.server.middleware.logging import LoggingMiddleware
from fastmcp.server.middleware.timing import TimingMiddleware
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware
from tunnel_manager.tunnel_manager import Tunnel

# Initialize FastMCP
mcp = FastMCP(name="TunnelServer")

# Configure default logging
logging.basicConfig(
    filename="tunnel_mcp.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def to_boolean(string: Union[str, bool] = None) -> bool:
    if isinstance(string, bool):
        return string
    if not string:
        return False
    normalized = str(string).strip().lower()
    true_values = {"t", "true", "y", "yes", "1"}
    false_values = {"f", "false", "n", "no", "0"}
    if normalized in true_values:
        return True
    elif normalized in false_values:
        return False
    else:
        raise ValueError(f"Cannot convert '{string}' to boolean")


def to_integer(string: Union[str, int] = None) -> int:
    if isinstance(string, int):
        return string
    if not string:
        return 0
    try:
        return int(string.strip())
    except ValueError:
        raise ValueError(f"Cannot convert '{string}' to integer")


class ResponseBuilder:
    @staticmethod
    def build(
        status: int,
        msg: str,
        details: Dict,
        error: str = "",
        stdout: str = "",  # Add this
        files: List = None,
        locations: List = None,
        errors: List = None,
    ) -> Dict:
        return {
            "status_code": status,
            "message": msg,
            "stdout": stdout,  # Use the parameter
            "stderr": error,
            "files_copied": files or [],
            "locations_copied_to": locations or [],
            "details": details,
            "errors": errors or ([error] if error else []),
        }


def setup_logging(log_file: Optional[str], logger: logging.Logger) -> Dict:
    if not log_file:
        return {}
    try:
        log_dir = os.path.dirname(os.path.abspath(log_file)) or os.getcwd()
        os.makedirs(log_dir, exist_ok=True)
        logging.basicConfig(
            filename=log_file,
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(level)s - %(msg)s",
        )
        return {}
    except Exception as e:
        logger.error(f"Log config fail: {e}")
        return ResponseBuilder.build(500, f"Log config fail: {e}", {}, str(e))


def load_inventory(
    inventory: str, group: str, logger: logging.Logger
) -> tuple[List[Dict], Dict]:
    try:
        with open(inventory, "r") as f:
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    cmd: str = Field(description="Shell command.", default=None),
    id_file: Optional[str] = Field(
        description="Private key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate: Optional[str] = Field(
        description="Teleport certificate.",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy: Optional[str] = Field(
        description="Teleport proxy.",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Run shell command on remote host. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Run cmd: host={host}, cmd={cmd}")
    if not host or not cmd:
        logger.error("Need host, cmd")
        return ResponseBuilder.build(
            400, "Need host, cmd", {"host": host, "cmd": cmd}, errors=["Need host, cmd"]
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
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        t.connect()
        out, error = t.run_command(cmd)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Cmd out: {out}, error: {error}")
        return ResponseBuilder.build(
            200,
            f"Cmd '{cmd}' done on {host}",
            {"host": host, "cmd": cmd},
            error,
            stdout=out,
            files=[],
            locations=[],
            errors=[],
        )
    except Exception as e:
        logger.error(f"Cmd fail: {e}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    lpath: str = Field(description="Local file path.", default=None),
    rpath: str = Field(description="Remote path.", default=None),
    id_file: Optional[str] = Field(
        description="Private key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate: Optional[str] = Field(
        description="Teleport certificate.",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy: Optional[str] = Field(
        description="Teleport proxy.",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Upload file to remote host. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    logger.debug(f"Upload: host={host}, local={lpath}, remote={rpath}")
    lpath = os.path.abspath(os.path.expanduser(lpath))  # Normalize to absolute
    rpath = os.path.expanduser(rpath)  # Handle ~ on remote
    logger.debug(
        f"Normalized: lpath={lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)}), rpath={rpath}, CWD={os.getcwd()}"
    )

    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Upload: host={host}, local={lpath}, remote={rpath}")
    if not host or not lpath or not rpath:
        logger.error("Need host, lpath, rpath")
        return ResponseBuilder.build(
            400,
            "Need host, lpath, rpath",
            {"host": host, "lpath": lpath, "rpath": rpath},
            errors=["Need host, lpath, rpath"],
        )
    if not os.path.exists(lpath) or not os.path.isfile(lpath):
        logger.error(
            f"Invalid file: {lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)})"
        )
        return ResponseBuilder.build(
            400,
            f"Invalid file: {lpath}",
            {"host": host, "lpath": lpath, "rpath": rpath},
            errors=[f"Invalid file: {lpath}"],
        )
    lpath = os.path.abspath(os.path.expanduser(lpath))
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
            logger.debug("Progress: 0/100")
        sftp = t.ssh_client.open_sftp()
        transferred = 0

        def progress_callback(transf, total):
            nonlocal transferred
            transferred = transf
            if ctx:
                asyncio.ensure_future(ctx.report_progress(progress=transf, total=total))

        sftp.put(lpath, rpath, callback=progress_callback)
        sftp.close()
        logger.debug(f"Uploaded: {lpath} -> {rpath}")
        return ResponseBuilder.build(
            200,
            f"Uploaded to {rpath}",
            {"host": host, "lpath": lpath, "rpath": rpath},
            files=[lpath],
            locations=[rpath],
            errors=[],
        )
    except Exception as e:
        logger.error(f"Unexpected error during file transfer: {str(e)}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    rpath: str = Field(description="Remote file path.", default=None),
    lpath: str = Field(description="Local file path.", default=None),
    id_file: Optional[str] = Field(
        description="Private key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate: Optional[str] = Field(
        description="Teleport certificate.",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy: Optional[str] = Field(
        description="Teleport proxy.",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Download file from remote host. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    lpath = os.path.abspath(os.path.expanduser(lpath))
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Download: host={host}, remote={rpath}, local={lpath}")
    if not host or not rpath or not lpath:
        logger.error("Need host, rpath, lpath")
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
            logger.debug("Progress: 0/100")
        sftp = t.ssh_client.open_sftp()
        sftp.stat(rpath)
        transferred = 0

        def progress_callback(transf, total):
            nonlocal transferred
            transferred = transf
            if ctx:
                asyncio.ensure_future(ctx.report_progress(progress=transf, total=total))

        sftp.get(rpath, lpath, callback=progress_callback)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        sftp.close()
        logger.debug(f"Downloaded: {rpath} -> {lpath}")
        return ResponseBuilder.build(
            200,
            f"Downloaded to {lpath}",
            {"host": host, "rpath": rpath, "lpath": lpath},
            files=[rpath],
            locations=[lpath],
            errors=[],
        )
    except Exception as e:
        logger.error(f"Download fail: {e}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    id_file: Optional[str] = Field(
        description="Private key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate: Optional[str] = Field(
        description="Teleport certificate.",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy: Optional[str] = Field(
        description="Teleport proxy.",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Check SSH server status. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Check SSH: host={host}")
    if not host:
        logger.error("Need host")
        return ResponseBuilder.build(
            400, "Need host", {"host": host}, errors=["Need host"]
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
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        success, msg = t.check_ssh_server()
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"SSH check: {msg}")
        return ResponseBuilder.build(
            200 if success else 400,
            f"SSH check: {msg}",
            {"host": host, "success": success},
            files=[],
            locations=[],
            errors=[] if success else [msg],
        )
    except Exception as e:
        logger.error(f"Check fail: {e}")
        return ResponseBuilder.build(500, f"Check fail: {e}", {"host": host}, str(e))
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    key: str = Field(
        description="Private key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Test key-based auth. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Test key: host={host}, key={key}")
    if not host or not key:
        logger.error("Need host, key")
        return ResponseBuilder.build(
            400, "Need host, key", {"host": host, "key": key}, errors=["Need host, key"]
        )
    try:
        t = Tunnel(remote_host=host, username=user, port=port, ssh_config_file=cfg)
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        success, msg = t.test_key_auth(key)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Key test: {msg}")
        return ResponseBuilder.build(
            200 if success else 400,
            f"Key test: {msg}",
            {"host": host, "key": key, "success": success},
            files=[],
            locations=[],
            errors=[] if success else [msg],
        )
    except Exception as e:
        logger.error(f"Key test fail: {e}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
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
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Setup passwordless SSH. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Setup SSH: host={host}, key={key}, key_type={key_type}")
    if not host or not password:
        logger.error("Need host, password")
        return ResponseBuilder.build(
            400,
            "Need host, password",
            {"host": host, "key": key, "key_type": key_type},
            errors=["Need host, password"],
        )
    if key_type not in ["rsa", "ed25519"]:
        logger.error(f"Invalid key_type: {key_type}")
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"host": host, "key": key, "key_type": key_type},
            errors=["key_type must be 'rsa' or 'ed25519'"],
        )
    try:
        t = Tunnel(
            remote_host=host,
            username=user,
            password=password,
            port=port,
            ssh_config_file=cfg,
        )
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        key = os.path.expanduser(key)
        pub_key = key + ".pub"
        if not os.path.exists(pub_key):
            if key_type == "rsa":
                os.system(f"ssh-keygen -t rsa -b 4096 -f {key} -N ''")
            else:  # ed25519
                os.system(f"ssh-keygen -t ed25519 -f {key} -N ''")
            logger.info(f"Generated {key_type} key: {key}, {pub_key}")
        t.setup_passwordless_ssh(local_key_path=key, key_type=key_type)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"SSH setup for {user}@{host}")
        return ResponseBuilder.build(
            200,
            f"SSH setup for {user}@{host}",
            {"host": host, "key": key, "user": user, "key_type": key_type},
            files=[pub_key],
            locations=[f"~/.ssh/authorized_keys on {host}"],
            errors=[],
        )
    except Exception as e:
        logger.error(f"SSH setup fail: {e}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    lcfg: str = Field(description="Local SSH config.", default=None),
    rcfg: str = Field(
        description="Remote SSH config.", default=os.path.expanduser("~/.ssh/config")
    ),
    id_file: Optional[str] = Field(
        description="Private key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate: Optional[str] = Field(
        description="Teleport certificate.",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy: Optional[str] = Field(
        description="Teleport proxy.",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Copy SSH config to remote host. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Copy cfg: host={host}, local={lcfg}, remote={rcfg}")
    if not host or not lcfg:
        logger.error("Need host, lcfg")
        return ResponseBuilder.build(
            400,
            "Need host, lcfg",
            {"host": host, "lcfg": lcfg, "rcfg": rcfg},
            errors=["Need host, lcfg"],
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
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        t.copy_ssh_config(lcfg, rcfg)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Copied cfg to {rcfg} on {host}")
        return ResponseBuilder.build(
            200,
            f"Copied cfg to {rcfg} on {host}",
            {"host": host, "lcfg": lcfg, "rcfg": rcfg},
            files=[lcfg],
            locations=[rcfg],
            errors=[],
        )
    except Exception as e:
        logger.error(f"Copy cfg fail: {e}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    user: Optional[str] = Field(
        description="Username.", default=os.environ.get("TUNNEL_USERNAME", None)
    ),
    password: Optional[str] = Field(
        description="Password.", default=os.environ.get("TUNNEL_PASSWORD", None)
    ),
    port: int = Field(
        description="Port.",
        default=to_integer(os.environ.get("TUNNEL_REMOTE_PORT", "22")),
    ),
    new_key: str = Field(description="New private key path.", default=None),
    key_type: str = Field(
        description="Key type to generate (rsa or ed25519).", default="ed25519"
    ),
    id_file: Optional[str] = Field(
        description="Current key path.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate: Optional[str] = Field(
        description="Teleport certificate.",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy: Optional[str] = Field(
        description="Teleport proxy.",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    cfg: str = Field(
        description="SSH config path.", default=os.path.expanduser("~/.ssh/config")
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Rotate SSH key on remote host. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Rotate key: host={host}, new_key={new_key}, key_type={key_type}")
    if not host or not new_key:
        logger.error("Need host, new_key")
        return ResponseBuilder.build(
            400,
            "Need host, new_key",
            {"host": host, "new_key": new_key, "key_type": key_type},
            errors=["Need host, new_key"],
        )
    if key_type not in ["rsa", "ed25519"]:
        logger.error(f"Invalid key_type: {key_type}")
        return ResponseBuilder.build(
            400,
            f"Invalid key_type: {key_type}",
            {"host": host, "new_key": new_key, "key_type": key_type},
            errors=["key_type must be 'rsa' or 'ed25519'"],
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
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        new_key = os.path.expanduser(new_key)
        new_public_key = new_key + ".pub"
        if not os.path.exists(new_key):
            if key_type == "rsa":
                os.system(f"ssh-keygen -t rsa -b 4096 -f {new_key} -N ''")
            else:  # ed25519
                os.system(f"ssh-keygen -t ed25519 -f {new_key} -N ''")
            logger.info(f"Generated {key_type} key: {new_key}")
        t.rotate_ssh_key(new_key, key_type=key_type)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Rotated {key_type} key to {new_key} on {host}")
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
        logger.error(f"Rotate fail: {e}")
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
        description="Remote host.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)
    ),
    known_hosts: str = Field(
        description="Known hosts path.",
        default=os.path.expanduser("~/.ssh/known_hosts"),
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Remove host key from known_hosts. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Remove key: host={host}, known_hosts={known_hosts}")
    if not host:
        logger.error("Need host")
        return ResponseBuilder.build(
            400,
            "Need host",
            {"host": host, "known_hosts": known_hosts},
            errors=["Need host"],
        )
    try:
        t = Tunnel(remote_host=host)
        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Progress: 0/100")
        known_hosts = os.path.expanduser(known_hosts)
        msg = t.remove_host_key(known_hosts_path=known_hosts)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Remove result: {msg}")
        return ResponseBuilder.build(
            200 if "Removed" in msg else 400,
            msg,
            {"host": host, "known_hosts": known_hosts},
            files=[],
            locations=[],
            errors=[] if "Removed" in msg else [msg],
        )
    except Exception as e:
        logger.error(f"Remove fail: {e}")
        return ResponseBuilder.build(
            500, f"Remove fail: {e}", {"host": host, "known_hosts": known_hosts}, str(e)
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
        default=os.environ.get("TUNNEL_INVENTORY", None),
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
    log: Optional[str] = Field(description="Log file.", default=None),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Setup passwordless SSH for all hosts in group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Setup SSH all: inv={inventory}, group={group}, key_type={key_type}")
    if not inventory:
        logger.error("Need inventory")
        return ResponseBuilder.build(
            400,
            "Need inventory",
            {"inventory": inventory, "group": group, "key_type": key_type},
            errors=["Need inventory"],
        )
    if key_type not in ["rsa", "ed25519"]:
        logger.error(f"Invalid key_type: {key_type}")
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
                os.system(f"ssh-keygen -t rsa -b 4096 -f {key} -N ''")
            else:  # ed25519
                os.system(f"ssh-keygen -t ed25519 -f {key} -N ''")
            logger.info(f"Generated {key_type} key: {key}, {pub_key}")
        with open(pub_key, "r") as f:
            pub = f.read().strip()
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)
            logger.debug(f"Progress: 0/{total}")

        async def setup_host(h: Dict, ctx: Context) -> Dict:
            host, user, password = h["hostname"], h["username"], h["password"]
            kpath = h.get("key_path", key)
            logger.info(f"Setup {user}@{host}")
            try:
                t = Tunnel(remote_host=host, username=user, password=password)
                t.remove_host_key()
                t.setup_passwordless_ssh(local_key_path=kpath, key_type=key_type)
                t.connect()
                t.run_command(f"echo '{pub}' >> ~/.ssh/authorized_keys")
                t.run_command("chmod 600 ~/.ssh/authorized_keys")
                logger.info(f"Added {key_type} key to {user}@{host}")
                res, msg = t.test_key_auth(kpath)
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"SSH setup for {user}@{host} with {key_type} key",
                    "errors": [] if res else [msg],
                }
            except Exception as e:
                logger.error(f"Setup fail {user}@{host}: {e}")
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = [
                    ex.submit(lambda h: asyncio.run(setup_host(h, ctx)), h)
                    for h in hosts
                ]
                for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        r = f.result()
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
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel error: {e}")
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
                    logger.debug(f"Progress: {i}/{total}")
        logger.debug(f"Done SSH setup for {group}")
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
            "; ".join(errors),
            files,
            locations,
            errors,
        )
    except Exception as e:
        logger.error(f"Setup all fail: {e}")
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
        default=os.environ.get("TUNNEL_INVENTORY", None),
    ),
    cmd: str = Field(description="Shell command.", default=None),
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
    log: Optional[str] = Field(description="Log file.", default=None),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Run command on all hosts in group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Run cmd all: inv={inventory}, group={group}, cmd={cmd}")
    if not inventory or not cmd:
        logger.error("Need inventory, cmd")
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
            logger.debug(f"Progress: 0/{total}")

        async def run_host(h: Dict, ctx: Context) -> Dict:
            host = h["hostname"]
            try:
                t = Tunnel(
                    remote_host=host,
                    username=h["username"],
                    password=h.get("password"),
                    identity_file=h.get("key_path"),
                )
                out, error = t.run_command(cmd)
                logger.info(f"Host {host}: Out: {out}, Err: {error}")
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Cmd '{cmd}' done on {host}",
                    "stdout": out,
                    "stderr": error,
                    "errors": [],
                }
            except Exception as e:
                logger.error(f"Cmd fail {host}: {e}")
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = [
                    ex.submit(lambda h: asyncio.run(run_host(h, ctx)), h) for h in hosts
                ]
                for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        r = f.result()
                        results.append(r)
                        errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel error: {e}")
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
                    logger.debug(f"Progress: {i}/{total}")
        logger.debug(f"Done cmd for {group}")
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
            "; ".join(errors),
            [],
            [],
            errors,
        )
    except Exception as e:
        logger.error(f"Cmd all fail: {e}")
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
        default=os.environ.get("TUNNEL_INVENTORY", None),
    ),
    cfg: str = Field(description="Local SSH config path.", default=None),
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
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Copy SSH config to all hosts in YAML group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(f"Copy SSH config: inv={inventory}, group={group}")

    if not inventory or not cfg:
        logger.error("Need inventory, cfg")
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
        logger.error(f"No cfg file: {cfg}")
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
            logger.debug(f"Progress: 0/{total}")

        results, files, locations, errors = [], [], [], []

        async def copy_host(h: Dict) -> Dict:
            try:
                t = Tunnel(
                    remote_host=h["hostname"],
                    username=h["username"],
                    password=h.get("password"),
                    identity_file=h.get("key_path"),
                )
                t.copy_ssh_config(cfg, rmt_cfg)
                logger.info(f"Copied cfg to {rmt_cfg} on {h['hostname']}")
                return {
                    "hostname": h["hostname"],
                    "status": "success",
                    "message": f"Copied cfg to {rmt_cfg}",
                    "errors": [],
                }
            except Exception as e:
                logger.error(f"Copy fail {h['hostname']}: {e}")
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = [
                    ex.submit(lambda h: asyncio.run(copy_host(h)), h) for h in hosts
                ]
                for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        r = f.result()
                        results.append(r)
                        if r["status"] == "success":
                            files.append(cfg)
                            locations.append(f"{rmt_cfg} on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel error: {e}")
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
                    logger.debug(f"Progress: {i}/{total}")

        logger.debug(f"Done SSH config copy for {group}")
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
            "; ".join(errors),
            files,
            locations,
            errors,
        )

    except Exception as e:
        logger.error(f"Copy all fail: {e}")
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
        default=os.environ.get("TUNNEL_INVENTORY", None),
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
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Rotate SSH keys for all hosts in YAML group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(
        f"Rotate SSH keys: inv={inventory}, group={group}, key_type={key_type}"
    )

    if not inventory:
        logger.error("Need inventory")
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
        logger.error(f"Invalid key_type: {key_type}")
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
            logger.debug(f"Progress: 0/{total}")

        results, files, locations, errors = [], [], [], []

        async def rotate_host(h: Dict) -> Dict:
            key = os.path.expanduser(key_pfx + h["hostname"])
            try:
                t = Tunnel(
                    remote_host=h["hostname"],
                    username=h["username"],
                    password=h.get("password"),
                    identity_file=h.get("key_path"),
                )
                t.rotate_ssh_key(key, key_type=key_type)
                logger.info(f"Rotated {key_type} key for {h['hostname']}: {key}")
                return {
                    "hostname": h["hostname"],
                    "status": "success",
                    "message": f"Rotated {key_type} key to {key}",
                    "errors": [],
                    "new_key_path": key,
                }
            except Exception as e:
                logger.error(f"Rotate fail {h['hostname']}: {e}")
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = [
                    ex.submit(lambda h: asyncio.run(rotate_host(h)), h) for h in hosts
                ]
                for i, f in enumerate(concurrent.fences.as_completed(futures), 1):
                    try:
                        r = f.result()
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
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel error: {e}")
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
                    logger.debug(f"Progress: {i}/{total}")

        logger.debug(f"Done SSH key rotate for {group}")
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
                "key_pfx": key_pfx,
                "key_type": key_type,
                "host_results": results,
            },
            "; ".join(errors),
            files,
            locations,
            errors,
        )

    except Exception as e:
        logger.error(f"Rotate all fail: {e}")
        return ResponseBuilder.build(
            500,
            f"Rotate all fail: {e}",
            {
                "inventory": inventory,
                "group": group,
                "key_pfx": key_pfx,
                "key_type": key_type,
            },
            str(e),
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
        default=os.environ.get("TUNNEL_INVENTORY", None),
    ),
    lpath: str = Field(description="Local file path.", default=None),
    rpath: str = Field(description="Remote destination path.", default=None),
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
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Upload a file to all hosts in the specified inventory group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    lpath = os.path.abspath(os.path.expanduser(lpath))  # Normalize
    rpath = os.path.expanduser(rpath)
    logger.debug(
        f"Normalized: lpath={lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)}), rpath={rpath}, CWD={os.getcwd()}"
    )
    if error := setup_logging(log, logger):
        return error
    logger.debug(
        f"Upload file all: inv={inventory}, group={group}, local={lpath}, remote={rpath}"
    )
    if not inventory or not lpath or not rpath:
        logger.error("Need inventory, lpath, rpath")
        return ResponseBuilder.build(
            400,
            "Need inventory, lpath, rpath",
            {"inventory": inventory, "group": group, "lpath": lpath, "rpath": rpath},
            errors=["Need inventory, lpath, rpath"],
        )
    if not os.path.exists(lpath) or not os.path.isfile(lpath):
        logger.error(f"Invalid file: {lpath}")
        return ResponseBuilder.build(
            400,
            f"Invalid file: {lpath}",
            {"inventory": inventory, "group": group, "lpath": lpath, "rpath": rpath},
            errors=[f"Invalid file: {lpath}"],
        )
    try:
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)
            logger.debug(f"Progress: 0/{total}")

        async def send_host(h: Dict) -> Dict:
            host = h["hostname"]
            try:
                t = Tunnel(
                    remote_host=host,
                    username=h["username"],
                    password=h.get("password"),
                    identity_file=h.get("key_path"),
                )
                t.connect()
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
                logger.info(f"Host {host}: Uploaded {lpath} to {rpath}")
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Uploaded {lpath} to {rpath}",
                    "errors": [],
                }
            except Exception as e:
                logger.error(f"Upload fail {host}: {e}")
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = [
                    ex.submit(lambda h: asyncio.run(send_host(h)), h) for h in hosts
                ]
                for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        r = f.result()
                        results.append(r)
                        if r["status"] == "success":
                            locations.append(f"{rpath} on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel error: {e}")
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
                    logger.debug(f"Progress: {i}/{total}")

        logger.debug(f"Done file upload for {group}")
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
                "lpath": lpath,
                "rpath": rpath,
                "host_results": results,
            },
            "; ".join(errors),
            files,
            locations,
            errors,
        )
    except Exception as e:
        logger.error(f"Upload all fail: {e}")
        return ResponseBuilder.build(
            500,
            f"Upload all fail: {e}",
            {"inventory": inventory, "group": group, "lpath": lpath, "rpath": rpath},
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
        default=os.environ.get("TUNNEL_INVENTORY", None),
    ),
    rpath: str = Field(description="Remote file path to download.", default=None),
    lpath_prefix: str = Field(
        description="Local directory path prefix to save files.", default=None
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
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Download a file from all hosts in the specified inventory group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if error := setup_logging(log, logger):
        return error
    logger.debug(
        f"Download file all: inv={inventory}, group={group}, remote={rpath}, local_prefix={lpath_prefix}"
    )
    if not inventory or not rpath or not lpath_prefix:
        logger.error("Need inventory, rpath, lpath_prefix")
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
            logger.debug(f"Progress: 0/{total}")

        async def receive_host(h: Dict) -> Dict:
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
                logger.info(f"Host {host}: Downloaded {rpath} to {lpath}")
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Downloaded {rpath} to {lpath}",
                    "errors": [],
                    "local_path": lpath,
                }
            except Exception as e:
                logger.error(f"Download fail {host}: {e}")
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
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as ex:
                futures = [
                    ex.submit(lambda h: asyncio.run(receive_host(h)), h) for h in hosts
                ]
                for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        r = f.result()
                        results.append(r)
                        if r["status"] == "success":
                            files.append(rpath)
                            locations.append(r["local_path"])
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel error: {e}")
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
                    logger.debug(f"Progress: {i}/{total}")

        logger.debug(f"Done file download for {group}")
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
            "; ".join(errors),
            files,
            locations,
            errors,
        )
    except Exception as e:
        logger.error(f"Download all fail: {e}")
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


def tunnel_manager_mcp():
    parser = argparse.ArgumentParser(
        description="Tunnel MCP Server for remote SSH and file operations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--transport",
        default="stdio",
        choices=["stdio", "http", "sse"],
        help="Transport method: 'stdio', 'http', or 'sse' [legacy] (default: stdio)",
    )
    parser.add_argument(
        "-s",
        "--host",
        default="0.0.0.0",
        help="Host address for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8000,
        help="Port number for HTTP transport (default: 8000)",
    )
    parser.add_argument(
        "--auth-type",
        default="none",
        choices=["none", "static", "jwt", "oauth-proxy", "oidc-proxy", "remote-oauth"],
        help="Authentication type for MCP server: 'none' (disabled), 'static' (internal), 'jwt' (external token verification), 'oauth-proxy', 'oidc-proxy', 'remote-oauth' (external) (default: none)",
    )
    # JWT/Token params
    parser.add_argument(
        "--token-jwks-uri", default=None, help="JWKS URI for JWT verification"
    )
    parser.add_argument(
        "--token-issuer", default=None, help="Issuer for JWT verification"
    )
    parser.add_argument(
        "--token-audience", default=None, help="Audience for JWT verification"
    )
    # OAuth Proxy params
    parser.add_argument(
        "--oauth-upstream-auth-endpoint",
        default=None,
        help="Upstream authorization endpoint for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-upstream-token-endpoint",
        default=None,
        help="Upstream token endpoint for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-upstream-client-id",
        default=None,
        help="Upstream client ID for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-upstream-client-secret",
        default=None,
        help="Upstream client secret for OAuth Proxy",
    )
    parser.add_argument(
        "--oauth-base-url", default=None, help="Base URL for OAuth Proxy"
    )
    # OIDC Proxy params
    parser.add_argument(
        "--oidc-config-url", default=None, help="OIDC configuration URL"
    )
    parser.add_argument("--oidc-client-id", default=None, help="OIDC client ID")
    parser.add_argument("--oidc-client-secret", default=None, help="OIDC client secret")
    parser.add_argument("--oidc-base-url", default=None, help="Base URL for OIDC Proxy")
    # Remote OAuth params
    parser.add_argument(
        "--remote-auth-servers",
        default=None,
        help="Comma-separated list of authorization servers for Remote OAuth",
    )
    parser.add_argument(
        "--remote-base-url", default=None, help="Base URL for Remote OAuth"
    )
    # Common
    parser.add_argument(
        "--allowed-client-redirect-uris",
        default=None,
        help="Comma-separated list of allowed client redirect URIs",
    )
    # Eunomia params
    parser.add_argument(
        "--eunomia-type",
        default="none",
        choices=["none", "embedded", "remote"],
        help="Eunomia authorization type: 'none' (disabled), 'embedded' (built-in), 'remote' (external) (default: none)",
    )
    parser.add_argument(
        "--eunomia-policy-file",
        default="mcp_policies.json",
        help="Policy file for embedded Eunomia (default: mcp_policies.json)",
    )
    parser.add_argument(
        "--eunomia-remote-url", default=None, help="URL for remote Eunomia server"
    )

    args = parser.parse_args()

    if args.port < 0 or args.port > 65535:
        print(f"Error: Port {args.port} is out of valid range (0-65535).")
        sys.exit(1)

    # Set auth based on type
    auth = None
    allowed_uris = (
        args.allowed_client_redirect_uris.split(",")
        if args.allowed_client_redirect_uris
        else None
    )

    if args.auth_type == "none":
        auth = None
    elif args.auth_type == "static":
        # Internal static tokens (hardcoded example)
        auth = StaticTokenVerifier(
            tokens={
                "test-token": {"client_id": "test-user", "scopes": ["read", "write"]},
                "admin-token": {"client_id": "admin", "scopes": ["admin"]},
            }
        )
    elif args.auth_type == "jwt":
        if not (args.token_jwks_uri and args.token_issuer and args.token_audience):
            print(
                "Error: jwt requires --token-jwks-uri, --token-issuer, --token-audience"
            )
            sys.exit(1)
        auth = JWTVerifier(
            jwks_uri=args.token_jwks_uri,
            issuer=args.token_issuer,
            audience=args.token_audience,
        )
    elif args.auth_type == "oauth-proxy":
        if not (
            args.oauth_upstream_auth_endpoint
            and args.oauth_upstream_token_endpoint
            and args.oauth_upstream_client_id
            and args.oauth_upstream_client_secret
            and args.oauth_base_url
            and args.token_jwks_uri
            and args.token_issuer
            and args.token_audience
        ):
            print(
                "Error: oauth-proxy requires --oauth-upstream-auth-endpoint, --oauth-upstream-token-endpoint, --oauth-upstream-client-id, --oauth-upstream-client-secret, --oauth-base-url, --token-jwks-uri, --token-issuer, --token-audience"
            )
            sys.exit(1)
        token_verifier = JWTVerifier(
            jwks_uri=args.token_jwks_uri,
            issuer=args.token_issuer,
            audience=args.token_audience,
        )
        auth = OAuthProxy(
            upstream_authorization_endpoint=args.oauth_upstream_auth_endpoint,
            upstream_token_endpoint=args.oauth_upstream_token_endpoint,
            upstream_client_id=args.oauth_upstream_client_id,
            upstream_client_secret=args.oauth_upstream_client_secret,
            token_verifier=token_verifier,
            base_url=args.oauth_base_url,
            allowed_client_redirect_uris=allowed_uris,
        )
    elif args.auth_type == "oidc-proxy":
        if not (
            args.oidc_config_url
            and args.oidc_client_id
            and args.oidc_client_secret
            and args.oidc_base_url
        ):
            print(
                "Error: oidc-proxy requires --oidc-config-url, --oidc-client-id, --oidc-client-secret, --oidc-base-url"
            )
            sys.exit(1)
        auth = OIDCProxy(
            config_url=args.oidc_config_url,
            client_id=args.oidc_client_id,
            client_secret=args.oidc_client_secret,
            base_url=args.oidc_base_url,
            allowed_client_redirect_uris=allowed_uris,
        )
    elif args.auth_type == "remote-oauth":
        if not (
            args.remote_auth_servers
            and args.remote_base_url
            and args.token_jwks_uri
            and args.token_issuer
            and args.token_audience
        ):
            print(
                "Error: remote-oauth requires --remote-auth-servers, --remote-base-url, --token-jwks-uri, --token-issuer, --token-audience"
            )
            sys.exit(1)
        auth_servers = [url.strip() for url in args.remote_auth_servers.split(",")]
        token_verifier = JWTVerifier(
            jwks_uri=args.token_jwks_uri,
            issuer=args.token_issuer,
            audience=args.token_audience,
        )
        auth = RemoteAuthProvider(
            token_verifier=token_verifier,
            authorization_servers=auth_servers,
            base_url=args.remote_base_url,
        )
    mcp.auth = auth
    if args.eunomia_type != "none":
        from eunomia_mcp import create_eunomia_middleware

        if args.eunomia_type == "embedded":
            if not args.eunomia_policy_file:
                print("Error: embedded Eunomia requires --eunomia-policy-file")
                sys.exit(1)
            middleware = create_eunomia_middleware(policy_file=args.eunomia_policy_file)
            mcp.add_middleware(middleware)
        elif args.eunomia_type == "remote":
            if not args.eunomia_remote_url:
                print("Error: remote Eunomia requires --eunomia-remote-url")
                sys.exit(1)
            middleware = create_eunomia_middleware(
                use_remote_eunomia=args.eunomia_remote_url
            )
            mcp.add_middleware(middleware)

    mcp.add_middleware(
        ErrorHandlingMiddleware(include_traceback=True, transform_errors=True)
    )
    mcp.add_middleware(
        RateLimitingMiddleware(max_requests_per_second=10.0, burst_capacity=20)
    )
    mcp.add_middleware(TimingMiddleware())
    mcp.add_middleware(LoggingMiddleware())

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "http":
        mcp.run(transport="http", host=args.host, port=args.port)
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        logger = logging.getLogger("TunnelServer")
        logger.error("Transport not supported")
        sys.exit(1)


if __name__ == "__main__":
    tunnel_manager_mcp()
