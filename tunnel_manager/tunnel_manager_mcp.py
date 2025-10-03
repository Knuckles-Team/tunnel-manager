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
from tunnel_manager.tunnel_manager import Tunnel
from fastmcp import FastMCP, Context
from pydantic import Field

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


class ResponseBuilder:
    @staticmethod
    def build(
        status: int,
        msg: str,
        details: Dict,
        err: str = "",
        files: List = None,
        locs: List = None,
        errors: List = None,
    ) -> Dict:
        return {
            "status_code": status,
            "message": msg,
            "stdout": "",
            "stderr": err,
            "files_copied": files or [],
            "locations_copied_to": locs or [],
            "details": details,
            "errors": errors or ([err] if err else []),
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
    inventory_path: str, group: str, logger: logging.Logger
) -> tuple[List[Dict], Dict]:
    try:
        with open(inventory_path, "r") as f:
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
                {"inventory_path": inventory_path, "group": group},
                errors=[f"Group '{group}' invalid"],
            )
        if not hosts:
            return [], ResponseBuilder.build(
                400,
                f"No hosts in group '{group}'",
                {"inventory_path": inventory_path, "group": group},
                errors=[f"No hosts in group '{group}'"],
            )
        return hosts, {}
    except Exception as e:
        logger.error(f"Load inv fail: {e}")
        return [], ResponseBuilder.build(
            500,
            f"Load inv fail: {e}",
            {"inventory_path": inventory_path, "group": group},
            str(e),
        )


@mcp.tool(
    annotations={
        "title": "Run Remote Command",
        "readOnlyHint": True,
        "destructiveHint": True,
        "idempotentHint": False,
    },
    tags={"remote_access"},
)
async def run_remote_command(
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
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
    if err := setup_logging(log, logger):
        return err
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
        out, err = t.run_command(cmd)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Cmd out: {out}, err: {err}")
        return ResponseBuilder.build(
            200,
            f"Cmd '{cmd}' done on {host}",
            {"host": host, "cmd": cmd},
            err,
            [],
            [],
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
        "title": "Upload File",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
    },
    tags={"remote_access"},
)
async def upload_file(
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
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
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Upload: host={host}, local={lpath}, remote={rpath}")
    if not host or not lpath or not rpath:
        logger.error("Need host, lpath, rpath")
        return ResponseBuilder.build(
            400,
            "Need host, lpath, rpath",
            {"host": host, "lpath": lpath, "rpath": rpath},
            errors=["Need host, lpath, rpath"],
        )
    if not os.path.exists(lpath):
        logger.error(f"No file: {lpath}")
        return ResponseBuilder.build(
            400,
            f"No file: {lpath}",
            {"host": host, "lpath": lpath, "rpath": rpath},
            errors=[f"No file: {lpath}"],
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
        transferred = 0

        def progress_callback(transf, total):
            nonlocal transferred
            transferred = transf
            if ctx:
                asyncio.ensure_future(ctx.report_progress(progress=transf, total=total))

        sftp.put(lpath, rpath, callback=progress_callback)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        sftp.close()
        logger.debug(f"Uploaded: {lpath} -> {rpath}")
        return ResponseBuilder.build(
            200,
            f"Uploaded to {rpath}",
            {"host": host, "lpath": lpath, "rpath": rpath},
            files=[lpath],
            locs=[rpath],
            errors=[],
        )
    except Exception as e:
        logger.error(f"Upload fail: {e}")
        return ResponseBuilder.build(
            500,
            f"Upload fail: {e}",
            {"host": host, "lpath": lpath, "rpath": rpath},
            str(e),
        )
    finally:
        if "t" in locals():
            t.close()


@mcp.tool(
    annotations={
        "title": "Download File",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
    },
    tags={"remote_access"},
)
async def download_file(
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
    ),
    rpath: str = Field(description="Remote file path.", default=None),
    lpath: str = Field(description="Local path.", default=None),
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
    if err := setup_logging(log, logger):
        return err
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
            locs=[lpath],
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
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
    if err := setup_logging(log, logger):
        return err
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
            locs=[],
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
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
    if err := setup_logging(log, logger):
        return err
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
            locs=[],
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
    ),
    key: str = Field(
        description="Private key path.", default=os.path.expanduser("~/.ssh/id_rsa")
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
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Setup SSH: host={host}, key={key}")
    if not host or not password:
        logger.error("Need host, password")
        return ResponseBuilder.build(
            400,
            "Need host, password",
            {"host": host, "key": key},
            errors=["Need host, password"],
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
            os.system(f"ssh-keygen -t rsa -b 4096 -f {key} -N ''")
            logger.info(f"Gen key: {key}, {pub_key}")
        t.setup_passwordless_ssh(key)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"SSH setup for {user}@{host}")
        return ResponseBuilder.build(
            200,
            f"SSH setup for {user}@{host}",
            {"host": host, "key": key, "user": user},
            files=[pub_key],
            locs=[f"~/.ssh/authorized_keys on {host}"],
            errors=[],
        )
    except Exception as e:
        logger.error(f"SSH setup fail: {e}")
        return ResponseBuilder.build(
            500, f"SSH setup fail: {e}", {"host": host, "key": key}, str(e)
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
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
    if err := setup_logging(log, logger):
        return err
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
            locs=[rcfg],
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
        description="Port.", default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22))
    ),
    new_key: str = Field(description="New private key path.", default=None),
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
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Rotate key: host={host}, new_key={new_key}")
    if not host or not new_key:
        logger.error("Need host, new_key")
        return ResponseBuilder.build(
            400,
            "Need host, new_key",
            {"host": host, "new_key": new_key},
            errors=["Need host, new_key"],
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
            os.system(f"ssh-keygen -t rsa -b 4096 -f {new_key} -N ''")
            logger.info(f"Gen key: {new_key}")
        t.rotate_ssh_key(new_key)
        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Progress: 100/100")
        logger.debug(f"Rotated key to {new_key} on {host}")
        return ResponseBuilder.build(
            200,
            f"Rotated key to {new_key} on {host}",
            {"host": host, "new_key": new_key, "old_key": id_file},
            files=[new_public_key],
            locs=[f"~/.ssh/authorized_keys on {host}"],
            errors=[],
        )
    except Exception as e:
        logger.error(f"Rotate fail: {e}")
        return ResponseBuilder.build(
            500, f"Rotate fail: {e}", {"host": host, "new_key": new_key}, str(e)
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
    if err := setup_logging(log, logger):
        return err
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
            locs=[],
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
async def setup_all_passwordless_ssh(
    inventory_path: str = Field(
        description="YAML inventory path.",
        default=os.environ.get("TUNNEL_INVENTORY", None),
    ),
    key: str = Field(
        description="Shared key path.",
        default=os.environ.get(
            "TUNNEL_IDENTITY_FILE", os.path.expanduser("~/.ssh/id_shared")
        ),
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
        description="Max threads.", default=int(os.environ.get("TUNNEL_MAX_THREADS", 5))
    ),
    log: Optional[str] = Field(description="Log file.", default=None),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Setup passwordless SSH for all hosts in group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Setup SSH all: inv={inventory_path}, group={group}")
    if not inventory_path:
        logger.error("Need inventory_path")
        return ResponseBuilder.build(
            400,
            "Need inventory_path",
            {"inventory_path": inventory_path, "group": group},
            errors=["Need inventory_path"],
        )
    try:
        key = os.path.expanduser(key)
        pub_key = key + ".pub"
        if not os.path.exists(key):
            os.system(f"ssh-keygen -t rsa -b 4096 -f {key} -N ''")
            logger.info(f"Gen key: {key}, {pub_key}")
        with open(pub_key, "r") as f:
            pub = f.read().strip()
        hosts, err = load_inventory(inventory_path, group, logger)
        if err:
            return err
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
                t.setup_passwordless_ssh(local_key_path=kpath)
                t.connect()
                t.run_command(f"echo '{pub}' >> ~/.ssh/authorized_keys")
                t.run_command("chmod 600 ~/.ssh/authorized_keys")
                logger.info(f"Added key to {user}@{host}")
                res, msg = t.test_key_auth(key)
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"SSH setup for {user}@{host}",
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

        results, files, locs, errors = [], [], [], []
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
                            locs.append(f"~/.ssh/authorized_keys on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel err: {e}")
                        results.append(
                            {
                                "hostname": "unknown",
                                "status": "failed",
                                "message": f"Parallel err: {e}",
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
                    locs.append(f"~/.ssh/authorized_keys on {r['hostname']}")
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
            {"inventory_path": inventory_path, "group": group, "host_results": results},
            "; ".join(errors),
            files,
            locs,
            errors,
        )
    except Exception as e:
        logger.error(f"Setup all fail: {e}")
        return ResponseBuilder.build(
            500,
            f"Setup all fail: {e}",
            {"inventory_path": inventory_path, "group": group},
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
async def run_command_on_all(
    inventory_path: str = Field(
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
        description="Max threads.", default=int(os.environ.get("TUNNEL_MAX_THREADS", 5))
    ),
    log: Optional[str] = Field(description="Log file.", default=None),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Run command on all hosts in group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Run cmd all: inv={inventory_path}, group={group}, cmd={cmd}")
    if not inventory_path or not cmd:
        logger.error("Need inventory_path, cmd")
        return ResponseBuilder.build(
            400,
            "Need inventory_path, cmd",
            {"inventory_path": inventory_path, "group": group, "cmd": cmd},
            errors=["Need inventory_path, cmd"],
        )
    try:
        hosts, err = load_inventory(inventory_path, group, logger)
        if err:
            return err
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
                out, err = t.run_command(cmd)
                logger.info(f"Host {host}: Out: {out}, Err: {err}")
                return {
                    "hostname": host,
                    "status": "success",
                    "message": f"Cmd '{cmd}' done on {host}",
                    "stdout": out,
                    "stderr": err,
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
                        logger.error(f"Parallel err: {e}")
                        results.append(
                            {
                                "hostname": "unknown",
                                "status": "failed",
                                "message": f"Parallel err: {e}",
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
                "inventory_path": inventory_path,
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
            {"inventory_path": inventory_path, "group": group, "cmd": cmd},
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
async def copy_ssh_config_on_all(
    inventory_path: str = Field(
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
        description="Max threads.", default=int(os.environ.get("TUNNEL_MAX_THREADS", 5))
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Copy SSH config to all hosts in YAML group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Copy SSH config: inv={inventory_path}, group={group}")

    if not inventory_path or not cfg:
        logger.error("Need inventory_path, cfg")
        return ResponseBuilder.build(
            400,
            "Need inventory_path, cfg",
            {
                "inventory_path": inventory_path,
                "group": group,
                "cfg": cfg,
                "rmt_cfg": rmt_cfg,
            },
            errors=["Need inventory_path, cfg"],
        )

    if not os.path.exists(cfg):
        logger.error(f"No cfg file: {cfg}")
        return ResponseBuilder.build(
            400,
            f"No cfg file: {cfg}",
            {
                "inventory_path": inventory_path,
                "group": group,
                "cfg": cfg,
                "rmt_cfg": rmt_cfg,
            },
            errors=[f"No cfg file: {cfg}"],
        )

    try:
        hosts, err = load_inventory(inventory_path, group, logger)
        if err:
            return err

        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)
            logger.debug(f"Progress: 0/{total}")

        results, files, locs, errors = [], [], [], []

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
                            locs.append(f"{rmt_cfg} on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel err: {e}")
                        results.append(
                            {
                                "hostname": "unknown",
                                "status": "failed",
                                "message": f"Parallel err: {e}",
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
                    locs.append(f"{rmt_cfg} on {r['hostname']}")
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
                "inventory_path": inventory_path,
                "group": group,
                "cfg": cfg,
                "rmt_cfg": rmt_cfg,
                "host_results": results,
            },
            "; ".join(errors),
            files,
            locs,
            errors,
        )

    except Exception as e:
        logger.error(f"Copy all fail: {e}")
        return ResponseBuilder.build(
            500,
            f"Copy all fail: {e}",
            {
                "inventory_path": inventory_path,
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
async def rotate_ssh_key_on_all(
    inventory_path: str = Field(
        description="YAML inventory path.",
        default=os.environ.get("TUNNEL_INVENTORY", None),
    ),
    key_pfx: str = Field(
        description="Prefix for new keys.", default=os.path.expanduser("~/.ssh/id_")
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
        description="Max threads.", default=int(os.environ.get("TUNNEL_MAX_THREADS", 5))
    ),
    log: Optional[str] = Field(
        description="Log file.", default=os.environ.get("TUNNEL_LOG_FILE", None)
    ),
    ctx: Context = Field(description="MCP context.", default=None),
) -> Dict:
    """Rotate SSH keys for all hosts in YAML group. Expected return object type: dict"""
    logger = logging.getLogger("TunnelServer")
    if err := setup_logging(log, logger):
        return err
    logger.debug(f"Rotate SSH keys: inv={inventory_path}, group={group}")

    if not inventory_path:
        logger.error("Need inventory_path")
        return ResponseBuilder.build(
            400,
            "Need inventory_path",
            {"inventory_path": inventory_path, "group": group, "key_pfx": key_pfx},
            errors=["Need inventory_path"],
        )

    try:
        hosts, err = load_inventory(inventory_path, group, logger)
        if err:
            return err

        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)
            logger.debug(f"Progress: 0/{total}")

        results, files, locs, errors = [], [], [], []

        async def rotate_host(h: Dict) -> Dict:
            key = os.path.expanduser(key_pfx + h["hostname"])
            try:
                t = Tunnel(
                    remote_host=h["hostname"],
                    username=h["username"],
                    password=h.get("password"),
                    identity_file=h.get("key_path"),
                )
                t.rotate_ssh_key(key)
                logger.info(f"Rotated key for {h['hostname']}: {key}")
                return {
                    "hostname": h["hostname"],
                    "status": "success",
                    "message": f"Rotated key to {key}",
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
                for i, f in enumerate(concurrent.futures.as_completed(futures), 1):
                    try:
                        r = f.result()
                        results.append(r)
                        if r["status"] == "success":
                            files.append(r["new_key_path"] + ".pub")
                            locs.append(f"~/.ssh/authorized_keys on {r['hostname']}")
                        else:
                            errors.extend(r["errors"])
                        if ctx:
                            await ctx.report_progress(progress=i, total=total)
                            logger.debug(f"Progress: {i}/{total}")
                    except Exception as e:
                        logger.error(f"Parallel err: {e}")
                        results.append(
                            {
                                "hostname": "unknown",
                                "status": "failed",
                                "message": f"Parallel err: {e}",
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
                    locs.append(f"~/.ssh/authorized_keys on {r['hostname']}")
                else:
                    errors.extend(r["errors"])
                if ctx:
                    await ctx.report_progress(progress=i, total=total)
                    logger.debug(f"Progress: {i}/{total}")

        logger.debug(f"Done SSH key rotate for {group}")
        msg = (
            f"Rotated keys for {group}"
            if not errors
            else f"Rotate failed for some in {group}"
        )
        return ResponseBuilder.build(
            200 if not errors else 500,
            msg,
            {
                "inventory_path": inventory_path,
                "group": group,
                "key_pfx": key_pfx,
                "host_results": results,
            },
            "; ".join(errors),
            files,
            locs,
            errors,
        )

    except Exception as e:
        logger.error(f"Rotate all fail: {e}")
        return ResponseBuilder.build(
            500,
            f"Rotate all fail: {e}",
            {"inventory_path": inventory_path, "group": group, "key_pfx": key_pfx},
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

    args = parser.parse_args()

    if args.port < 0 or args.port > 65535:
        print(f"Error: Port {args.port} is out of valid range (0-65535).")
        sys.exit(1)

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
