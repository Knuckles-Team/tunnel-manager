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
import requests
from eunomia_mcp.middleware import EunomiaMcpMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from pydantic import Field
from fastmcp import FastMCP
from fastmcp.server.auth.oidc_proxy import OIDCProxy
from fastmcp.server.auth import OAuthProxy, RemoteAuthProvider
from fastmcp.server.auth.providers.jwt import JWTVerifier, StaticTokenVerifier
from fastmcp.server.middleware.logging import LoggingMiddleware
from fastmcp.server.middleware.timing import TimingMiddleware
from fastmcp.server.middleware.rate_limiting import RateLimitingMiddleware
from fastmcp.server.middleware.error_handling import ErrorHandlingMiddleware
from fastmcp import Context
from fastmcp.utilities.logging import get_logger
from tunnel_manager.tunnel_manager import Tunnel
from tunnel_manager.utils import (
    to_boolean,
    to_integer,
)
from tunnel_manager.middlewares import UserTokenMiddleware, JWTClaimsLoggingMiddleware

logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = get_logger("TunnelManager")

config = {
    "enable_delegation": to_boolean(os.environ.get("ENABLE_DELEGATION", "False")),
    "audience": os.environ.get("AUDIENCE", None),
    "delegated_scopes": os.environ.get("DELEGATED_SCOPES", "api"),
    "token_endpoint": None,  # Will be fetched dynamically from OIDC config
    "oidc_client_id": os.environ.get("OIDC_CLIENT_ID", None),
    "oidc_client_secret": os.environ.get("OIDC_CLIENT_SECRET", None),
    "oidc_config_url": os.environ.get("OIDC_CONFIG_URL", None),
    "jwt_jwks_uri": os.getenv("FASTMCP_SERVER_AUTH_JWT_JWKS_URI", None),
    "jwt_issuer": os.getenv("FASTMCP_SERVER_AUTH_JWT_ISSUER", None),
    "jwt_audience": os.getenv("FASTMCP_SERVER_AUTH_JWT_AUDIENCE", None),
    "jwt_algorithm": os.getenv("FASTMCP_SERVER_AUTH_JWT_ALGORITHM", None),
    "jwt_secret": os.getenv("FASTMCP_SERVER_AUTH_JWT_PUBLIC_KEY", None),
    "jwt_required_scopes": os.getenv("FASTMCP_SERVER_AUTH_JWT_REQUIRED_SCOPES", None),
}

DEFAULT_TRANSPORT = os.environ.get("TRANSPORT", "stdio")
DEFAULT_HOST = os.environ.get("HOST", "0.0.0.0")
DEFAULT_PORT = to_integer(os.environ.get("PORT", "8000"))


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


def register_tools(mcp: FastMCP):
    @mcp.custom_route("/health", methods=["GET"])
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "OK"})

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
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
        logger.debug(f"Run cmd: host={host}, cmd={cmd}")
        if not host or not cmd:
            logger.error("Need host, cmd")
            return ResponseBuilder.build(
                400,
                "Need host, cmd",
                {"host": host, "cmd": cmd},
                errors=["Need host, cmd"],
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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
                    asyncio.ensure_future(
                        ctx.report_progress(progress=transf, total=total)
                    )

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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
        lpath = os.path.abspath(os.path.expanduser(lpath))
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
                    asyncio.ensure_future(
                        ctx.report_progress(progress=transf, total=total)
                    )

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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
        logger.debug(f"Test key: host={host}, key={key}")
        if not host or not key:
            logger.error("Need host, key")
            return ResponseBuilder.build(
                400,
                "Need host, key",
                {"host": host, "key": key},
                errors=["Need host, key"],
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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
            description="Remote SSH config.",
            default=os.path.expanduser("~/.ssh/config"),
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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
            description="Remote host.",
            default=os.environ.get("TUNNEL_REMOTE_HOST", None),
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
        logger.debug(
            f"Setup SSH all: inv={inventory}, group={group}, key_type={key_type}"
        )
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
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
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
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
                    futures = [
                        ex.submit(lambda h: asyncio.run(run_host(h, ctx)), h)
                        for h in hosts
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
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
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
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
                    futures = [
                        ex.submit(lambda h: asyncio.run(rotate_host(h)), h)
                        for h in hosts
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
        lpath = os.path.abspath(os.path.expanduser(lpath))  # Normalize
        rpath = os.path.expanduser(rpath)
        logger.debug(
            f"Normalized: lpath={lpath} (exists={os.path.exists(lpath)}, isfile={os.path.isfile(lpath)}), rpath={rpath}, CWD={os.getcwd()}"
        )
        logger.debug(
            f"Upload file all: inv={inventory}, group={group}, local={lpath}, remote={rpath}"
        )
        if not inventory or not lpath or not rpath:
            logger.error("Need inventory, lpath, rpath")
            return ResponseBuilder.build(
                400,
                "Need inventory, lpath, rpath",
                {
                    "inventory": inventory,
                    "group": group,
                    "lpath": lpath,
                    "rpath": rpath,
                },
                errors=["Need inventory, lpath, rpath"],
            )
        if not os.path.exists(lpath) or not os.path.isfile(lpath):
            logger.error(f"Invalid file: {lpath}")
            return ResponseBuilder.build(
                400,
                f"Invalid file: {lpath}",
                {
                    "inventory": inventory,
                    "group": group,
                    "lpath": lpath,
                    "rpath": rpath,
                },
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
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
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
                with concurrent.futures.ThreadPoolExecutor(
                    max_workers=max_threads
                ) as ex:
                    futures = [
                        ex.submit(lambda h: asyncio.run(receive_host(h)), h)
                        for h in hosts
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
    )
    parser.add_argument(
        "-t",
        "--transport",
        default=DEFAULT_TRANSPORT,
        choices=["stdio", "streamable-http", "sse"],
        help="Transport method: 'stdio', 'streamable-http', or 'sse' [legacy] (default: stdio)",
    )
    parser.add_argument(
        "-s",
        "--host",
        default=DEFAULT_HOST,
        help="Host address for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
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
    parser.add_argument(
        "--token-algorithm",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_ALGORITHM"),
        choices=[
            "HS256",
            "HS384",
            "HS512",
            "RS256",
            "RS384",
            "RS512",
            "ES256",
            "ES384",
            "ES512",
        ],
        help="JWT signing algorithm (required for HMAC or static key). Auto-detected for JWKS.",
    )
    parser.add_argument(
        "--token-secret",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_PUBLIC_KEY"),
        help="Shared secret for HMAC (HS*) or PEM public key for static asymmetric verification.",
    )
    parser.add_argument(
        "--token-public-key",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_PUBLIC_KEY"),
        help="Path to PEM public key file or inline PEM string (for static asymmetric keys).",
    )
    parser.add_argument(
        "--required-scopes",
        default=os.getenv("FASTMCP_SERVER_AUTH_JWT_REQUIRED_SCOPES"),
        help="Comma-separated list of required scopes (e.g., gitlab.read,gitlab.write).",
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
    # Delegation params
    parser.add_argument(
        "--enable-delegation",
        action="store_true",
        default=to_boolean(os.environ.get("ENABLE_DELEGATION", "False")),
        help="Enable OIDC token delegation",
    )
    parser.add_argument(
        "--audience",
        default=os.environ.get("AUDIENCE", None),
        help="Audience for the delegated token",
    )
    parser.add_argument(
        "--delegated-scopes",
        default=os.environ.get("DELEGATED_SCOPES", "api"),
        help="Scopes for the delegated token (space-separated)",
    )
    parser.add_argument(
        "--openapi-file",
        default=None,
        help="Path to the OpenAPI JSON file to import additional tools from",
    )
    parser.add_argument(
        "--openapi-base-url",
        default=None,
        help="Base URL for the OpenAPI client (overrides instance URL)",
    )
    parser.add_argument(
        "--openapi-use-token",
        action="store_true",
        help="Use the incoming Bearer token (from MCP request) to authenticate OpenAPI import",
    )

    parser.add_argument(
        "--openapi-username",
        default=os.getenv("OPENAPI_USERNAME"),
        help="Username for basic auth during OpenAPI import",
    )

    parser.add_argument(
        "--openapi-password",
        default=os.getenv("OPENAPI_PASSWORD"),
        help="Password for basic auth during OpenAPI import",
    )

    parser.add_argument(
        "--openapi-client-id",
        default=os.getenv("OPENAPI_CLIENT_ID"),
        help="OAuth client ID for OpenAPI import",
    )

    parser.add_argument(
        "--openapi-client-secret",
        default=os.getenv("OPENAPI_CLIENT_SECRET"),
        help="OAuth client secret for OpenAPI import",
    )

    args = parser.parse_args()

    if args.port < 0 or args.port > 65535:
        print(f"Error: Port {args.port} is out of valid range (0-65535).")
        sys.exit(1)

    # Update config with CLI arguments
    config["enable_delegation"] = args.enable_delegation
    config["audience"] = args.audience or config["audience"]
    config["delegated_scopes"] = args.delegated_scopes or config["delegated_scopes"]
    config["oidc_config_url"] = args.oidc_config_url or config["oidc_config_url"]
    config["oidc_client_id"] = args.oidc_client_id or config["oidc_client_id"]
    config["oidc_client_secret"] = (
        args.oidc_client_secret or config["oidc_client_secret"]
    )

    # Configure delegation if enabled
    if config["enable_delegation"]:
        if args.auth_type != "oidc-proxy":
            logger.error("Token delegation requires auth-type=oidc-proxy")
            sys.exit(1)
        if not config["audience"]:
            logger.error("audience is required for delegation")
            sys.exit(1)
        if not all(
            [
                config["oidc_config_url"],
                config["oidc_client_id"],
                config["oidc_client_secret"],
            ]
        ):
            logger.error(
                "Delegation requires complete OIDC configuration (oidc-config-url, oidc-client-id, oidc-client-secret)"
            )
            sys.exit(1)

        # Fetch OIDC configuration to get token_endpoint
        try:
            logger.info(
                "Fetching OIDC configuration",
                extra={"oidc_config_url": config["oidc_config_url"]},
            )
            oidc_config_resp = requests.get(config["oidc_config_url"])
            oidc_config_resp.raise_for_status()
            oidc_config = oidc_config_resp.json()
            config["token_endpoint"] = oidc_config.get("token_endpoint")
            if not config["token_endpoint"]:
                logger.error("No token_endpoint found in OIDC configuration")
                raise ValueError("No token_endpoint found in OIDC configuration")
            logger.info(
                "OIDC configuration fetched successfully",
                extra={"token_endpoint": config["token_endpoint"]},
            )
        except Exception as e:
            print(f"Failed to fetch OIDC configuration: {e}")
            logger.error(
                "Failed to fetch OIDC configuration",
                extra={"error_type": type(e).__name__, "error_message": str(e)},
            )
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
        auth = StaticTokenVerifier(
            tokens={
                "test-token": {"client_id": "test-user", "scopes": ["read", "write"]},
                "admin-token": {"client_id": "admin", "scopes": ["admin"]},
            }
        )
    elif args.auth_type == "jwt":
        # Fallback to env vars if not provided via CLI
        jwks_uri = args.token_jwks_uri or os.getenv("FASTMCP_SERVER_AUTH_JWT_JWKS_URI")
        issuer = args.token_issuer or os.getenv("FASTMCP_SERVER_AUTH_JWT_ISSUER")
        audience = args.token_audience or os.getenv("FASTMCP_SERVER_AUTH_JWT_AUDIENCE")
        algorithm = args.token_algorithm
        secret_or_key = args.token_secret or args.token_public_key
        public_key_pem = None

        if not (jwks_uri or secret_or_key):
            logger.error(
                "JWT auth requires either --token-jwks-uri or --token-secret/--token-public-key"
            )
            sys.exit(1)
        if not (issuer and audience):
            logger.error("JWT requires --token-issuer and --token-audience")
            sys.exit(1)

        # Load static public key from file if path is given
        if args.token_public_key and os.path.isfile(args.token_public_key):
            try:
                with open(args.token_public_key, "r") as f:
                    public_key_pem = f.read()
                logger.info(f"Loaded static public key from {args.token_public_key}")
            except Exception as e:
                print(f"Failed to read public key file: {e}")
                logger.error(f"Failed to read public key file: {e}")
                sys.exit(1)
        elif args.token_public_key:
            public_key_pem = args.token_public_key  # Inline PEM

        # Validation: Conflicting options
        if jwks_uri and (algorithm or secret_or_key):
            logger.warning(
                "JWKS mode ignores --token-algorithm and --token-secret/--token-public-key"
            )

        # HMAC mode
        if algorithm and algorithm.startswith("HS"):
            if not secret_or_key:
                logger.error(f"HMAC algorithm {algorithm} requires --token-secret")
                sys.exit(1)
            if jwks_uri:
                logger.error("Cannot use --token-jwks-uri with HMAC")
                sys.exit(1)
            public_key = secret_or_key
        else:
            public_key = public_key_pem

        # Required scopes
        required_scopes = None
        if args.required_scopes:
            required_scopes = [
                s.strip() for s in args.required_scopes.split(",") if s.strip()
            ]

        try:
            auth = JWTVerifier(
                jwks_uri=jwks_uri,
                public_key=public_key,
                issuer=issuer,
                audience=audience,
                algorithm=(
                    algorithm if algorithm and algorithm.startswith("HS") else None
                ),
                required_scopes=required_scopes,
            )
            logger.info(
                "JWTVerifier configured",
                extra={
                    "mode": (
                        "JWKS"
                        if jwks_uri
                        else (
                            "HMAC"
                            if algorithm and algorithm.startswith("HS")
                            else "Static Key"
                        )
                    ),
                    "algorithm": algorithm,
                    "required_scopes": required_scopes,
                },
            )
        except Exception as e:
            print(f"Failed to initialize JWTVerifier: {e}")
            logger.error(f"Failed to initialize JWTVerifier: {e}")
            sys.exit(1)
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
                "oauth-proxy requires oauth-upstream-auth-endpoint, oauth-upstream-token-endpoint, "
                "oauth-upstream-client-id, oauth-upstream-client-secret, oauth-base-url, token-jwks-uri, "
                "token-issuer, token-audience"
            )
            logger.error(
                "oauth-proxy requires oauth-upstream-auth-endpoint, oauth-upstream-token-endpoint, "
                "oauth-upstream-client-id, oauth-upstream-client-secret, oauth-base-url, token-jwks-uri, "
                "token-issuer, token-audience",
                extra={
                    "auth_endpoint": args.oauth_upstream_auth_endpoint,
                    "token_endpoint": args.oauth_upstream_token_endpoint,
                    "client_id": args.oauth_upstream_client_id,
                    "base_url": args.oauth_base_url,
                    "jwks_uri": args.token_jwks_uri,
                    "issuer": args.token_issuer,
                    "audience": args.token_audience,
                },
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
            logger.error(
                "oidc-proxy requires oidc-config-url, oidc-client-id, oidc-client-secret, oidc-base-url",
                extra={
                    "config_url": args.oidc_config_url,
                    "client_id": args.oidc_client_id,
                    "base_url": args.oidc_base_url,
                },
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
            logger.error(
                "remote-oauth requires remote-auth-servers, remote-base-url, token-jwks-uri, token-issuer, token-audience",
                extra={
                    "auth_servers": args.remote_auth_servers,
                    "base_url": args.remote_base_url,
                    "jwks_uri": args.token_jwks_uri,
                    "issuer": args.token_issuer,
                    "audience": args.token_audience,
                },
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

    # === 2. Build Middleware List ===
    middlewares: List[
        Union[
            UserTokenMiddleware,
            ErrorHandlingMiddleware,
            RateLimitingMiddleware,
            TimingMiddleware,
            LoggingMiddleware,
            JWTClaimsLoggingMiddleware,
            EunomiaMcpMiddleware,
        ]
    ] = [
        ErrorHandlingMiddleware(include_traceback=True, transform_errors=True),
        RateLimitingMiddleware(max_requests_per_second=10.0, burst_capacity=20),
        TimingMiddleware(),
        LoggingMiddleware(),
        JWTClaimsLoggingMiddleware(),
    ]
    if config["enable_delegation"] or args.auth_type == "jwt":
        middlewares.insert(0, UserTokenMiddleware(config=config))  # Must be first

    if args.eunomia_type in ["embedded", "remote"]:
        try:
            from eunomia_mcp import create_eunomia_middleware

            policy_file = args.eunomia_policy_file or "mcp_policies.json"
            eunomia_endpoint = (
                args.eunomia_remote_url if args.eunomia_type == "remote" else None
            )
            eunomia_mw = create_eunomia_middleware(
                policy_file=policy_file, eunomia_endpoint=eunomia_endpoint
            )
            middlewares.append(eunomia_mw)
            logger.info(f"Eunomia middleware enabled ({args.eunomia_type})")
        except Exception as e:
            print(f"Failed to load Eunomia middleware: {e}")
            logger.error("Failed to load Eunomia middleware", extra={"error": str(e)})
            sys.exit(1)

    mcp = FastMCP(name="TunnelManagerMCP", auth=auth)
    register_tools(mcp)

    for mw in middlewares:
        mcp.add_middleware(mw)

    print("\nStarting Tunnel Manager MCP Server")
    print(f"  Transport: {args.transport.upper()}")
    print(f"  Auth: {args.auth_type}")
    print(f"  Delegation: {'ON' if config['enable_delegation'] else 'OFF'}")
    print(f"  Eunomia: {args.eunomia_type}")

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
    tunnel_manager_mcp()
