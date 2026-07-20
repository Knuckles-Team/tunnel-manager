"""MCP tools for remote operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import logging
import os
import subprocess

from agent_utilities.base_utilities import to_integer
from agent_utilities.core.config import setting
from agent_utilities.mcp.concurrency import run_blocking
from agent_utilities.mcp.context_helpers import (
    ctx_confirm_destructive,
    ctx_log,
    ctx_progress,
)
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.connection_security import (
    max_transfer_bytes,
    resolve_secret_ref,
    validate_timeout,
)
from tunnel_manager.mcp_server import ResponseBuilder, _resolve_host
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger("tunnel-manager-mcp")


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
            default=to_integer(setting("TUNNEL_REMOTE_PORT", "22")),
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
            if os.path.getsize(_lpath) > max_transfer_bytes():
                return ResponseBuilder.build(
                    400,
                    "Managed file transfer limit exceeded",
                    {},
                    errors=["Managed file transfer limit exceeded"],
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

        elif action == "test_key_auth":
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

        elif action == "setup_passwordless":
            _key = key or os.path.expanduser("~/.ssh/id_rsa")
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
                if not os.path.exists(pub_key):
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
                                _key,
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
                                _key,
                                "-N",
                                "",
                            ],
                            check=True,
                            timeout=30,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
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
                msg = await run_blocking(
                    t.remove_host_key, known_hosts_path=_known_hosts
                )
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
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: run_command, send_file, receive_file, check_ssh, test_key_auth, setup_passwordless, copy_ssh_config, rotate_key, remove_host_key"
                ],
            )
