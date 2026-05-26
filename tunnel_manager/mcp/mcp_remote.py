"""MCP tools for remote operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import asyncio
import logging
import os
import subprocess

from agent_utilities.base_utilities import to_integer
from agent_utilities.mcp_utilities import ctx_confirm_destructive, ctx_log, ctx_progress
from fastmcp import Context, FastMCP
from pydantic import Field

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
                out, error = t.run_command(cmd)
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
