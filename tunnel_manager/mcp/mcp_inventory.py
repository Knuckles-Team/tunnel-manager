"""MCP tools for inventory operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import asyncio
import concurrent.futures
import logging
import os
import subprocess

from agent_utilities.base_utilities import to_boolean, to_integer
from agent_utilities.mcp_utilities import ctx_log, ctx_progress
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.mcp_server import (
    _DEFAULT_INVENTORY_PATH,
    ResponseBuilder,
    load_inventory,
)
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger("tunnel-manager-mcp")


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
