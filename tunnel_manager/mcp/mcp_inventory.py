"""MCP tools for inventory operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import asyncio
import concurrent.futures
import logging
import os
import shlex
import subprocess

from agent_utilities.base_utilities import to_boolean, to_integer
from agent_utilities.core.config import setting
from agent_utilities.mcp.concurrency import run_blocking
from agent_utilities.mcp.context_helpers import (
    ctx_log,
    ctx_progress,
)
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.connection_security import (
    max_concurrency,
    max_transfer_bytes,
    validate_public_key,
    validate_timeout,
)
from tunnel_manager.mcp_server import (
    _DEFAULT_INVENTORY_PATH,
    ResponseBuilder,
    load_inventory,
    resolve_single_host,
)
from tunnel_manager.models import HostConfig
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger("tunnel-manager-mcp")


async def _tm_inventory_configure_key_auth(
    action: str,
    inventory,
    group,
    parallel,
    max_threads,
    key,
    key_type,
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
        if not os.path.exists(_key):
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
        with open(pub_key) as f:
            pub = validate_public_key(f.read())
        hosts, error = load_inventory(inventory, group, logger)
        if error:
            return error
        total = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def setup_host(h: dict, ctx: Context) -> dict:
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
                await run_blocking(
                    t.run_command, "chmod 600 ~/.ssh/authorized_keys"
                )
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
                                "message": "Parallel error",
                                "errors": [type(e).__name__],
                            }
                        )
                        errors.append(type(e).__name__)
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
        ctx_log(ctx, logger, "error", "Setup all fail")
        return ResponseBuilder.build(
            500,
            "Setup all fail",
            {"inventory": inventory, "group": group, "key_type": key_type},
            type(e).__name__,
        )



async def _tm_inventory_mesh_bootstrap(
    action: str,
    inventory,
    group,
    parallel,
    max_threads,
    key,
    key_type,
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
    action: str,
    inventory,
    group,
    host,
    preview,
    parallel,
    max_threads,
    cmd,
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
            return ResponseBuilder.build(
                200,
                f"Preview: '{cmd}' would run on {len(hosts)} host(s)"
                + (f" (host={host})" if host else f" (group={group})"),
                {
                    "inventory": inventory,
                    "group": group,
                    "host": host,
                    "cmd": cmd,
                    "resolved_hosts": resolved_hosts,
                    "preview": True,
                },
                errors=[],
            )
        if ctx:
            await ctx.report_progress(progress=0, total=total)

        async def run_host(h: dict, ctx: Context) -> dict:
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
                out, error = await run_blocking(
                    t.run_command, cmd, timeout=timeout
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
                                "message": "Parallel error",
                                "stdout": "",
                                "stderr": type(e).__name__,
                                "errors": [type(e).__name__],
                            }
                        )
                        errors.append(type(e).__name__)
        else:
            for i, h in enumerate(hosts, 1):
                r = await run_host(h, ctx)
                results.append(r)
                errors.extend(r["errors"])
                if ctx:
                    await ctx.report_progress(progress=i, total=total)
        target_label = f"host={host}" if host else f"group={group}"
        msg = (
            f"Cmd '{cmd}' done on {target_label}"
            if not errors
            else f"Cmd '{cmd}' failed for some in {target_label}"
        )
        return ResponseBuilder.build(
            200 if not errors else 500,
            msg,
            {
                "inventory": inventory,
                "group": group,
                "host": host,
                "cmd": cmd,
                "resolved_hosts": resolved_hosts,
                "host_results": results,
            },
            error="; ".join(errors),
            files=[],
            locations=[],
            errors=errors,
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
    action: str,
    inventory,
    group,
    parallel,
    max_threads,
    cfg,
    rmt_cfg,
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
        results, files, locations, errors = [], [], [], []

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
                                "message": "Parallel error",
                                "errors": [type(e).__name__],
                            }
                        )
                        errors.append(type(e).__name__)
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
    action: str,
    inventory,
    group,
    parallel,
    max_threads,
    key,
    key_type,
    key_pfx,
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
        results, files, locations, errors = [], [], [], []

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
                                "message": "Parallel error",
                                "errors": [type(e).__name__],
                                "new_key_path": None,
                            }
                        )
                        errors.append(type(e).__name__)
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
    action: str,
    inventory,
    group,
    parallel,
    max_threads,
    lpath,
    rpath,
    ctx,
) -> dict:
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
    if os.path.getsize(_lpath) > max_transfer_bytes():
        return ResponseBuilder.build(
            400,
            "Managed file transfer limit exceeded",
            {},
            errors=["Managed file transfer limit exceeded"],
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
                                "message": "Parallel error",
                                "errors": [type(e).__name__],
                            }
                        )
                        errors.append(type(e).__name__)
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
    action: str,
    inventory,
    group,
    parallel,
    max_threads,
    rpath,
    lpath_prefix,
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
                                "message": "Parallel error",
                                "errors": [type(e).__name__],
                                "local_path": None,
                            }
                        )
                        errors.append(type(e).__name__)
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
            default=to_boolean(setting("TUNNEL_PARALLEL", False)),
            description="Run parallel.",
        ),
        max_threads: int = Field(
            default=to_integer(setting("TUNNEL_MAX_THREADS", "6")),
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

        if action == "configure_key_auth":
            return await _tm_inventory_configure_key_auth(
                action, inventory, group, parallel, max_threads, key, key_type, ctx
            )
        elif action == "mesh_bootstrap":
            return await _tm_inventory_mesh_bootstrap(
                action, inventory, group, parallel, max_threads, key, key_type, ctx
            )
        elif action == "run_command":
            return await _tm_inventory_run_command(
                action, inventory, group, host, preview, parallel, max_threads, cmd, timeout, ctx
            )
        elif action == "copy_ssh_config":
            return await _tm_inventory_copy_ssh_config(
                action, inventory, group, parallel, max_threads, cfg, rmt_cfg, ctx
            )
        elif action == "rotate_key":
            return await _tm_inventory_rotate_key(
                action, inventory, group, parallel, max_threads, key, key_type, key_pfx, ctx
            )
        elif action == "send_file":
            return await _tm_inventory_send_file(
                action, inventory, group, parallel, max_threads, lpath, rpath, ctx
            )
        elif action == "receive_file":
            return await _tm_inventory_receive_file(
                action, inventory, group, parallel, max_threads, rpath, lpath_prefix, ctx
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
