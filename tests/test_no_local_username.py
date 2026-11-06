"""CONN-TUNNEL-MANAGER-INVENTORY-R003: SSH works with no local username (uid without passwd entry)."""

from __future__ import annotations

import getpass
import logging

import pytest

from tunnel_manager.models import HostConfig
from tunnel_manager.tunnel_manager import Tunnel


def _no_local_user(monkeypatch):
    for var in ("USER", "LOGNAME", "LNAME", "USERNAME"):
        monkeypatch.delenv(var, raising=False)

    def boom():
        raise OSError("No username set in the environment")

    monkeypatch.setattr(getpass, "getuser", boom)


def test_tunnel_uses_explicit_user_without_local_username(monkeypatch, tmp_path):
    _no_local_user(monkeypatch)
    t = Tunnel(
        config=HostConfig(hostname="192.0.2.10", user="inventoryuser"),
        ssh_config_file=str(tmp_path / "absent"),
    )
    assert t.username == "inventoryuser"


def test_tunnel_without_any_username_still_fails_clearly(monkeypatch, tmp_path):
    _no_local_user(monkeypatch)
    with pytest.raises((OSError, ValueError)):
        Tunnel(remote_host="192.0.2.10", ssh_config_file=str(tmp_path / "absent"))


def _run_command_args(**given):
    """Arguments of the remote run_command implementation; unset ones are empty."""
    args = dict(
        action="run_command", host="", user=None, password_ref=None, password=None,
        port=None, id_file=None, certificate=None, proxy=None, cfg=None,
        cmd="uptime", lpath="", rpath="", key="", key_type="ed25519", new_key="",
        lcfg="", rcfg="", known_hosts="", timeout=5, ctx=None,
    )  # fmt: skip
    args.update(given)
    return args


def test_tool_error_path_logs_cause(monkeypatch, caplog):
    import asyncio

    from tunnel_manager import mcp_server as mcp_remote

    def boom(**kwargs):
        raise OSError("No username set in the environment")

    monkeypatch.setattr(mcp_remote, "_resolve_host", boom)
    caplog.set_level(logging.ERROR, logger="tunnel-manager-mcp")
    result = asyncio.run(
        mcp_remote._tm_remote_run_command(
            **_run_command_args(host="r710", user=None, port=22)
        )
    )
    assert "OSError" in str(result)
    assert "Cmd fail" in caplog.text


def test_run_command_returns_specific_policy_cause(
    monkeypatch, tmp_path, grant_broad_access
):
    import asyncio

    from tunnel_manager import mcp_server as mcp_remote

    key = tmp_path / "id_rsa"
    key.write_text("x")
    grant_broad_access(key)
    monkeypatch.setenv("TUNNEL_IDENTITY_FILE", str(key))
    result = asyncio.run(
        mcp_remote._tm_remote_run_command(
            **_run_command_args(
                host="192.0.2.10",
                user="u",
                port=22,
                id_file=str(key),
                cfg=str(tmp_path / "nocfg"),
            )
        )
    )
    text = str(result)
    assert "permissions are unsafe" in text
    assert "0644" in text or "S-1-1-0" in text
