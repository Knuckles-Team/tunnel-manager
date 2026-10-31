"""TM-INVENTORY-R003: SSH works with no local username (uid without passwd entry)."""

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


def test_tool_error_path_logs_cause(monkeypatch, caplog):
    import asyncio

    from tunnel_manager.mcp import mcp_remote

    def boom(**kwargs):
        raise OSError("No username set in the environment")

    monkeypatch.setattr(mcp_remote, "_resolve_host", boom)
    caplog.set_level(logging.ERROR, logger="tunnel-manager-mcp")
    result = asyncio.run(
        mcp_remote._tm_remote_run_command(
            "r710", None, None, 22, None, None, None, None, "uptime", 5, None
        )
    )
    assert "OSError" in str(result)
    assert "No username set in the environment" in caplog.text


def test_run_command_returns_specific_policy_cause(
    monkeypatch, tmp_path, grant_broad_access
):
    import asyncio

    from tunnel_manager.mcp import mcp_remote

    key = tmp_path / "id_rsa"
    key.write_text("x")
    grant_broad_access(key)
    monkeypatch.setenv("TUNNEL_IDENTITY_FILE", str(key))
    result = asyncio.run(
        mcp_remote._tm_remote_run_command(
            "192.0.2.10",
            "u",
            None,
            22,
            str(key),
            None,
            None,
            str(tmp_path / "nocfg"),
            "uptime",
            5,
            None,
        )
    )
    text = str(result)
    assert "permissions are unsafe" in text
    assert "0644" in text or "S-1-1-0" in text
