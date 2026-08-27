"""CXA-FL-TUNNELMANAGER-01 characterization tests for
``tunnel_manager.mcp.mcp_inventory.register_inventory_tools.tm_inventory``
(CCN 116).

This module has ZERO prior test coverage anywhere in the suite: unlike its
near-identical sibling in ``tunnel_manager/mcp_server.py`` (covered by
``tests/test_mcp_server.py`` / ``tests/test_action_discovery.py``), nothing
imports ``tunnel_manager.mcp.mcp_inventory`` except its own package
``__init__.py``. It is not wired into the live MCP server (see the
CXA-FL-TUNNELMANAGER-01 bug report for that finding) but it is NOT dead code
either -- it is exported in ``tunnel_manager/mcp/__init__.py.__all__``, which
disqualifies it from the five-point deletion bar. These tests are therefore
this function's first-ever characterization, one per action plus guard-clause
cases, using the same MagicMock-decorator-capture + patched Tunnel/
load_inventory pattern already proven in ``tests/test_mcp_server.py``.
"""

import os
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest


def _capture_tm_inventory():
    from tunnel_manager.mcp.mcp_inventory import register_inventory_tools

    mcp = MagicMock()
    captured = {}

    def decorator(fn):
        captured["fn"] = fn
        return fn

    mcp.tool.return_value = decorator
    register_inventory_tools(mcp)
    assert "fn" in captured
    return captured["fn"]


def _base_kwargs(**overrides):
    kwargs = dict(
        action="run_command",
        inventory="/fake/inventory.yaml",
        group="all",
        host="",
        preview=False,
        parallel=False,
        max_threads=6,
        cmd="",
        key="",
        key_type="ed25519",
        key_pfx="",
        cfg="",
        rmt_cfg="~/.ssh/config",
        lpath="",
        rpath="",
        lpath_prefix="",
        timeout=60,
        ctx=AsyncMock(),
    )
    kwargs.update(overrides)
    return kwargs


@pytest.fixture
def mock_hosts():
    return [
        {
            "hostname": "192.0.2.20",
            "username": "testuser",
            "key_path": "/fake/key",
        }
    ]


@pytest.mark.asyncio
async def test_unknown_action_is_rejected(mock_hosts):
    """CXA-FL-TUNNELMANAGER-01 characterization: an action string outside the
    7 known actions is REJECTED with a 400 (this module does not call
    resolve_action, so this is a reachable guard, unlike the byte-identical
    branch in mcp_server.py which is masked by resolve_action upstream)."""
    fn = _capture_tm_inventory()
    result = await fn(**_base_kwargs(action="definitely_not_a_real_action"))
    assert result["status_code"] == 400
    assert "Unknown action" in result["message"]


@pytest.mark.asyncio
async def test_run_command_forwards_timeout_and_cmd(mock_hosts):
    fn = _capture_tm_inventory()
    with (
        patch(
            "tunnel_manager.mcp.mcp_inventory.load_inventory",
            return_value=(mock_hosts, None),
        ),
        patch("tunnel_manager.mcp.mcp_inventory.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel.run_command.return_value = ("stdout output", "stderr output")
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(action="run_command", cmd="uptime", timeout=45)
        )

        mock_tunnel_cls.assert_called_once()
        mock_tunnel.run_command.assert_called_once_with("uptime", timeout=45)
        assert result["status_code"] == 200
        assert result["details"]["host_results"][0]["stdout"] == "stdout output"


@pytest.mark.asyncio
async def test_run_command_needs_cmd(mock_hosts):
    fn = _capture_tm_inventory()
    result = await fn(**_base_kwargs(action="run_command", cmd=""))
    assert result["status_code"] == 400
    assert "Need cmd" in result["message"]


@pytest.mark.asyncio
async def test_configure_key_auth_success(tmp_path, mock_hosts):
    key_path = tmp_path / "id_ed25519"
    pub_path = tmp_path / "id_ed25519.pub"
    key_path.write_text("fake-private-key")
    pub_path.write_text("ssh-ed25519 " + "A" * 64 + " test@host\n")

    fn = _capture_tm_inventory()
    with (
        patch(
            "tunnel_manager.mcp.mcp_inventory.load_inventory",
            return_value=(mock_hosts, None),
        ),
        patch("tunnel_manager.mcp.mcp_inventory.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel.test_key_auth.return_value = (True, "ok")
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="configure_key_auth",
                key=str(key_path),
                key_type="ed25519",
            )
        )

        mock_tunnel.setup_passwordless_ssh.assert_called_once()
        assert result["status_code"] == 200
        assert result["details"]["host_results"][0]["status"] == "success"


@pytest.mark.asyncio
async def test_configure_key_auth_rejects_bad_key_type(mock_hosts):
    fn = _capture_tm_inventory()
    result = await fn(**_base_kwargs(action="configure_key_auth", key_type="dsa"))
    assert result["status_code"] == 400
    assert "key_type" in result["message"]


@pytest.mark.asyncio
async def test_mesh_bootstrap_success(mock_hosts):
    fn = _capture_tm_inventory()
    fake_result = {
        "status": "success",
        "host_results": [{"hostname": "192.0.2.20", "status": "success"}],
        "errors": [],
    }
    with patch(
        "tunnel_manager.mcp.mcp_inventory.Tunnel.setup_full_mesh_ssh",
        return_value=fake_result,
    ) as mock_mesh:
        result = await fn(**_base_kwargs(action="mesh_bootstrap", key_type="ed25519"))
        mock_mesh.assert_called_once()
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_mesh_bootstrap_rejects_bad_key_type(mock_hosts):
    fn = _capture_tm_inventory()
    result = await fn(**_base_kwargs(action="mesh_bootstrap", key_type="dsa"))
    assert result["status_code"] == 400
    assert "key_type" in result["message"]


@pytest.mark.asyncio
async def test_copy_ssh_config_success(tmp_path, mock_hosts):
    cfg_path = tmp_path / "config"
    cfg_path.write_text("Host *\n")

    fn = _capture_tm_inventory()
    with (
        patch(
            "tunnel_manager.mcp.mcp_inventory.load_inventory",
            return_value=(mock_hosts, None),
        ),
        patch("tunnel_manager.mcp.mcp_inventory.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(action="copy_ssh_config", cfg=str(cfg_path))
        )

        mock_tunnel.copy_ssh_config.assert_called_once_with(
            str(cfg_path), "~/.ssh/config"
        )
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_copy_ssh_config_needs_existing_cfg_file(tmp_path):
    fn = _capture_tm_inventory()
    result = await fn(
        **_base_kwargs(
            action="copy_ssh_config", cfg=str(tmp_path / "does-not-exist")
        )
    )
    assert result["status_code"] == 400
    assert "No cfg file" in result["message"]


@pytest.mark.asyncio
async def test_rotate_key_success(mock_hosts):
    fn = _capture_tm_inventory()
    with (
        patch(
            "tunnel_manager.mcp.mcp_inventory.load_inventory",
            return_value=(mock_hosts, None),
        ),
        patch("tunnel_manager.mcp.mcp_inventory.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="rotate_key", key_pfx="/fake/id_", key_type="ed25519"
            )
        )

        mock_tunnel.rotate_ssh_key.assert_called_once()
        assert result["status_code"] == 200
        # sanitize_for_persistence (inside ResponseBuilder.build) redacts the
        # IPv4-looking hostname out of the persisted payload -- expected.
        assert result["details"]["host_results"][0]["new_key_path"].startswith(
            "/fake/id_"
        )


@pytest.mark.asyncio
async def test_send_file_success(tmp_path, mock_hosts):
    local_file = tmp_path / "payload.txt"
    local_file.write_text("hello")

    fn = _capture_tm_inventory()
    with (
        patch(
            "tunnel_manager.mcp.mcp_inventory.load_inventory",
            return_value=(mock_hosts, None),
        ),
        patch("tunnel_manager.mcp.mcp_inventory.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="send_file", lpath=str(local_file), rpath="/remote/payload.txt"
            )
        )

        mock_tunnel.send_file.assert_called_once_with(
            str(local_file), "/remote/payload.txt"
        )
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_send_file_rejects_missing_local_file(tmp_path):
    fn = _capture_tm_inventory()
    result = await fn(
        **_base_kwargs(
            action="send_file",
            lpath=str(tmp_path / "missing.txt"),
            rpath="/remote/x",
        )
    )
    assert result["status_code"] == 400
    assert "Invalid file" in result["message"]


@pytest.mark.asyncio
async def test_receive_file_success(tmp_path, mock_hosts):
    dest_prefix = tmp_path / "downloads"

    fn = _capture_tm_inventory()
    with (
        patch(
            "tunnel_manager.mcp.mcp_inventory.load_inventory",
            return_value=(mock_hosts, None),
        ),
        patch("tunnel_manager.mcp.mcp_inventory.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="receive_file",
                rpath="/remote/payload.txt",
                lpath_prefix=str(dest_prefix),
            )
        )

        mock_tunnel.receive_file.assert_called_once_with(
            "/remote/payload.txt",
            os.path.join(str(dest_prefix), "192.0.2.20", "payload.txt"),
        )
        assert result["status_code"] == 200
        assert dest_prefix.joinpath("192.0.2.20").is_dir()


@pytest.mark.asyncio
async def test_receive_file_needs_rpath_and_lpath_prefix():
    fn = _capture_tm_inventory()
    result = await fn(**_base_kwargs(action="receive_file", rpath="", lpath_prefix=""))
    assert result["status_code"] == 400
    assert "Need rpath, lpath_prefix" in result["message"]
