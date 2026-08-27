"""CXA-FL-TUNNELMANAGER-01 characterization tests for
``tunnel_manager.mcp.mcp_remote.register_remote_tools.tm_remote`` (CCN 82).

Like ``tunnel_manager.mcp.mcp_inventory``, nothing in the suite exercised this
module's *behavior* before: ``tests/test_connection_security.py`` only checks
its tool schema (no ``password`` param, has ``password_ref``) via a fake
``mcp.tool()`` decorator, never invokes the registered function. These tests
are this function's first-ever behavioral characterization: one per action,
patterned on the MagicMock-decorator-capture technique already proven in
``tests/test_mcp_server.py`` / ``tests/test_mcp_mcp_inventory.py``.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _capture_tm_remote():
    from tunnel_manager.mcp.mcp_remote import register_remote_tools

    mcp = MagicMock()
    captured = {}

    def decorator(fn):
        captured["fn"] = fn
        return fn

    mcp.tool.return_value = decorator
    register_remote_tools(mcp)
    assert "fn" in captured
    return captured["fn"]


def _base_kwargs(**overrides):
    kwargs = dict(
        action="run_command",
        host="192.0.2.30",
        user="testuser",
        password_ref="",
        port=22,
        id_file="",
        certificate="",
        proxy="",
        cfg=os.path.expanduser("~/.ssh/config"),
        cmd="",
        lpath="",
        rpath="",
        key="",
        key_type="ed25519",
        new_key="",
        lcfg="",
        rcfg=os.path.expanduser("~/.ssh/config"),
        known_hosts=os.path.expanduser("~/.ssh/known_hosts"),
        timeout=60,
        ctx=AsyncMock(),
    )
    kwargs.update(overrides)
    return kwargs


def _fake_conf(**overrides):
    conf = {
        "hostname": "192.0.2.30",
        "user": "testuser",
        "password": None,
        "port": 22,
        "identity_file": None,
        "certificate_file": None,
        "proxy_command": None,
        "known_hosts_file": None,
    }
    conf.update(overrides)
    return conf


@pytest.mark.asyncio
async def test_unknown_action_is_rejected():
    fn = _capture_tm_remote()
    result = await fn(**_base_kwargs(action="definitely_not_a_real_action"))
    assert result["status_code"] == 400
    assert "Unknown action" in result["message"]


@pytest.mark.asyncio
async def test_invalid_password_ref_is_rejected():
    fn = _capture_tm_remote()
    result = await fn(**_base_kwargs(password_ref="not-a-valid-ref"))
    assert result["status_code"] == 400
    assert "credential" in result["message"].lower()


@pytest.mark.asyncio
async def test_run_command_success():
    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel.run_command.return_value = ("out", "err")
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(**_base_kwargs(action="run_command", cmd="uptime"))

        mock_tunnel.run_command.assert_called_once_with("uptime", timeout=60)
        mock_tunnel.close.assert_called_once()
        assert result["status_code"] == 200
        assert result["stdout"] == "out"


@pytest.mark.asyncio
async def test_run_command_needs_host_and_cmd():
    fn = _capture_tm_remote()
    result = await fn(**_base_kwargs(action="run_command", host="", cmd=""))
    assert result["status_code"] == 400
    assert "Need host, cmd" in result["message"]


@pytest.mark.asyncio
async def test_send_file_success(tmp_path):
    local_file = tmp_path / "payload.txt"
    local_file.write_text("hello")

    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
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
    fn = _capture_tm_remote()
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
async def test_receive_file_success(tmp_path):
    dest = tmp_path / "local.txt"

    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="receive_file", rpath="/remote/x.txt", lpath=str(dest)
            )
        )

        mock_tunnel.receive_file.assert_called_once_with("/remote/x.txt", str(dest))
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_receive_file_needs_host_rpath_lpath():
    fn = _capture_tm_remote()
    result = await fn(
        **_base_kwargs(action="receive_file", rpath="", lpath="")
    )
    assert result["status_code"] == 400
    assert "Need host, rpath, lpath" in result["message"]


@pytest.mark.asyncio
async def test_check_ssh_success():
    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel.check_ssh_server.return_value = (True, "reachable")
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(**_base_kwargs(action="check_ssh"))

        assert result["status_code"] == 200
        assert result["details"]["success"] is True


@pytest.mark.asyncio
async def test_check_ssh_needs_host():
    fn = _capture_tm_remote()
    result = await fn(**_base_kwargs(action="check_ssh", host=""))
    assert result["status_code"] == 400
    assert "Need host" in result["message"]


@pytest.mark.asyncio
async def test_test_key_auth_success():
    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel.test_key_auth.return_value = (True, "ok")
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(**_base_kwargs(action="test_key_auth", key="/fake/key"))

        mock_tunnel.test_key_auth.assert_called_once_with("/fake/key")
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_test_key_auth_needs_host_and_key():
    fn = _capture_tm_remote()
    with patch(
        "tunnel_manager.mcp.mcp_remote.setting", return_value=""
    ):
        result = await fn(**_base_kwargs(action="test_key_auth", host="", key=""))
    assert result["status_code"] == 400
    assert "Need host, key" in result["message"]


@pytest.mark.asyncio
async def test_setup_passwordless_success(tmp_path, monkeypatch):
    monkeypatch.setenv("CXA_FAKE_REF", "runtime-only-value")
    key_path = tmp_path / "id_ed25519"

    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(password="secret"), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
        patch("os.path.exists", return_value=True),
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="setup_passwordless",
                password_ref="env://CXA_FAKE_REF",
                key=str(key_path),
                key_type="ed25519",
            )
        )

        mock_tunnel.setup_passwordless_ssh.assert_called_once_with(
            local_key_path=str(key_path), key_type="ed25519"
        )
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_setup_passwordless_rejects_bad_key_type(monkeypatch):
    monkeypatch.setenv("CXA_FAKE_REF", "runtime-only-value")
    fn = _capture_tm_remote()
    result = await fn(
        **_base_kwargs(
            action="setup_passwordless",
            password_ref="env://CXA_FAKE_REF",
            key_type="dsa",
        )
    )
    assert result["status_code"] == 400
    assert "key_type" in result["message"]


@pytest.mark.asyncio
async def test_copy_ssh_config_success(tmp_path):
    local_cfg = tmp_path / "config"
    local_cfg.write_text("Host *\n")

    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(action="copy_ssh_config", lcfg=str(local_cfg))
        )

        mock_tunnel.copy_ssh_config.assert_called_once_with(
            str(local_cfg), os.path.expanduser("~/.ssh/config")
        )
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_copy_ssh_config_needs_host_and_lcfg():
    fn = _capture_tm_remote()
    result = await fn(**_base_kwargs(action="copy_ssh_config", lcfg=""))
    assert result["status_code"] == 400
    assert "Need host, lcfg" in result["message"]


@pytest.mark.asyncio
async def test_rotate_key_success(tmp_path):
    new_key = tmp_path / "id_new"

    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), "~/.ssh/config"),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
        patch("os.path.exists", return_value=True),
    ):
        mock_tunnel = MagicMock()
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(
            **_base_kwargs(
                action="rotate_key", new_key=str(new_key), key_type="ed25519"
            )
        )

        mock_tunnel.rotate_ssh_key.assert_called_once_with(
            str(new_key), key_type="ed25519"
        )
        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_rotate_key_needs_host_and_new_key():
    fn = _capture_tm_remote()
    result = await fn(**_base_kwargs(action="rotate_key", new_key=""))
    assert result["status_code"] == 400
    assert "Need host, new_key" in result["message"]


@pytest.mark.asyncio
async def test_remove_host_key_success():
    fn = _capture_tm_remote()
    with (
        patch(
            "tunnel_manager.mcp.mcp_remote._resolve_host",
            return_value=(_fake_conf(), None),
        ),
        patch("tunnel_manager.mcp.mcp_remote.Tunnel") as mock_tunnel_cls,
        patch(
            "tunnel_manager.mcp.mcp_remote.ctx_confirm_destructive",
            new=AsyncMock(return_value=True),
        ),
    ):
        mock_tunnel = MagicMock()
        mock_tunnel.remove_host_key.return_value = "Removed managed-host key"
        mock_tunnel_cls.return_value = mock_tunnel

        result = await fn(**_base_kwargs(action="remove_host_key"))

        assert result["status_code"] == 200


@pytest.mark.asyncio
async def test_remove_host_key_needs_confirmation():
    fn = _capture_tm_remote()
    with patch(
        "tunnel_manager.mcp.mcp_remote.ctx_confirm_destructive",
        new=AsyncMock(return_value=False),
    ):
        result = await fn(**_base_kwargs(action="remove_host_key"))
    assert result["status"] == "cancelled"
