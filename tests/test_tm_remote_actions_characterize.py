"""Characterization tests for `register_remote_tools.tm_remote`
(CXA-FL-TUNNELMANAGER-01, CCN 83 in tunnel_manager/mcp_server.py).

Before this file, tm_remote had no per-action functional coverage (only
generic list_actions/bogus-action discovery checks in
tests/test_action_discovery.py, and a schema-only password-field check in
tests/test_connection_security.py). These tests pin the happy-path (and,
where a bug was found, the AS-IS buggy) behaviour of all 9 actions —
run_command, send_file, receive_file, check_ssh, test_key_auth,
setup_passwordless, copy_ssh_config, rotate_key, remove_host_key.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest


def _capture_tm_remote():
    from tunnel_manager.mcp_server import register_remote_tools

    mcp = MagicMock()
    captured = {}

    def decorator(fn):
        captured["fn"] = fn
        return fn

    mcp.tool.return_value = decorator
    register_remote_tools(mcp)
    assert "fn" in captured
    return captured["fn"]


DEFAULT_KWARGS = dict(
    host="192.0.2.50",
    user="deploy",
    password_ref="",
    port=22,
    id_file="",
    certificate="",
    proxy="",
    cfg="/fake/.ssh/config",
    cmd="",
    lpath="",
    rpath="",
    key="",
    key_type="ed25519",
    new_key="",
    lcfg="",
    rcfg="/fake/.ssh/config",
    known_hosts="/fake/.ssh/known_hosts",
    timeout=60,
    ctx=None,
)


def _call(fn, **overrides):
    kwargs = dict(DEFAULT_KWARGS)
    kwargs.update(overrides)
    return fn(**kwargs)


def _resolved_conf():
    return (
        {
            "hostname": "192.0.2.50",
            "user": "deploy",
            "password": None,
            "port": 22,
            "identity_file": None,
            "certificate_file": None,
            "proxy_command": None,
            "known_hosts_file": None,
        },
        "/fake/.ssh/config",
    )


class TestRunCommand:
    @pytest.mark.asyncio
    async def test_happy_path(self):
        fn = _capture_tm_remote()
        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.run_command.return_value = ("out", "")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(fn, action="run_command", cmd="uptime")

        assert result["status_code"] == 200
        assert result["stdout"] == "out"
        mock_tunnel.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_cmd_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(fn, action="run_command", cmd="")
        assert result["status_code"] == 400


class TestSendFile:
    @pytest.mark.asyncio
    async def test_happy_path_pins_wrong_logger_name(self, tmp_path):
        """CXA-FL-TUNNELMANAGER-01 FINDING: send_file's exception handler
        logs via `_logger = logging.getLogger("TunnelServer")`
        (mcp_server.py) instead of the module logger (`get_logger(
        "TunnelManager")`) every sibling action uses. This test exercises
        the happy path (logger only matters on the error path) but documents
        the finding; see the fork report for the raise-path evidence."""
        fn = _capture_tm_remote()
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hi")

        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="send_file", lpath=str(local), rpath="/remote/payload.bin"
            )

        assert result["status_code"] == 200
        mock_tunnel.send_file.assert_called_once_with(str(local), "/remote/payload.bin")
        mock_tunnel.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_uses_wrong_logger_on_error_path(self, tmp_path):
        """Pins the FINDING directly: on failure, send_file logs through the
        'TunnelServer' logger, not 'TunnelManager' like every other action."""
        fn = _capture_tm_remote()
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hi")

        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
            patch("tunnel_manager.mcp_server.ctx_log") as mock_ctx_log,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.send_file.side_effect = RuntimeError("boom")
            mock_tunnel_cls.return_value = mock_tunnel

            await _call(
                fn, action="send_file", lpath=str(local), rpath="/remote/payload.bin"
            )

        mock_ctx_log.assert_called_once()
        logger_arg = mock_ctx_log.call_args.args[1]
        assert logger_arg.name == "TunnelServer"

    @pytest.mark.asyncio
    async def test_missing_lpath_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(fn, action="send_file", lpath="", rpath="/r")
        assert result["status_code"] == 400


class TestReceiveFile:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path):
        fn = _capture_tm_remote()
        local = tmp_path / "out.bin"
        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="receive_file", rpath="/remote/out.bin", lpath=str(local)
            )

        assert result["status_code"] == 200
        mock_tunnel.receive_file.assert_called_once_with("/remote/out.bin", str(local))
        mock_tunnel.close.assert_called_once()


class TestCheckSsh:
    @pytest.mark.asyncio
    async def test_happy_path_success(self):
        fn = _capture_tm_remote()
        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.check_ssh_server.return_value = (True, "reachable")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(fn, action="check_ssh")

        assert result["status_code"] == 200
        mock_tunnel.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_happy_path_failure_status_400(self):
        fn = _capture_tm_remote()
        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.check_ssh_server.return_value = (False, "unreachable")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(fn, action="check_ssh")

        assert result["status_code"] == 400


class TestTestKeyAuth:
    @pytest.mark.asyncio
    async def test_happy_path_pins_missing_close_bug(self):
        """CXA-FL-TUNNELMANAGER-01 BUG: unlike every sibling action (and
        unlike check_ssh immediately above it), test_key_auth has no
        `finally: await run_blocking(t.close)` -- the Tunnel it opens is
        never closed. This test pins that AS-IS (do not fix here)."""
        fn = _capture_tm_remote()
        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.test_key_auth.return_value = (True, "ok")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(fn, action="test_key_auth", key="/fake/key")

        assert result["status_code"] == 200
        # BUG, pinned as-is: close() is never called for this action.
        mock_tunnel.close.assert_not_called()

    @pytest.mark.asyncio
    async def test_missing_key_rejected(self):
        fn = _capture_tm_remote()
        with patch("tunnel_manager.mcp_server.setting", return_value=""):
            result = await _call(fn, action="test_key_auth", key="")
        assert result["status_code"] == 400


class TestSetupPasswordless:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TUNNEL_TEST_PASSWORD", "s3cret")
        fn = _capture_tm_remote()
        key = tmp_path / "id_ed25519"
        pub = tmp_path / "id_ed25519.pub"
        pub.write_text("ssh-ed25519 " + "A" * 68)

        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn,
                action="setup_passwordless",
                password_ref="env://TUNNEL_TEST_PASSWORD",
                key=str(key),
                key_type="ed25519",
            )

        assert result["status_code"] == 200
        mock_tunnel.setup_passwordless_ssh.assert_called_once_with(
            local_key_path=str(key), key_type="ed25519"
        )
        mock_tunnel.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_password_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(fn, action="setup_passwordless", password_ref="")
        assert result["status_code"] == 400
        assert "password_ref" in result["message"]


class TestCopySshConfig:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path):
        fn = _capture_tm_remote()
        lcfg = tmp_path / "config"
        lcfg.write_text("Host *\n")

        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="copy_ssh_config", lcfg=str(lcfg), rcfg="/remote/config"
            )

        assert result["status_code"] == 200
        mock_tunnel.copy_ssh_config.assert_called_once_with(str(lcfg), "/remote/config")
        mock_tunnel.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_lcfg_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(fn, action="copy_ssh_config", lcfg="")
        assert result["status_code"] == 400


class TestRotateKey:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path):
        fn = _capture_tm_remote()
        new_key = tmp_path / "id_new"
        new_key.write_text("fake")

        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=_resolved_conf(),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="rotate_key", new_key=str(new_key), key_type="ed25519"
            )

        assert result["status_code"] == 200
        mock_tunnel.rotate_ssh_key.assert_called_once_with(
            str(new_key), key_type="ed25519"
        )
        mock_tunnel.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_missing_new_key_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(fn, action="rotate_key", new_key="")
        assert result["status_code"] == 400


class TestRemoveHostKey:
    @pytest.mark.asyncio
    async def test_happy_path_removed(self):
        fn = _capture_tm_remote()
        with (
            patch(
                "tunnel_manager.mcp_server._resolve_host",
                return_value=({"hostname": "192.0.2.50"}, None),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
            patch(
                "tunnel_manager.mcp_server.ctx_confirm_destructive",
                new=AsyncMock(return_value=True),
            ),
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.remove_host_key.return_value = "Removed key for 192.0.2.50"
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(fn, action="remove_host_key")

        assert result["status_code"] == 200

    @pytest.mark.asyncio
    async def test_cancelled_by_confirm(self):
        fn = _capture_tm_remote()
        with patch(
            "tunnel_manager.mcp_server.ctx_confirm_destructive",
            new=AsyncMock(return_value=False),
        ):
            result = await _call(fn, action="remove_host_key")
        assert result == {
            "status": "cancelled",
            "message": "Operation cancelled by user",
        }

    @pytest.mark.asyncio
    async def test_missing_host_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(fn, action="remove_host_key", host="")
        assert result["status_code"] == 400


class TestSharedValidation:
    @pytest.mark.asyncio
    async def test_invalid_password_ref_rejected(self):
        fn = _capture_tm_remote()
        result = await _call(
            fn, action="run_command", cmd="uptime", password_ref="not-a-valid-ref"
        )
        assert result["status_code"] == 400
        assert "credential" in result["message"].lower()

    @pytest.mark.asyncio
    async def test_unresolvable_action_raises_before_dispatch(self):
        fn = _capture_tm_remote()
        with pytest.raises(ValueError, match="Unknown action"):
            await _call(fn, action="not_a_real_action")
