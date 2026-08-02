"""Tests for mcp_server.py - MCP server tool registration."""

from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest


class TestGetMcpInstance:
    def test_get_mcp_instance(self):
        from tunnel_manager.mcp_server import get_mcp_instance

        with patch("tunnel_manager.mcp_server.create_mcp_server") as mock_create:
            mock_create.return_value = (MagicMock(), MagicMock(), [MagicMock()])

            mcp, args, middlewares, registered_tags = get_mcp_instance()

            assert mcp is not None


class TestVersion:
    def test_version_defined(self):
        from tunnel_manager.mcp_server import __version__

        assert __version__ is not None
        assert isinstance(__version__, str)


class TestTmInventoryTimeout:
    def test_tm_inventory_timeout_parameter(self):
        import inspect

        from pydantic.fields import FieldInfo

        from tunnel_manager.mcp_server import register_inventory_tools

        with (
            patch(
                "tunnel_manager.mcp_server.to_boolean",
                side_effect=lambda x: x == "True" or x is True,
                create=True,
            ),
            patch("tunnel_manager.mcp_server.to_integer", side_effect=int, create=True),
        ):
            mcp = MagicMock()

            def captured_fn(*args, **kwargs):
                return {"args": args, "kwargs": kwargs}

            def decorator(fn):
                nonlocal captured_fn
                captured_fn = fn
                return fn

            mcp.tool.return_value = decorator

            register_inventory_tools(mcp)

            assert captured_fn is not None
            sig = inspect.signature(captured_fn)
            assert "timeout" in sig.parameters
            param = sig.parameters["timeout"]

            if isinstance(param.default, FieldInfo):
                assert param.default.default == 60
            else:
                assert param.default == 60

    @pytest.mark.asyncio
    async def test_tm_inventory_forwards_timeout(self):
        from tunnel_manager.mcp_server import register_inventory_tools

        with (
            patch(
                "tunnel_manager.mcp_server.to_boolean",
                side_effect=lambda x: x == "True" or x is True,
                create=True,
            ),
            patch("tunnel_manager.mcp_server.to_integer", side_effect=int, create=True),
        ):
            mcp = MagicMock()

            async def captured_fn(*args, **kwargs):
                return {"args": args, "kwargs": kwargs}

            def decorator(fn):
                nonlocal captured_fn
                captured_fn = fn
                return fn

            mcp.tool.return_value = decorator

            register_inventory_tools(mcp)

            from unittest.mock import AsyncMock

            mock_hosts = [
                {
                    "hostname": "192.0.2.17",
                    "username": "testuser",
                    "key_path": "/fake/key",
                }
            ]
            mock_ctx = AsyncMock()

            # Mock load_inventory to return the dummy hosts and no error
            with (
                patch(
                    "tunnel_manager.mcp_server.load_inventory",
                    return_value=(mock_hosts, None),
                ),
                patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
            ):
                mock_tunnel = MagicMock()
                mock_tunnel.run_command.return_value = (
                    "stdout output",
                    "stderr output",
                )
                mock_tunnel_cls.return_value = mock_tunnel

                # Invoke captured tm_inventory function with all parameters to avoid FieldInfo defaults
                result = await captured_fn(
                    action="run_command",
                    inventory="/fake/inventory.yaml",
                    group="all",
                    host="",
                    preview=False,
                    parallel=False,
                    max_threads=6,
                    cmd="uptime",
                    key="",
                    key_type="ed25519",
                    key_pfx="",
                    cfg="",
                    rmt_cfg="",
                    lpath="",
                    rpath="",
                    lpath_prefix="",
                    timeout=45,
                    ctx=mock_ctx,
                )

                # Verify that Tunnel was instantiated with correctly passed params
                mock_tunnel_cls.assert_called_once()
                config = mock_tunnel_cls.call_args.kwargs["config"]
                assert config.hostname == "192.0.2.17"
                assert config.user == "testuser"
                assert config.password_ref is None
                assert config.identity_file == "/fake/key"

                # Verify that run_command was called with the correct custom timeout
                mock_tunnel.run_command.assert_called_once_with("uptime", timeout=45)

                # Verify result status
                assert result["status_code"] == 200
                assert result["details"]["host_results"][0]["stdout"] == "stdout output"


class TestTmInventoryHostSelector:
    """D-CDX-88: ``tm_inventory(action=run_command)`` single-host selector.

    ``host`` resolves exactly ONE host through the same entitlement-checked
    alias store (:data:`tunnel_manager.mcp_server.host_manager`) that
    ``tm_remote``/``tm_hosts`` authorize against — the fix bridges the two
    inventory sources instead of leaving ``tm_inventory`` only able to fan
    out to a whole configured group. ``preview`` returns the exact resolved
    target(s) without executing, and every run_command response (preview or
    real) carries ``resolved_hosts`` so a caller never gets surprise fan-out.
    """

    @staticmethod
    def _capture_tm_inventory():
        from tunnel_manager.mcp_server import register_inventory_tools

        mcp = MagicMock()
        captured = {}

        def decorator(fn):
            captured["fn"] = fn
            return fn

        mcp.tool.return_value = decorator
        register_inventory_tools(mcp)
        return captured["fn"]

    @staticmethod
    async def _call(fn, **overrides):
        base = dict(
            action="run_command",
            inventory="/fake/inventory.yaml",
            group="all",
            host="",
            preview=False,
            parallel=False,
            max_threads=6,
            cmd="uptime",
            key="",
            key_type="ed25519",
            key_pfx="",
            cfg="",
            rmt_cfg="",
            lpath="",
            rpath="",
            lpath_prefix="",
            timeout=45,
            ctx=AsyncMock(),
        )
        base.update(overrides)
        return await fn(**base)

    @pytest.mark.asyncio
    async def test_single_host_targets_only_that_host(self):
        """Selecting one host must never touch the whole-group fan-out path."""
        from tunnel_manager.models import HostConfig

        fn = self._capture_tm_inventory()
        gb10_config = HostConfig(
            hostname="gb10.hosts.example",
            user="ops",
            port=22,
            identity_file="/fake/key",
        )

        with (
            patch(
                "tunnel_manager.mcp_server.host_manager.get_host",
                return_value=gb10_config,
            ),
            patch("tunnel_manager.mcp_server.load_inventory") as mock_load_inv,
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.run_command.return_value = ("ok", "")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await self._call(fn, host="gb10", group="homelab")

            # The safety property: choosing a single host never falls back
            # to (or fans out through) the whole-group inventory loader.
            mock_load_inv.assert_not_called()
            mock_tunnel_cls.assert_called_once()
            config = mock_tunnel_cls.call_args.kwargs["config"]
            assert config.hostname == "gb10.hosts.example"
            assert result["status_code"] == 200
            assert result["details"]["resolved_hosts"] == ["gb10.hosts.example"]
            assert len(result["details"]["host_results"]) == 1

    @pytest.mark.asyncio
    async def test_unknown_host_alias_is_rejected_not_skipped(self):
        """An unknown alias must fail loudly (400), never silently no-op."""
        fn = self._capture_tm_inventory()

        with (
            patch(
                "tunnel_manager.mcp_server.host_manager.get_host",
                return_value=None,
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            result = await self._call(fn, host="ghost-host")

            assert result["status_code"] == 400
            assert any("ghost-host" in e for e in result["errors"])
            mock_tunnel_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_unauthorized_host_alias_is_denied(self):
        """A known-but-not-entitled alias is denied, matching tm_remote's
        cross-tenant PermissionError semantics (never weakened, only reused).
        """
        fn = self._capture_tm_inventory()

        with (
            patch(
                "tunnel_manager.mcp_server.host_manager.get_host",
                side_effect=PermissionError("not entitled to ssh host 'prod-db'"),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            result = await self._call(fn, host="prod-db")

            assert result["status_code"] == 403
            assert result["status_code"] != 200
            mock_tunnel_cls.assert_not_called()

    @pytest.mark.asyncio
    async def test_group_fanout_is_unchanged_when_no_host_selected(self):
        """Regression: omitting 'host' must reproduce the pre-existing
        whole-group fan-out behavior exactly, via the same load_inventory
        YAML-group path — host_manager is never consulted.
        """
        fn = self._capture_tm_inventory()
        mock_hosts = [
            {
                "hostname": "node1.hosts.example",
                "username": "ops",
                "key_path": "/fake/key",
            },
            {
                "hostname": "node2.hosts.example",
                "username": "ops",
                "key_path": "/fake/key",
            },
        ]

        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(mock_hosts, None),
            ) as mock_load_inv,
            patch("tunnel_manager.mcp_server.host_manager.get_host") as mock_get_host,
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.run_command.return_value = ("ok", "")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await self._call(fn, host="", group="homelab")

            mock_load_inv.assert_called_once_with(
                "/fake/inventory.yaml", "homelab", ANY
            )
            mock_get_host.assert_not_called()
            assert result["status_code"] == 200
            assert result["details"]["resolved_hosts"] == [
                "node1.hosts.example",
                "node2.hosts.example",
            ]
            assert len(result["details"]["host_results"]) == 2

    @pytest.mark.asyncio
    async def test_preview_resolves_target_without_executing(self):
        """preview=True must resolve and report the target(s) without
        running anything — the resolved-target-preview safety property.
        """
        from tunnel_manager.models import HostConfig

        fn = self._capture_tm_inventory()
        gb10_config = HostConfig(hostname="gb10.hosts.example", user="ops")

        with (
            patch(
                "tunnel_manager.mcp_server.host_manager.get_host",
                return_value=gb10_config,
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            result = await self._call(fn, host="gb10", preview=True)

            mock_tunnel_cls.assert_not_called()
            assert result["status_code"] == 200
            assert result["details"]["preview"] is True
            assert result["details"]["resolved_hosts"] == ["gb10.hosts.example"]
