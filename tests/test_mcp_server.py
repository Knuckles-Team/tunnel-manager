"""Tests for mcp_server.py - MCP server tool registration."""

from unittest.mock import MagicMock, patch

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
            ),
            patch("tunnel_manager.mcp_server.to_integer", side_effect=int),
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
            ),
            patch("tunnel_manager.mcp_server.to_integer", side_effect=int),
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
                    "hostname": "10.0.0.17",
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
                mock_tunnel_cls.assert_called_once_with(
                    remote_host="10.0.0.17",
                    username="testuser",
                    password=None,
                    identity_file="/fake/key",
                )

                # Verify that run_command was called with the correct custom timeout
                mock_tunnel.run_command.assert_called_once_with("uptime", timeout=45)

                # Verify result status
                assert result["status_code"] == 200
                assert result["details"]["host_results"][0]["stdout"] == "stdout output"
