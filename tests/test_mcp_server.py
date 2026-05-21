"""Tests for mcp_server.py - MCP server tool registration."""

from unittest.mock import MagicMock, patch


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
