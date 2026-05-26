"""Tests for tunnel_manager.py - HostManager and Tunnel classes."""

import os
import tempfile
from unittest.mock import Mock, mock_open, patch

import pytest
import yaml

from tunnel_manager.tunnel_manager import HostManager, Tunnel


class TestHostManager:
    """Test HostManager class."""

    @patch("os.path.exists")
    def test_init_default_config(self, mock_exists):
        """Test HostManager initialization with default config."""
        mock_exists.return_value = False
        hm = HostManager()
        assert hm.config_file == os.path.expanduser("~/.tunnel_manager/hosts.yaml")
        assert hm.hosts == {}

    def test_init_custom_config(self):
        """Test HostManager initialization with custom config."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            assert hm.config_file == config_path
            assert hm.hosts == {}
        finally:
            os.unlink(config_path)

    def test_load_inventory_existing_file(self):
        """Test loading inventory from existing file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump({"test_host": {"hostname": "example.com", "user": "test"}}, f)
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            hm.load_inventory()
            assert hm.hosts == {
                "test_host": {"hostname": "example.com", "user": "test"}
            }
        finally:
            os.unlink(config_path)

    def test_load_inventory_nonexistent_file(self):
        """Test loading inventory from nonexistent file."""
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=True) as f:
            config_path = f.name
        hm = HostManager(config_file=config_path)
        hm.load_inventory()
        assert hm.hosts == {}

    def test_load_inventory_invalid_yaml(self):
        """Test loading inventory from invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            hm.load_inventory()
            assert hm.hosts == {}
        finally:
            os.unlink(config_path)

    def test_save_inventory(self):
        """Test saving inventory to file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            hm.hosts = {"test_host": {"hostname": "example.com", "user": "test"}}
            hm.save_inventory()
            with open(config_path) as f:
                loaded = yaml.safe_load(f)
            assert loaded == {"test_host": {"hostname": "example.com", "user": "test"}}
        finally:
            os.unlink(config_path)

    def test_add_host(self):
        """Test adding a host to inventory."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            hm.add_host(
                alias="test",
                hostname="example.com",
                user="testuser",
                port=2222,
                identity_file="/path/to/key",
                password="testpass",
                proxy_command="proxy cmd",
            )
            assert "test" in hm.hosts
            assert hm.hosts["test"]["hostname"] == "example.com"
            assert hm.hosts["test"]["user"] == "testuser"
            assert hm.hosts["test"]["port"] == 2222
            assert hm.hosts["test"]["identity_file"] == "/path/to/key"
            assert hm.hosts["test"]["password"] == "testpass"
            assert hm.hosts["test"]["proxy_command"] == "proxy cmd"
        finally:
            os.unlink(config_path)

    def test_remove_host_existing(self):
        """Test removing an existing host."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            hm.hosts = {"test": {"hostname": "example.com"}}
            hm.remove_host("test")
            assert "test" not in hm.hosts
        finally:
            os.unlink(config_path)

    def test_remove_host_nonexistent(self):
        """Test removing a nonexistent host."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_path = f.name
        try:
            hm = HostManager(config_file=config_path)
            hm.hosts = {}
            hm.remove_host("test")  # Should not raise
            assert "test" not in hm.hosts
        finally:
            os.unlink(config_path)

    def test_list_hosts(self):
        """Test listing all hosts."""
        from tunnel_manager.models import HostConfig

        hm = HostManager()
        hm.hosts = {
            "host1": {"hostname": "example1.com"},
            "host2": {"hostname": "example2.com"},
        }
        result = hm.list_hosts()
        assert result == {
            "host1": HostConfig(hostname="example1.com"),
            "host2": HostConfig(hostname="example2.com"),
        }

    def test_get_host_existing(self):
        """Test getting an existing host."""

        hm = HostManager()
        hm.hosts = {"test": {"hostname": "example.com"}}
        result = hm.get_host("test")
        assert result is not None
        assert result.hostname == "example.com"

    def test_get_host_nonexistent(self):
        """Test getting a nonexistent host."""
        hm = HostManager()
        hm.hosts = {}
        result = hm.get_host("test")
        assert result is None


class TestTunnel:
    """Test Tunnel class."""

    @patch("paramiko.SSHConfig")
    def test_init_minimal(self, mock_ssh_config):
        """Test Tunnel initialization with minimal parameters."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            assert t.remote_host == "example.com"
            assert t.username == "testuser"
            assert t.password == "testpass"
            assert t.port == 22

    @patch("paramiko.SSHConfig")
    def test_init_with_identity_file(self, mock_ssh_config):
        """Test Tunnel initialization with identity file."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {
            "user": "config_user",
            "identityfile": ["/config/key"],
        }
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=True):
            t = Tunnel(
                remote_host="example.com",
                username="testuser",
                identity_file="/test/key",
            )
            assert t.username == "testuser"  # Parameter overrides config
            assert t.identity_file == "/test/key"

    @patch("paramiko.SSHConfig")
    def test_init_missing_username(self, mock_ssh_config):
        """Test Tunnel initialization fails without username."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=False):
            with pytest.raises(ValueError, match="Username must be provided"):
                Tunnel(remote_host="example.com", password="testpass")

    @patch("paramiko.SSHConfig")
    def test_init_missing_auth(self, mock_ssh_config):
        """Test Tunnel initialization succeeds without explicit auth (falling back to agent)."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {"user": "testuser"}
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(remote_host="example.com", username="testuser")
            assert t.username == "testuser"
            assert t.identity_file is None
            assert t.password is None

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_connect_identity_file(self, mock_ssh_client, mock_ssh_config):
        """Test connecting with identity file."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            with patch("paramiko.Ed25519Key.from_private_key_file") as mock_key:
                mock_key.return_value = Mock()
                t = Tunnel(
                    remote_host="example.com",
                    username="testuser",
                    identity_file="/test/key",
                )
                t.connect()
                mock_client_instance.connect.assert_called_once()

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_connect_password(self, mock_ssh_client, mock_ssh_config):
        """Test connecting with password."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            t.connect()
            mock_client_instance.connect.assert_called_once()

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_connect_already_connected(self, mock_ssh_client, mock_ssh_config):
        """Test connecting when already connected."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_transport = Mock()
        mock_transport.is_active.return_value = True
        mock_client_instance.get_transport.return_value = mock_transport
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            t.ssh_client = mock_client_instance
            t.connect()
            # Should not call connect again
            mock_client_instance.connect.assert_not_called()

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    @patch("paramiko.ProxyCommand")
    def test_connect_with_proxy(
        self, mock_proxy_command, mock_ssh_client, mock_ssh_config
    ):
        """Test connecting with proxy command."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {"proxycommand": "proxy_cmd"}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_proxy = Mock()
        mock_proxy_command.return_value = mock_proxy

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com",
                username="testuser",
                password="testpass",
                proxy_command="custom_proxy",
            )
            t.connect()
            mock_client_instance.connect.assert_called_once()
            # Verify proxy was used
            call_kwargs = mock_client_instance.connect.call_args[1]
            assert "sock" in call_kwargs

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_connect_with_certificate(self, mock_ssh_client, mock_ssh_config):
        """Test connecting with certificate file."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with tempfile.NamedTemporaryFile(delete=False) as f:
            key_path = f.name
        try:
            with patch("paramiko.Ed25519Key.from_private_key_file") as mock_key:
                mock_key.return_value = Mock()
                with patch("os.path.exists", return_value=False):
                    t = Tunnel(
                        remote_host="example.com",
                        username="testuser",
                        identity_file=key_path,
                        certificate_file="/test/cert",
                    )
                    t.connect()
                    # Verify certificate was loaded
                    mock_key.return_value.load_certificate.assert_called_once_with(
                        "/test/cert"
                    )
        finally:
            os.unlink(key_path)

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_run_command_error(self, mock_ssh_client, mock_ssh_config):
        """Test run_command with error."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_stdout = Mock()
        mock_stdout.read.return_value = b""
        mock_stderr = Mock()
        mock_stderr.read.return_value = b"error message"
        mock_client_instance.exec_command.return_value = (
            None,
            mock_stdout,
            mock_stderr,
        )

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            out, err = t.run_command("ls")
            assert err == "error message"

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_send_file_permission_error(self, mock_ssh_client, mock_ssh_config):
        """Test send_file with permission error."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = f.name
        try:
            with patch("os.path.exists", return_value=True):
                with patch("os.path.isfile", return_value=True):
                    with patch("os.access", return_value=False):  # No read permission
                        with patch(
                            "os.path.exists", return_value=False
                        ):  # For Tunnel __init__
                            t = Tunnel(
                                remote_host="example.com",
                                username="testuser",
                                password="testpass",
                            )
                        with patch("os.path.exists", return_value=True):
                            with patch("os.path.isfile", return_value=True):
                                with patch("os.access", return_value=False):
                                    with pytest.raises(PermissionError):
                                        t.send_file(local_path, "/remote/path")
        finally:
            os.unlink(local_path)

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_receive_file_error(self, mock_ssh_client, mock_ssh_config):
        """Test receive_file with error."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_sftp = Mock()
        mock_sftp.get.side_effect = Exception("SFTP error")
        mock_client_instance.open_sftp.return_value = mock_sftp

        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = f.name
        try:
            with patch("os.path.exists", return_value=False):
                t = Tunnel(
                    remote_host="example.com", username="testuser", password="testpass"
                )
                with pytest.raises(Exception, match="SFTP error"):
                    t.receive_file("/remote/file", local_path)
        finally:
            os.unlink(local_path)

    @patch("paramiko.SSHConfig")
    def test_setup_passwordless_ssh_invalid_key_type(self, mock_ssh_config):
        """Test setup_passwordless_ssh with invalid key type."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            with pytest.raises(ValueError, match="key_type must be"):
                t.setup_passwordless_ssh(local_key_path="/test/key", key_type="invalid")

    @patch("paramiko.SSHConfig")
    def test_setup_passwordless_ssh_no_password(self, mock_ssh_config):
        """Test setup_passwordless_ssh without password."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com",
                username="testuser",
                identity_file="/test/key",
            )
            with pytest.raises(
                ValueError, match="Password-based authentication required"
            ):
                t.setup_passwordless_ssh(local_key_path="/test/key")

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_check_ssh_server_error(self, mock_ssh_client, mock_ssh_config):
        """Test check_ssh_server with error."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            with patch.object(
                t, "run_command", side_effect=Exception("Connection error")
            ):
                success, msg = t.check_ssh_server()
                assert success is False
                assert "Failed to check SSH server" in msg

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_test_key_auth_error(self, mock_ssh_client, mock_ssh_config):
        """Test test_key_auth with error."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            with patch.object(Tunnel, "__init__", side_effect=Exception("Auth error")):
                success, msg = t.test_key_auth("/test/key")
                assert success is False
                assert "Key auth test failed" in msg

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_run_command(self, mock_ssh_client, mock_ssh_config):
        """Test running a command."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_stdout = Mock()
        mock_stdout.read.return_value = b"output"
        mock_stderr = Mock()
        mock_stderr.read.return_value = b"error"
        mock_client_instance.exec_command.return_value = (
            None,
            mock_stdout,
            mock_stderr,
        )

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            out, err = t.run_command("ls")
            assert out == "output"
            assert err == "error"

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_send_file(self, mock_ssh_client, mock_ssh_config):
        """Test sending a file."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_sftp = Mock()
        mock_client_instance.open_sftp.return_value = mock_sftp

        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = f.name
        try:
            # Mock the SSH config file existence check in __init__
            with patch("os.path.exists", return_value=False):
                t = Tunnel(
                    remote_host="example.com", username="testuser", password="testpass"
                )
                # Now mock the file existence for send_file
                with patch("os.path.exists", return_value=True):
                    with patch("os.path.isfile", return_value=True):
                        with patch("os.access", return_value=True):
                            with patch("builtins.open", mock_open(read_data=b"test")):
                                t.send_file(local_path, "/remote/path")
                                mock_sftp.put.assert_called_once()
        finally:
            os.unlink(local_path)

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_send_file_not_exists(self, mock_ssh_client, mock_ssh_config):
        """Test sending a file that doesn't exist."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            with pytest.raises(OSError, match="Local file does not exist"):
                t.send_file("/nonexistent/file", "/remote/path")

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_receive_file(self, mock_ssh_client, mock_ssh_config):
        """Test receiving a file."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_sftp = Mock()
        mock_client_instance.open_sftp.return_value = mock_sftp

        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = f.name
        try:
            with patch("os.path.exists", return_value=False):
                t = Tunnel(
                    remote_host="example.com", username="testuser", password="testpass"
                )
                t.receive_file("/remote/path", local_path)
                mock_sftp.get.assert_called_once()
        finally:
            os.unlink(local_path)

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_close(self, mock_ssh_client, mock_ssh_config):
        """Test closing the connection."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            t.ssh_client = mock_client_instance
            t.close()
            mock_client_instance.close.assert_called_once()
            assert t.ssh_client is None

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_check_ssh_server(self, mock_ssh_client, mock_ssh_config):
        """Test checking SSH server status."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        # Mock the SSH check command output to indicate running with key auth
        mock_stdout = Mock()
        mock_stdout.read.return_value = b"running\nPubkeyAuthentication yes"
        mock_stderr = Mock()
        mock_stderr.read.return_value = b""

        # First call returns running status, second returns PubkeyAuthentication yes
        mock_client_instance.exec_command.side_effect = [
            (None, mock_stdout, mock_stderr),
            (None, mock_stdout, mock_stderr),
        ]

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            # Mock the run_command calls within check_ssh_server
            with patch.object(
                t,
                "run_command",
                side_effect=[("running\n", ""), ("PubkeyAuthentication yes\n", "")],
            ):
                success, msg = t.check_ssh_server()
                assert success is True

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_test_key_auth(self, mock_ssh_client, mock_ssh_config):
        """Test testing key authentication."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com", username="testuser", password="testpass"
            )
            # The test_key_auth method creates a new Tunnel instance and tests it
            # We need to mock the Tunnel class to return a successful test
            with patch.object(Tunnel, "__init__", return_value=None):
                with patch.object(Tunnel, "connect"):
                    with patch.object(Tunnel, "close"):
                        success, msg = t.test_key_auth("/test/key")
                        assert success is True

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_setup_passwordless_ssh(self, mock_ssh_client, mock_ssh_config):
        """Test setting up passwordless SSH."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        mock_stdout = Mock()
        mock_stdout.read.return_value = b""
        mock_stderr = Mock()
        mock_stderr.read.return_value = b""
        mock_client_instance.exec_command.return_value = (
            None,
            mock_stdout,
            mock_stderr,
        )

        with tempfile.NamedTemporaryFile(mode="w", suffix=".pub", delete=False) as f:
            pub_key_path = f.name
            f.write("ssh-rsa test_key")
        try:
            private_key_path = pub_key_path.replace(".pub", "")
            with patch("os.path.exists", side_effect=lambda x: x == pub_key_path):
                t = Tunnel(
                    remote_host="example.com", username="testuser", password="testpass"
                )
                t.setup_passwordless_ssh(
                    local_key_path=private_key_path, key_type="rsa"
                )
        finally:
            if os.path.exists(pub_key_path):
                os.unlink(pub_key_path)

    @patch("os.path.exists")
    @patch("paramiko.HostKeys")
    @patch("paramiko.SSHConfig")
    def test_remove_host_key(self, mock_ssh_config, mock_host_keys_class, mock_exists):
        """Test removing host key from known_hosts."""
        mock_exists.return_value = True

        class MockHostKeys(dict):
            def load(self, path):
                self.loaded_path = path

            def save(self, path):
                self.saved_path = path

        mock_kh = MockHostKeys({"example.com": "some-key"})
        mock_host_keys_class.return_value = mock_kh

        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        t = Tunnel(remote_host="example.com", username="testuser", password="testpass")
        res = t.remove_host_key("/mock/path")

        assert mock_kh.loaded_path == "/mock/path"
        assert "example.com" not in mock_kh
        assert mock_kh.saved_path == "/mock/path"
        assert "Removed host key" in res

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_copy_ssh_config(self, mock_ssh_client, mock_ssh_config):
        """Test copying SSH config to remote host."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_config_path = f.name
        try:
            with patch("os.path.exists", return_value=False):  # For Tunnel __init__
                t = Tunnel(
                    remote_host="example.com", username="testuser", password="testpass"
                )
                # Mock the run_command and send_file calls within copy_ssh_config
                with patch.object(t, "run_command"):
                    with patch.object(t, "send_file"):
                        t.copy_ssh_config(local_config_path)
        finally:
            os.unlink(local_config_path)

    @patch("os.path.exists")
    @patch("subprocess.run")
    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_rotate_ssh_key(
        self, mock_ssh_client, mock_ssh_config, mock_subprocess, mock_exists
    ):
        """Test rotating SSH key."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        # Mock existences
        # new_key_path doesn't exist (triggering generation)
        # old_pub_path exists (reading old pub key)
        def exists_side_effect(path):
            if "new" in path:
                return False
            return True

        mock_exists.side_effect = exists_side_effect

        t = Tunnel(
            remote_host="example.com", username="testuser", identity_file="/old/key"
        )
        t.connect = (
            Mock()
        )  # Avoid real connection setup and paramiko private key parsing

        # Mock run_command responses
        def run_cmd_side_effect(cmd):
            if "cat" in cmd:
                return ("old-pub-key-content\nother-key", "")
            return ("", "")

        t.run_command = Mock(side_effect=run_cmd_side_effect)

        # We need mock_open to return different contents for different paths
        file_contents = {
            "/new/key.pub": "new-pub-key-content",
            "/old/key.pub": "old-pub-key-content",
        }

        original_open = open

        def custom_open(file, *args, **kwargs):
            if isinstance(file, str) and file in file_contents:
                return mock_open(read_data=file_contents[file])()
            return original_open(file, *args, **kwargs)

        with patch("builtins.open", side_effect=custom_open):
            t.rotate_ssh_key("/new/key", key_type="ed25519")

        # Verify subprocess.run called to generate ed25519 key
        mock_subprocess.assert_called_once()
        assert mock_subprocess.call_args[0][0][2] == "ed25519"

        # Verify run_command was called with updated authorized_keys
        # It should contain other-key and new-pub-key-content, but not old-pub-key-content
        called_cmds = [call[0][0] for call in t.run_command.call_args_list]
        assert any("new-pub-key-content" in cmd for cmd in called_cmds)
        assert not any("old-pub-key-content" in cmd for cmd in called_cmds)

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    def test_connect_path_expansion(self, mock_ssh_client, mock_ssh_config):
        """Test relative path expansion for identity and certificate files in connect()."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=True):
            with patch("paramiko.Ed25519Key.from_private_key_file") as mock_key:
                mock_key.return_value = Mock()
                t = Tunnel(
                    remote_host="example.com",
                    username="testuser",
                    identity_file="~/relative/key",
                    certificate_file="~/relative/cert",
                )

                # Mock expanduser to simulate actual expansion
                with patch(
                    "os.path.expanduser",
                    side_effect=lambda x: x.replace("~", "/home/user"),
                ):
                    t.connect()

                    # Verify they were expanded and passed resolved paths
                    expected_key = os.path.abspath("/home/user/relative/key")
                    expected_cert = os.path.abspath("/home/user/relative/cert")

                    mock_key.assert_called_once_with(expected_key)
                    mock_key.return_value.load_certificate.assert_called_once_with(
                        expected_cert
                    )

    @patch("paramiko.SSHConfig")
    @patch("paramiko.SSHClient")
    @patch("paramiko.ProxyCommand")
    def test_connect_proxy_command_token_expansion(
        self, mock_proxy_command, mock_ssh_client, mock_ssh_config
    ):
        """Test token expansion in proxy command in connect()."""
        mock_config_instance = Mock()
        mock_config_instance.lookup.return_value = {}
        mock_ssh_config.return_value = mock_config_instance

        mock_client_instance = Mock()
        mock_ssh_client.return_value = mock_client_instance

        with patch("os.path.exists", return_value=False):
            t = Tunnel(
                remote_host="example.com",
                username="testuser",
                password="password",
                proxy_command="tsh proxy ssh %r@%h:%p",
            )

            with patch("shutil.which", return_value="/usr/bin/tsh"):
                t.connect()
                # Verify that token expansion replaced placeholders and shutil.which resolved executable
                mock_proxy_command.assert_called_once_with(
                    "/usr/bin/tsh proxy ssh testuser@example.com:22"
                )


class TestTunnelStaticMethods:
    """Test Tunnel static methods for inventory operations."""

    def test_execute_on_inventory(self):
        """Test executing function on inventory."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            results = []

            def test_func(host):
                results.append(host)

            Tunnel.execute_on_inventory(inventory_path, test_func, group="all")
            assert len(results) == 1
            assert results[0]["hostname"] == "example1.com"
        finally:
            os.unlink(inventory_path)

    def test_execute_on_inventory_file_not_found(self):
        """Test executing function on nonexistent inventory."""
        with pytest.raises(FileNotFoundError):
            Tunnel.execute_on_inventory("/nonexistent/inventory.yaml", lambda x: None)

    def test_execute_on_inventory_invalid_yaml(self):
        """Test executing function on invalid YAML inventory."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: [")
            inventory_path = f.name
        try:
            with pytest.raises(yaml.YAMLError):
                Tunnel.execute_on_inventory(inventory_path, lambda x: None)
        finally:
            os.unlink(inventory_path)

    def test_execute_on_inventory_invalid_group(self):
        """Test executing function on invalid group."""
        inventory_data = {"all": {"hosts": {}}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with pytest.raises(ValueError, match="Group.*not found"):
                Tunnel.execute_on_inventory(
                    inventory_path, lambda x: None, group="invalid"
                )
        finally:
            os.unlink(inventory_path)

    def test_execute_on_inventory_parallel(self):
        """Test executing function on inventory in parallel."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    },
                    "host2": {
                        "ansible_host": "example2.com",
                        "ansible_user": "user2",
                        "ansible_ssh_pass": "pass2",
                    },
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            results = []

            def test_func(host):
                results.append(host)

            Tunnel.execute_on_inventory(
                inventory_path, test_func, group="all", parallel=True
            )
            assert len(results) == 2
        finally:
            os.unlink(inventory_path)

    def test_run_command_on_inventory(self):
        """Test running command on inventory."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with patch.object(Tunnel, "__init__", return_value=None):
                with patch.object(
                    Tunnel, "run_command", return_value=("output", "error")
                ):
                    with patch.object(Tunnel, "close"):
                        Tunnel.run_command_on_inventory(inventory_path, "ls")
        finally:
            os.unlink(inventory_path)

    def test_setup_all_passwordless_ssh(self):
        """Test setting up passwordless SSH for all hosts."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".pub", delete=False
            ) as f:
                pub_key_path = f.name
                f.write("ssh-rsa test_key")
            try:
                private_key_path = pub_key_path.replace(".pub", "")
                with patch("os.path.exists", side_effect=lambda x: x == pub_key_path):
                    with patch.object(Tunnel, "__init__", return_value=None):
                        with patch.object(Tunnel, "remove_host_key"):
                            with patch.object(Tunnel, "setup_passwordless_ssh"):
                                with patch.object(Tunnel, "connect"):
                                    with patch.object(
                                        Tunnel, "run_command", return_value=("", "")
                                    ):
                                        with patch.object(Tunnel, "close"):
                                            with patch.object(
                                                Tunnel,
                                                "test_key_auth",
                                                return_value=(True, "success"),
                                            ):
                                                Tunnel.setup_all_passwordless_ssh(
                                                    inventory_path, private_key_path
                                                )
            finally:
                if os.path.exists(pub_key_path):
                    os.unlink(pub_key_path)
        finally:
            os.unlink(inventory_path)

    def test_copy_ssh_config_on_inventory(self):
        """Test copying SSH config to all hosts."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                config_path = f.name
            try:
                with patch.object(Tunnel, "__init__", return_value=None):
                    with patch.object(Tunnel, "copy_ssh_config"):
                        with patch.object(Tunnel, "close"):
                            Tunnel.copy_ssh_config_on_inventory(
                                inventory_path, config_path
                            )
            finally:
                os.unlink(config_path)
        finally:
            os.unlink(inventory_path)

    def test_rotate_ssh_key_on_inventory(self):
        """Test rotating SSH keys for all hosts."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with patch.object(Tunnel, "__init__", return_value=None):
                with patch.object(Tunnel, "rotate_ssh_key"):
                    with patch.object(Tunnel, "close"):
                        Tunnel.rotate_ssh_key_on_inventory(inventory_path)
        finally:
            os.unlink(inventory_path)

    def test_send_file_on_inventory(self):
        """Test sending file to all hosts."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with tempfile.NamedTemporaryFile(delete=False) as f:
                local_path = f.name
            try:
                with patch.object(Tunnel, "__init__", return_value=None):
                    with patch.object(Tunnel, "send_file"):
                        with patch.object(Tunnel, "close"):
                            Tunnel.send_file_on_inventory(
                                inventory_path, local_path, "/remote/path"
                            )
            finally:
                os.unlink(local_path)
        finally:
            os.unlink(inventory_path)

    def test_send_file_on_inventory_file_not_exists(self):
        """Test sending file to inventory when local file doesn't exist."""
        inventory_data = {"all": {"hosts": {}}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with pytest.raises(ValueError, match="Local file does not exist"):
                Tunnel.send_file_on_inventory(
                    inventory_path, "/nonexistent/file", "/remote/path"
                )
        finally:
            os.unlink(inventory_path)

    def test_receive_file_on_inventory(self):
        """Test receiving file from all hosts."""
        inventory_data = {
            "all": {
                "hosts": {
                    "host1": {
                        "ansible_host": "example1.com",
                        "ansible_user": "user1",
                        "ansible_ssh_pass": "pass1",
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                with patch.object(Tunnel, "__init__", return_value=None):
                    with patch.object(Tunnel, "receive_file"):
                        with patch.object(Tunnel, "close"):
                            Tunnel.receive_file_on_inventory(
                                inventory_path, "/remote/file", tmpdir
                            )
        finally:
            os.unlink(inventory_path)


class TestTunnelCLI:
    """Test Tunnel CLI functionality."""

    def test_tunnel_manager_cli(self):
        """Test tunnel_manager CLI entry point."""
        from tunnel_manager.tunnel_manager import tunnel_manager

        # Test with --help
        with patch("sys.argv", ["tunnel-manager", "--help"]):
            try:
                tunnel_manager()
            except SystemExit:
                pass  # --help causes sys.exit


class TestAsyncTunnelManager:
    """Test AsyncTunnelManager class."""

    @pytest.mark.asyncio
    @patch("asyncssh.connect")
    async def test_async_run_command_on_host_agent_and_tokens(self, mock_connect):
        """Test async connect with path expansion, tokens, and agent fallback."""
        from tunnel_manager.async_tunnel import AsyncTunnelManager
        from tunnel_manager.models import HostConfig

        # Mock async context manager for asyncssh.connect
        mock_conn = Mock()
        mock_result = Mock()
        mock_result.exit_status = 0
        mock_result.stdout = "success_output"
        mock_result.stderr = ""

        # Async mock conn.run
        async def mock_run(cmd):
            return mock_result

        mock_conn.run = mock_run

        class AsyncContextManagerMock:
            async def __aenter__(self):
                return mock_conn

            async def __aexit__(self, *args):
                pass

        mock_connect.return_value = AsyncContextManagerMock()

        host_config = HostConfig(
            hostname="example.com",
            user="testuser",
            port=2222,
            identity_file="~/relative/key",
            proxy_command="tsh proxy ssh %r@%h:%p",
            extra_config={"certificate_file": "~/relative/cert"},
        )

        with patch(
            "os.path.expanduser", side_effect=lambda x: x.replace("~", "/home/user")
        ):
            with patch("shutil.which", return_value="/usr/bin/tsh"):
                res = await AsyncTunnelManager.async_run_command_on_host(
                    host_config, "ls"
                )

                # Verify results
                assert res.success is True
                assert res.stdout == "success_output"

                # Verify connect was called with expanded and resolved paths/tokens
                expected_key = os.path.abspath("/home/user/relative/key")
                expected_cert = os.path.abspath("/home/user/relative/cert")
                expected_proxy = "/usr/bin/tsh proxy ssh testuser@example.com:2222"

                call_kwargs = mock_connect.call_args[1]
                assert call_kwargs["host"] == "example.com"
                assert call_kwargs["port"] == 2222
                assert call_kwargs["username"] == "testuser"
                assert call_kwargs["client_keys"] == [(expected_key, expected_cert)]
                assert call_kwargs["proxy_command"] == expected_proxy


class TestSetupFullMeshSsh:
    """Test full-mesh SSH bootstrap functionality."""

    @patch("tunnel_manager.tunnel_manager.Tunnel")
    def test_setup_full_mesh_ssh_success(self, mock_tunnel_cls):
        """Test setup_full_mesh_ssh runs successfully for a mix of Linux and Windows targets."""
        # 1. Custom mock open to allow actual YAML files to be read normally while mocking SSH key reads
        original_open = open

        def custom_open(file, mode="r", *args, **kwargs):
            if "id_ed25519" in str(file):
                return mock_open(
                    read_data="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPubkey local_user@local_host"
                )()
            return original_open(file, mode, *args, **kwargs)

        # 2. Mock inventory data
        inventory_data = {
            "all": {
                "hosts": {
                    "node1": {
                        "ansible_host": "192.168.1.10",
                        "ansible_user": "root",
                        "ansible_ssh_pass": "secret1",
                    },
                    "node2": {
                        "ansible_host": "192.168.1.20",
                        "ansible_user": "Administrator",
                        "ansible_ssh_pass": "secret2",
                    },
                }
            }
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(inventory_data, f)
            inventory_path = f.name

        try:
            # 3. Mock Tunnel connections and behavior
            mock_t1 = Mock()  # node1 (Linux)
            mock_t2 = Mock()  # node2 (Windows)

            def tunnel_init(remote_host, username, password=None, **kwargs):
                if remote_host == "192.168.1.10":
                    return mock_t1
                elif remote_host == "192.168.1.20":
                    return mock_t2
                raise ValueError("Unexpected host")

            mock_tunnel_cls.side_effect = tunnel_init

            from tunnel_manager.models import CommandResult

            def run_cmd_t1(cmd):
                if "uname -s" in cmd:
                    return CommandResult(success=True, stdout="Linux\n")
                elif "id_ed25519.pub" in cmd:
                    return CommandResult(
                        success=True, stdout="ssh-ed25519 AAAAnode1pub root@node1\n"
                    )
                elif "SSH_CONNECTION" in cmd:
                    return CommandResult(
                        success=True, stdout="192.168.1.5 54321 192.168.1.10 22\n"
                    )
                elif "authorized_keys" in cmd and "cat" in cmd:
                    return CommandResult(success=True, stdout="")
                return CommandResult(success=True, stdout="")

            mock_t1.run_command.side_effect = run_cmd_t1
            mock_t1.test_key_auth.return_value = (True, "")

            def run_cmd_t2(cmd):
                if "uname -s" in cmd:
                    return CommandResult(
                        success=False, stderr="uname: command not found"
                    )
                elif "id_ed25519.pub" in cmd:
                    return CommandResult(
                        success=True,
                        stdout="ssh-ed25519 AAAAnode2pub administrator@node2\n",
                    )
                elif "SSH_CONNECTION" in cmd:
                    return CommandResult(
                        success=True, stdout="192.168.1.5 54322 192.168.1.20 22\n"
                    )
                elif "authorized_keys" in cmd and "type" in cmd:
                    return CommandResult(success=True, stdout="")
                return CommandResult(success=True, stdout="")

            mock_t2.run_command.side_effect = run_cmd_t2
            mock_t2.test_key_auth.return_value = (True, "")

            # 4. Run the mesh bootstrap function
            with (
                patch("os.path.exists", return_value=True),
                patch("tunnel_manager.tunnel_manager.open", side_effect=custom_open),
            ):
                result = Tunnel.setup_full_mesh_ssh(
                    inventory=inventory_path,
                    key_path="~/.ssh/id_ed25519",
                    key_type="ed25519",
                    parallel=False,
                )

            # 5. Verify the results
            assert result["status"] == "success", f"Result: {result}"
            assert len(result["errors"]) == 0

            host_map = {r["hostname"]: r for r in result["host_results"]}
            assert "192.168.1.10" in host_map
            assert "192.168.1.20" in host_map
            assert host_map["192.168.1.10"]["status"] == "success"
            assert host_map["192.168.1.20"]["status"] == "success"

        finally:
            os.unlink(inventory_path)
