"""Adversarial checks for fail-closed SSH server identity verification."""

from pathlib import Path
from unittest.mock import Mock, patch

import paramiko
import pytest

from tunnel_manager.async_tunnel import AsyncTunnelManager
from tunnel_manager.connection_security import (
    ConnectionPolicyError,
    validated_known_hosts_path,
)
from tunnel_manager.models import HostConfig
from tunnel_manager.tunnel_manager import Tunnel


def _known_hosts(tmp_path: Path) -> Path:
    path = tmp_path / "known_hosts"
    path.write_text("host.invalid ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake\n")
    path.chmod(0o600)
    return path


@patch("tunnel_manager.tunnel_manager.paramiko.SSHConfig")
@patch("tunnel_manager.tunnel_manager.paramiko.SSHClient")
def test_sync_tunnel_always_rejects_unknown_host_keys(
    mock_client, mock_config, tmp_path
):
    mock_config.return_value.lookup.return_value = {}
    client = mock_client.return_value
    client.get_transport.return_value = None
    known_hosts = _known_hosts(tmp_path)

    tunnel = Tunnel(
        remote_host="host.invalid",
        username="operator",
        known_hosts_file=str(known_hosts),
        ssh_config_file=str(tmp_path / "missing-config"),
        connect_retries=1,
    )
    tunnel.connect()

    client.load_host_keys.assert_called_once_with(str(known_hosts.resolve()))
    policy = client.set_missing_host_key_policy.call_args.args[0]
    assert isinstance(policy, paramiko.RejectPolicy)


def test_unknown_host_key_escape_hatches_are_rejected():
    with pytest.raises(ValueError, match="unknown SSH host keys"):
        HostConfig(
            hostname="host.invalid",
            user="operator",
            allow_unknown_host_keys=True,
        )
    with pytest.raises(TypeError):
        Tunnel(
            remote_host="host.invalid",
            username="operator",
            allow_unknown_host_keys=True,
        )


def test_plaintext_password_field_is_rejected_even_when_empty():
    with pytest.raises(ValueError, match="plaintext SSH passwords"):
        HostConfig(hostname="host.invalid", user="operator", password="")


@pytest.mark.asyncio
@patch("tunnel_manager.async_tunnel.asyncssh.connect")
async def test_async_tunnel_passes_explicit_verified_known_hosts(
    mock_connect, tmp_path
):
    known_hosts = _known_hosts(tmp_path)

    class ConnectionContext:
        async def __aenter__(self):
            raise RuntimeError("stop after validating connection arguments")

        async def __aexit__(self, *_args):
            return None

    mock_connect.return_value = ConnectionContext()
    host = HostConfig(
        hostname="host.invalid",
        user="operator",
        known_hosts_file=str(known_hosts),
    )

    response = await AsyncTunnelManager.async_run_command_on_host(host, "true")

    assert response.success is False
    assert mock_connect.call_args.kwargs["known_hosts"] == str(known_hosts.resolve())
    assert mock_connect.call_args.kwargs["connect_timeout"] == 10
    assert mock_connect.call_args.kwargs["login_timeout"] == 15


@pytest.mark.asyncio
@patch("tunnel_manager.async_tunnel.asyncssh.connect")
async def test_async_tunnel_fails_before_connect_without_trust_file(
    mock_connect, monkeypatch, tmp_path
):
    monkeypatch.setenv("HOME", str(tmp_path))
    host = HostConfig(hostname="host.invalid", user="operator")

    response = await AsyncTunnelManager.async_run_command_on_host(host, "true")

    assert response.success is False
    mock_connect.assert_not_called()


def test_known_hosts_rejects_symlinks_and_writable_files(tmp_path):
    target = _known_hosts(tmp_path)
    link = tmp_path / "linked-known-hosts"
    link.symlink_to(target)
    with pytest.raises(ConnectionPolicyError, match="trusted SSH known-hosts"):
        validated_known_hosts_path(str(link))

    target.chmod(0o622)
    with pytest.raises(ConnectionPolicyError, match="securely owned"):
        validated_known_hosts_path(str(target))


def test_sftp_rejects_local_symlink_sources_and_destinations(tmp_path):
    target = tmp_path / "target"
    target.write_text("sensitive", encoding="utf-8")
    link = tmp_path / "link"
    link.symlink_to(target)
    tunnel = Tunnel(remote_host="host.invalid", username="operator")
    tunnel.connect = Mock()

    with pytest.raises(OSError, match="regular file"):
        tunnel.send_file(str(link), "/remote/path")
    with pytest.raises(ConnectionPolicyError, match="destination is unsafe"):
        tunnel.receive_file("/remote/path", str(link))

    tunnel.connect.assert_not_called()
