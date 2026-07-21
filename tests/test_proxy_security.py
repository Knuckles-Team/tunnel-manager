"""Adversarial tests for inventory-provided SSH proxy commands."""

from pathlib import Path
from unittest.mock import patch

import pytest

from tunnel_manager.proxy_security import ProxyCommandError, proxy_command_argv


def test_shell_interpreters_are_not_proxy_executables(monkeypatch):
    monkeypatch.delenv("TUNNEL_PROXY_EXECUTABLES", raising=False)
    with pytest.raises(ProxyCommandError, match="allowlisted"):
        proxy_command_argv(
            "sh -c 'touch /tmp/owned'",
            hostname="target.example",
            port=22,
            username="operator",
        )


def test_executable_must_resolve_from_trusted_directory(monkeypatch, tmp_path):
    fake_dir = tmp_path / "untrusted"
    fake_dir.mkdir()
    fake = fake_dir / "ssh"
    fake.write_text("not executable", encoding="utf-8")
    monkeypatch.setenv("TUNNEL_PROXY_EXECUTABLES", "ssh")
    monkeypatch.setenv("TUNNEL_PROXY_TRUSTED_DIRS", str(tmp_path / "trusted"))
    with patch("shutil.which", return_value=str(fake)):
        with pytest.raises(ProxyCommandError, match="outside"):
            proxy_command_argv(
                "ssh -W %h:%p jump.example",
                hostname="target.example",
                port=22,
                username="operator",
            )


def test_placeholders_expand_as_single_argv_elements(monkeypatch, tmp_path):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    executable = trusted / "ssh"
    executable.write_text("binary", encoding="utf-8")
    monkeypatch.setenv("TUNNEL_PROXY_EXECUTABLES", "ssh")
    monkeypatch.setenv("TUNNEL_PROXY_TRUSTED_DIRS", str(trusted))
    with patch("shutil.which", return_value=str(executable)):
        argv = proxy_command_argv(
            "ssh -W %h:%p jump.example",
            hostname="target.example;touch-owned",
            port=22,
            username="operator",
        )
    assert argv[0] == str(Path(executable).resolve())
    assert argv[2] == "target.example;touch-owned:22"
    assert "touch-owned" not in argv[-1]


@pytest.mark.parametrize(
    "command",
    [
        "ssh -o ProxyCommand='sh -c id' -W %h:%p jump.example",
        "ssh -F /tmp/attacker-config -W %h:%p jump.example",
        "nc -e /bin/sh %h %p",
        "ncat --sh-exec id %h %p",
    ],
)
def test_allowlisted_tools_cannot_enable_nested_processes(
    command, monkeypatch, tmp_path
):
    trusted = tmp_path / "trusted"
    trusted.mkdir()
    executable = trusted / command.split()[0]
    executable.write_text("binary", encoding="utf-8")
    monkeypatch.setenv("TUNNEL_PROXY_EXECUTABLES", "ssh,nc,ncat")
    monkeypatch.setenv("TUNNEL_PROXY_TRUSTED_DIRS", str(trusted))
    with patch("shutil.which", return_value=str(executable)):
        with pytest.raises(ProxyCommandError, match="not permitted"):
            proxy_command_argv(
                command,
                hostname="target.example",
                port=22,
                username="operator",
            )
