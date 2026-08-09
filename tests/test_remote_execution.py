"""Security and contract tests for the RMDD-14 remote execution seam."""

from __future__ import annotations

import importlib
import shlex
from pathlib import Path
from unittest.mock import Mock

import pytest
import yaml
from agent_utilities.security.brain_context import ActorContext
from pydantic import ValidationError

from tunnel_manager.models import CommandResult, HostConfig
from tunnel_manager.remote_execution import (
    AuthorizedTarget,
    ExecutionOutcome,
    FailureClass,
    HostInventory,
    RemoteCommandRequest,
    RemoteTargetError,
    TunnelCommandExecutor,
    render_remote_command,
)
from tunnel_manager.tunnel_manager import Tunnel


def _actor(*roles: str) -> ActorContext:
    return ActorContext(
        actor_id="agent:repository-manager",
        tenant_id="tenant:development",
        authenticated=True,
        roles=roles,
    )


def _known_hosts(tmp_path: Path) -> Path:
    path = tmp_path / "known_hosts"
    path.write_text("remote.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFake\n")
    path.chmod(0o600)
    return path


def _config(tmp_path: Path, *, hostname: str = "remote.example") -> HostConfig:
    return HostConfig(
        hostname=hostname,
        user="operator",
        known_hosts_file=str(_known_hosts(tmp_path)),
    )


class _Inventory:
    def __init__(self, configs: dict[str, HostConfig]):
        self.configs = configs

    def get_host(self, alias: str) -> HostConfig | None:
        return self.configs.get(alias)


class _Transport:
    def __init__(
        self,
        result: CommandResult | None = None,
        *,
        connect_error: Exception | None = None,
        run_error: Exception | None = None,
        close_error: Exception | None = None,
    ):
        self.result = result or CommandResult(success=True, stdout="ok")
        self.connect_error = connect_error
        self.run_error = run_error
        self.close_error = close_error
        self.connected = False
        self.closed = False
        self.commands: list[tuple[str, int | None]] = []

    def connect(self, timeout: int | None = None) -> None:
        if self.connect_error:
            raise self.connect_error
        self.connected = True

    def run_command(self, command: str, timeout: int | None = None) -> CommandResult:
        self.commands.append((command, timeout))
        if self.run_error:
            raise self.run_error
        return self.result

    def close(self) -> None:
        self.closed = True
        if self.close_error:
            raise self.close_error


@pytest.fixture
def entitled_inventory(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.identity_scoped_resources",
        lambda _namespace, available, **_kwargs: tuple(available),
    )
    config = _config(tmp_path)
    manager = _Inventory({"build-host": config})
    inventory = HostInventory(manager_factory=lambda: manager)
    return inventory, config


def _request(**overrides) -> RemoteCommandRequest:
    values = {"argv": ("printf", "%s", "ok"), "workdir": "/workspace"}
    values.update(overrides)
    return RemoteCommandRequest(**values)


def test_inventory_uses_tunnel_inventory_override(monkeypatch):
    manager = Mock()
    manager.get_host.return_value = None
    manager_class = Mock(return_value=manager)
    monkeypatch.setattr("tunnel_manager.remote_execution.HostManager", manager_class)
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.setting",
        lambda name, default=None: (
            "/private/inventory.yml" if name == "TUNNEL_INVENTORY" else default
        ),
    )
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.identity_scoped_resources",
        lambda _namespace, available, **_kwargs: tuple(available),
    )
    with pytest.raises(RemoteTargetError):
        HostInventory().resolve("missing", _actor("ssh:*"))
    manager_class.assert_called_once_with(config_file="/private/inventory.yml")


def test_inventory_uses_canonical_default_resolver_when_no_override(monkeypatch):
    manager = Mock()
    manager.get_host.return_value = None
    manager_class = Mock(return_value=manager)
    monkeypatch.setattr("tunnel_manager.remote_execution.HostManager", manager_class)
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.setting",
        lambda name, default=None: None if name == "TUNNEL_INVENTORY" else default,
    )
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.default_inventory_path",
        lambda: "/xdg/agent-utilities/inventory.yml",
    )
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.identity_scoped_resources",
        lambda *_args, **_kwargs: (),
    )

    with pytest.raises(RemoteTargetError):
        HostInventory().resolve("missing", _actor("ssh:*"))

    manager_class.assert_called_once_with(
        config_file="/xdg/agent-utilities/inventory.yml"
    )


def test_real_host_manager_is_the_only_inventory_loader(monkeypatch, tmp_path):
    inventory_path = tmp_path / "inventory.yml"
    known_hosts = _known_hosts(tmp_path)
    inventory_path.write_text(
        yaml.safe_dump(
            {
                "build-host": {
                    "hostname": "remote.example",
                    "user": "operator",
                    "known_hosts_file": str(known_hosts),
                }
            }
        )
    )
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.setting",
        lambda name, default=None: (
            str(inventory_path) if name == "TUNNEL_INVENTORY" else default
        ),
    )

    target = HostInventory().resolve("build-host", _actor("ssh:build-host"))

    assert target.alias == "build-host"


def test_inventory_resolve_returns_opaque_alias_only(entitled_inventory):
    inventory, config = entitled_inventory
    target = inventory.resolve("build-host", _actor("ssh:build-host"))

    assert target.alias == "build-host"
    payload = target.model_dump()
    assert payload == {
        "contract_version": "1",
        "kind": "inventory_alias",
        "alias": "build-host",
        "capability_labels": ("ssh",),
    }
    serialized = repr(target)
    assert config.hostname not in serialized
    assert config.user not in serialized
    assert "password_ref" not in serialized


@pytest.mark.parametrize("alias", ["unknown", "operator@host", "host/path", "host:22"])
def test_unknown_or_malformed_alias_fails_closed(entitled_inventory, alias):
    inventory, _ = entitled_inventory
    with pytest.raises(RemoteTargetError):
        inventory.resolve(alias, _actor("ssh:build-host"))


def test_unauthorized_and_revoked_alias_fail_closed(monkeypatch, tmp_path):
    manager = _Inventory({"build-host": _config(tmp_path)})
    monkeypatch.setattr(
        "tunnel_manager.remote_execution.identity_scoped_resources",
        lambda *_args, **_kwargs: (),
    )
    inventory = HostInventory(manager_factory=lambda: manager)
    with pytest.raises(RemoteTargetError):
        inventory.resolve("build-host", _actor("ssh:other-host"))


def test_dispatch_reloads_inventory_and_reauthorizes(entitled_inventory, tmp_path):
    inventory, first_config = entitled_inventory
    second_config = _config(tmp_path, hostname="new-build-host.example")
    configs = iter(
        [
            _Inventory({"build-host": first_config}),
            _Inventory({"build-host": second_config}),
        ]
    )
    inventory = HostInventory(manager_factory=lambda: next(configs))
    transport = _Transport()
    seen: list[str] = []

    def factory(config: HostConfig):
        seen.append(config.hostname)
        return transport

    target = inventory.resolve("build-host", _actor("ssh:build-host"))
    result = TunnelCommandExecutor(
        inventory,
        transport_factory=factory,
    ).execute(target, _request(), _actor("ssh:build-host"))

    assert result.outcome is ExecutionOutcome.SUCCEEDED
    assert seen == ["new-build-host.example"]
    assert transport.closed is True


def test_public_models_reject_connection_fields_and_raw_shell():
    with pytest.raises(ValidationError):
        AuthorizedTarget(alias="build-host", hostname="remote.example")
    with pytest.raises(ValidationError):
        RemoteCommandRequest(
            argv=("echo", "ok"),
            workdir="/workspace",
            user="operator",
        )
    with pytest.raises(ValidationError, match="raw shell"):
        RemoteCommandRequest(argv=("sh", "-c", "echo unsafe"), workdir="/workspace")


def test_metacharacter_argument_is_one_quoted_argv_element():
    request = _request(argv=("printf", "%s", "safe; touch /tmp/owned"))
    rendered = render_remote_command(request)
    assert rendered.count("&&") == 1
    assert shlex.split(rendered)[-1] == "safe; touch /tmp/owned"
    assert "&& touch" not in rendered


def test_known_hosts_policy_refuses_before_transport(entitled_inventory):
    _, config = entitled_inventory
    bad_config = config.model_copy(update={"known_hosts_file": "/missing/known_hosts"})
    manager = _Inventory({"build-host": bad_config})
    transport_factory = Mock()
    executor = TunnelCommandExecutor(
        HostInventory(manager_factory=lambda: manager),
        transport_factory=transport_factory,
    )

    result = executor.execute(
        AuthorizedTarget(alias="build-host"), _request(), _actor("ssh:build-host")
    )

    assert result.outcome is ExecutionOutcome.REFUSED
    assert result.failure_class is FailureClass.WORKER_ENVIRONMENT_FAILURE
    transport_factory.assert_not_called()


@pytest.mark.parametrize("field", ["identity_file", "proxy_command"])
def test_key_and_proxy_policy_refuse_before_transport(
    entitled_inventory, tmp_path, field
):
    _, config = entitled_inventory
    if field == "identity_file":
        key = tmp_path / "key"
        key.write_text("private-key")
        key.chmod(0o600)
        link = tmp_path / "key-link"
        link.symlink_to(key)
        bad_config = config.model_copy(update={field: str(link)})
    else:
        bad_config = config.model_copy(update={field: "sh -c 'touch /tmp/owned'"})
    manager = _Inventory({"build-host": bad_config})
    transport_factory = Mock()
    result = TunnelCommandExecutor(
        HostInventory(manager_factory=lambda: manager),
        transport_factory=transport_factory,
    ).execute(
        AuthorizedTarget(alias="build-host"), _request(), _actor("ssh:build-host")
    )

    assert result.outcome is ExecutionOutcome.REFUSED
    assert result.failure_class is FailureClass.WORKER_ENVIRONMENT_FAILURE
    transport_factory.assert_not_called()


def test_timeout_disconnect_and_bounded_redacted_output(
    entitled_inventory, monkeypatch
):
    _, config = entitled_inventory
    monkeypatch.setenv("REMOTE_PASSWORD", "private-secret")
    config = config.model_copy(update={"password_ref": "env://REMOTE_PASSWORD"})
    manager = _Inventory({"build-host": config})
    transport = _Transport(run_error=TimeoutError())
    executor = TunnelCommandExecutor(
        HostInventory(manager_factory=lambda: manager),
        transport_factory=lambda _: transport,
    )

    result = executor.execute(
        AuthorizedTarget(alias="build-host"),
        _request(max_stdout_bytes=8, max_stderr_bytes=8),
        _actor("ssh:build-host"),
    )

    assert result.outcome is ExecutionOutcome.TIMED_OUT
    assert result.failure_class is FailureClass.CANCELLED_DEADLINE
    assert transport.closed is True
    assert config.hostname not in repr(result)
    assert config.user not in repr(result)
    assert "private-secret" not in repr(result)
    assert "REMOTE_PASSWORD" not in repr(result)


def test_close_on_connect_error_and_cleanup_failure(entitled_inventory):
    inventory, _ = entitled_inventory
    transport = _Transport(connect_error=ConnectionError(), close_error=RuntimeError())
    executor = TunnelCommandExecutor(
        inventory,
        transport_factory=lambda _: transport,
    )

    result = executor.execute(
        AuthorizedTarget(alias="build-host"), _request(), _actor("ssh:build-host")
    )

    assert transport.closed is True
    assert result.cleanup_ok is False
    assert result.outcome is ExecutionOutcome.FAILED
    assert result.failure_class is FailureClass.WORKER_ENVIRONMENT_FAILURE


def test_default_real_tunnel_path_connects_once_and_closes(
    entitled_inventory, monkeypatch
):
    inventory, _ = entitled_inventory
    tunnel_module = importlib.import_module("tunnel_manager.tunnel_manager")
    ssh_config = Mock()
    ssh_config.lookup.return_value = {}
    client = Mock()
    transport = Mock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport
    stdout = Mock()
    stdout.channel = Mock()
    stdout.read.return_value = b"ok"
    stderr = Mock()
    stderr.read.return_value = b""
    stdout.channel.recv_exit_status.return_value = 0
    client.exec_command.return_value = (Mock(), stdout, stderr)
    monkeypatch.setattr(tunnel_module.paramiko, "SSHConfig", lambda: ssh_config)
    monkeypatch.setattr(tunnel_module.paramiko, "SSHClient", lambda: client)
    connect_calls: list[int] = []
    original_connect = Tunnel.connect

    def counted_connect(self, *args, **kwargs):
        connect_calls.append(1)
        return original_connect(self, *args, **kwargs)

    monkeypatch.setattr(Tunnel, "connect", counted_connect)
    result = TunnelCommandExecutor(inventory).execute(
        AuthorizedTarget(alias="build-host"), _request(), _actor("ssh:build-host")
    )

    assert result.outcome is ExecutionOutcome.SUCCEEDED
    assert connect_calls == [1]
    client.connect.assert_called_once()
    client.close.assert_called_once()


@pytest.mark.parametrize(
    ("mode", "outcome", "failure_class"),
    [
        (
            "timeout",
            ExecutionOutcome.TIMED_OUT,
            FailureClass.CANCELLED_DEADLINE,
        ),
        (
            "output_limit",
            ExecutionOutcome.REFUSED,
            FailureClass.WORKER_ENVIRONMENT_FAILURE,
        ),
    ],
)
def test_default_real_tunnel_path_preserves_typed_failures_and_closes(
    entitled_inventory, monkeypatch, mode, outcome, failure_class
):
    inventory, _ = entitled_inventory
    tunnel_module = importlib.import_module("tunnel_manager.tunnel_manager")
    ssh_config = Mock()
    ssh_config.lookup.return_value = {}
    client = Mock()
    transport = Mock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport
    if mode == "timeout":
        client.exec_command.side_effect = TimeoutError("command deadline")
    else:
        monkeypatch.setattr(tunnel_module, "max_output_bytes", lambda: 8)
        stdout = Mock()
        stdout.channel = Mock()
        stdout.read.return_value = b"x" * 9
        stderr = Mock()
        stderr.read.return_value = b""
        client.exec_command.return_value = (Mock(), stdout, stderr)
    monkeypatch.setattr(tunnel_module.paramiko, "SSHConfig", lambda: ssh_config)
    monkeypatch.setattr(tunnel_module.paramiko, "SSHClient", lambda: client)
    connect_calls: list[int] = []
    original_connect = Tunnel.connect

    def counted_connect(self, *args, **kwargs):
        connect_calls.append(1)
        return original_connect(self, *args, **kwargs)

    monkeypatch.setattr(Tunnel, "connect", counted_connect)
    result = TunnelCommandExecutor(inventory).execute(
        AuthorizedTarget(alias="build-host"), _request(), _actor("ssh:build-host")
    )

    assert result.outcome is outcome
    assert result.failure_class is failure_class
    assert connect_calls == [1]
    client.connect.assert_called_once()
    client.close.assert_called_once()


def test_tunnel_legacy_run_command_error_shape_remains_default():
    tunnel = object.__new__(Tunnel)
    tunnel.logger = Mock()
    tunnel.connect = Mock()
    tunnel.ssh_client = Mock()
    tunnel.ssh_client.exec_command.side_effect = TimeoutError("deadline")

    legacy_result = tunnel.run_command("printf ok")

    assert legacy_result.success is False
    assert legacy_result.error_message == "ManagedCommandError"
    with pytest.raises(TimeoutError):
        tunnel.run_command("printf ok", propagate_errors=True)


def test_nonzero_command_is_candidate_failure_and_output_is_bounded(entitled_inventory):
    inventory, _ = entitled_inventory
    transport = _Transport(
        result=CommandResult(
            success=False,
            stdout="1234567890",
            stderr="failed",
        )
    )
    result = TunnelCommandExecutor(
        inventory,
        transport_factory=lambda _: transport,
    ).execute(
        AuthorizedTarget(alias="build-host"),
        _request(max_stdout_bytes=4, max_stderr_bytes=3),
        _actor("ssh:build-host"),
    )

    assert result.outcome is ExecutionOutcome.FAILED
    assert result.failure_class is FailureClass.VALIDATION_CANDIDATE_FAILURE
    assert result.exit_code == 1
    assert result.stdout_tail == "1234"
    assert result.stderr_tail == "fai"


def test_environment_refs_are_not_silently_ignored(entitled_inventory):
    inventory, _ = entitled_inventory
    factory = Mock()
    result = TunnelCommandExecutor(
        inventory,
        transport_factory=factory,
    ).execute(
        AuthorizedTarget(alias="build-host"),
        _request(environment_refs=("REMOTE_ENV",)),
        _actor("ssh:build-host"),
    )

    assert result.outcome is ExecutionOutcome.REFUSED
    assert result.failure_class is FailureClass.INVALID_REQUEST
    factory.assert_not_called()
