"""Security-boundary tests for SSH inputs, secrets, limits, and diagnostics."""

import inspect
from importlib import import_module

import pytest

from tunnel_manager.connection_security import (
    LOOPBACK_BIND_HOST,
    ConnectionPolicyError,
    max_output_bytes,
    validate_command,
    validate_forward_target,
    validate_host,
    validate_local_bind,
    validate_port,
    validate_secret_ref,
    validate_username,
)
from tunnel_manager.doctor import diagnose


@pytest.mark.parametrize(
    "value",
    ["-oProxyCommand=x", "user@host", "host/path", "host\nname", " host"],
)
def test_host_validation_rejects_option_and_delimiter_injection(value):
    with pytest.raises(ConnectionPolicyError, match="Invalid SSH host"):
        validate_host(value)


@pytest.mark.parametrize("value", ["user@host", "-operator", "user name", "user\n"])
def test_username_validation_rejects_injection(value):
    with pytest.raises(ConnectionPolicyError, match="Invalid SSH username"):
        validate_username(value)


@pytest.mark.parametrize("value", [0, 65_536, -1, True, "not-a-port"])
def test_port_validation_is_bounded(value):
    with pytest.raises(ConnectionPolicyError, match="Invalid SSH port"):
        validate_port(value)


def test_forwarding_is_loopback_only_and_targets_are_validated():
    assert validate_local_bind() == LOOPBACK_BIND_HOST
    assert validate_local_bind("::1") == "::1"
    assert validate_forward_target("host.invalid", 443) == ("host.invalid", 443)
    with pytest.raises(ConnectionPolicyError, match="loopback"):
        validate_local_bind("0.0.0.0")


@pytest.mark.parametrize(
    "reference",
    ["env://SSH_PASSWORD", "vault://ssh/managed/password", "secret://ssh/password"],
)
def test_only_opaque_secret_references_are_accepted(reference):
    assert validate_secret_ref(reference) == reference


@pytest.mark.parametrize("value", ["literal-secret", "${SSH_PASSWORD}", "", "env://"])
def test_literal_or_malformed_credentials_are_rejected(value):
    with pytest.raises(ConnectionPolicyError):
        validate_secret_ref(value, required=True)


def test_command_and_output_limits_are_bounded(monkeypatch):
    monkeypatch.setenv("TUNNEL_MAX_COMMAND_CHARS", "8")
    with pytest.raises(ConnectionPolicyError, match="Invalid managed command"):
        validate_command("x" * 9)
    monkeypatch.setenv("TUNNEL_MAX_OUTPUT_BYTES", str(16 * 1024 * 1024 + 1))
    with pytest.raises(ConnectionPolicyError, match="resource-limit"):
        max_output_bytes()


def test_doctor_returns_metadata_only(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("TUNNEL_PASSWORD", "must-not-be-returned")
    result = diagnose()
    serialized = repr(result)
    assert result["status"] == "action_required"
    assert "must-not-be-returned" not in serialized
    assert str(tmp_path) not in serialized


def test_doctor_rejects_empty_legacy_password_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("TUNNEL_PASSWORD", "")

    result = diagnose()

    assert result["checks"]["plaintext_password_env_absent"] is False


def test_active_mcp_tool_schemas_do_not_accept_literal_passwords():
    mcp_server = import_module("tunnel_manager.mcp_server")

    registrars = (
        mcp_server.register_host_tools,
        mcp_server.register_remote_tools,
        mcp_server.register_system_tools,
        mcp_server.register_file_tools,
        mcp_server.register_security_tools,
        import_module("tunnel_manager.mcp.mcp_host").register_host_tools,
        import_module("tunnel_manager.mcp.mcp_remote").register_remote_tools,
        import_module("tunnel_manager.mcp.mcp_system").register_system_tools,
        import_module("tunnel_manager.mcp.mcp_file").register_file_tools,
        import_module("tunnel_manager.mcp.mcp_security").register_security_tools,
    )
    for registrar in registrars:
        captured = []

        class FakeMcp:
            def __init__(self, sink):
                self.sink = sink

            def tool(self, **_kwargs):
                def decorator(function):
                    self.sink.append(function)
                    return function

                return decorator

        registrar(FakeMcp(captured))
        signature = inspect.signature(captured[0])
        assert "password" not in signature.parameters
        assert "password_ref" in signature.parameters


def test_mcp_server_uses_shared_hardened_network_boundary():
    mcp_server = import_module("tunnel_manager.mcp_server")
    source = inspect.getsource(mcp_server.mcp_server)

    assert "mcp_network_run_kwargs(args)" in source
    assert "apply_served_security_profile" in source
    assert 'mcp.run(transport="stdio")' in source
    # B-19: stdio purity is now owned fd-level by the MCP SDK's own stdio_server()
    # inside agent-utilities (it claims fd 1 and dup2()s stderr over it for every
    # other writer), so the served module must NOT call a process-wide patch.
    # Inverted into a regression guard against the monkeypatch being reintroduced.
    assert "protect_stdio_jsonrpc" not in source
