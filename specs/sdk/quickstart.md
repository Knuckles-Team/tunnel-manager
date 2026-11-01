# CONN-TUNNEL-MANAGER-SDK — Quickstart

The shortest path that shows the served behaviour working.

```text
uv run pytest tests/test_connection_security.py tests/test_host_key_security.py tests/test_no_local_username.py tests/test_tm_remote_actions_characterize.py tests/test_transport_parity_integration.py tests/test_tunnel_manager.py tests/test_windows_portability.py
```

The command starts the connector in process and calls the served tools through the MCP client. A test marked planned in `test-spec.md` runs once the code change that lands its row adds it.
