# CONN-TUNNEL-MANAGER-SDK requirements

Each row defines one requirement. [`status.json`](status.json) holds the generated state.

| ID | Requirement | Verification |
|---|---|---|
| `CONN-TUNNEL-MANAGER-SDK-R001` | **Secret references resolve through the SDK.** tunnel-manager must resolve each env:// and openbao:// SSH credential reference through the SDK credential resolver. It must not parse reference schemes itself This row follows `SDK-CENTRALIZED-CAPABILITIES-R009`. | A unit test resolves env:// and openbao:// references and rejects malformed ones |
| `CONN-TUNNEL-MANAGER-SDK-R002` | **SDK floor and dependency set.** The package must require agent-connector-sdk 0.3.11 or later. It must not pin requests This row follows `SDK-CENTRALIZED-CAPABILITIES-R040`. | pyproject.toml shows the floor and no requests pin |
| `CONN-TUNNEL-MANAGER-SDK-R003` | **Production wiring.** `resolve_secret_ref` in `tunnel_manager/connection_security.py` calls `resolve_secret_reference`. The MCP tools in `tunnel_manager/mcp_server.py` call it for every `password_ref` | A test enters at the production entry point and reaches the wired call site. |
| `CONN-TUNNEL-MANAGER-SDK-R004` | **Hot-path proof.** A test calls `resolve_secret_ref` with an env:// reference set in the environment. The test reaches the SDK resolver and returns the value | The named integration test passes. |
