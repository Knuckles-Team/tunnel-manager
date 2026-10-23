# CONN-TUNNEL-MANAGER-SDK test specification

Tests use synthetic credentials and mock transports. They need no network.

| Scenario | Requirements | Expected result |
|---|---|---|
| Secret references resolve through the SDK | `CONN-TUNNEL-MANAGER-SDK-R001` | A unit test resolves env:// and openbao:// references and rejects malformed ones |
| SDK floor and dependency set | `CONN-TUNNEL-MANAGER-SDK-R002` | pyproject.toml shows the floor and no requests pin |
| Production wiring | `CONN-TUNNEL-MANAGER-SDK-R003` | A test enters at the production entry point and reaches the wired call site. |
| Hot-path proof | `CONN-TUNNEL-MANAGER-SDK-R004` | The named integration test passes. |
