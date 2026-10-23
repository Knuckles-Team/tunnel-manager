# CONN-TUNNEL-MANAGER-SDK tasks

| Task | Deliverable | Proof |
|---|---|---|
| T01 | Secret references resolve through the SDK | A unit test resolves env:// and openbao:// references and rejects malformed ones |
| T02 | SDK floor and dependency set | pyproject.toml shows the floor and no requests pin |
| T03 | Production wiring | A test enters at the production entry point and reaches the wired call site. |
| T04 | Hot-path proof | The named integration test passes. |
