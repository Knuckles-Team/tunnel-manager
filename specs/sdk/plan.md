# CONN-TUNNEL-MANAGER-SDK — Implementation plan

Governing spec: [spec.md](spec.md). Rows: [requirements.md](requirements.md).

## Summary

This plan states how `tunnel-manager` delivers the rows of `CONN-TUNNEL-MANAGER-SDK`. The live caller is the `tunnel-manager` console script. The owner is the `tunnel_manager` package. The rows reuse the `scion-sdk` helpers and add no second authority. The plan changes no runtime code.

## Technical Context

- **Language/Version**: Python >=3.12, <3.15
- **Primary Dependencies**: scion-sdk[mcp]>=0.6.5,<0.7.0; fastmcp; further pins in `pyproject.toml` (scion-sdk[mcp]>=0.6.5,<0.7.0, fastmcp>=4.1.2, paramiko>=5.0.0, asyncssh>=2.24.1)
- **Storage**: N/A, the connector keeps no store of its own
- **Testing**: pytest; each row names the proving test as `path::name`
- **Target Platform**: Linux container and stdio or streamable HTTP MCP clients
- **Project Type**: connector
- **Performance Goals**: N/A, the vendor service sets the latency
- **Constraints**: vendor calls go through the SDK governed client; no connector-local transport
- **Scale/Scope**: 9 active row(s) in this spec

## Constitution Check

- Organization constitution 1.5.0, spec-first change: pass. Every behaviour is a row of this spec with a bound or planned test.
- Repository article R-I, connector scope: pass. The rows stay inside this connector's one external system and reuse the SDK for shared capabilities.

## Project Structure

- `tunnel_manager/mcp_server.py` (existing)
- `tunnel_manager/connection_security.py` (existing)
- `tests/test_connection_security.py` (existing)
- `pyproject.toml` (existing)
- `tests/test_served_actor_binding.py` (existing)
- `tests/test_transport_parity_integration.py` (existing)
- `tests/test_windows_portability.py` (existing)
- `tests/test_host_key_security.py` (existing)
- `tests/test_no_local_username.py` (existing)
- `.github/workflows/connector.yml` (existing)
- `tests/test_tm_remote_actions_characterize.py` (existing)
- `tests/test_tunnel_manager.py` (existing)

## Phase 0: Research

No unknowns. Every row names its code and test; the caller chain of each row was read from the code.

## Phase 1: Design

### Summary

This plan states how `tunnel-manager` delivers the rows of `CONN-TUNNEL-MANAGER-SDK`. The live caller is the `tunnel-manager` console script. The owner is the `tunnel_manager` package. The rows reuse the `scion-sdk` helpers and add no second authority. The plan changes no runtime code.

### Technical Context

- **Language/Version**: Python >=3.12, <3.15
- **Primary Dependencies**: scion-sdk[mcp]>=0.6.5,<0.7.0; fastmcp; further pins in `pyproject.toml` (scion-sdk[mcp]>=0.6.5,<0.7.0, fastmcp>=4.1.2, paramiko>=5.0.0, asyncssh>=2.24.1)
- **Storage**: N/A, the connector keeps no store of its own
- **Testing**: pytest; each row names the proving test as `path::name`
- **Target Platform**: Linux container and stdio or streamable HTTP MCP clients
- **Project Type**: connector
- **Performance Goals**: N/A, the vendor service sets the latency
- **Constraints**: vendor calls go through the SDK governed client; no connector-local transport
- **Scale/Scope**: 9 active row(s) in this spec

### Constitution Check

- Organization constitution 1.5.0, spec-first change: pass. Every behaviour is a row of this spec with a bound or planned test.
- Repository article R-I, connector scope: pass. The rows stay inside this connector's one external system and reuse the SDK for shared capabilities.

### Project Structure

- `tunnel_manager/mcp_server.py` (existing)
- `tunnel_manager/connection_security.py` (existing)
- `tests/test_connection_security.py` (existing)
- `pyproject.toml` (existing)
- `tests/test_served_actor_binding.py` (existing)
- `tests/test_transport_parity_integration.py` (existing)
- `tests/test_windows_portability.py` (existing)
- `tests/test_host_key_security.py` (existing)
- `tests/test_no_local_username.py` (existing)
- `.github/workflows/connector.yml` (existing)
- `tests/test_tm_remote_actions_characterize.py` (existing)
- `tests/test_tunnel_manager.py` (existing)

### Phase 0: Research

No unknowns. Every row names its code and test; the caller chain of each row was read from the code.

### Phase 1: Design

### Summary

This plan states how `tunnel-manager` delivers the rows of `CONN-TUNNEL-MANAGER-SDK`. The live caller is the `tunnel-manager` console script. The owner is the `tunnel_manager` package. The rows reuse the `scion-sdk` helpers and add no second authority. The plan changes no runtime code.

### Technical Context

- **Language/Version**: Python >=3.12, <3.15
- **Primary Dependencies**: scion-sdk[mcp]>=0.6.5,<0.7.0; fastmcp; further pins in `pyproject.toml` (scion-sdk[mcp]>=0.6.5,<0.7.0, fastmcp>=4.1.2, paramiko>=5.0.0, asyncssh>=2.24.1)
- **Storage**: N/A, the connector keeps no store of its own
- **Testing**: pytest; each row names the proving test as `path::name`
- **Target Platform**: Linux container and stdio or streamable HTTP MCP clients
- **Project Type**: connector
- **Performance Goals**: N/A, the vendor service sets the latency
- **Constraints**: vendor calls go through the SDK governed client; no connector-local transport
- **Scale/Scope**: 9 active row(s) in this spec

### Constitution Check

- Organization constitution 1.5.0, spec-first change: pass. Every behaviour is a row of this spec with a bound or planned test.
- Repository article R-I, connector scope: pass. The rows stay inside this connector's one external system and reuse the SDK for shared capabilities.

### Project Structure

- `tunnel_manager/connection_security.py` (existing)
- `tunnel_manager/mcp_server.py` (existing)
- `tests/test_served_actor_binding.py` (existing)
- `tests/test_transport_parity_integration.py` (existing)
- `tests/test_tm_remote_actions_characterize.py` (existing)
- `tests/test_tunnel_manager.py` (existing)

### Phase 0: Research

No unknowns. Every row names its code and test; the caller chain of each row was read from the code.

### Phase 1: Design

### Summary

This plan states how `tunnel-manager` delivers the rows of `CONN-TUNNEL-MANAGER-SDK`. The live caller is the `tunnel-manager` console script. The owner is the `tunnel_manager` package. The rows reuse the `scion-sdk` helpers and add no second authority. The plan changes no runtime code.

### Technical Context

- **Language/Version**: Python >=3.12, <3.15
- **Primary Dependencies**: scion-sdk[mcp]>=0.6.5,<0.7.0; fastmcp; further pins in `pyproject.toml` (scion-sdk[mcp]>=0.6.5,<0.7.0, fastmcp>=4.1.2, paramiko>=5.0.0, asyncssh>=2.24.1)
- **Storage**: N/A, the connector keeps no store of its own
- **Testing**: pytest; each row names the proving test as `path::name`
- **Target Platform**: Linux container and stdio or streamable HTTP MCP clients
- **Project Type**: connector
- **Performance Goals**: N/A, the vendor service sets the latency
- **Constraints**: vendor calls go through the SDK governed client; no connector-local transport
- **Scale/Scope**: 9 active row(s) in this spec

### Constitution Check

- Organization constitution 1.5.0, spec-first change: pass. Every behaviour is a row of this spec with a bound or planned test.
- Repository article R-I, connector scope: pass. The rows stay inside this connector's one external system and reuse the SDK for shared capabilities.

### Project Structure

- `tunnel_manager/connection_security.py` (existing)
- `tunnel_manager/mcp_server.py` (existing)
- `tests/test_served_actor_binding.py` (existing)
- `tests/test_transport_parity_integration.py` (existing)
- `tests/test_tm_remote_actions_characterize.py` (existing)
- `tests/test_tunnel_manager.py` (existing)

### Phase 0: Research

No unknowns. Every row names its code and test; the caller chain of each row was read from the code.

### Phase 1: Design

### Existing system and reuse

The SDK owns every capability named in the rows. tunnel-manager adds no module that repeats one. Each row deletes connector code and calls the SDK module.

### Live call path

`resolve_secret_ref` in `tunnel_manager/connection_security.py` calls `resolve_secret_reference`. The MCP tools in `tunnel_manager/mcp_server.py` call it for every `password_ref`

### Compatibility

Tool names, arguments, and results stay identical. The SDK floor is `scion-sdk>=0.3.11`.

### Phase 2: Task approach

`tasks.md` holds one task per row, producer first. Rows that depend on none run in parallel. A task is checked when its `Spec:` trailer is on the default branch.

### Complexity Tracking

None. The constitution check passed.

### Build contract

- `pre-commit run --all-files` runs ruff check, ruff format, the shared `connector-standard`, `spec`, `secrets` and `dependency-readiness` gates at the pinned shared revision.
- `uv run pytest tests` runs the proving tests; the shared complexity, duplication and KISS gates apply their org thresholds and this repository sets no local override.
- A change adds no scanner suppression and no duplicate implementation of an SDK helper.

### Production caller chain


### Cross-repo seams

None. The rows depend only on the published `scion-sdk` package, which the connector imports.

### Phase 2: Task approach

`tasks.md` holds one task per row, producer first. Rows that depend on none run in parallel. A task is checked when its `Spec:` trailer is on the default branch.

### Complexity Tracking

None. The constitution check passed.

### Build contract

- `pre-commit run --all-files` runs ruff check, ruff format, the shared `connector-standard`, `spec`, `secrets` and `dependency-readiness` gates at the pinned shared revision.
- `uv run pytest tests` runs the proving tests; the shared complexity, duplication and KISS gates apply their org thresholds and this repository sets no local override.
- A change adds no scanner suppression and no duplicate implementation of an SDK helper.

### Production caller chain


### Cross-repo seams

None. The rows depend only on the published `scion-sdk` package, which the connector imports.

### Phase 2: Task approach

`tasks.md` holds one task per row, producer first. Rows that depend on none run in parallel. A task is checked when its `Spec:` trailer is on the default branch.

### Complexity Tracking

None. The constitution check passed.

### Build contract

- `pre-commit run --all-files` runs ruff check, ruff format, the shared `connector-standard`, `spec`, `secrets` and `dependency-readiness` gates at the pinned shared revision.
- `uv run pytest tests` runs the proving tests; the shared complexity, duplication and KISS gates apply their org thresholds and this repository sets no local override.
- A change adds no scanner suppression and no duplicate implementation of an SDK helper.

### Production caller chain

- `CONN-TUNNEL-MANAGER-SDK-R001`: an MCP tool of `tunnel_manager/mcp_server.py` reads a `password_ref`, which `resolve_secret_ref` (tunnel_manager/connection_security.py:179) resolves through the SDK `resolve_secret_reference` (tunnel_manager/connection_security.py:190).
- `CONN-TUNNEL-MANAGER-SDK-R002`: the installer and the `dependency-readiness` pre-commit gate read `[project] dependencies` in `pyproject.toml`.
- `CONN-TUNNEL-MANAGER-SDK-R003`: an MCP tool of `tunnel_manager/mcp_server.py` reads a `password_ref`, which `resolve_secret_ref` (tunnel_manager/connection_security.py:179) resolves through the SDK `resolve_secret_reference` (tunnel_manager/connection_security.py:190).
- `CONN-TUNNEL-MANAGER-SDK-R004`: an MCP tool of `tunnel_manager/mcp_server.py` reads a `password_ref`, which `resolve_secret_ref` (tunnel_manager/connection_security.py:179) resolves through the SDK `resolve_secret_reference` (tunnel_manager/connection_security.py:190).
- `CONN-TUNNEL-MANAGER-SDK-R005.1`: every `tm_*` tool calls `resolve_target` (tunnel_manager/mcp_server.py:397) to turn a host name into connection settings.
- `CONN-TUNNEL-MANAGER-SDK-R005.2`: a client on stdio, no-auth HTTP or JWT HTTP calls any of the 41 tools of `tunnel_manager/mcp_server.py`.
- `CONN-TUNNEL-MANAGER-SDK-R005.3`: any tool failure in `tunnel_manager/mcp_server.py` is rendered as `Type: message`; destructive tools take `confirm=true` when the client cannot elicit.
- `CONN-TUNNEL-MANAGER-SDK-R006`: the package imports on Windows; private file helpers `secure_descriptor` and `secure_path` of `tunnel_manager/` harden key and known-hosts files.

### Cross-repo seams

None. The rows depend only on the published `scion-sdk` package, which the connector imports.

## Phase 2: Task approach

`tasks.md` holds one task per row, producer first. Rows that depend on none run in parallel. A task is checked when its `Spec:` trailer is on the default branch.

## Complexity Tracking

None. The constitution check passed.

## Build contract

- `pre-commit run --all-files` runs ruff check, ruff format, the shared `connector-standard`, `spec`, `secrets` and `dependency-readiness` gates at the pinned shared revision.
- `uv run pytest tests` runs the proving tests; the shared complexity, duplication and KISS gates apply their org thresholds and this repository sets no local override.
- A change adds no scanner suppression and no duplicate implementation of an SDK helper.

## Production caller chain

- `CONN-TUNNEL-MANAGER-SDK-R001`: an MCP tool of `tunnel_manager/mcp_server.py` reads a `password_ref`, which `resolve_secret_ref` (tunnel_manager/connection_security.py:179) resolves through the SDK `resolve_secret_reference` (tunnel_manager/connection_security.py:190).
- `CONN-TUNNEL-MANAGER-SDK-R002`: the installer and the `dependency-readiness` pre-commit gate read `[project] dependencies` in `pyproject.toml`.
- `CONN-TUNNEL-MANAGER-SDK-R003`: an MCP tool of `tunnel_manager/mcp_server.py` reads a `password_ref`, which `resolve_secret_ref` (tunnel_manager/connection_security.py:179) resolves through the SDK `resolve_secret_reference` (tunnel_manager/connection_security.py:190).
- `CONN-TUNNEL-MANAGER-SDK-R004`: an MCP tool of `tunnel_manager/mcp_server.py` reads a `password_ref`, which `resolve_secret_ref` (tunnel_manager/connection_security.py:179) resolves through the SDK `resolve_secret_reference` (tunnel_manager/connection_security.py:190).
- `CONN-TUNNEL-MANAGER-SDK-R005.1`: every `tm_*` tool calls `resolve_target` (tunnel_manager/mcp_server.py:397) to turn a host name into connection settings.
- `CONN-TUNNEL-MANAGER-SDK-R005.2`: a client on stdio, no-auth HTTP or JWT HTTP calls any of the 41 tools of `tunnel_manager/mcp_server.py`.
- `CONN-TUNNEL-MANAGER-SDK-R005.3`: any tool failure in `tunnel_manager/mcp_server.py` is rendered as `Type: message`; destructive tools take `confirm=true` when the client cannot elicit.
- `CONN-TUNNEL-MANAGER-SDK-R006`: the package imports on Windows; private file helpers `secure_descriptor` and `secure_path` of `tunnel_manager/` harden key and known-hosts files.

## Cross-repo seams

None. The rows depend only on the published `scion-sdk` package, which the connector imports.
