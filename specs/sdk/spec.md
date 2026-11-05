# CONN-TUNNEL-MANAGER-SDK — Shared SDK capabilities in tunnel-manager

**Owner:** tunnel-manager.

See [`requirements.md`](requirements.md) for each row and [`status.json`](status.json) for its generated state.

## Purpose

tunnel-manager must use the scion-sdk capability for each concern the SDK centralizes. A connector copy of a centralized capability splits policy across the fleet.

## Why a new spec

Search: `git grep -n "SDK" -- specs` found no row that owns SDK capability use in tunnel-manager. The SDK index spec `SCION-CENTRALIZED-CAPABILITIES` owns the capabilities. This spec owns the connector side of each one.

## Delivery mapping

Component: tunnel-manager connector

Code: ../../tunnel_manager/__init__.py

## User Scenarios & Testing

### User Story 1 - Secret references resolve through the SDK (Priority: P1)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: tunnel-manager must resolve each env:// and openbao:// SSH credential reference through the SDK credential resolver. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver` runs, **Then** a unit test resolves env:// and openbao:// references and rejects malformed ones.

### User Story 2 - SDK floor and dependency set (Priority: P1)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: The package must require scion-sdk 0.3.11 or later. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_connection_security.py::test_dependencies_carry_sdk_floor_and_no_requests_pin` runs, **Then** pyproject.toml shows the floor and no requests pin.

### User Story 3 - Production wiring (Priority: P1)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: `resolve_secret_ref` in `tunnel_manager/connection_security.py` calls `resolve_secret_reference`. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver` runs, **Then** a test enters at the production entry point and reaches the wired call site.

### User Story 4 - Hot-path proof (Priority: P2)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: A test calls `resolve_secret_ref` with an env:// reference set in the environment. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver` runs, **Then** the named integration test passes.

### User Story 5 - One wiring for every transport (Priority: P2)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: stdio, streamable HTTP with an explicit `--auth-type none`, and streamable HTTP with a JWT serve the same tools through scion-sdk's one actor and entitlement path. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_transport_parity_integration.py::test_jwt_refusals_name_their_cause` runs, **Then** `tests/test_served_actor_binding.py`; `tests/test_transport_parity_integration.py::test_jwt_refusals_name_their_cause`.

### User Story 6 - One connection resolver (Priority: P2)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: `mcp_server.resolve_target` is the only place a host name becomes connection settings. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_transport_parity_integration.py::test_stdio_serves_every_tool` runs, **Then** `tests/test_transport_parity_integration.py` asserts that the listed port is the inventory group's port, not 22, and that both tools refuse an unknown alias identically.

### User Story 7 - Every tool behaves the same on every transport (Priority: P2)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: Against an in-process SSH host whose user and port live only in group vars, each of the 41 tools gives the same outcome over stdio, no-auth HTTP on 0.0.0.0, and JWT HTTP. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_transport_parity_integration.py::test_http_with_jwt_serves_every_tool_identically` runs, **Then** `tests/test_transport_parity_integration.py::test_stdio_serves_every_tool`, `::test_http_without_auth_serves_every_tool_identically` and `::test_http_with_jwt_serves_every_tool_identically`, run in CI.

### User Story 8 - Failures name their cause; no host binaries (Priority: P2)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: Every tool failure reports `Type: message`, sanitized of secrets and local paths, never a bare exception type. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_transport_parity_integration.py::test_stdio_no_auth_destructive_call` runs, **Then** `tests/test_transport_parity_integration.py` (per-tool outcomes carry the cause). `tests/test_tm_remote_actions_characterize.py::TestRemoveHostKey::test_explicit_confirm_skips_elicitation`. `tests/test_transport_parity_integration.py::test_stdio_no_auth_destructive_call`, `::test_http_no_auth_localhost_destructive_call` and `::test_http_jwt_destructive_call` (real stdio, no-auth HTTP and JWT HTTP, with and without client elicitation). `tests/test_tunnel_manager.py::TestTunnel::test_check_ssh_server` and `::test_rotate_ssh_key`.

### User Story 9 - Windows portability (Priority: P2)

The fleet operator and the engine rely on this behaviour of `tunnel-manager`: The package imports and runs on Windows with no POSIX-only API. It is proven independently of the other stories.

**Acceptance Scenarios**:

1. **Given** the `tunnel-manager` connector built from the default branch, **When** `tests/test_windows_portability.py::test_package_imports_no_posix_only_modules` runs, **Then** `tests/test_windows_portability.py`; `tests/test_host_key_security.py::test_known_hosts_rejects_symlinks_and_writable_files`; `tests/test_no_local_username.py::test_run_command_returns_specific_policy_cause`; the `Windows tests` job in `.github/workflows/connector.yml`.

### Edge Cases

- The vendor service is unreachable or rejects the credential: the connector returns the SDK typed error and never a partial result.
- An argument outside the documented inputs is refused with the SDK typed refusal and causes no effect on the vendor service.

## Requirements

- **FR-001**: Secret references resolve through the SDK. Rows: `CONN-TUNNEL-MANAGER-SDK-R001`.
- **FR-002**: SDK floor and dependency set. Rows: `CONN-TUNNEL-MANAGER-SDK-R002`.
- **FR-003**: Production wiring. Rows: `CONN-TUNNEL-MANAGER-SDK-R003`.
- **FR-004**: Hot-path proof. Rows: `CONN-TUNNEL-MANAGER-SDK-R004`.
- **FR-005**: One wiring for every transport. Rows: `CONN-TUNNEL-MANAGER-SDK-R005`.
- **FR-006**: One connection resolver. Rows: `CONN-TUNNEL-MANAGER-SDK-R005.1`.
- **FR-007**: Every tool behaves the same on every transport. Rows: `CONN-TUNNEL-MANAGER-SDK-R005.2`.
- **FR-008**: Failures name their cause; no host binaries. Rows: `CONN-TUNNEL-MANAGER-SDK-R005.3`.
- **FR-009**: Windows portability. Rows: `CONN-TUNNEL-MANAGER-SDK-R006`.

## Success Criteria

- **SC-001**: A unit test resolves env:// and openbao:// references and rejects malformed ones. Rows: `CONN-TUNNEL-MANAGER-SDK-R001`.
- **SC-002**: pyproject.toml shows the floor and no requests pin. Rows: `CONN-TUNNEL-MANAGER-SDK-R002`.
- **SC-003**: A test enters at the production entry point and reaches the wired call site. Rows: `CONN-TUNNEL-MANAGER-SDK-R003`.
- **SC-004**: The named integration test passes. Rows: `CONN-TUNNEL-MANAGER-SDK-R004`.
- **SC-005**: `tests/test_served_actor_binding.py`; `tests/test_transport_parity_integration.py::test_jwt_refusals_name_their_cause`. Rows: `CONN-TUNNEL-MANAGER-SDK-R005`.
- **SC-006**: `tests/test_transport_parity_integration.py` asserts that the listed port is the inventory group's port, not 22, and that both tools refuse an unknown alias identically. Rows: `CONN-TUNNEL-MANAGER-SDK-R005.1`.
- **SC-007**: `tests/test_transport_parity_integration.py::test_stdio_serves_every_tool`, `::test_http_without_auth_serves_every_tool_identically` and `::test_http_with_jwt_serves_every_tool_identically`, run in CI. Rows: `CONN-TUNNEL-MANAGER-SDK-R005.2`.
- **SC-008**: `tests/test_transport_parity_integration.py` (per-tool outcomes carry the cause). `tests/test_tm_remote_actions_characterize.py::TestRemoveHostKey::test_explicit_confirm_skips_elicitation`. `tests/test_transport_parity_integration.py::test_stdio_no_auth_destructive_call`, `::test_http_no_auth_localhost_destructive_call` and `::test_http_jwt_destructive_call` (real stdio, no-auth HTTP and JWT HTTP, with and without client elicitation). `tests/test_tunnel_manager.py::TestTunnel::test_check_ssh_server` and `::test_rotate_ssh_key`. Rows: `CONN-TUNNEL-MANAGER-SDK-R005.3`.
- **SC-009**: `tests/test_windows_portability.py`; `tests/test_host_key_security.py::test_known_hosts_rejects_symlinks_and_writable_files`; `tests/test_no_local_username.py::test_run_command_returns_specific_policy_cause`; the `Windows tests` job in `.github/workflows/connector.yml`. Rows: `CONN-TUNNEL-MANAGER-SDK-R006`.

## Assumptions

- The `tunnel-manager` package keeps the entry point and module layout named in the rows.
- The shared SDK supplies the transport, authentication, retry and certification helpers the rows reuse.

## Traceability

| Label | Rows | Design section | Test ID | Evidence |
|---|---|---|---|---|
| FR-001 | `CONN-TUNNEL-MANAGER-SDK-R001` | plan.md Production caller chain | T-001 | tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver |
| FR-002 | `CONN-TUNNEL-MANAGER-SDK-R002` | plan.md Production caller chain | T-002 | tests/test_connection_security.py::test_dependencies_carry_sdk_floor_and_no_requests_pin |
| FR-003 | `CONN-TUNNEL-MANAGER-SDK-R003` | plan.md Production caller chain | T-003 | tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver |
| FR-004 | `CONN-TUNNEL-MANAGER-SDK-R004` | plan.md Production caller chain | T-004 | tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver |
| FR-005 | `CONN-TUNNEL-MANAGER-SDK-R005` | plan.md Production caller chain | T-005 | tests/test_transport_parity_integration.py::test_jwt_refusals_name_their_cause |
| FR-006 | `CONN-TUNNEL-MANAGER-SDK-R005.1` | plan.md Production caller chain | T-006 | tests/test_transport_parity_integration.py::test_stdio_serves_every_tool |
| FR-007 | `CONN-TUNNEL-MANAGER-SDK-R005.2` | plan.md Production caller chain | T-007 | tests/test_transport_parity_integration.py::test_http_with_jwt_serves_every_tool_identically |
| FR-008 | `CONN-TUNNEL-MANAGER-SDK-R005.3` | plan.md Production caller chain | T-008 | tests/test_transport_parity_integration.py::test_stdio_no_auth_destructive_call |
| FR-009 | `CONN-TUNNEL-MANAGER-SDK-R006` | plan.md Production caller chain | T-009 | tests/test_windows_portability.py::test_package_imports_no_posix_only_modules |
