# CONN-TUNNEL-MANAGER-SDK — Test specification

Governing spec: [spec.md](spec.md).

| Test ID | Requirement | Proving test | Expected observation |
|---|---|---|---|
| T-001 | `CONN-TUNNEL-MANAGER-SDK-R001` | `tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver` | A unit test resolves env:// and openbao:// references and rejects malformed ones |
| T-002 | `CONN-TUNNEL-MANAGER-SDK-R002` | `tests/test_connection_security.py::test_dependencies_carry_sdk_floor_and_no_requests_pin` | pyproject.toml shows the floor and no requests pin |
| T-003 | `CONN-TUNNEL-MANAGER-SDK-R003` | `tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver` | A test enters at the production entry point and reaches the wired call site. |
| T-004 | `CONN-TUNNEL-MANAGER-SDK-R004` | `tests/test_connection_security.py::test_secret_ref_resolves_through_sdk_resolver` | The named integration test passes. |
| T-005 | `CONN-TUNNEL-MANAGER-SDK-R005` | covered by the child rows | `tests/test_served_actor_binding.py`; `tests/test_transport_parity_integration.py::test_jwt_refusals_name_their_cause`. |
| T-006 | `CONN-TUNNEL-MANAGER-SDK-R005.1` | `tests/test_transport_parity_integration.py::test_stdio_serves_every_tool` | `tests/test_transport_parity_integration.py` asserts that the listed port is the inventory group's port, not 22, and that both tools refuse an unknown alias identically. |
| T-007 | `CONN-TUNNEL-MANAGER-SDK-R005.2` | `tests/test_transport_parity_integration.py::test_http_with_jwt_serves_every_tool_identically` | `tests/test_transport_parity_integration.py::test_stdio_serves_every_tool`, `::test_http_without_auth_serves_every_tool_identically` and `::test_http_with_jwt_serves_every_tool_identically`, run in CI. |
| T-008 | `CONN-TUNNEL-MANAGER-SDK-R005.3` | `tests/test_transport_parity_integration.py::test_stdio_no_auth_destructive_call` | `tests/test_transport_parity_integration.py` (per-tool outcomes carry the cause). `tests/test_tm_remote_actions_characterize.py::TestRemoveHostKey::test_explicit_confirm_skips_elicitation`. `tests/test_transport_parity_integration.py::test_stdio_no_auth_destructive_call`, `::test_http_no_auth_localhost_destructive_call` and `::test_http_jwt_destructive_call` (real stdio, no-auth HTTP and JWT HTTP, with and without client elicitation). `tests/test_tunnel_manager.py::TestTunnel::test_check_ssh_server` and `::test_rotate_ssh_key`. |
| T-009 | `CONN-TUNNEL-MANAGER-SDK-R006` | `tests/test_windows_portability.py::test_package_imports_no_posix_only_modules` (planned) | `tests/test_windows_portability.py`; `tests/test_host_key_security.py::test_known_hosts_rejects_symlinks_and_writable_files`; `tests/test_no_local_username.py::test_run_command_returns_specific_policy_cause`; the `Windows tests` job in `.github/workflows/connector.yml`. |

## Negative and boundary cases

Each proving test above includes the refusal or error case that its row names. A vendor outage or an unauthorised call must return the SDK typed error.

## Quality and release proof

Run `uv run pytest tests` and `pre-commit run --all-files` from the repository root. A planned test is added by the code change that lands the row.

## Adoption of scion-sdk 0.10.0 (`CONN-TUNNEL-MANAGER-SDK-R007`)

| Requirement | Test | Observation |
|---|---|---|
| `CONN-TUNNEL-MANAGER-SDK-R007` | `tests/test_scion_sdk_0_10_imports.py::test_every_scion_sdk_import_resolves_on_the_pinned_release` | Every `scion_sdk` import resolves on the pinned release; a removed path fails the test. |
