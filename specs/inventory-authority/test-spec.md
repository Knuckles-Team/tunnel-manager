# CONN-TUNNEL-MANAGER-INVENTORY — Test specification

Governing spec: [spec.md](spec.md).

| Test ID | Requirement | Proving test | Expected observation |
|---|---|---|---|
| T-001 | `CONN-TUNNEL-MANAGER-INVENTORY-R001` | `tests/test_inventory_path.py::test_single_canonical_inventory_path` | A fixture with only the canonical file present confirms every automatic reader resolves it, while a container-mount test confirms the deployed container reads the identical file read-only. |
| T-002 | `CONN-TUNNEL-MANAGER-INVENTORY-R002` | `tests/test_fleet_name.py::test_connector_name_is_the_fleet_name` | Every connector name in the package is `tunnel-manager-mcp`. |
| T-003 | `CONN-TUNNEL-MANAGER-INVENTORY-R003` | `tests/test_no_local_username.py::test_tunnel_uses_explicit_user_without_local_username` | With `getpass.getuser` raising `OSError`, a `Tunnel` built from an inventory entry resolves its username, and a failing tool call logs the underlying exception. |
| T-004 | `CONN-TUNNEL-MANAGER-INVENTORY-R004` | `tests/test_inventory_rollback.py::test_failed_add_host_does_not_leave_a_ghost` | With `save_inventory` raising, `add_host` raises and the alias is absent; `remove_host` raises and the alias is still present. |
| T-005 | `CONN-TUNNEL-MANAGER-INVENTORY-R005` | `tests/test_jump_host.py::test_jump_host_chain_verifies_each_hop_and_refuses_free_form_arguments` | The test named in the row passes. |
| T-006 | `CONN-TUNNEL-MANAGER-INVENTORY-R006` | `tests/test_pin_host_key.py::test_pin_writes_only_on_a_matching_fingerprint` | The test named in the row passes. |
| T-007 | `CONN-TUNNEL-MANAGER-INVENTORY-R007` | `tests/test_rotate_key_verified.py::test_old_key_is_kept_until_the_new_key_logs_in_and_inventory_is_updated` | The test named in the row passes. |

## Negative and boundary cases

Each proving test above includes the refusal or error case that its row names. A vendor outage or an unauthorised call must return the SDK typed error.

## Quality and release proof

Run `uv run pytest tests` and `pre-commit run --all-files` from the repository root. A planned test is added by the code change that lands the row.

## Machine roll-up proofs

- `CONN-TUNNEL-MANAGER-INVENTORY-R008`: `tests/test_system_hardware.py::test_served_hardware_tool_returns_the_probe_schema` (planned; the owning change adds the test)
- `CONN-TUNNEL-MANAGER-INVENTORY-R008.1`: `tests/test_machine_rollup.py::test_host_rolls_up_to_machine_and_ingest_emits_observes_links` (planned; the owning change adds the test)
- `CONN-TUNNEL-MANAGER-INVENTORY-R008.2`: `tests/test_system_hardware.py::test_hardware_payload_matches_the_probe_schema` (planned; the owning change adds the test)
- `CONN-TUNNEL-MANAGER-INVENTORY-R008.3`: `tests/test_system_hardware.py::test_served_tool_set_lists_the_hardware_tool` (planned; the owning change adds the test)
- `CONN-TUNNEL-MANAGER-INVENTORY-R008.4`: `tests/test_system_hardware.py::test_served_hardware_tool_returns_the_probe_schema` (planned; the owning change adds the test)
