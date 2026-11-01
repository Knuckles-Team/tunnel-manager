# CONN-TUNNEL-MANAGER-INVENTORY — Test specification

Governing spec: [spec.md](spec.md).

| Test ID | Requirement | Proving test | Expected observation |
|---|---|---|---|
| T-001 | `CONN-TUNNEL-MANAGER-INVENTORY-R001` | `tests/test_inventory_path.py::test_single_canonical_inventory_path` | A fixture with only the canonical file present confirms every automatic reader resolves it, while a container-mount test confirms the deployed container reads the identical file read-only. |
| T-002 | `CONN-TUNNEL-MANAGER-INVENTORY-R002` | `tests/test_fleet_name.py::test_connector_name_is_the_fleet_name` | Every connector name in the package is `tunnel-manager-mcp`. |
| T-003 | `CONN-TUNNEL-MANAGER-INVENTORY-R003` | `tests/test_no_local_username.py::test_tunnel_uses_explicit_user_without_local_username` | With `getpass.getuser` raising `OSError`, a `Tunnel` built from an inventory entry resolves its username, and a failing tool call logs the underlying exception. |

## Negative and boundary cases

Each proving test above includes the refusal or error case that its row names. A vendor outage or an unauthorised call must return the SDK typed error.

## Quality and release proof

Run `uv run pytest tests` and `pre-commit run --all-files` from the repository root. A planned test is added by the code change that lands the row.
