# TM-INVENTORY requirements

Every requirement this specification owns, with the proof that closes it. Delivery state and
public evidence for each ID are recorded in [`status.json`](status.json); this file defines what
each ID means. The design is in [`spec.md`](spec.md) and [`plan.md`](plan.md), the test contract
in [`test-spec.md`](test-spec.md), and the work order in [`tasks.md`](tasks.md).

| ID | Requirement | Verification |
|---|---|---|
| `TM-INVENTORY-R001` | **One canonical host inventory path across surfaces.** tunnel-manager resolves the shared host inventory from exactly one path, `$XDG_CONFIG_HOME/agent-connector-sdk/inventory.yml` (using the XDG platform default when unset), with no working-directory, packaged-resource, legacy `.yaml`, or per-service fallback, and every CLI, library, MCP, and container surface reads that same file. | A fixture with only the canonical file present confirms every automatic reader resolves it, while a container-mount test confirms the deployed container reads the identical file read-only. |
| `TM-INVENTORY-R002` | **Fleet name.** `pyproject.toml` declares `tunnel-manager-mcp` as the single `agent_connector_sdk.connector` entry point. The content pack, the manifest `connector`, the fingerprints and the ingest binding all carry `tunnel-manager-mcp`. Proving test: `tests/test_fleet_name.py::test_connector_name_is_the_fleet_name`. | Every connector name in the package is `tunnel-manager-mcp`. |
