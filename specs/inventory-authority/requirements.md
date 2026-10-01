# TM-INVENTORY-001 requirements

Every requirement this specification owns, with the proof that closes it. Delivery state and
public evidence for each ID are recorded in [`status.json`](status.json); this file defines what
each ID means. The design is in [`spec.md`](spec.md) and [`plan.md`](plan.md), the test contract
in [`test-spec.md`](test-spec.md), and the work order in [`tasks.md`](tasks.md).

| ID | Requirement | Verification |
|---|---|---|
| `TM-INVENTORY-R001` | **One canonical host inventory path across surfaces.** tunnel-manager resolves the shared host inventory from exactly one path, `$XDG_CONFIG_HOME/agent-utilities/inventory.yml` (using the XDG platform default when unset), with no working-directory, packaged-resource, legacy `.yaml`, or per-service fallback, and every CLI, library, MCP, and container surface reads that same file. | A fixture with only the canonical file present confirms every automatic reader resolves it, while a container-mount test confirms the deployed container reads the identical file read-only. |
