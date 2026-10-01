# TM-INVENTORY-001 — One operator inventory authority

**Owner:** tunnel-manager. **Requirement:** TM-INVENTORY-R001. **Delivery:** SPECIFIED. **Acceptance:** NOT_AUDITED.

See [`requirements.md`](requirements.md) for the definition of every requirement ID this spec owns and [`status.json`](status.json) for their current delivery and acceptance state.

## Purpose and state

An operator can keep one host inventory in the user's XDG configuration directory and run tunnel-manager as a CLI, library, MCP server, or container without creating a second inventory authority. This is a build specification. Source already implements part of the behavior, but the default resolver still falls back to `inventory.yaml`, the CLI still offers a legacy migration, and a released deployment plus runtime proof has not been audited.

`SPECIFIED` means the behavior and tests below are defined; it does not claim source is complete. `LANDED` requires an exact public default-branch revision. `ACCEPTED` additionally requires the source, container, and negative runtime receipts in [test-spec.md](test-spec.md). `NOT_AUDITED` means acceptance evidence has not been checked.

## Actors and user stories

1. **Operator (P1):** place `inventory.yml` under the selected user's `$XDG_CONFIG_HOME/agent-utilities/`, then use `inventory show`, `doctor`, `tm_hosts`, and `tm_inventory` against that same file.
2. **Container deployer (P1):** bind the operator file read-only to an inventory-reading runtime and see a clear startup failure if the source, mount, or path identity is wrong.
3. **Offline caller (P2):** inspect a deliberately supplied inventory file through an explicit non-serving API without silently changing the serving process authority.

## Requirements and acceptance scenarios

| ID | Requirement | Observable acceptance |
| --- | --- | --- |
| INVENTORY-1 | The automatic inventory path is exactly `$XDG_CONFIG_HOME/agent-utilities/inventory.yml`, using the XDG platform default when unset. No working-directory, package-resource, `.yaml`, or service-local fallback is allowed. | With only the XDG file present, every automatic reader resolves its normalized path; with only a legacy file present, no automatic reader uses it. |
| INVENTORY-2 | CLI, `HostManager`, MCP host tools, bulk inventory tools, and remote execution consume the same resolved file and source identity. A serving process cannot redirect one surface to another path through `TUNNEL_INVENTORY` or a per-call argument. | A divergent serving selector is rejected before inventory-dependent actions; all surfaces report the same source digest in a synthetic fixture. |
| INVENTORY-3 | Explicit file selection is confined to a named offline/replay boundary. It cannot replace the shared serving inventory, bypass authorization, or be inferred from a filename suffix. | Explicit offline input works with a temporary file; a serving call with a different file fails closed. |
| INVENTORY-4 | Missing, malformed, unreadable, stale-digest, and wrong-source files are distinguishable errors for inventory-dependent serving actions. Empty inventory is accepted only when explicitly valid for the operation; no failed read is converted to an empty host set that can later be saved over the source. | Each negative fixture yields a deterministic failure and leaves source bytes unchanged. |
| INVENTORY-5 | Inventory content is data, never a place for plaintext passwords, private keys, tokens, or unrestricted credential paths. Existing secret-reference and identity checks remain mandatory. A saved operator file is private and atomically replaced; containers have no write route to it. | Secret-value fixtures are rejected without echoing values; local save has private mode; a container write attempt fails. |
| INVENTORY-6 | Compose, Kubernetes, and equivalent inventory-reading profiles project the exact operator `inventory.yml` source to one fixed in-container file, read-only. The source is a deployment input rooted under the selected user's XDG config home; the image never seeds or mutates it. | Generated manifests identify the same basename/source identity; a disposable container reads the expected digest and cannot write the mount. |
| INVENTORY-7 | Documentation, examples, generated manifests, and user-facing errors describe this one path and the explicit offline boundary. Legacy readers and migration switches are removed after a deterministic migration guide is available. | A source scan and fresh-install walkthrough find no active fallback or contradictory instructions. |

### Failure and edge cases

XDG may be unset, point to a path with spaces, or be projected into a container; resolution uses normalized paths and never a hard-coded operator home. A stale environment selector is an error rather than a precedence contest. A dangling symlink, non-regular file, invalid YAML, duplicate/invalid host alias, or unreadable source fails closed. A concurrent file revision must be detected before write to avoid overwriting another operator's change. An inventory with no hosts is distinct from an unreadable inventory.

## Ownership and cross-repository contracts

| Requirement | Owner | Consumer / boundary | Acceptance evidence |
| --- | --- | --- | --- |
| INVENTORY-1 through INVENTORY-5, INVENTORY-7 | `Knuckles-Team/tunnel-manager` | `Knuckles-Team/agent-utilities` supplies shared config and identity services; tunnel-manager owns its inventory readers and writes. | Focused tests and source revision. |
| INVENTORY-6 | `Knuckles-Team/tunnel-manager` owns its deployable examples; the corresponding service manifest owner owns its generated runtime projection. | `Knuckles-Team/container-manager-mcp` is a **consumer** of the same operator file, never a second writer or authority. | Generated manifest diff, source digest, read-only runtime receipt. |

The stable inter-repository contract is [contracts/inventory-volume.md](contracts/inventory-volume.md). Each consumer must implement and test that contract in its own repository. A consumer's implementation or a tunnel-manager source commit alone does not accept the ecosystem cutover.

## Existing wiring and required design

`tunnel_manager/tunnel_manager.py::default_inventory_path`, `HostManager`, the `inventory` CLI, `tunnel_manager/mcp_server.py`'s process-wide manager, `mcp/mcp_inventory.py`, and `remote_execution.py` are the existing execution path. Reuse them; do not add an independent inventory store or a second path resolver. Current `default_inventory_path()` prefers `.yml` but reads `.yaml` when `.yml` is absent; `inventory doctor --fix` migrates that legacy file; `HostManager.save_inventory()` chooses serialization by suffix. The design in [plan.md](plan.md) closes those gaps and separates offline selection from a serving authority.

Out of scope: owning a workspace repository manifest, discovering a particular organization's hosts, modifying another package's credentials, or treating a graph projection as an inventory source. The quality and test obligations are in [test-spec.md](test-spec.md); implementation units are in [tasks.md](tasks.md).
