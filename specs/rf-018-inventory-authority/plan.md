# RF-018 design and implementation plan

## Architecture

The operator file is the only writable inventory authority. A composition boundary resolves the user's XDG config home once, validates the selected `inventory.yml`, and hands an immutable normalized path plus source digest to the existing tunnel-manager readers. The CLI, process-wide MCP `HostManager`, bulk tools, and remote execution must use that same object or the same checked resolver outcome. No tool may compute a second default or re-read an environment selector after process startup. The source is data for operations; any KG record, cached host list, or container mount is a derived view.

```text
operator XDG inventory.yml (private, writable by operator)
                 |
       validated path + digest
                 |
      existing HostManager/CLI/MCP readers
                 |
      authorized host actions / derived views

operator XDG inventory.yml --read-only projection--> serving container
```

Use `default_inventory_path()` as the migration point for automatic selection, `HostManager` for parsing and controlled save, and existing MCP/remote execution registrations for consumption. Keep shape handling in the existing parser; the selected file's extension must not choose a different data model. The shared XDG directory is a *relative* contract, not a machine-specific path. An application image does not contain an inventory seed.

## Decisions and boundaries

1. The automatic path is `$XDG_CONFIG_HOME/agent-utilities/inventory.yml`; when XDG is unset use the platform XDG default for the executing user. Normalize before comparison. Reject a conflicting serving selector, including `TUNNEL_INVENTORY`, rather than silently taking a later or earlier value. Keep a migration message that tells operators how to move an old file; do not perform automatic rename at startup or doctor.
2. Preserve a separate explicit path capability only for local/offline operation. Its API or CLI mode must be visibly named and may not be reachable through the serving MCP transport as an alternate inventory authority. Any required permission checks apply to the selected file as well as host actions.
3. Treat malformed or inaccessible source as a typed startup/operation error. `HostManager` currently marks `_inventory_load_failed` and refuses to save; extend that fail-closed pattern to every inventory-dependent serving entry point. A deliberately empty but valid file is an explicit state, not a substitute for a read failure.
4. For operator writes, use the existing atomic private YAML writer. Preserve the loaded document shape based on parsed structure, check source revision before write, and reject plaintext secret fields. For serving containers, prohibit writes by mount and runtime permissions; no save operation may appear to succeed on a read-only projection.
5. A deployment generator receives the selected operator XDG root as an input, resolves `agent-utilities/inventory.yml`, and emits the fixed read-only file mount defined in [contracts/inventory-volume.md](contracts/inventory-volume.md). Fail generation if the source is absent, wrong type, outside the selected XDG root, or mapped writable. Record source digest for a reproducibility receipt without logging content or secrets.
6. When changing CLI/MCP defaults, update the code-facing docs and example environment together. No general `/docs` gate is required; only the inventory instructions affected by this behavior need alignment. Keep public instructions executable with a user's own XDG directory and disposable test inventory.

## Compatibility and rollout

First ship a deterministic offline conversion command or documented manual copy with validation. Then remove `.yaml` fallback, `doctor --fix` migration, and stale serving override behavior in one reviewed source change. Deprecation messaging must identify the old input without trying to read it as the new authority. Existing callers using explicit `HostManager(config_file=...)` need either the named offline boundary or a clear validation error. Coordinate the consumer's release separately; deployment is complete only when all inventory-reading services project the same source identity and no legacy source remains active.

## Observability and security

Emit an inventory-resolution receipt containing source label, normalized path class, digest, revision if present, and outcome; never log inventory bytes, raw secrets, or private key paths. Runtime readiness reports missing source, digest mismatch, bad mount, and write denial separately. Health must not say ready for inventory actions when the source failed validation. The threat boundary is the operator's file: the container is a read-only consumer and the MCP caller does not gain filesystem selection rights by supplying a tool argument.

## Open design decision

The shared typed path-set and inventory schema are being defined across repositories. Tunnel-manager must use the one published shared contract when available; until then it must enforce the path, source, and digest rules here without inventing a second schema or weakening its current host YAML parser. This decision does not block a testable tunnel-manager implementation.
