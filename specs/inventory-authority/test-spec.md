# TM-INVENTORY-001 test specification

All fixtures use temporary XDG roots, synthetic host aliases, and non-routable example addresses. Do not require a live private fleet or publish inventory contents. Record the exact source revision, command, result, and generated manifest digest with each acceptance claim.

| Scenario | Requirements | Fixture and action | Expected result / evidence |
| --- | --- | --- | --- |
| Canonical path | 01, 02 | Temporary XDG root with `agent-utilities/inventory.yml`; exercise CLI, `HostManager`, MCP host tools, bulk tools, and remote execution. | One normalized path and digest; no second resolver result. Unit and integration tests. |
| Legacy-only negative | 01, 07 | Place only `inventory.yaml`, then invoke all automatic readers and `doctor`. | No fallback, rename, auto-seed, or success from legacy content; clear migration guidance. |
| Divergent selector | 02, 03 | Set `TUNNEL_INVENTORY` or supply a serving MCP inventory argument pointing to a different file. | Deterministic conflict/refusal before any SSH or write action. |
| Explicit offline file | 03 | Named offline/replay API with a temporary noncanonical file. | Read succeeds without changing process-wide inventory identity; authorization and input validation still apply. |
| Read failure matrix | 04 | Missing file, directory, dangling symlink, unreadable file, malformed YAML, stale expected digest, and concurrent edit. | Distinct failure class, no fabricated empty inventory, no overwrite, no secret-bearing error body. |
| Content and save | 04, 05 | Flat and Ansible-shaped synthetic YAML; valid secret references; plaintext password and token fields; concurrent revision. | Structure preserved by parser shape; private atomic save; prohibited values and stale write rejected. |
| Manifest contract | 06 | Generate Compose and Kubernetes projections using a temporary operator XDG root. | Exact source basename and target, read-only flags, no package seed or machine-specific checked-in path; snapshot/digest receipt. |
| Runtime denial | 05, 06 | Start disposable container/pod with generated projection; try read then write and mutate source. | Read yields selected digest; write fails; changed source is detected before readiness/next action. |
| Public docs scan | 07 | Scan active CLI help, README, inventory guide, example env, and deployable manifests. | No active `.yaml` fallback or conflicting default; migration note and offline boundary are clear. |

## Quality and evidence policy

Run the repository's applicable unit/integration checks and configured pre-commit checks for changed code. CCCC, `jscpd`, and Dupehound are required quality dimensions for any implementation: report command, configured threshold, and result when the tooling is configured. This repository currently exposes no checked-in command or threshold for those three tools, so the implementation PR must either add a reproducible configuration or explicitly record that gap and seek the ecosystem's agreed threshold; it cannot claim those gates passed by omission. KISS requires reusing `default_inventory_path`, `HostManager`, the existing MCP registrations, and the atomic writer; a new store or parallel resolver needs a demonstrated necessity.

Acceptance requires positive and negative source tests, manifest reproducibility, a disposable runtime read/write-denial receipt, and a source/consumer revision pair. A source-only unit pass can justify `LANDED`, not `ACCEPTED`.
