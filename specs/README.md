# tunnel-manager specifications

This tracked `specs/` directory is the public build contract for tunnel-manager. Each owner spec contains the behavior, architecture, interfaces, tests, quality requirements, and acceptance criteria needed to implement it from public repository contents. A draft source may inform a spec, but it is not a dependency for contributors.

## Structure

Create `specs/<stable-id>/` with `spec.md` for user outcomes and requirements, `plan.md` for architecture and existing wiring, `test-spec.md` for positive and negative proof, `tasks.md` for implementation order, `requirements.md` for the definition of every requirement ID the spec owns, and `status.json` for machine-readable delivery and acceptance evidence, with one entry per requirement ID in its `requirements` array, each carrying its own `delivery_state` and evidence. Use [`_template/`](_template/) as the starting point. Additional `contracts/`, `data-model.md`, or `quickstart.md` files belong inside the owner spec when needed. The tracked [constitution](../.specify/memory/constitution.md) governs this repository's specs. A requirement counts as delivered only once its evidence includes a merged-head commit on the default branch.

The workflow follows GitHub Spec Kit's specify, plan, and tasks sequence, with an explicit test contract. Each spec must name one owner and stable requirement IDs, inventory existing components, reuse live wiring, and fully describe cross-repository interfaces it owns. Link public counterpart specs where useful; every requirement needed to build this repository's slice remains here. CCCC, `jscpd`, Dupehound, KISS, language-native, security, contract, and release checks must be specified where applicable. Unknown tooling or thresholds are stated as gaps, never invented as passing results.

## Status legend

`status.json` feeds the public HTML report. Delivery states are `UNKNOWN`, `SPECIFIED`, `BUILDING`, `BUILT`, `LANDED`, `CLOSED`, `DEFERRED`, and `REJECTED`; acceptance states are `NOT_AUDITED`, `PENDING`, `ACCEPTED`, and `FAILED`.

| State | Meaning |
| --- | --- |
| `UNKNOWN` | Existing behavior has not received an exact-revision audit. |
| `SPECIFIED` | The owner contract and tests are documented; implementation is not established. |
| `BUILDING` | Implementation is in progress. |
| `BUILT` | Source exists, but the required public default-branch landing is not recorded. |
| `LANDED` | Exact owning-repository source revision is merged to the public default branch. |
| `CLOSED` | The obligation has a documented disposition with evidence. |
| `DEFERRED` | Work is intentionally postponed with a recorded reason. |
| `REJECTED` | The proposed work was declined with a recorded reason. |
| `NOT_AUDITED` | Acceptance evidence has not been evaluated. |
| `PENDING` | Acceptance review is open. |
| `ACCEPTED` | Required source, quality, consumer, and runtime receipts pass. |
| `FAILED` | A required acceptance condition failed. |

Use `SPECIFIED/NOT_AUDITED` for a complete build spec with open implementation. `LANDED` requires an exact public merged revision; `ACCEPTED` additionally requires the checked-in test and consumer or runtime receipts. A spec publication, source-only test, or generated report does not itself prove acceptance. Record public PR, issue, check, and commit links in the owner spec and `evidence` array.

## Owner map and index

| Stable ID | Owner spec | Responsibility | State |
| --- | --- | --- | --- |
| `TM-INVENTORY-001` | [One operator inventory authority](inventory-authority/spec.md) | XDG inventory selection, tunnel-manager consumers, and read-only runtime projection contract | `SPECIFIED / NOT_AUDITED` |

Related public owner specs: [agent-utilities](https://github.com/Knuckles-Team/agent-utilities/tree/main/specs) owns shared application services; [graph-os](https://github.com/Knuckles-Team/graph-os/tree/main/specs) owns serving composition; [repository-manager](https://github.com/Knuckles-Team/repository-manager/tree/main/specs) owns repository/workspace discovery. [container-manager-mcp](https://github.com/Knuckles-Team/container-manager-mcp) consumes the inventory projection. Tunnel-manager remains the owner of its reader and write behavior.

## Contributions

Read `AGENTS.md` and the [constitution](../.specify/memory/constitution.md). Propose `spec.md`, resolve architecture in `plan.md`, define proof in `test-spec.md`, then implement `tasks.md` in a dedicated branch or worktree. Link PRs to stable IDs and change status only with exact receipts. Contributors can use the public [universal-skills spec-generator](https://github.com/Knuckles-Team/universal-skills/tree/main/universal_skills/development/spec-generator), [spec-verifier](https://github.com/Knuckles-Team/universal-skills/tree/main/universal_skills/development/spec-verifier), [task-planner](https://github.com/Knuckles-Team/universal-skills/tree/main/universal_skills/development/task-planner), [SDD full lifecycle](https://github.com/Knuckles-Team/universal-skills/tree/main/universal_skills/development-workflows/sdd-full-lifecycle), and [graph-os-development](https://github.com/Knuckles-Team/graph-os/blob/main/graph_os/skills/graph-os-development/SKILL.md) skill.
