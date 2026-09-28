# tunnel-manager constitution

Status: PROPOSED. Drafted: 2026-09-28. Version: 0.1.0. Specification index: [specs/README.md](../../specs/README.md).

## I. One owner and one inventory authority

Tunnel-manager owns its inventory readers, operator writes, SSH actions, and tool registration. A design must inspect the existing CLI, `HostManager`, MCP, and remote execution paths before adding code. Use one operator XDG inventory source and one resolved identity across those paths. A container or downstream service is a consumer, never a second authority.

## II. Complete public specification

Each feature has `spec.md` for behavior, `plan.md` for architecture and reuse, `test-spec.md` for positive and negative proof, `tasks.md` for delivery, and `status.json` for evidence. A contributor can implement the tunnel-manager slice using only public repository material. Unresolved design choices are explicit.

## III. Real integration and safe failure

Acceptance follows an actual entry point through authorization, inventory resolution, SSH or file effect, and the observed result. Tests cover denial, invalid configuration, idempotency and recovery where relevant. A failed inventory read cannot be treated as a valid empty source or overwritten. No spec may claim runtime acceptance from a source-only test.

## IV. Quality and release discipline

Apply applicable CCCC, `jscpd`, Dupehound, KISS, Python-native, security, contract, package, and release checks. If a scanner is unconfigured, record the missing command or threshold rather than claiming a pass. Fix real complexity and duplication at the owner; reuse existing wiring and remove superseded paths when consumers move. Update only the public docs affected by the feature.

## V. Amendment and state

Amend this constitution in a reviewed change that names the reason and impact. Mark a spec `LANDED` only with the exact public default-branch source revision. Mark it `ACCEPTED` only after required quality, consumer, runtime, and release evidence meets the spec's acceptance criteria. Record delivery and acceptance separately.
