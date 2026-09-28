# RF-018 delivery tasks

| Task | Owner and deliverable | Required proof | State |
| --- | --- | --- | --- |
| T01 | tunnel-manager: replace the automatic `.yaml` fallback with exact XDG `.yml` resolution. | Canonical-path and legacy-only tests. | TODO |
| T02 | tunnel-manager: route CLI, MCP, bulk tools, and remote execution through one resolved serving source; reject divergent serving selectors. | Surface-parity and conflict tests. | TODO |
| T03 | tunnel-manager: define the named explicit offline path boundary and preserve caller authorization. | Offline positive and serving-negative tests. | TODO |
| T04 | tunnel-manager: fail closed on unreadable/malformed/stale source and preserve atomic private writes. | Read-failure, secret, and concurrent-write tests. | TODO |
| T05 | tunnel-manager deployment examples and service manifest owner: project the exact operator XDG file read-only. | Generated Compose/Kubernetes diff and source digest. | TODO |
| T06 | container-manager-mcp consumer owner: adopt the same source identity as a read-only consumer. | Consumer contract tests and revision. | TODO |
| T07 | tunnel-manager: align CLI help, README, inventory guide, example env, and migration instructions. | Public docs scan and fresh-install walkthrough. | TODO |
| T08 | release owner: verify disposable runtime read, write denial, digest parity, and absence of active legacy readers. | Exact public revisions, test receipts, and runtime evidence. | TODO |

Each task closes only with a link to a public revision or attached reproducible receipt. Do not mark this spec landed because a draft exists, and do not mark it accepted because one implementation slice passes tests. If a tool requires unavailable infrastructure, keep that specific acceptance item open and retain the local deterministic proof.
