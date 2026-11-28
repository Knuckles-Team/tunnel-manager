# CONN-TUNNEL-MANAGER-INVENTORY — Implementation tasks

Governing spec: [spec.md](spec.md). Design: [plan.md](plan.md). Rows: [requirements.md](requirements.md).

Each task line reads `- [x] T001 [P] [US1] <ID>-R012.4 description`. Tasks run producer first; a checked task has landed.

- [x] T001 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R001 One canonical host inventory path across surfaces.
- [x] T002 [US2] CONN-TUNNEL-MANAGER-INVENTORY-R002 Fleet name.
- [ ] T003 [US3] CONN-TUNNEL-MANAGER-INVENTORY-R003 SSH runs without a local username.
- [ ] T004 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R005 Structured jump host replaces free-form proxy arguments.
- [ ] T005 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R006 First contact pins the host key against an operator fingerprint.
- [ ] T006 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R007 Key rotation verifies the new key and updates the inventory.
- [ ] T007 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R008 Machine roll-up and hardware facts (rollup).
- [ ] T008 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R008.1 SSH host rolls up to the machine class.
- [ ] T009 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R008.2 Hardware facts tool.
- [ ] T010 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R008.3 Wiring.
- [ ] T011 [US1] CONN-TUNNEL-MANAGER-INVENTORY-R008.4 Hot-path proof: the served tool returns the schema.
