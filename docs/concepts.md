# Concept Registry — tunnel-manager

> **Prefix**: `CONCEPT:TUN-*`
> **Version**: 1.14.0
> **Bridge**: [`CONCEPT:AU-ECO.messaging.native-backend-abstraction`](https://github.com/Knuckles-Team/agent-utilities/blob/main/docs/concepts.md) (Unified Toolkit Ingestion)

---

## Project-Specific Concepts

| Concept ID | Name | Description |
|------------|------|-------------|
| `CONCEPT:TM-OS.governance.tun` | File Operations | MCP tool domain `file` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.tun-2` | Host Operations | MCP tool domain `host` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.tun-3` | Inventory Operations | MCP tool domain `inventory` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.tun-4` | Operations Operations | MCP tool domain `operations` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.tun-5` | Remote Operations | MCP tool domain `remote` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.tun-6` | Security Operations | MCP tool domain `security` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.tun-7` | System Information & Health | MCP tool domain `system` — Action-routed dynamic tool registration |
| `CONCEPT:TM-OS.governance.entitlement-aware-remote-execution` | Entitlement-aware remote execution | Alias-only structured worker boundary for Repository Manager; canonical inventory and SSH policy remain in tunnel-manager |

## Cross-Project References (from agent-utilities)

| Concept ID | Name | Origin |
|------------|------|--------|
| `CONCEPT:AU-ECO.messaging.native-backend-abstraction` | Unified Toolkit Ingestion | agent-utilities |
| `CONCEPT:AU-ORCH.adapter.hot-cache-invalidation` | Confidence-Gated Router | agent-utilities |
| `CONCEPT:AU-OS.config.secrets-authentication` | Prompt Injection Defense | agent-utilities |
| `CONCEPT:AU-OS.state.cognitive-scheduler-preemption` | Cognitive Scheduler | agent-utilities |
| `CONCEPT:AU-OS.governance.reactive-multi-axis-budget` | Guardrail Engine | agent-utilities |
| `CONCEPT:AU-OS.governance.wasm-micro-agent-sandbox` | Audit Logging | agent-utilities |
| `CONCEPT:AU-KG.query.object-graph-mapper` | Knowledge Graph Core | agent-utilities |

## Synergy with agent-utilities

This project integrates with `agent-utilities` via `CONCEPT:AU-ECO.messaging.native-backend-abstraction` (Unified Toolkit Ingestion). The `tunnel_manager` MCP server registers its tools with the agent-utilities FastMCP middleware, enabling automatic discovery, telemetry, and Knowledge Graph ingestion of all TUN-* concepts.
