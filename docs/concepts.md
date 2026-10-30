# Concept Registry — tunnel-manager

> **Prefix**: `CONCEPT:TUN-*`
> **Version**: 1.14.0
> **Bridge**: [`CONCEPT:AU-ECO.messaging.native-backend-abstraction`](https://github.com/Knuckles-Team/scion-sdk/blob/main/docs/concepts.md) (Unified Toolkit Ingestion)

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

## Cross-Project References (from scion-sdk)

| Concept ID | Name | Origin |
|------------|------|--------|
| `CONCEPT:AU-ECO.messaging.native-backend-abstraction` | Unified Toolkit Ingestion | scion-sdk |
| `CONCEPT:AU-ORCH.adapter.hot-cache-invalidation` | Confidence-Gated Router | scion-sdk |
| `CONCEPT:AU-OS.config.secrets-authentication` | Prompt Injection Defense | scion-sdk |
| `CONCEPT:AU-OS.state.cognitive-scheduler-preemption` | Cognitive Scheduler | scion-sdk |
| `CONCEPT:AU-OS.governance.reactive-multi-axis-budget` | Guardrail Engine | scion-sdk |
| `CONCEPT:AU-OS.governance.wasm-micro-agent-sandbox` | Audit Logging | scion-sdk |
| `CONCEPT:AU-KG.query.object-graph-mapper` | Knowledge Graph Core | scion-sdk |

## Synergy with scion-sdk

This project integrates with `scion-sdk` via `CONCEPT:AU-ECO.messaging.native-backend-abstraction` (Unified Toolkit Ingestion). The `tunnel_manager` MCP server registers its tools with the scion-sdk FastMCP middleware, enabling automatic discovery, telemetry, and Knowledge Graph ingestion of all TUN-* concepts.
