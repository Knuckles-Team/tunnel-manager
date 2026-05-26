# Concept Registry — tunnel-manager

> **Prefix**: `CONCEPT:TUN-*`
> **Version**: 1.14.0
> **Bridge**: [`CONCEPT:ECO-4.0`](../../agent-utilities/docs/concepts.md) (Unified Toolkit Ingestion)

---

## Project-Specific Concepts

| Concept ID | Name | Description |
|------------|------|-------------|
| `CONCEPT:TUN-001` | File Operations | MCP tool domain `file` — Action-routed dynamic tool registration |
| `CONCEPT:TUN-002` | Host Operations | MCP tool domain `host` — Action-routed dynamic tool registration |
| `CONCEPT:TUN-003` | Inventory Operations | MCP tool domain `inventory` — Action-routed dynamic tool registration |
| `CONCEPT:TUN-004` | Operations Operations | MCP tool domain `operations` — Action-routed dynamic tool registration |
| `CONCEPT:TUN-005` | Remote Operations | MCP tool domain `remote` — Action-routed dynamic tool registration |
| `CONCEPT:TUN-006` | Security Operations | MCP tool domain `security` — Action-routed dynamic tool registration |
| `CONCEPT:TUN-007` | System Information & Health | MCP tool domain `system` — Action-routed dynamic tool registration |

## Cross-Project References (from agent-utilities)

| Concept ID | Name | Origin |
|------------|------|--------|
| `CONCEPT:ECO-4.0` | Unified Toolkit Ingestion | agent-utilities |
| `CONCEPT:ORCH-1.2` | Confidence-Gated Router | agent-utilities |
| `CONCEPT:OS-5.1` | Prompt Injection Defense | agent-utilities |
| `CONCEPT:OS-5.2` | Cognitive Scheduler | agent-utilities |
| `CONCEPT:OS-5.3` | Guardrail Engine | agent-utilities |
| `CONCEPT:OS-5.4` | Audit Logging | agent-utilities |
| `CONCEPT:KG-2.0` | Knowledge Graph Core | agent-utilities |

## Synergy with agent-utilities

This project integrates with `agent-utilities` via `CONCEPT:ECO-4.0` (Unified Toolkit Ingestion). The `tunnel_manager` MCP server registers its tools with the agent-utilities FastMCP middleware, enabling automatic discovery, telemetry, and Knowledge Graph ingestion of all TUN-* concepts.
