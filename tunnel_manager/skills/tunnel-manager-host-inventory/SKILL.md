---
name: tunnel-manager-host-inventory
description: >-
  Manage the shared SSH host inventory via the tunnel-manager MCP server — list,
  add, and remove host aliases (hostname, user, port, identity_file) and push the
  inventory into the knowledge graph as typed :Host / :HostGroup / :SshKey nodes.
  Use when the agent must register a new SSH target, look up how a host is reached,
  prune a stale alias, or sync the fleet inventory into the KG. Do NOT use to run
  commands on a host (use tunnel-manager-remote-execution) or to set up key auth /
  audits (use tunnel-manager-ssh-hardening).
license: MIT
tags: [tunnel-manager, ssh, inventory, hosts, mcp]
metadata:
  author: Genius
  version: '0.1.0'
---
# Tunnel Manager — Host Inventory

Domain-typed access to the shared SSH inventory (`$XDG_CONFIG_HOME/agent-utilities/inventory.yml`)
via the **`tunnel-manager`** MCP server. One inventory, shared with the HostManager
library, container-manager, and the `ssh-bootstrap` skill.

## When to use
- Register a new SSH target (alias → hostname / user / port / identity_file).
- List existing aliases or read how a host is reached.
- Remove a stale alias.
- Push the current inventory into the knowledge graph (`:Host` nodes).

## When NOT to use
- Running a command / copying a file on a host → `tunnel-manager-remote-execution`.
- Passwordless key setup, key rotation, mesh, or security audit →
  `tunnel-manager-ssh-hardening`.
- Editing container/service definitions → `container-manager` skills.

## Prerequisites & environment
Connect via the `mcp-client` skill against the **`tunnel-manager`** MCP server.

| Variable | Required | Notes |
|----------|----------|-------|
| `TUNNEL_INVENTORY` | optional | Inventory YAML path (defaults to the shared XDG file) |
| `TUNNEL_INVENTORY_GROUP` | optional | Default target group (`all`) |
| `TUNNEL_KG_INGEST` | optional | Set `false` to disable the default-on KG ingest on `list` |

The inventory is an Ansible-style YAML (`all` → `children` → groups → `hosts`); the
server flattens it to aliases automatically.

## Tools & actions
| Condensed tool | Actions |
|----------------|---------|
| `tm_hosts` | `list`, `add`, `remove` |
| `tunnel_ingest_hosts` | (no action — lists + pushes to KG) |

### Key parameters
- `alias` — the inventory key; required for `add` / `remove`.
- `hostname`, `user` — required for `add`; `port` (default 22), `identity_file`,
  `password`, `proxy_command` optional.
- `group` (on `tunnel_ingest_hosts`) — the `:HostGroup` to attach hosts to.

## Recipes
List every managed host (also default-on ingests them to the KG):
```json
{"action": "list"}
```
Add a key-authenticated host:
```json
{"action": "add", "alias": "rw710", "hostname": "10.0.0.14", "user": "genius", "port": 22, "identity_file": "~/.ssh/id_shared"}
```
Remove a stale alias (destructive — the server confirms):
```json
{"action": "remove", "alias": "old-box"}
```
Sync the inventory into the knowledge graph:
```json
{"group": "homelab"}
```

## Gotchas
- `add` needs `alias` + `hostname` + `user` — a 400 comes back otherwise.
- `remove` is destructive and prompts for confirmation via the MCP context.
- Adds are written back to the **shared** inventory file (Ansible layout preserved);
  other tools/skills read the same file, so an added alias is fleet-wide.
- `identity_file` (or the legacy `key_path`) is preferred over `password`; a host
  with an identity file becomes a `:SshKey` node linked by `:usesKey` on ingest.
- KG ingest is best-effort: with no reachable engine it silently no-ops, and `list`
  still returns the hosts.

## Related
- `tunnel-manager-remote-execution` — act on the hosts you register here.
- `tunnel-manager-ssh-hardening` — set up key auth for these hosts.
- The `ssh-bootstrap` universal skill seeds the same shared inventory file.
