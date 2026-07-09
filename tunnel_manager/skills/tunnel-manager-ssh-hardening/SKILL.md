---
name: tunnel-manager-ssh-hardening
skill_type: skill
description: >-
  Harden and audit SSH access across a host fleet via the tunnel-manager MCP
  server — set up passwordless key auth, build a full-mesh trust, rotate SSH keys
  fleet-wide, distribute a shared ssh config, and run security / compliance /
  vulnerability audits against a host. Use when the agent must move a fleet off
  password auth, rotate keys, or assess a host's security posture. Do NOT use to
  add host aliases (use tunnel-manager-host-inventory) or to run arbitrary commands
  / copy files (use tunnel-manager-remote-execution).
license: MIT
tags: [tunnel-manager, ssh, hardening, keys, security-audit, mcp]
metadata:
  author: Genius
  version: '0.1.0'
---
# Tunnel Manager — SSH Hardening & Audit

Move a fleet onto key-based auth and assess its security posture via the
**`tunnel-manager`** MCP server.

## When to use
- Set up passwordless (key) auth to one host or a whole group.
- Build a full-mesh SSH trust so every host can reach every other.
- Rotate the SSH key fleet-wide and distribute a shared `~/.ssh/config`.
- Run a security audit, compliance check, or vulnerability scan against a host.

## When NOT to use
- Registering / removing host aliases → `tunnel-manager-host-inventory`.
- One-off command execution or file copy → `tunnel-manager-remote-execution`.
- Container/service security posture → `container-manager` / `security-tools`.

## Prerequisites & environment
Connect via the `mcp-client` skill against the **`tunnel-manager`** MCP server.
Initial key setup / mesh needs a working credential (password or an existing key)
to bootstrap from.

| Variable | Required | Notes |
|----------|----------|-------|
| `TUNNEL_INVENTORY` / `TUNNEL_INVENTORY_GROUP` | optional | Fleet scope for `tm_inventory` |
| `TUNNEL_IDENTITY_FILE` | optional | Shared key path (default `~/.ssh/id_shared`) |
| `TUNNEL_PARALLEL` / `TUNNEL_MAX_THREADS` | optional | Parallel fan-out controls |

## Tools & actions
| Condensed tool | Actions |
|----------------|---------|
| `tm_inventory` | `configure_key_auth`, `mesh_bootstrap`, `rotate_key`, `copy_ssh_config` |
| `tm_remote` | `setup_passwordless`, `rotate_key`, `copy_ssh_config`, `test_key_auth` (single host) |
| `tm_security` | `security_audit`, `compliance_check`, `vulnerability_scan`, `access_control_audit` |
| `tm_system` | `get_info`, `discover_services`, `analyze_logs`, `network_topology` |

### Key parameters
- `group`, `parallel`, `max_threads` — fleet scope + fan-out on `tm_inventory`.
- `key` / `key_type` (`ed25519`|`rsa`) — key material for setup / rotation.
- `new_key` — target path for `rotate_key`.
- `remote_host`, `username`, `identity_file` — target for `tm_security` / `tm_system`.
- `standard` — `cis_benchmark` | `pci_dss` | `hipaa` for `compliance_check`.
- `scan_type` — `basic` | `package` | `config` for `vulnerability_scan`.

## Recipes
Set up passwordless key auth across a group:
```json
{"action": "configure_key_auth", "group": "homelab", "key": "~/.ssh/id_shared", "key_type": "ed25519"}
```
Bootstrap a full-mesh trust (every host trusts every other):
```json
{"action": "mesh_bootstrap", "group": "homelab", "parallel": true, "max_threads": 6}
```
Rotate the fleet key:
```json
{"action": "rotate_key", "group": "homelab", "new_key": "~/.ssh/id_shared_2026", "key_type": "ed25519"}
```
CIS compliance check against one host:
```json
{"action": "compliance_check", "remote_host": "rw710", "username": "genius", "identity_file": "~/.ssh/id_shared", "standard": "cis_benchmark"}
```

## Gotchas
- Key setup / mesh must **bootstrap** from an existing credential — you need a
  working password or key on the target before you can install the new one.
- `rotate_key` changes the key hosts trust; verify with `test_key_auth` BEFORE
  removing the old key, or you can lock yourself out of the fleet.
- Mesh bootstrap is O(n²) trust edges — scope the group; `parallel` speeds it up.
- `tm_security` / `tm_system` are read-only assessments; they do not remediate.
- `compliance_check` results are advisory — map findings to changes yourself.

## Related
- `tunnel-manager-host-inventory` — the hosts / groups you harden here.
- `tunnel-manager-remote-execution` — run remediation commands the audit surfaces.
- `rotate-credentials` universal skill — for non-SSH secret rotation.
