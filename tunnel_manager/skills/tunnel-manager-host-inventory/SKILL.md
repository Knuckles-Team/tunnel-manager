---
name: tunnel-manager-host-inventory
skill_type: skill
description: >-
  Manage the shared SSH host inventory through tunnel-manager: list and look up host aliases, add, remove, load and save them, and push the inventory into the knowledge graph. Use to register an SSH target, see how a host is reached, prune a stale alias, or sync the fleet into the graph.
---

# Tunnel manager host inventory

Hosts are addressed by alias. The inventory file is declared by `TUNNEL_INVENTORY` and may be read-only.

## Read

- `tunnel_manager_list_hosts` lists every alias.
- `tunnel_manager_get_host` (`alias`) returns hostname, user, port and identity reference.

## Change

1. `tunnel_manager_load_inventory` reloads the file from disk.
2. `tunnel_manager_add_host` (`alias`, `hostname`, `user`, optional `port`, `identity_file`, `password_ref`, `known_hosts_file`, `proxy_command`). Use `password_ref`, a secret reference; never a literal password.
3. `tunnel_manager_remove_host` (`alias`) needs `confirm=true`.
4. `tunnel_manager_save_inventory` writes the file. If the inventory is read-only the add, remove and save refuse; report the refusal, do not retry.
5. `tunnel_manager_list_hosts` again to prove the change.

## Graph

`tunnel_ingest_hosts` (`group`) writes `Host`, `HostGroup` and `SshKey` nodes to the knowledge graph.
