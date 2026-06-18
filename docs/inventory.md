# Inventory — setup, creation & overrides

tunnel-manager works from a single YAML **inventory** that maps short host aliases
(e.g. `r820`) to their connection details (IP, SSH user, port, key). Every entry
point — the `HostManager` Python API, the `tunnel-manager` CLI, the
`tunnel-manager-mcp` MCP server, **and** `container-manager-mcp` and the
`ssh-bootstrap` skill — reads the **same file**, so you define your fleet once.

## Default location

```
$XDG_CONFIG_HOME/agent-utilities/inventory.yaml
```

which is `~/.config/agent-utilities/inventory.yaml` on a typical Linux/macOS host
(`XDG_CONFIG_HOME` defaults to `~/.config`). If the file does not exist, tunnel-manager
starts with an empty inventory (no error) and you can add hosts via the API/CLI.

> **Note:** this is the `agent-utilities` config directory on purpose — the inventory
> is shared across the ecosystem. Earlier builds of the MCP server defaulted to
> `~/.config/tunnel-manager/inventory.yml`; that has been unified to the path above.

## Create your inventory

The fastest start is to copy the bundled example and edit it:

```bash
mkdir -p ~/.config/agent-utilities
cp inventory.example.yaml ~/.config/agent-utilities/inventory.yaml
$EDITOR ~/.config/agent-utilities/inventory.yaml
```

See [`inventory.example.yaml`](https://github.com/Knuckles-Team/tunnel-manager/blob/main/inventory.example.yaml)
for a fully-commented template.

### Format

Two layouts are accepted:

**Ansible-style (recommended)** — supports group-level `vars` and `children` groups:

```yaml
all:
  vars:
    ansible_user: genius
    ansible_ssh_private_key_file: ~/.ssh/id_rsa
  hosts:
    r820:
      ansible_host: 10.0.0.13
    gpu-node:
      ansible_host: 10.0.0.16
      ansible_user: ml
      ansible_port: 2222
  children:
    storage:
      hosts:
        nas: { ansible_host: 10.0.0.10 }
```

**Flat** — top-level keys are aliases (no `all:` wrapper):

```yaml
r820:
  hostname: 10.0.0.13
  user: genius
  identity_file: ~/.ssh/id_rsa
```

### Recognized per-host keys

| Ansible alias | Native key | Meaning |
|---|---|---|
| `ansible_host` | `hostname` | IP / DNS name (defaults to the alias). |
| `ansible_user` | `user` | SSH user. |
| `ansible_port` | `port` | SSH port (default 22). |
| `ansible_ssh_private_key_file` | `identity_file` / `key_path` | Path to the private key. |
| `ansible_ssh_pass` | `password` | Password auth (prefer keys). |
| `ansible_ssh_common_args` | `proxy_command` | Extra SSH args / jump host. |

Group-level `vars` apply to all hosts in the group; per-host values override them.

### Build it programmatically instead

```python
from tunnel_manager.tunnel_manager import HostManager

hm = HostManager()                      # uses the default path
hm.add_host("r820", hostname="10.0.0.13", user="genius", identity_file="~/.ssh/id_rsa")
hm.save_inventory()                     # writes back to the inventory file
```

## Override the default location

| Surface | How |
|---|---|
| CLI | `tunnel-manager --inventory /path/to/inventory.yaml <subcommand>` |
| MCP server | `export TUNNEL_INVENTORY=/path/to/inventory.yaml` (or pass the `inventory` arg to `tm_inventory`) |
| Python API | `HostManager(config_file="/path/to/inventory.yaml")` |

The MCP `tm_inventory` tool also takes an optional `group` arg (default `all`) to
scope operations to one Ansible group; the env equivalent is `TUNNEL_INVENTORY_GROUP`.

## Use it: SSH mesh bootstrap

Once the inventory exists, establish passwordless full-mesh SSH across the fleet:

```bash
# CLI
tunnel-manager setup-all --parallel
```

```jsonc
// MCP (tm_inventory)
{ "action": "mesh_bootstrap" }   // inventory defaults to the XDG path above
```

This is exactly what the `ssh-bootstrap` skill drives. From there, remote command
execution, key rotation, and config copy all resolve hosts by their inventory alias.
