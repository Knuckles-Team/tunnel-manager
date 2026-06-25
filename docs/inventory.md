# Inventory — setup, creation & overrides

tunnel-manager works from a single YAML **inventory** that maps short host aliases
(e.g. `r820`) to their connection details (IP, SSH user, port, key). Every entry
point — the `HostManager` Python API, the `tunnel-manager` CLI, the
`tunnel-manager-mcp` MCP server, **and** `container-manager-mcp` and the
`ssh-bootstrap` skill — reads the **same file**, so you define your fleet once.

## Default location

```
$XDG_CONFIG_HOME/agent-utilities/inventory.yml      # preferred
$XDG_CONFIG_HOME/agent-utilities/inventory.yaml     # legacy fallback
```

which is `~/.config/agent-utilities/inventory.yml` on a typical Linux/macOS host
(`XDG_CONFIG_HOME` defaults to `~/.config`). The path is **resolved** in this order:

1. `inventory.yml` if it exists — the standard for fresh installs, **else**
2. `inventory.yaml` if it exists — the legacy filename, still fully supported, **else**
3. `inventory.yml` — the path a fresh `init` writes to.

So existing `.yaml` users keep working untouched, while new installs standardize on
`.yml`. If neither file exists, tunnel-manager starts with an empty inventory (no error)
and you can add hosts via the API/CLI.

> **Note:** this is the `agent-utilities` config directory on purpose — the inventory
> is shared across the ecosystem. Earlier builds of the MCP server defaulted to
> `~/.config/tunnel-manager/inventory.yml`; that has been unified to the path above.

## Create your inventory

The fastest start is the `init` command, which writes a fully-commented template to
the resolved path:

```bash
tunnel-manager inventory init        # writes ~/.config/agent-utilities/inventory.yml
$EDITOR ~/.config/agent-utilities/inventory.yml
tunnel-manager inventory doctor      # validate it
```

`init` refuses to clobber an existing file unless you pass `--force`, and creates the
parent directory for you. The template documents every supported host field with
example hosts and group structure (reproduced under [Template](#template) below).

### Inventory CLI commands

| Command | What it does |
|---|---|
| `tunnel-manager inventory init [--inventory PATH] [--force]` | Write the commented `inventory.yml` template to the resolved path (or `--inventory`). Refuses to overwrite without `--force`. |
| `tunnel-manager inventory doctor [--inventory PATH] [--fix]` | Validate: file exists + parses, each host has required fields, groups reference real hosts. Exits non-zero on hard errors. With `--fix`, migrate a legacy `inventory.yaml` to `inventory.yml`. |
| `tunnel-manager inventory show [--inventory PATH]` | Print the resolved inventory path plus a host/group summary. |

### Template

This is the copy-paste template `tunnel-manager inventory init` writes (comments
trimmed here for brevity):

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
      vars:
        ansible_user: admin
      hosts:
        nas:
          ansible_host: 10.0.0.10
          # ansible_ssh_pass: changeme
          # ansible_ssh_common_args: "-J jump@bastion"
```

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
| CLI | `tunnel-manager --inventory /path/to/inventory.yml <subcommand>` |
| MCP server | `export TUNNEL_INVENTORY=/path/to/inventory.yml` (or pass the `inventory` arg to `tm_inventory`) |
| Python API | `HostManager(config_file="/path/to/inventory.yml")` |

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
