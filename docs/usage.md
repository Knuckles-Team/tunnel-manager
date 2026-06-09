# Usage — API / CLI / MCP

`tunnel-manager` exposes the same capability three ways: as **MCP tools** an agent
calls, as a **Python API** (`HostManager` and `Tunnel`) you import, and as a **CLI**.
For the ecosystem role and the distributed-SSH scaling model, see
[Overview](overview.md).

## As an MCP server

Once [deployed](deployment.md), the server registers seven action-routed tools. Each
tool dispatches on an `action` argument, which keeps the LLM tool surface compact:

| Tool | Toggle | Representative actions |
|---|---|---|
| `tm_hosts` | `TM_HOSTS_TOOL` | `add`, `list`, `remove` |
| `tm_remote` | `TM_REMOTE_TOOL` | `run_command`, `send_file`, `receive_file`, `setup_passwordless`, `rotate_key`, `check_ssh` |
| `tm_inventory` | `TM_INVENTORY_TOOL` | `run_command`, `send_file`, `receive_file`, `configure_key_auth`, `mesh_bootstrap`, `rotate_key` |
| `tm_operations` | `TM_OPERATIONS_TOOL` | `start`, `get_progress`, `cancel`, `get_metrics`, `list_sessions` |
| `tm_system` | `TM_SYSTEM_TOOL` | `get_info`, `discover_services`, `analyze_logs`, `network_topology` |
| `tm_files` | `TM_FILES_TOOL` | `recursive_ops`, `content_search`, `watch`, `diff_compare`, `backup` |
| `tm_security` | `TM_SECURITY_TOOL` | `security_audit`, `compliance_check`, `vulnerability_scan`, `access_control_audit` |

Example agent prompts that map onto these tools:

- *"Run `uptime` on every host in the `web` inventory group"* → `tm_inventory` (`run_command`)
- *"Bootstrap full-mesh passwordless SSH across my inventory"* → `tm_inventory` (`mesh_bootstrap`)
- *"What OS and services is host `db-01` running?"* → `tm_system` (`get_info`, `discover_services`)
- *"Audit `db-01` against the CIS benchmark"* → `tm_security` (`compliance_check`)

## As a Python API

The core client layer is `HostManager` (the inventory) and `Tunnel` (a single SSH
connection), both in `tunnel_manager.tunnel_manager`.

```python
from tunnel_manager.tunnel_manager import HostManager, Tunnel

# The inventory — defaults to ~/.config/agent-utilities/inventory.yaml
hosts = HostManager()
hosts.add_host(
    alias="db-01",
    hostname="10.0.0.21",
    user="ops",
    identity_file="~/.ssh/id_ed25519",
)
inventory = hosts.list_hosts()           # {alias: HostConfig}
config = hosts.get_host("db-01")

# A single connection — driven from a HostConfig or explicit kwargs
tunnel = Tunnel(config=config)
tunnel.connect()

# Reads
result = tunnel.run_command("cat /etc/os-release")   # CommandResult
print(result.stdout)

ok = tunnel.check_ssh_server()           # reachability probe
tunnel.receive_file("/var/log/syslog", "./syslog.txt")

tunnel.close()
```

Run a command across the whole inventory with bounded parallelism:

```python
results = tunnel.run_command_on_inventory(
    hosts.list_hosts(),
    command="uptime",
    parallel=True,
)
```

### Provisioning operations

Key-management and file-transfer operations are first-class:

```python
tunnel.setup_passwordless_ssh(local_key_path="~/.ssh/id_ed25519.pub")
tunnel.rotate_ssh_key(new_key_path="~/.ssh/id_ed25519_new", key_type="ed25519")
tunnel.send_file("./deploy.sh", "/opt/deploy.sh")
```

## As a CLI

The `tunnel-manager` console script drives the same operations across an inventory.
Subcommands include `setup-all`, `run-command`, `copy-config`, `rotate-key`, `send`
and `receive`:

```bash
# Bootstrap passwordless SSH for every host in the inventory
tunnel-manager setup-all --parallel

# Run a command fleet-wide
tunnel-manager run-command --remote-command "uptime" --parallel

# Distribute and rotate keys
tunnel-manager copy-config --parallel
tunnel-manager rotate-key --parallel

# Move files
tunnel-manager send --local-path ./deploy.sh --remote-path /opt/deploy.sh --parallel
tunnel-manager receive --remote-path /var/log/syslog --parallel
```

```bash
tunnel-manager --help          # full subcommand and flag reference
```
