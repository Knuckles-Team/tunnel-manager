# Usage — API / CLI / MCP

`tunnel-manager` exposes the same capability three ways: as **MCP tools** an agent
calls, as a **Python API** (`HostManager` and `Tunnel`) the operator import, and as a **CLI**.
For the ecosystem role and the distributed-SSH scaling model, see
[Overview](overview.md).

## As an MCP server

Once [deployed](deployment.md), the server serves one typed tool per operation:

| Area | Tools |
|---|---|
| Host inventory | `tunnel_manager_list_hosts`, `tunnel_manager_get_host`, `tunnel_manager_add_host`, `tunnel_manager_remove_host`, `tunnel_manager_load_inventory`, `tunnel_manager_save_inventory`, `tunnel_ingest_hosts` |
| One host | `tm_remote_run_command`, `tm_remote_send_file`, `tm_remote_receive_file`, `tm_remote_check_ssh`, `tm_remote_test_key_auth`, `tm_remote_setup_passwordless`, `tm_remote_copy_ssh_config`, `tm_remote_rotate_key`, `tm_remote_remove_host_key` |
| A group | `tm_inventory_run_command`, `tm_inventory_send_file`, `tm_inventory_receive_file`, `tm_inventory_configure_key_auth`, `tm_inventory_mesh_bootstrap`, `tm_inventory_copy_ssh_config`, `tm_inventory_rotate_key` |
| Operations | `tm_operation_start`, `tm_operation_get_progress`, `tm_operation_get_metrics`, `tm_operation_list_sessions`, `tm_operation_cancel` |
| System | `tm_system_get_info`, `tm_system_discover_services`, `tm_system_analyze_logs`, `tm_system_network_topology` |
| Files | `tm_file_content_search`, `tm_file_diff_compare`, `tm_file_backup`, `tm_file_watch`, `tm_file_recursive_ops` |
| Security | `tm_security_security_audit`, `tm_security_access_control_audit`, `tm_security_compliance_check`, `tm_security_vulnerability_scan` |

Example agent prompts that map onto these tools:

- *"Run `uptime` on every host in the `web` inventory group"* → `tm_inventory_run_command`
- *"Bootstrap full-mesh passwordless SSH across my inventory"* → `tm_inventory_mesh_bootstrap`
- *"What OS and services is host `db-01` running?"* → `tm_system_get_info`, `tm_system_discover_services`
- *"Audit `db-01` against the CIS benchmark"* → `tm_security_compliance_check`

## As a Python API

The core client layer is `HostManager` (the inventory) and `Tunnel` (a single SSH
connection), both in `tunnel_manager.tunnel_manager`.

```python
from tunnel_manager.tunnel_manager import HostManager, Tunnel

# The inventory — defaults to ~/.config/scion-sdk/inventory.yml
hosts = HostManager()
hosts.add_host(
    alias="db-01",
    hostname="192.0.2.21",
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

### Repository-worker execution

Repository Manager uses the alias-only structured boundary documented in
[Structured remote execution](remote_execution.md). It does not call
`HostManager.hosts`, pass raw SSH fields, or submit a shell string. The
plan-time alias view is re-resolved and re-authorized immediately before each
dispatch, and the transport is closed even when validation, authentication, or
the command fails.

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
