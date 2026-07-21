# Tunnel Manager Remote Execution

Run shell commands and transfer files over SSH via the tunnel-manager MCP server — on a single host (tm_remote) or fanned out across an inventory group (tm_inventory), plus SSH reachability and key-auth checks. Use when the agent must execute a command remotely, copy a file to/from a host, run something across a whole group, or verify a host is reachable. Do NOT use to add/remove host aliases (use tunnel-manager-host-inventory) or to set up passwordless auth / audit a host (use tunnel-manager-ssh-hardening).

# Tunnel Manager — Remote Execution

Execute commands and move files over SSH via the **`tunnel-manager`** MCP server —
either against one host or fanned out across an inventory group.

## When to use
- Run a shell command on a single host and read stdout/stderr.
- Send or receive a file to/from a host (SFTP).
- Run the same command across every host in a group (optionally in parallel).
- Check SSH reachability or verify key auth before relying on a host.

## When NOT to use
- Registering / removing host aliases → `tunnel-manager-host-inventory`.
- Passwordless key setup, key rotation, mesh, or security audits →
  `tunnel-manager-ssh-hardening`.
- Long-running orchestration you want to track → pair with `tm_operations`.

## Prerequisites & environment
Connect via the `mcp-client` skill against the **`tunnel-manager`** MCP server.

| Variable | Required | Notes |
|----------|----------|-------|
| `TUNNEL_REMOTE_HOST` / `TUNNEL_USERNAME` | optional | Defaults for single-host `tm_remote` |
| `TUNNEL_IDENTITY_FILE` | optional | Default private key path |
| `TUNNEL_PASSWORD_REF` | optional | Opaque runtime secret reference; literal passwords are rejected |
| `TUNNEL_KNOWN_HOSTS` | recommended | Governed host-key trust file checked by the doctor |
| `TUNNEL_INVENTORY` / `TUNNEL_INVENTORY_GROUP` | optional | Group ops with `tm_inventory` |
| `TUNNEL_PARALLEL` / `TUNNEL_MAX_THREADS` | optional | Parallel fan-out controls |

## Tools & actions
| Condensed tool | Actions |
|----------------|---------|
| `tm_remote` | `run_command`, `send_file`, `receive_file`, `check_ssh`, `test_key_auth`, `remove_host_key` |
| `tm_inventory` | `run_command`, `send_file`, `receive_file` (group fan-out) |

### Key parameters
- `host`, `user`, `port`, `id_file` — single-host connection; `password_ref` is
  available when key or agent authentication cannot be used.
- `cmd` — the shell command for `run_command`.
- `lpath` / `rpath` — local / remote paths for `send_file` / `receive_file`.
- `group`, `parallel`, `max_threads` — fan-out controls on `tm_inventory`.
- `timeout` — per-command timeout in seconds (default 60).

## Recipes
Run a command on one host:
```json
{"action": "run_command", "host": "managed-node", "user": "operator", "id_file": "~/.ssh/id_ed25519", "cmd": "uptime"}
```
Copy a file up to a host:
```json
{"action": "send_file", "host": "managed-node", "user": "operator", "lpath": "./artifact", "rpath": "/srv/app/artifact"}
```
Verify a host is reachable before using it:
```json
{"action": "check_ssh", "host": "managed-node", "user": "operator", "id_file": "~/.ssh/id_ed25519"}
```
Fan a command across a whole group (`tm_inventory`), in parallel:
```json
{"action": "run_command", "group": "managed", "cmd": "df -h /", "parallel": true, "max_threads": 6}
```

## Gotchas
- Prefer key or agent authentication. If password authentication is required,
  pass only `password_ref`; literal credentials are rejected.
- `run_command` returns a `CommandResult` (`success`, `stdout`, `stderr`) — inspect
  `success` and `stderr`, not just `stdout`.
- Set a sane `timeout`; a hung remote command will otherwise block up to the default.
- Group fan-out (`tm_inventory`) runs the SAME command on EVERY host in the group —
  scope the group and avoid destructive commands without confirmation.
- First-time connections require an independently verified host key in
  `known_hosts`. There is no accept-unknown or trust-on-first-use mode.
- Output, transfer size, fleet concurrency, command size, and execution time are
  capped. Increase only the documented bounded settings when justified.

## Related
- `tunnel-manager-host-inventory` — register the hosts / groups you target here.
- `tunnel-manager-ssh-hardening` — get key auth working so these calls need no password.
- `tm_operations` — track a long-running fan-out as a progress-bearing operation.
