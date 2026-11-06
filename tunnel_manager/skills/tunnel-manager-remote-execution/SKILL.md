---
name: tunnel-manager-remote-execution
skill_type: skill
description: >-
  Run commands and move files over SSH through tunnel-manager, on one host (tm_remote_*) or across an inventory group (tm_inventory_*), with a reachability check first. Use to execute a command remotely, copy a file to or from hosts, or run something across a group.
---

# Tunnel manager remote execution

## One host

1. `tm_remote_check_ssh` (`host`) proves the host answers.
2. `tm_remote_run_command` (`host`, `cmd`, optional `user`, `port`, `id_file`, `timeout`) returns stdout, stderr and a status code.
3. `tm_remote_send_file` and `tm_remote_receive_file` (`host`, `lpath`, `rpath`) copy over SFTP.

## A group

1. `tm_inventory_run_command` with `preview=true` lists the hosts and the command without running it. Show that list.
2. Run it again with `preview=false`; `parallel` and `max_threads` control fan-out. The same command runs on every host in the group.
3. `tm_inventory_send_file` and `tm_inventory_receive_file` (`lpath`, `rpath`, `lpath_prefix`) copy to or from each host.
4. Report each host's result on its own line.

## Rules

- Address hosts by inventory alias. An unknown alias is refused.
- Credentials are secret references (`password_ref`), never literals.
- Track a long fan-out with the operation tools in `tunnel-manager-operations`.
