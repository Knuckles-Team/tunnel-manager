---
name: tunnel-manager-operations
skill_type: skill
description: >-
  Inspect hosts, track long operations and work with remote files through tunnel-manager: system information, services, logs and network topology; start, watch, measure and cancel tracked operations; search, compare, back up, watch and bulk-change files. Use for read-only host discovery, for progress on a long fan-out, or for file work on a host.
---

# Tunnel manager operations

## Inspect a host

`tm_system_get_info`, `tm_system_discover_services`, `tm_system_analyze_logs` (`log_paths`, `patterns`) and `tm_system_network_topology` take `remote_host` and only read.

## Track an operation

1. `tm_operation_start` (`operation_type`, `total_steps`, `details`) returns an `operation_id`.
2. `tm_operation_get_progress` and `tm_operation_get_metrics` (`operation_id`) show state.
3. `tm_operation_list_sessions` lists tracked operations.
4. `tm_operation_cancel` (`operation_id`) stops one and needs `confirm=true`.

## Files on a host

All take `remote_host` and an `operation` value that names the variant:

- `tm_file_content_search` (`search_paths`, `pattern`, `case_sensitive`, `recursive`, `max_results`).
- `tm_file_diff_compare` (`host1`, `host2`, `file_path`) compares a file across hosts.
- `tm_file_backup` (`backup_paths`, `backup_dest`, `compression`, `incremental`).
- `tm_file_watch` (`watch_paths`, `duration`) reports changes for a period.
- `tm_file_recursive_ops` (`source`, `destination`, `mode`, `owner`, `group`) changes many files; it writes, so confirm first.
