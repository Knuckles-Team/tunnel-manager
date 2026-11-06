"""Surface contracts: tool use, links, data locations and business roles."""

from scion_sdk.surface_contracts import (
    BusinessRole,
    DataLocation,
    Refusal,
    SurfaceLink,
    ToolStep,
    ToolUseContract,
)

CONTRACTS = (
    ToolUseContract(
        task="look-up-hosts",
        description="List the inventory aliases and read how one host is reached.",
        steps=(
            ToolStep(
                tool="tunnel_manager_list_hosts",
                params=(),
                result=("hosts",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tunnel_manager_get_host",
                params=("alias",),
                result=("alias", "hostname", "user", "port"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal("NOT_FOUND", "no alias has that name"),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="maintain-host-inventory",
        description="Add, remove, load and save host aliases in the inventory.",
        steps=(
            ToolStep(
                tool="tunnel_manager_load_inventory",
                params=(),
                result=("hosts",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tunnel_manager_add_host",
                params=(
                    "alias",
                    "hostname",
                    "user",
                    "port",
                    "identity_file",
                    "password",
                    "password_ref",
                    "known_hosts_file",
                    "proxy_command",
                    "params_json",
                ),
                result=("alias",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "INVENTORY_READ_ONLY", "the inventory is declared read-only"
                    ),
                ),
            ),
            ToolStep(
                tool="tunnel_manager_remove_host",
                params=("alias", "confirm"),
                result=("alias",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tunnel_manager_save_inventory",
                params=(),
                result=("path",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="sync-inventory-to-graph",
        description="Push the host inventory into the knowledge graph.",
        steps=(
            ToolStep(
                tool="tunnel_manager_list_hosts",
                params=(),
                result=("hosts",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tunnel_ingest_hosts",
                params=("group",),
                result=("hosts", "groups"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="run-command-on-host",
        description="Check SSH reachability, then run one command on one host.",
        steps=(
            ToolStep(
                tool="tm_remote_check_ssh",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("reachable",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_remote_run_command",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("stdout", "stderr", "status_code"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                    Refusal("UNKNOWN_HOST", "the host is not an inventory alias"),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="copy-file-with-host",
        description="Send a file to one host or fetch one from it.",
        steps=(
            ToolStep(
                tool="tm_remote_send_file",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("files", "status_code"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_remote_receive_file",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("files", "status_code"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="run-command-on-group",
        description="Preview, then run one command on every host of an inventory group.",
        steps=(
            ToolStep(
                tool="tm_inventory_run_command",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results", "status_code"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="copy-file-with-group",
        description="Send a file to every host of a group or fetch one from each.",
        steps=(
            ToolStep(
                tool="tm_inventory_send_file",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results", "status_code"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_inventory_receive_file",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results", "status_code"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="set-up-key-auth-on-host",
        description="Test key login on one host, install a key, and copy the SSH config.",
        steps=(
            ToolStep(
                tool="tm_remote_test_key_auth",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("authenticated",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_remote_setup_passwordless",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("status_code",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_remote_copy_ssh_config",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("status_code",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="rotate-key-on-host",
        description="Replace the SSH key of one host and drop a stale host key.",
        steps=(
            ToolStep(
                tool="tm_remote_test_key_auth",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("authenticated",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_remote_rotate_key",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("status_code",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_remote_remove_host_key",
                params=(
                    "host",
                    "user",
                    "password_ref",
                    "port",
                    "id_file",
                    "certificate",
                    "proxy",
                    "cfg",
                    "cmd",
                    "lpath",
                    "rpath",
                    "key",
                    "key_type",
                    "new_key",
                    "lcfg",
                    "rcfg",
                    "known_hosts",
                    "timeout",
                    "confirm",
                ),
                result=("status_code",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="set-up-key-auth-on-group",
        description="Install a shared key on a group, bootstrap a host-to-host mesh and copy the SSH config.",
        steps=(
            ToolStep(
                tool="tm_inventory_configure_key_auth",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_inventory_mesh_bootstrap",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_inventory_copy_ssh_config",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="rotate-key-on-group",
        description="Replace the SSH key across a group.",
        steps=(
            ToolStep(
                tool="tm_inventory_rotate_key",
                params=(
                    "inventory",
                    "group",
                    "host",
                    "preview",
                    "parallel",
                    "max_threads",
                    "cmd",
                    "key",
                    "key_type",
                    "key_pfx",
                    "cfg",
                    "rmt_cfg",
                    "lpath",
                    "rpath",
                    "lpath_prefix",
                    "timeout",
                ),
                result=("results",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="audit-host-security",
        description="Audit security, access control, compliance and vulnerabilities of a host (read only).",
        steps=(
            ToolStep(
                tool="tm_security_security_audit",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "scope",
                    "standard",
                    "scan_type",
                ),
                result=("findings",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_security_access_control_audit",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "scope",
                    "standard",
                    "scan_type",
                ),
                result=("findings",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_security_compliance_check",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "scope",
                    "standard",
                    "scan_type",
                ),
                result=("findings",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_security_vulnerability_scan",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "scope",
                    "standard",
                    "scan_type",
                ),
                result=("findings",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="inspect-host",
        description="Read system information, services, logs and network topology of a host.",
        steps=(
            ToolStep(
                tool="tm_system_get_info",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "log_paths",
                    "patterns",
                ),
                result=("os", "cpu", "memory"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_system_discover_services",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "log_paths",
                    "patterns",
                ),
                result=("services",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_system_analyze_logs",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "log_paths",
                    "patterns",
                ),
                result=("matches",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_system_network_topology",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "log_paths",
                    "patterns",
                ),
                result=("interfaces", "connections"),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="track-operation",
        description="Start, watch and cancel a tracked long-running operation.",
        steps=(
            ToolStep(
                tool="tm_operation_start",
                params=(
                    "operation_id",
                    "operation_type",
                    "total_steps",
                    "details",
                    "confirm",
                ),
                result=("operation_id",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_operation_get_progress",
                params=(
                    "operation_id",
                    "operation_type",
                    "total_steps",
                    "details",
                    "confirm",
                ),
                result=("progress",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_operation_get_metrics",
                params=(
                    "operation_id",
                    "operation_type",
                    "total_steps",
                    "details",
                    "confirm",
                ),
                result=("metrics",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_operation_list_sessions",
                params=(
                    "operation_id",
                    "operation_type",
                    "total_steps",
                    "details",
                    "confirm",
                ),
                result=("sessions",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
            ToolStep(
                tool="tm_operation_cancel",
                params=(
                    "operation_id",
                    "operation_type",
                    "total_steps",
                    "details",
                    "confirm",
                ),
                result=("result",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                    Refusal(
                        "CONFIRMATION_REQUIRED",
                        "the caller has not confirmed the destructive call",
                    ),
                ),
            ),
        ),
    ),
    ToolUseContract(
        task="manage-remote-files",
        description="Search, compare, back up, watch and bulk-change files on a host.",
        steps=(
            ToolStep(
                tool="tm_file_content_search",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "operation",
                    "source",
                    "destination",
                    "mode",
                    "owner",
                    "group",
                    "search_paths",
                    "pattern",
                    "case_sensitive",
                    "recursive",
                    "max_results",
                    "watch_paths",
                    "duration",
                    "file_path",
                    "host1",
                    "host2",
                    "backup_paths",
                    "backup_dest",
                    "compression",
                    "incremental",
                ),
                result=("matches",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_file_diff_compare",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "operation",
                    "source",
                    "destination",
                    "mode",
                    "owner",
                    "group",
                    "search_paths",
                    "pattern",
                    "case_sensitive",
                    "recursive",
                    "max_results",
                    "watch_paths",
                    "duration",
                    "file_path",
                    "host1",
                    "host2",
                    "backup_paths",
                    "backup_dest",
                    "compression",
                    "incremental",
                ),
                result=("differences",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_file_backup",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "operation",
                    "source",
                    "destination",
                    "mode",
                    "owner",
                    "group",
                    "search_paths",
                    "pattern",
                    "case_sensitive",
                    "recursive",
                    "max_results",
                    "watch_paths",
                    "duration",
                    "file_path",
                    "host1",
                    "host2",
                    "backup_paths",
                    "backup_dest",
                    "compression",
                    "incremental",
                ),
                result=("backup",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_file_watch",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "operation",
                    "source",
                    "destination",
                    "mode",
                    "owner",
                    "group",
                    "search_paths",
                    "pattern",
                    "case_sensitive",
                    "recursive",
                    "max_results",
                    "watch_paths",
                    "duration",
                    "file_path",
                    "host1",
                    "host2",
                    "backup_paths",
                    "backup_dest",
                    "compression",
                    "incremental",
                ),
                result=("events",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
            ToolStep(
                tool="tm_file_recursive_ops",
                params=(
                    "remote_host",
                    "username",
                    "password_ref",
                    "identity_file",
                    "operation",
                    "source",
                    "destination",
                    "mode",
                    "owner",
                    "group",
                    "search_paths",
                    "pattern",
                    "case_sensitive",
                    "recursive",
                    "max_results",
                    "watch_paths",
                    "duration",
                    "file_path",
                    "host1",
                    "host2",
                    "backup_paths",
                    "backup_dest",
                    "compression",
                    "incremental",
                ),
                result=("changed",),
                refusals=(
                    Refusal(
                        "ACCESS_DENIED", "the credential lacks access to the operation"
                    ),
                    Refusal(
                        "INVALID_ARGUMENT", "the upstream system rejects the input"
                    ),
                ),
            ),
        ),
    ),
)

LINKS = (
    SurfaceLink(
        task="look-up-hosts",
        tools=("tunnel_manager_list_hosts", "tunnel_manager_get_host"),
        prompts=("tunnel-manager-operator", "tunnel-manager-inventory-administrator"),
        skills=("tunnel-manager-host-inventory",),
    ),
    SurfaceLink(
        task="maintain-host-inventory",
        tools=(
            "tunnel_manager_load_inventory",
            "tunnel_manager_add_host",
            "tunnel_manager_remove_host",
            "tunnel_manager_save_inventory",
        ),
        prompts=("tunnel-manager-operator", "tunnel-manager-inventory-administrator"),
        skills=("tunnel-manager-host-inventory",),
    ),
    SurfaceLink(
        task="sync-inventory-to-graph",
        tools=("tunnel_manager_list_hosts", "tunnel_ingest_hosts"),
        prompts=("tunnel-manager-operator", "tunnel-manager-inventory-administrator"),
        skills=("tunnel-manager-host-inventory",),
    ),
    SurfaceLink(
        task="run-command-on-host",
        tools=("tm_remote_check_ssh", "tm_remote_run_command"),
        prompts=("tunnel-manager-operator", "tunnel-manager-remote-operator"),
        skills=("tunnel-manager-remote-execution",),
    ),
    SurfaceLink(
        task="copy-file-with-host",
        tools=("tm_remote_send_file", "tm_remote_receive_file"),
        prompts=("tunnel-manager-operator", "tunnel-manager-remote-operator"),
        skills=("tunnel-manager-remote-execution",),
    ),
    SurfaceLink(
        task="run-command-on-group",
        tools=("tm_inventory_run_command",),
        prompts=("tunnel-manager-operator", "tunnel-manager-remote-operator"),
        skills=("tunnel-manager-remote-execution",),
    ),
    SurfaceLink(
        task="copy-file-with-group",
        tools=("tm_inventory_send_file", "tm_inventory_receive_file"),
        prompts=("tunnel-manager-operator", "tunnel-manager-remote-operator"),
        skills=("tunnel-manager-remote-execution",),
    ),
    SurfaceLink(
        task="set-up-key-auth-on-host",
        tools=(
            "tm_remote_test_key_auth",
            "tm_remote_setup_passwordless",
            "tm_remote_copy_ssh_config",
        ),
        prompts=(
            "tunnel-manager-operator",
            "tunnel-manager-ssh-security-administrator",
        ),
        skills=("tunnel-manager-ssh-hardening",),
    ),
    SurfaceLink(
        task="rotate-key-on-host",
        tools=(
            "tm_remote_test_key_auth",
            "tm_remote_rotate_key",
            "tm_remote_remove_host_key",
        ),
        prompts=(
            "tunnel-manager-operator",
            "tunnel-manager-ssh-security-administrator",
        ),
        skills=("tunnel-manager-ssh-hardening",),
    ),
    SurfaceLink(
        task="set-up-key-auth-on-group",
        tools=(
            "tm_inventory_configure_key_auth",
            "tm_inventory_mesh_bootstrap",
            "tm_inventory_copy_ssh_config",
        ),
        prompts=(
            "tunnel-manager-operator",
            "tunnel-manager-ssh-security-administrator",
        ),
        skills=("tunnel-manager-ssh-hardening",),
    ),
    SurfaceLink(
        task="rotate-key-on-group",
        tools=("tm_inventory_rotate_key",),
        prompts=(
            "tunnel-manager-operator",
            "tunnel-manager-ssh-security-administrator",
        ),
        skills=("tunnel-manager-ssh-hardening",),
    ),
    SurfaceLink(
        task="audit-host-security",
        tools=(
            "tm_security_security_audit",
            "tm_security_access_control_audit",
            "tm_security_compliance_check",
            "tm_security_vulnerability_scan",
        ),
        prompts=(
            "tunnel-manager-operator",
            "tunnel-manager-ssh-security-administrator",
        ),
        skills=("tunnel-manager-ssh-hardening",),
    ),
    SurfaceLink(
        task="inspect-host",
        tools=(
            "tm_system_get_info",
            "tm_system_discover_services",
            "tm_system_analyze_logs",
            "tm_system_network_topology",
        ),
        prompts=(
            "tunnel-manager-operator",
            "tunnel-manager-remote-operator",
            "tunnel-manager-ssh-security-administrator",
        ),
        skills=("tunnel-manager-operations",),
    ),
    SurfaceLink(
        task="track-operation",
        tools=(
            "tm_operation_start",
            "tm_operation_get_progress",
            "tm_operation_get_metrics",
            "tm_operation_list_sessions",
            "tm_operation_cancel",
        ),
        prompts=("tunnel-manager-operator", "tunnel-manager-remote-operator"),
        skills=("tunnel-manager-operations",),
    ),
    SurfaceLink(
        task="manage-remote-files",
        tools=(
            "tm_file_content_search",
            "tm_file_diff_compare",
            "tm_file_backup",
            "tm_file_watch",
            "tm_file_recursive_ops",
        ),
        prompts=("tunnel-manager-operator", "tunnel-manager-remote-operator"),
        skills=("tunnel-manager-operations",),
    ),
)

LOCATIONS = (
    DataLocation(
        name="ssh-inventory",
        holds=("Host", "HostGroup"),
        instance="TUNNEL_INVENTORY",
        read_tool="tunnel_manager_list_hosts",
        federation_key="alias",
    ),
    DataLocation(
        name="ssh-operations",
        holds=("Operation", "CommandExecution", "FileTransfer"),
        instance="TUNNEL_INVENTORY",
        read_tool="tm_operation_list_sessions",
        federation_key="operation_id",
    ),
    DataLocation(
        name="ssh-security",
        holds=("SecurityAudit",),
        instance="TUNNEL_INVENTORY",
        read_tool="tm_security_security_audit",
        route_param="remote_host",
    ),
    DataLocation(
        name="ssh-keys",
        holds=("SshKey",),
        instance="TUNNEL_INVENTORY",
        read_tool="tm_remote_test_key_auth",
        route_param="host",
    ),
    DataLocation(
        name="ssh-topology",
        holds=("Tunnel",),
        instance="TUNNEL_INVENTORY",
        read_tool="tm_system_network_topology",
        route_param="remote_host",
    ),
)

ROLES = (
    BusinessRole(
        name="host inventory administrator",
        description="Keep the SSH host inventory complete and in step with the knowledge graph.",
        tasks=("look-up-hosts", "maintain-host-inventory", "sync-inventory-to-graph"),
    ),
    BusinessRole(
        name="remote operator",
        description="Run commands, move files and inspect hosts and groups on request.",
        tasks=(
            "run-command-on-host",
            "copy-file-with-host",
            "run-command-on-group",
            "copy-file-with-group",
            "inspect-host",
            "track-operation",
            "manage-remote-files",
        ),
    ),
    BusinessRole(
        name="ssh security administrator",
        description="Keep SSH access key-based, rotated and audited across the fleet.",
        tasks=(
            "set-up-key-auth-on-host",
            "rotate-key-on-host",
            "set-up-key-auth-on-group",
            "rotate-key-on-group",
            "audit-host-security",
            "inspect-host",
        ),
    ),
)
