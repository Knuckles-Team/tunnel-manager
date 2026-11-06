---
name: tunnel-manager-ssh-hardening
skill_type: skill
description: >-
  Harden SSH access through tunnel-manager: test key login, install and rotate keys on one host or a group, bootstrap host-to-host mesh access, copy SSH config, drop stale host keys, and run read-only security, access, compliance and vulnerability audits. Use to move a fleet to key authentication or check its SSH posture.
---

# Tunnel manager SSH hardening

## One host

1. `tm_remote_test_key_auth` (`host`, `key`) tests key login. Run it before and after a change.
2. `tm_remote_setup_passwordless` (`host`, `key`, `key_type`) installs a key.
3. `tm_remote_copy_ssh_config` (`lcfg`, `rcfg`) copies an SSH config.
4. `tm_remote_rotate_key` (`key`, `new_key`) swaps the key and needs `confirm=true`.
5. `tm_remote_remove_host_key` (`known_hosts`) drops a stale entry from known hosts and needs `confirm=true`.

## A group

- `tm_inventory_configure_key_auth` installs one key on every host of `group`.
- `tm_inventory_mesh_bootstrap` lets the hosts reach each other by key.
- `tm_inventory_copy_ssh_config` copies the SSH config to each host.
- `tm_inventory_rotate_key` rotates the key across the group and needs `confirm=true`.
- Use `preview=true` first and show the host list.

## Audits (read only)

`tm_security_security_audit`, `tm_security_access_control_audit`, `tm_security_compliance_check` (`standard`) and `tm_security_vulnerability_scan` (`scan_type`) take `remote_host` and report findings. They do not change the host.

## Rules

- Never rotate or remove a key without a passing key-login test first.
- Never print a private key or secret reference value.
