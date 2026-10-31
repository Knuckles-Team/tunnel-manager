# Changelog

All notable changes to `tunnel-manager` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.4.4] - 2026-10-30

### Fixed
- Windows: inventory writes, downloads, key generation and authorized_keys rotation no longer call `os.fchmod`, which Windows lacks. Private files are hardened by `secure_descriptor` and `secure_path` (`S_IREAD | S_IWRITE` on Windows, 0o600 on POSIX).
- `os.getuid` is no longer required: the known-hosts owner check and the SSH-config lookup fallback use `current_uid`.
- `tm_remote` and `tm_inventory` key setup and rotation generate key pairs natively instead of running `/usr/bin/ssh-keygen`.
- The test suite now runs in a Windows CI job.

## [3.4.3] - 2026-10-30

### Fixed
- Tool errors keep the local file paths that name their cause. Responses pass through `scion_sdk.privacy.sanitize_tool_response`, which redacts only secrets.
- Requires scion-sdk 0.6.3: the trusted local caller (stdio, or HTTP with `--auth-type none`) is no longer rate limited, and the rate limiter keys on the same bound actor as entitlements.

## [3.4.2] - 2026-10-30

### Fixed
- `tm_remote_*` no longer connects to port 22 (or the default key and SSH config) when an alias names its own. Every tool resolves a host through one resolver: explicit argument, then inventory host vars, then group vars, then `TUNNEL_*` settings, then built-in defaults.
- `tm_system_*`, `tm_file_*` and `tm_security_*` accept an inventory alias.
- Failures report `Type: message`, not only the exception type.
- Key pairs are generated natively; the image needs no `ssh-keygen`.
- `check_ssh` no longer reports key auth disabled when it works; `test_key_auth` keeps the target port.
- `tm_remote_remove_host_key` accepts `confirm=true` when the client cannot elicit.
- A read-only inventory reports `inventory is read-only: <path>`.
- `mesh_bootstrap` reads group vars like every other inventory action; `compliance_check` no longer fails on its own result.
- Requires `scion-sdk>=0.6.2`: one actor path for stdio, explicit no-auth HTTP and JWT HTTP.

## [3.4.1] - 2026-10-30

### Fixed
- A no-auth HTTP deployment (`--auth-type none`, for example behind arbora) lists every host and runs commands again: with `scion-sdk>=0.6.1` its callers are the trusted local actor, not anonymous.
- Authorization refusals name their cause (anonymous caller, unauthenticated, no tenant, or `not entitled to ssh:<alias>`) instead of a bare "remote target authorization failed". `tm_remote_run_command` returns it as a 403 and logs it; a refused remote execution carries it in `stderr_tail`.

## [3.4.0] - 2026-10-30

### Changed
- Migrated to `scion-sdk` 0.6.x: the `scion_sdk` import package, `scion_sdk.*` entry-point groups and `scion-sdk>=0.6.0,<0.7.0`. The actor resolves from the transport, so no startup `use_actor` binding is needed.

### Fixed
- SSH connects without a local username (inventory user is used) and tool failures name their cause (released as 3.3.8 source; first tagged release is 3.4.0).

## [3.3.8] - 2026-10-30

### Fixed
- SSH no longer depends on the local process username: a container uid with no passwd entry and no `USER`/`LOGNAME` connects using the inventory user. The published image runs as a real uid 1000 user.
- Tool failures are logged with their cause, and `ConnectionPolicyError` names the failing check and path or setting.

## [3.3.7] - 2026-10-29

### Changed
- Built on `scion-sdk>=0.5.9`: served tool calls bind an actor (SYSTEM for local transport, the token actor for authenticated HTTP).

### Security
- `fastmcp>=4.1.2` (GHSA-7xgj-8392-5q4r, GHSA-vqqp-x5qm-5qp4) and `certifi` 2026.10.23 (PYSEC-2026-4320) in the lock.

## [3.3.5] - 2026-10-24

### Changed
- Central connector migration: requires `agent-connector-sdk>=0.5.4`; server bootstrap, version, containers, ontology artifacts, security scaffold and pre-commit config are provided centrally.

## [3.3.4] - 2026-10-23

### Changed
- Requires `agent-connector-sdk>=0.4.1`; data sources are declared in code (`connector_sources`).

## [Unreleased]

### Fixed
- `remove_host` now prunes removed aliases from the Ansible-format inventory.
  `save_inventory()` merged `self.hosts` into the existing
  `all.children.<group>.hosts` map but never removed aliases removed from
  `self.hosts`, so `remove_host()` left the host in `inventory.yaml`. Aliases
  absent from `self.hosts` are now pruned from the file before writing;
  add/update behaviour and the Ansible nested format/vars are preserved.

## [1.14.0] - 2026-05-22

### Added
- Initial CHANGELOG.md creation
- docs/concepts.md with CONCEPT ID registry

### Changed
- Standardized project structure per agent-packages ecosystem conventions
