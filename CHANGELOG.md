# Changelog

All notable changes to `tunnel-manager` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
