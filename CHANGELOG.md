# Changelog

All notable changes to `tunnel-manager` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- `remove_host` now prunes removed aliases from the Ansible-format inventory.
  `save_inventory()` merged `self.hosts` into the existing
  `all.children.homelab.hosts` map but never deleted aliases removed from
  `self.hosts`, so `remove_host()` left the host in `inventory.yaml`. Aliases
  absent from `self.hosts` are now pruned from the file before writing;
  add/update behaviour and the Ansible nested format/vars are preserved.

## [1.14.0] - 2026-05-22

### Added
- Initial CHANGELOG.md creation
- docs/concepts.md with CONCEPT ID registry

### Changed
- Standardized project structure per agent-packages ecosystem conventions
