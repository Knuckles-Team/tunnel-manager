# CONN-TUNNEL-MANAGER-SDK — Shared SDK capabilities in tunnel-manager

**Owner:** tunnel-manager.

See [`requirements.md`](requirements.md) for each row and [`status.json`](status.json) for its generated state.

## Purpose

tunnel-manager must use the scion-sdk capability for each concern the SDK centralizes. A connector copy of a centralized capability splits policy across the fleet.

## Why a new spec

Search: `git grep -n "SDK" -- specs` found no row that owns SDK capability use in tunnel-manager. The SDK index spec `SCION-CENTRALIZED-CAPABILITIES` owns the capabilities. This spec owns the connector side of each one.

## Requirements

- `CONN-TUNNEL-MANAGER-SDK-R001`: Secret references resolve through the SDK.
- `CONN-TUNNEL-MANAGER-SDK-R002`: SDK floor and dependency set.
- `CONN-TUNNEL-MANAGER-SDK-R003`: Production wiring.
- `CONN-TUNNEL-MANAGER-SDK-R004`: Hot-path proof.
- `CONN-TUNNEL-MANAGER-SDK-R005`: Served actor binding.
