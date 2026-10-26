---
name: tunnel-manager-development
skill_type: skill
description: >-
  Develop, test, and publish tunnel-manager without breaking its typed SSH
  inventory, remote-execution, MCP action, packaged-content, spec-dashboard, or
  governed Pages contracts. Use when changing connector code, docs, skills,
  workflows, or repository-owned specifications.
license: MIT
tags: [tunnel-manager, ssh, connector, development, testing, pages, specs]
metadata:
  author: Genius
  version: '0.1.0'
---
# Tunnel Manager Development

Use this skill for changes inside the tunnel-manager package. The connector
turns an authorized SSH inventory into typed MCP actions for remote commands,
operations, system discovery, files, security, and graph ingestion. Keep the
HostManager/Tunnel library, action registrations, agent entry point, and
packaged resources aligned when a change crosses a boundary.

## Repository map

- `tunnel_manager/tunnel_manager.py` owns HostManager, Tunnel, inventory parsing,
  SSH policy, and the compatibility CLI.
- `tunnel_manager/remote_execution.py` is the typed alias-only execution seam;
  it resolves entitlements, secret references, known-host policy, bounded
  commands, redacted results, and transport failures.
- `tunnel_manager/mcp_server.py` registers the action-routed MCP surfaces for
  remote, inventory, operations, system, files, security, and ingest calls.
- `tunnel_manager/agent_server.py` owns the optional Pydantic-AI agent; do not
  route application behavior around the MCP contract.
- `tunnel_manager/skills/`, `prompts/`, `ontology/`, and `connectors/` are
  package resources exposed by the connector entry point.
- `specs/connector-content/`, `specs/inventory-authority/`, and `specs/sdk/`
  own the repository specifications and generated status evidence.

## Before editing

1. Start from a real worktree based on the current `origin/main` and identify
   the owning row under `specs/`; status JSON is generated evidence and is never
   hand-edited.
2. Trace a changed request from the MCP action and Pydantic model through
   HostManager/Tunnel or the remote-execution adapter to its response. Preserve
   action names and the stable connector identity `tunnel-manager-mcp`.
3. Use task-local fake transports, inventory files, and actor contexts in tests.
   Never make live SSH calls, resolve a real secret, or persist a hostname/key.
4. Preserve the shared inventory path and secret-reference boundary. Plaintext
   passwords, raw private keys, and unrestricted host targets do not belong in
   source, fixtures, logs, or returned results.

## Implementation contract

- Keep MCP action dispatch discoverable through each surface's `list_actions`
  path and preserve the `tm_remote`, `tm_inventory`, `tm_operation`,
  `tm_system`, `tm_file`, and `tm_security` prefixes.
- Resolve remote targets from authorized inventory aliases only. Enforce actor
  entitlement checks before loading host configuration, and return bounded,
  redacted output with stable failure classes.
- Keep inventory mutations atomic and owner-readable. Use SDK secret references
  and known-host verification; never introduce a plaintext credential fallback.
- Exercise refusal, malformed input, entitlement failure, transport failure,
  and successful response-shape paths when behavior changes.
- Keep all package resources under the existing setuptools package-data globs so
  wheels and sdists expose the same skills, prompts, ontology, and manifests.

## Rapid delivery: the 5-minute contract

Specs are already designed. Deliver one small, reviewable change at a time.

- Name the owning requirement and the proof before editing.
- Keep a slice to one connector concern: source behavior, one test seam, one
  workflow/configuration repair, or one substantive skill.
- Run the smallest relevant checks first, then the repository pre-commit suite
  and required pre-push hooks. Fix failures and warnings rather than bypassing
  hooks.
- Record exact source and test commands in the review handoff. Stage only the
  reviewed paths; never stage caches, credentials, generated site output, or a
  whole shared checkout.
- Never claim a spec or Pages row from a YAML marker alone. Generated status
  records, the successful exact-source workflow, and the published snapshot
  must agree.

## Spec delivery and Pages

The canonical Pages caller is `.github/workflows/pages.yml`. It uses the `docs`
content source, enables the version-1 dashboard with
`.config/spec-dashboard.json`, and runs on the default branch plus an explicit
`workflow_dispatch`. Keep the `specs/**`, dashboard config, and workflow paths
in the push trigger. The shared renderer owns the HTML layout and writes
`spec-delivery/snapshot.json`; do not commit generated site output.

Add or preserve the `spec-delivery/` documentation link. Rebuild status evidence
through the central pipeline hook after a spec change and inspect the diff. The
Pages proof is complete only when a successful hosted run has `headSha` equal to
the source revision and the public snapshot returns HTTP 200 with the connector
records. Local rendering proves wiring, not publication.

## Verification

From the repository root:

    pre-commit run --all-files
    pytest --cov=tunnel_manager --cov-report=term-missing

For Pages changes, also validate the JSON configuration, the generated status
records, and the exact-source hosted snapshot. Use mocked transports and
task-local output directories; do not run live SSH or connector calls.

## Safety

Never commit `.env` files, tokens, raw host identifiers, generated site output,
or inventory dumps. Preserve actor scoping, secret redaction, known-host checks,
and destructive-operation guards. If packaged metadata changes, bump the
canonical project version and refresh `uv.lock` in the same coherent release
slice, explaining why in the review.
