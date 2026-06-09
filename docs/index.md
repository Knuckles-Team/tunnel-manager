# tunnel-manager

An **SSH tunnel, remote-execution and MCP/agent server** for the agent-utilities
ecosystem — the agentless execution arm that lets agents run commands, transfer
files and audit fleets of remote hosts over plain SSH.

!!! info "Official documentation"
    This site is the canonical reference for `tunnel-manager`, maintained alongside
    every release.

[![PyPI](https://img.shields.io/pypi/v/tunnel-manager)](https://pypi.org/project/tunnel-manager/)
![MCP Server](https://badge.mcpx.dev?type=server 'MCP Server')
[![License](https://img.shields.io/pypi/l/tunnel-manager)](https://github.com/Knuckles-Team/tunnel-manager/blob/main/LICENSE)
[![GitHub](https://img.shields.io/badge/source-GitHub-181717?logo=github)](https://github.com/Knuckles-Team/tunnel-manager)

## Overview

`tunnel-manager` provisions SSH tunnels to remote hosts and exposes them as typed,
deterministic MCP tools and a Pydantic-AI agent. It is the *agentless execution arm*
of the Agent OS — agents call it to run commands, copy files, bootstrap passwordless
SSH and audit hosts at scale without deploying persistent daemons. It provides:

- **`HostManager` and `Tunnel`** — a `paramiko` / `asyncssh` client layer over the
  inventory and individual SSH connections, with native Linux and Windows path and
  certificate resolution (including Teleport `tsh` proxy tunnelling).
- **Seven action-routed MCP tools** — host inventory, single-host remote operations,
  bulk inventory operations, operation lifecycle, system intelligence, advanced file
  operations and security auditing, each toggled independently.
- **An integrated Pydantic-AI agent** — exposed over the Agent Control Protocol with
  an optional web UI, wired to the MCP server through `MCP_URL`.

## Explore the documentation

<div class="grid cards" markdown>

- :material-rocket-launch: **[Installation](installation.md)** — pip, source, extras, and the prebuilt Docker image.
- :material-server-network: **[Deployment](deployment.md)** — run the MCP and agent servers, Docker Compose, Caddy + Technitium.
- :material-console: **[Usage](usage.md)** — the MCP tools, the `HostManager` / `Tunnel` API, and the CLI.
- :material-sitemap: **[Overview](overview.md)** — ecosystem role, distributed SSH swarm scaling, MCP configuration.
- :material-transit-connection-variant: **[Teleport Architecture](teleport_architecture.md)** — certificate, proxy and cross-OS connection model.
- :material-tag-multiple: **[Concepts](concepts.md)** — the `CONCEPT:TUN-*` registry.

</div>

## Quick start

```bash
pip install "tunnel-manager[mcp]"
tunnel-manager-mcp                   # stdio MCP server (default transport)
```

Run it as a network server with a published port:

```bash
tunnel-manager-mcp --transport streamable-http --host 0.0.0.0 --port 8000
```

See **[Installation](installation.md)** and **[Deployment](deployment.md)** for the
full matrix (PyPI extras, Docker image, every transport, the agent server, reverse
proxy and DNS).
