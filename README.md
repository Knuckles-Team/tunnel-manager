# Tunnel Manager
## CLI or API | MCP | Agent

![PyPI - Version](https://img.shields.io/pypi/v/tunnel-manager)
![MCP Server](https://badge.mcpx.dev?type=server 'MCP Server')
![PyPI - Downloads](https://img.shields.io/pypi/dd/tunnel-manager)
![GitHub Repo stars](https://img.shields.io/github/stars/Knuckles-Team/tunnel-manager)
![GitHub forks](https://img.shields.io/github/forks/Knuckles-Team/tunnel-manager)
![GitHub contributors](https://img.shields.io/github/contributors/Knuckles-Team/tunnel-manager)
![PyPI - License](https://img.shields.io/pypi/l/tunnel-manager)
![GitHub](https://img.shields.io/github/license/Knuckles-Team/tunnel-manager)
![GitHub last commit (by committer)](https://img.shields.io/github/last-commit/Knuckles-Team/tunnel-manager)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Knuckles-Team/tunnel-manager)
![GitHub closed pull requests](https://img.shields.io/github/issues-pr-closed/Knuckles-Team/tunnel-manager)
![GitHub issues](https://img.shields.io/github/issues/Knuckles-Team/tunnel-manager)
![GitHub top language](https://img.shields.io/github/languages/top/Knuckles-Team/tunnel-manager)
![GitHub language count](https://img.shields.io/github/languages/count/Knuckles-Team/tunnel-manager)
![GitHub repo size](https://img.shields.io/github/repo-size/Knuckles-Team/tunnel-manager)
![GitHub repo file count (file type)](https://img.shields.io/github/directory-file-count/Knuckles-Team/tunnel-manager)
![PyPI - Wheel](https://img.shields.io/pypi/wheel/tunnel-manager)
![PyPI - Implementation](https://img.shields.io/pypi/implementation/tunnel-manager)

*Version: 1.33.0*

> **Documentation** — Installation, deployment, usage across the API, CLI, and MCP
> and agent interfaces are maintained in the
> [official documentation](https://knuckles-team.github.io/tunnel-manager/).

---

## Overview

**Tunnel Manager** is a production-grade Agent and Model Context Protocol (MCP) server designed to interface directly with Create SSH Tunnels to your remote hosts and host as an MCP Server for Agentic AI!.

---

## Key Features

- **Consolidated Action-Routed MCP Tools:** Minimizes token overhead and eliminates tool bloat in LLM contexts by grouping methods into optimized, togglable tool modules.
- **Enterprise-Grade Security:** Comprehensive support for Eunomia policies, OIDC token delegation, and granular execution context tracking.
- **Integrated Graph Agent:** Built-in Pydantic AI agent supporting the Agent Control Protocol (ACP) and standard Web interfaces (AG-UI).
- **Native Telemetry & Tracing:** Out-of-the-box OpenTelemetry exports and native Langfuse tracing.

---

## CLI or API

This agent wraps the Create SSH Tunnels to your remote hosts and host as an MCP Server for Agentic AI! API. You can interact with it programmatically or via its integrated execution entrypoints.

Detailed instructions on how to use the underlying API wrappers, extended schema bindings, and developer SDK references are maintained in [docs/index.md](docs/index.md).

---

## MCP

This server utilizes dynamic Action-Routed tools to optimize token overhead and maximize IDE compatibility.

### Available MCP Tools

_Auto-generated from the live MCP server — do not edit by hand._

<!-- MCP-TOOLS-TABLE:START -->

| MCP Tool | Toggle Env Var | Description |
|----------|----------------|-------------|
| `tm_files` | `TM_FILES_TOOL` | Advanced file operations on remote hosts. |
| `tm_hosts` | `TM_HOSTS_TOOL` | Manage the local host alias inventory. |
| `tm_inventory` | `TM_INVENTORY_TOOL` | Bulk inventory operations against YAML host groups. |
| `tm_operations` | `TM_OPERATIONS_TOOL` | Operation lifecycle and session management. |
| `tm_remote` | `TM_REMOTE_TOOL` | Single-host SSH operations with shared connection params. |
| `tm_security` | `TM_SECURITY_TOOL` | Security scanning and compliance. |
| `tm_system` | `TM_SYSTEM_TOOL` | Remote system intelligence via SSH. |

_7 action-routed tools (default `MCP_TOOL_MODE=condensed`). Each is enabled unless its toggle is set false; set `MCP_TOOL_MODE=verbose` (or `both`) for the 1:1 per-operation surface. Auto-generated — do not edit._
<!-- MCP-TOOLS-TABLE:END -->

Detailed tool schemas, parameter shapes, and validation constraints are preserved in [docs/mcp.md](docs/mcp.md).

### Dynamic Tool Selection & Visibility

This MCP server supports dynamic toolset selection and visibility filtering at runtime. This allows you to restrict the set of exposed tools in order to prevent blowing up the LLM's context window.

You can configure tool filtering via multiple input channels:

- **CLI Arguments:** Pass `--tools` or `--toolsets` (or their disabled counterparts `--disabled-tools` and `--disabled-toolsets`) during startup.
- **Environment Variables:** Define standard environment variables:
  - `MCP_ENABLED_TOOLS` / `MCP_DISABLED_TOOLS`
  - `MCP_ENABLED_TAGS` / `MCP_DISABLED_TAGS`
- **HTTP SSE Request Headers:** Pass custom headers during transport initialization:
  - `x-mcp-enabled-tools` / `x-mcp-disabled-tools`
  - `x-mcp-enabled-tags` / `x-mcp-disabled-tags`
- **HTTP SSE Request Query Parameters:** Append query parameters directly to your transport connection URL:
  - `?tools=tool1,tool2`
  - `?tags=tag1`

When query strings or parameters are supplied, an LLM-free **Knowledge Graph resolution layer** (using `DynamicToolOrchestrator`) matches query intents against known tool tags, names, or descriptions, with safe fallback and automated 24-hour background cache refreshing.

---

### MCP Configuration Examples

> **Install the slim `[mcp]` extra.** All examples below install
> `tunnel-manager[mcp]` — the MCP-server extra that pulls only the FastMCP /
> FastAPI tooling (`agent-utilities[mcp]`). It deliberately **excludes** the heavy
> agent runtime (the epistemic-graph engine, `pydantic-ai`, `dspy`, `llama-index`,
> `tree-sitter`), so `uvx`/container installs are dramatically smaller and faster.
> Use the full `[agent]` extra only when you need the integrated Pydantic AI agent
> (see [Installation](#installation)).

#### stdio Transport (Recommended for local IDEs e.g., Cursor, Claude Desktop)
Configure your IDE's `mcp.json` to launch the MCP server via `uvx`:

```json
{
  "mcpServers": {
    "tunnel-manager": {
      "command": "uvx",
      "args": [
        "--from",
        "tunnel-manager[mcp]",
        "tunnel-manager-mcp"
      ],
      "env": {
        "TUNNEL_IDENTITY_FILE": "your_tunnel_identity_file_here",
        "DEBUG": "your_debug_here",
        "PYTHONUNBUFFERED": "your_pythonunbuffered_here"
      }
    }
  }
}
```

#### Streamable-HTTP Transport (Recommended for production deployments)
Configure your client's `mcp.json` to launch the Streamable-HTTP server via `uvx` with explicit host and port definition:

```json
{
  "mcpServers": {
    "tunnel-manager": {
      "command": "uvx",
      "args": [
        "--from",
        "tunnel-manager[mcp]",
        "tunnel-manager-mcp"
      ],
      "env": {
        "TRANSPORT": "streamable-http",
        "HOST": "0.0.0.0",
        "PORT": "8000",
        "TUNNEL_IDENTITY_FILE": "your_tunnel_identity_file_here",
        "DEBUG": "your_debug_here",
        "PYTHONUNBUFFERED": "your_pythonunbuffered_here"
      }
    }
  }
}
```

Alternatively, connect to a pre-deployed remote or local Streamable-HTTP instance:

```json
{
  "mcpServers": {
    "tunnel-manager": {
      "url": "http://localhost:8000/tunnel-manager/mcp"
    }
  }
}
```

Deploying the Streamable-HTTP server via Docker:

```bash
docker run -d \
  --name tunnel-manager-mcp \
  -p 8000:8000 \
  -e TRANSPORT=streamable-http \
  -e PORT=8000 \
  -e TUNNEL_IDENTITY_FILE="your_value" \
  -e DEBUG="your_value" \
  -e PYTHONUNBUFFERED="your_value" \
  knucklessg1/tunnel-manager:mcp
```

> The `:mcp` tag is the **slim MCP-server image** (built from
> `docker/Dockerfile --target mcp`, installing `tunnel-manager[mcp]`). The default
> `:latest` tag is the **full agent image** (`--target agent`, `tunnel-manager[agent]`)
> which also bundles the Pydantic AI agent and the epistemic-graph engine — use it
> when you run `tunnel-manager-agent` (the agent), not just the MCP server. See
> [Container images](#container-images-mcp-vs-agent).

---

<!-- BEGIN GENERATED: additional-deployment-options -->
### Additional Deployment Options

`tunnel-manager` can also run as a **local container** (Docker / Podman / `uv`) or be
consumed from a **remote deployment**. The
[Deployment guide](https://knuckles-team.github.io/tunnel-manager/deployment/) has full, copy-paste
`mcp_config.json` for all four transports — **stdio**, **streamable-http**,
**local container / uv**, and **remote URL**:

- **Local container / uv** — launch the server from `mcp_config.json` via `uvx`,
  `docker run`, or `podman run`, or point at a local streamable-http container by `url`.
- **Remote URL** — connect to a server deployed behind Caddy at
  `http://tunnel-manager-mcp.arpa/mcp` using the `"url"` key.
<!-- END GENERATED: additional-deployment-options -->

---

## Inventory

tunnel-manager works from a single shared YAML **inventory** that maps short host
aliases (e.g. `r820`) to their SSH connection details. Every ecosystem surface reads
the **same file** — the `HostManager` API, the `tunnel-manager` CLI, the MCP server,
**container-manager-mcp** (its `cm_*` host aliases), and the `ssh-bootstrap` skill — so
you define your fleet once.

- **Location** — `~/.config/agent-utilities/inventory.yml` (`.yml` preferred). A legacy
  `inventory.yaml` at the same path is still read when no `.yml` exists, so existing
  installs keep working. Override with `TUNNEL_INVENTORY`.
- **Manage it** with the `inventory` subcommand:

  ```bash
  tunnel-manager inventory init     # write a commented inventory.yml template (--force to overwrite)
  tunnel-manager inventory doctor   # validate hosts/groups; --fix migrates legacy .yaml -> .yml
  tunnel-manager inventory show     # print the resolved path + host/group summary
  ```

Full schema, every host field, the copy-paste template, and override options live in the
[Inventory guide](docs/inventory.md).

---

## Environment Variables

<!-- ENV-VARS-TABLE:START -->

#### Package environment variables

| Variable | Example | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` |  |
| `PORT` | `8000` |  |
| `TRANSPORT` | `stdio` | options: stdio, streamable-http, sse |
| `ENABLE_OTEL` | `True` |  |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `http://localhost:8080/api/public/otel` |  |
| `OTEL_EXPORTER_OTLP_PUBLIC_KEY` | `pk-...` |  |
| `OTEL_EXPORTER_OTLP_SECRET_KEY` | `sk-...` |  |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` |  |
| `EUNOMIA_TYPE` | `none` | options: none, embedded, remote |
| `EUNOMIA_POLICY_FILE` | `mcp_policies.json` |  |
| `EUNOMIA_REMOTE_URL` | `http://eunomia-server:8000` |  |
| `TUNNEL_IDENTITY_FILE` | `~/.ssh/id_ed25519` |  |
| `DEBUG` | `False` |  |
| `PYTHONUNBUFFERED` | `1` |  |
| `TM_HOSTS_TOOL` | `True` |  |
| `TM_REMOTE_TOOL` | `True` |  |
| `TM_INVENTORY_TOOL` | `True` |  |
| `TM_OPERATIONS_TOOL` | `True` |  |
| `TM_SYSTEM_TOOL` | `True` |  |
| `TM_FILES_TOOL` | `True` |  |
| `TM_SECURITY_TOOL` | `True` |  |

#### Inherited agent-utilities variables (apply to every connector)

| Variable | Example | Description |
|----------|---------|-------------|
| `MCP_TOOL_MODE` | `condensed` | Tool surface: `condensed` | `verbose` | `both` |
| `MCP_ENABLED_TOOLS` | — | Comma-separated tool allow-list |
| `MCP_DISABLED_TOOLS` | — | Comma-separated tool deny-list |
| `MCP_ENABLED_TAGS` | — | Comma-separated tag allow-list |
| `MCP_DISABLED_TAGS` | — | Comma-separated tag deny-list |
| `MCP_CLIENT_AUTH` | — | Outbound MCP auth (`oidc-client-credentials` for fleet calls) |
| `OIDC_CLIENT_ID` | — | OIDC client id (service-account auth) |
| `OIDC_CLIENT_SECRET` | — | OIDC client secret (service-account auth) |
| `MCP_URL` | `http://localhost:8000/mcp` | URL of the MCP server the agent connects to |
| `PROVIDER` | `openai` | LLM provider for the agent |
| `MODEL_ID` | `gpt-4o` | Model id for the agent |
| `ENABLE_WEB_UI` | `True` | Serve the AG-UI web interface |

_21 package + 12 inherited variable(s). Auto-generated from `.env.example` + the shared agent-utilities set — do not edit._
<!-- ENV-VARS-TABLE:END -->


Every variable the server reads, grouped by purpose. See [`.env.example`](.env.example)
for a copy-paste starting point.

### SSH connection & credentials
| Variable | Description | Default |
|----------|-------------|---------|
| `TUNNEL_IDENTITY_FILE` | Path to the SSH private key | `~/.ssh/id_ed25519` |
| `TUNNEL_USERNAME` | SSH username | — |
| `TUNNEL_PASSWORD` | SSH password (when not using a key) | — |
| `TUNNEL_CERTIFICATE` | Path to an SSH certificate | — |
| `TUNNEL_REMOTE_HOST` | Default remote host | — |
| `TUNNEL_REMOTE_PORT` | Default remote SSH port | `22` |
| `TUNNEL_PROXY_COMMAND` | SSH `ProxyCommand` for jump hosts | — |

### Inventory & parallelism
| Variable | Description | Default |
|----------|-------------|---------|
| `TUNNEL_INVENTORY` | Path to the shared inventory (`.yml` preferred, `.yaml` legacy fallback) | `~/.config/agent-utilities/inventory.yml` |
| `TUNNEL_INVENTORY_GROUP` | Default inventory host group | — |
| `TUNNEL_PARALLEL` | Run bulk operations in parallel | — |
| `TUNNEL_MAX_THREADS` | Max concurrent SSH worker threads | — |
| `XDG_CONFIG_HOME` | Base config dir used to resolve the inventory | `~/.config` |

### MCP server / transport
| Variable | Description | Default |
|----------|-------------|---------|
| `TRANSPORT` | `stdio`, `streamable-http`, or `sse` | `stdio` |
| `HOST` | Bind host (HTTP transports) | `0.0.0.0` |
| `PORT` | Bind port (HTTP transports) | `8000` |
| `MCP_TOOL_MODE` | Tool surface: `condensed`, `verbose`, or `both` | `condensed` |
| `MCP_ENABLED_TOOLS` / `MCP_DISABLED_TOOLS` | Comma-separated tool allow/deny list | — |
| `MCP_ENABLED_TAGS` / `MCP_DISABLED_TAGS` | Comma-separated tag allow/deny list | — |
| `DEBUG` | Verbose logging | `False` |
| `PYTHONUNBUFFERED` | Unbuffered stdout (recommended in containers) | `1` |

### Tool toggles
Each action-routed tool can be disabled individually via its toggle env var (set to `false`).
The full list is in the [Available MCP Tools](#available-mcp-tools) table above
(`TM_HOSTS_TOOL`, `TM_REMOTE_TOOL`, `TM_INVENTORY_TOOL`, `TM_OPERATIONS_TOOL`,
`TM_SYSTEM_TOOL`, `TM_FILES_TOOL`, `TM_SECURITY_TOOL`).

### Telemetry & governance
| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_OTEL` | Enable OpenTelemetry export | `True` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP collector endpoint | — |
| `OTEL_EXPORTER_OTLP_PUBLIC_KEY` / `OTEL_EXPORTER_OTLP_SECRET_KEY` | OTLP auth keys | — |
| `OTEL_EXPORTER_OTLP_PROTOCOL` | OTLP protocol (e.g. `http/protobuf`) | — |
| `EUNOMIA_TYPE` | Authorization mode: `none`, `embedded`, `remote` | `none` |
| `EUNOMIA_POLICY_FILE` | Embedded policy file | `mcp_policies.json` |
| `EUNOMIA_REMOTE_URL` | Remote Eunomia server URL | — |

### Agent runtime (full `[agent]` runtime only)
| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_URL` | URL of the MCP server the agent connects to | `http://localhost:8000/mcp` |
| `PROVIDER` | LLM provider (e.g. `openai`) | `openai` |
| `MODEL_ID` | Model id (e.g. `gpt-4o`) | `gpt-4o` |
| `ENABLE_WEB_UI` | Serve the AG-UI web interface | `True` |

## Agent

This repository features a fully integrated Pydantic AI Graph Agent. It communicates over the **Agent Control Protocol (ACP)** and interacts seamlessly with the **Agent Web UI (AG-UI)** and Terminal interface.

### Running the Agent CLI
To start the interactive command-line agent:

```bash
# Set credentials
export TUNNEL_IDENTITY_FILE="your_value"
export DEBUG="your_value"
export PYTHONUNBUFFERED="your_value"

# Run the agent server
tunnel-manager-agent --provider openai --model-id gpt-4o
```

### Docker Compose Orchestration
The following `docker/agent.compose.yml` configures the Agent, Web UI, and Terminal Interface together:

```yaml
version: '3.8'

services:
  tunnel-manager-mcp:
    image: knucklessg1/tunnel-manager:mcp
    container_name: tunnel-manager-mcp
    hostname: tunnel-manager-mcp
    restart: always
    env_file:
      - ../.env
    environment:
      - PYTHONUNBUFFERED=1
      - HOST=0.0.0.0
      - PORT=8000
      - TRANSPORT=streamable-http
    ports:
      - "8000:8000"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

  tunnel-manager-agent:
    image: knucklessg1/tunnel-manager:latest
    container_name: tunnel-manager-agent
    hostname: tunnel-manager-agent
    restart: always
    depends_on:
      - tunnel-manager-mcp
    env_file:
      - ../.env
    command: [ "tunnel-manager-agent" ]
    environment:
      - PYTHONUNBUFFERED=1
      - HOST=0.0.0.0
      - PORT=9002
      - MCP_URL=http://tunnel-manager-mcp:8000/mcp
      - PROVIDER=${PROVIDER:-openai}
      - MODEL_ID=${MODEL_ID:-gpt-4o}
      - ENABLE_WEB_UI=True
      - ENABLE_OTEL=True
    ports:
      - "9002:9002"
    healthcheck:
      test: ["CMD", "python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:9002/health')"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"

```

Detailed graph node architecture explanations, custom skill configurations, and agentic trace guides are available in [docs/agent.md](docs/agent.md).

---

## Security & Governance

Built directly upon the enterprise-ready [`agent-utilities`](https://github.com/Knuckles-Team/agent-utilities) core, standard security parameters are fully supported:

### Access Control & Policy Enforcement
- **Eunomia Policies:** Fine-grained, policy-driven tool authorization. Supports `none`, local `embedded` (`mcp_policies.json`), or centralized `remote` modes.
- **OIDC Token Delegation:** Compliant with RFC 8693 token exchange for flowing authenticating user credentials from Web UI / ACP → Agent → MCP.
- **Scoped Credentials:** Execution context runs restricted to the specific caller identity.

### Runtime Security Grid
| Feature | Functionality | Enablement |
|---------|---------------|------------|
| **Tool Guard** | Sensitivity inspection with human-in-the-loop validation | Enabled by default |
| **Prompt Injection Defense** | Input scanning, repetition monitoring, and recursive loop blocks | Enabled by default |
| **Context Safety Guard** | Stuck-loop detectors and contextual overflow preemptive alerts | Enabled by default |

---

## Installation

Pick the extra that matches what you want to run:

| Extra | Installs | Use when |
|-------|----------|----------|
| `tunnel-manager[mcp]` | Slim MCP server only (`agent-utilities[mcp]` — FastMCP/FastAPI) | You only run the **MCP server** (smallest install / image) |
| `tunnel-manager[agent]` | Full agent runtime (`agent-utilities[agent,logfire]` — Pydantic AI + the epistemic-graph engine) | You run the **integrated agent** |
| `tunnel-manager[all]` | Everything (`mcp` + `agent` + `logfire`) | Development / both surfaces |

```bash
# MCP server only (recommended for tool hosting — slim deps)
uv pip install "tunnel-manager[mcp]"

# Full agent runtime (Pydantic AI + epistemic-graph engine)
uv pip install "tunnel-manager[agent]"

# Everything (development)
uv pip install "tunnel-manager[all]"      # or: python -m pip install "tunnel-manager[all]"
```

### Container images (`:mcp` vs `:agent`)

One multi-stage `docker/Dockerfile` builds two right-sized images, selected by `--target`:

| Image tag | Build target | Contents | Entrypoint |
|-----------|--------------|----------|------------|
| `knucklessg1/tunnel-manager:mcp` | `--target mcp` | `tunnel-manager[mcp]` — **slim**, no engine/`pydantic-ai`/`dspy`/`llama-index`/`tree-sitter` | `tunnel-manager-mcp` |
| `knucklessg1/tunnel-manager:latest` | `--target agent` (default) | `tunnel-manager[agent]` — **full** agent runtime + epistemic-graph engine | `tunnel-manager-agent` |

```bash
docker build --target mcp   -t knucklessg1/tunnel-manager:mcp    docker/   # slim MCP server
docker build --target agent -t knucklessg1/tunnel-manager:latest docker/   # full agent
```

`docker/mcp.compose.yml` runs the slim `:mcp` server; `docker/agent.compose.yml` runs the
agent (`:latest`) with a co-located `:mcp` sidecar.

### Knowledge-graph database (`epistemic-graph`)

The **full agent** (`[agent]` / `:latest`) embeds the **epistemic-graph** engine (pulled in
transitively via `agent-utilities[agent]`). For production — or to share one knowledge graph
across multiple agents — run **epistemic-graph as its own database container** and point the
agent at it instead of embedding it. Deployment recipes (single-node + Raft HA), connection
config, and the full database architecture (with diagrams) are documented in the
[epistemic-graph deployment guide](https://knuckles-team.github.io/epistemic-graph/deployment/).
The slim `[mcp]` server does **not** require the database.

---

## Documentation

The complete documentation is published as the
[official documentation site](https://knuckles-team.github.io/tunnel-manager/) and is
the recommended reference for installation, deployment, and day-to-day operation.

| Page | Contents |
|---|---|
| [Installation](https://knuckles-team.github.io/tunnel-manager/installation/) | pip, source, extras, prebuilt Docker image |
| [Inventory](https://knuckles-team.github.io/tunnel-manager/inventory/) | the shared `inventory.yaml` — default location, how to create it, formats, overrides |
| [Deployment](https://knuckles-team.github.io/tunnel-manager/deployment/) | run the MCP and agent servers, Compose, Caddy + Technitium, env config |
| [Usage](https://knuckles-team.github.io/tunnel-manager/usage/) | the MCP tools, the `HostManager` / `Tunnel` API, the CLI |
| [Overview](https://knuckles-team.github.io/tunnel-manager/overview/) | ecosystem role, distributed SSH swarm scaling, MCP configuration |
| [Teleport Architecture](https://knuckles-team.github.io/tunnel-manager/teleport_architecture/) | certificate, proxy and cross-OS connection model |
| [Concepts](https://knuckles-team.github.io/tunnel-manager/concepts/) | concept registry (`CONCEPT:TUN-*`) |

`AGENTS.md` is the canonical contributor/agent guidance.

## Repository Owners

<img width="100%" height="180em" src="https://github-readme-stats.vercel.app/api?username=Knucklessg1&show_icons=true&hide_border=true&&count_private=true&include_all_commits=true" />

![GitHub followers](https://img.shields.io/github/followers/Knucklessg1)
![GitHub User's stars](https://img.shields.io/github/stars/Knucklessg1)

---

## Contribute

Contributions are welcome! Please ensure code quality by executing local checks before submitting pull requests:
- Format code using `ruff format .`
- Lint code using `ruff check .`
- Validate type-safety with `mypy .`
- Execute test suites using `pytest`


<!-- BEGIN agent-os-genesis-deploy (generated; do not edit between markers) -->

## Deploy with `agent-os-genesis`

This package can be provisioned for you — skill-guided — by the **`agent-os-genesis`**
universal skill (its *single-package deploy mode*): it picks your install method, seeds
secrets to OpenBao/Vault (or `.env`), trusts your enterprise CA, registers the MCP
server, and verifies it — the same machinery that stands up the whole Agent OS, narrowed
to just this package. Ask your agent to **"deploy `tunnel-manager` with agent-os-genesis"**.

| Install mode | Command |
|------|---------|
| Bare-metal, prod (PyPI) | `uvx tunnel-manager-mcp` · or `uv tool install tunnel-manager` |
| Bare-metal, dev (editable) | `uv pip install -e ".[all]"` · or `pip install -e ".[all]"` |
| Container, prod | deploy `knucklessg1/tunnel-manager:latest` via docker-compose / swarm / podman / podman-compose / kubernetes |
| Container, dev (editable) | deploy `docker/compose.dev.yml` (source-mounted at `/src`; edits live on restart) |

Secrets are read-existing + seeded via `vault_sync` — you are only prompted for what's missing.

<!-- END agent-os-genesis-deploy -->
