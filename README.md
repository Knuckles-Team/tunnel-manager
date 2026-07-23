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

*Version: 3.0.0*

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

#### Condensed action-routed tools (default — `MCP_TOOL_MODE=condensed`)

| MCP Tool | Toggle Env Var | Description |
|----------|----------------|-------------|
| `tm_files` | `FILETOOL` | Advanced file operations on remote hosts. |
| `tm_hosts` | `HOSTTOOL` | Manage the local host alias inventory. |
| `tm_inventory` | `INVENTORYTOOL` | Bulk inventory operations against YAML host groups. |
| `tm_operations` | `OPERATIONSTOOL` | Operation lifecycle and session management. |
| `tm_remote` | `REMOTETOOL` | Single-host SSH operations with shared connection params. |
| `tm_security` | `SECURITYTOOL` | Security scanning and compliance. |
| `tm_system` | `SYSTEMTOOL` | Remote system intelligence via SSH. |
| `tunnel_ingest_hosts` | `INGESTTOOL` | List the managed SSH inventory and push it into the epistemic-graph KG. |

#### Verbose 1:1 API-mapped tools (`MCP_TOOL_MODE=verbose` or `both`)

<details>
<summary>6 per-operation tools — one per public API method (click to expand)</summary>

| MCP Tool | Toggle Env Var | Description |
|----------|----------------|-------------|
| `tunnel_manager_add_host` | `HOST_MANAGERTOOL` | Invoke the add_host operation. |
| `tunnel_manager_get_host` | `HOST_MANAGERTOOL` | Invoke the get_host operation. |
| `tunnel_manager_list_hosts` | `HOST_MANAGERTOOL` | Invoke the list_hosts operation. |
| `tunnel_manager_load_inventory` | `HOST_MANAGERTOOL` | Invoke the load_inventory operation. |
| `tunnel_manager_remove_host` | `HOST_MANAGERTOOL` | Invoke the remove_host operation. |
| `tunnel_manager_save_inventory` | `HOST_MANAGERTOOL` | Invoke the save_inventory operation. |

</details>

_8 action-routed tool(s) (default) · 6 verbose 1:1 tool(s). Each is enabled unless its `<DOMAIN>TOOL` toggle is set false; `MCP_TOOL_MODE` selects the surface (`condensed` default · `verbose` 1:1 · `both`). Auto-generated — do not edit._
<!-- MCP-TOOLS-TABLE:END -->

Detailed tool schemas, parameter shapes, and validation constraints are preserved in [docs/usage.md](docs/usage.md).

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

<!-- MCP-CONFIG-EXAMPLES:START -->

> **Install the connector-focused `[mcp]` extra.** Examples use `tunnel-manager[mcp]` to add
> FastMCP / FastAPI through `agent-utilities[mcp]`; the required Agent Utilities core
> still carries `epistemic-graph[full]`. The `[agent-runtime]` extra additionally
> enables model orchestration.

#### stdio Transport (local IDEs — Cursor, Claude Desktop, VS Code)

```json
{
  "mcpServers": {
    "tunnel-manager-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "tunnel-manager[mcp]",
        "tunnel-manager-mcp"
      ],
      "env": {
        "MCP_TOOL_MODE": "intent",
        "FILETOOL": "True",
        "HOSTTOOL": "True",
        "INGESTTOOL": "True",
        "INVENTORYTOOL": "True",
        "OPERATIONSTOOL": "True",
        "REMOTETOOL": "True",
        "SECURITYTOOL": "True",
        "SYSTEMTOOL": "True",
        "TUNNEL_IDENTITY_FILE": "~/.ssh/id_ed25519",
        "TUNNEL_INVENTORY_GROUP": "all",
        "TUNNEL_KG_INGEST": "true",
        "TUNNEL_KNOWN_HOSTS": "~/.ssh/known_hosts",
        "TUNNEL_MANAGER_HEALTH_AGGREGATE_S": "3600",
        "TUNNEL_MANAGER_HEALTH_INGEST": "true",
        "TUNNEL_MANAGER_HEALTH_NOTIFY_URL": "",
        "TUNNEL_MANAGER_HOSTS": "r510,r710,r820,rw710",
        "TUNNEL_MAX_THREADS": "6",
        "TUNNEL_PARALLEL": "False",
        "TUNNEL_REMOTE_PORT": "22"
      }
    }
  }
}
```

Runtime references require an alias-aware launcher such as GraphOS. Other
launchers must omit those entries and inject the resolved values through their
own runtime secret boundary.

#### Streamable-HTTP Transport (networked / production)

```json
{
  "mcpServers": {
    "tunnel-manager-mcp": {
      "command": "uvx",
      "args": [
        "--from",
        "tunnel-manager[mcp]",
        "tunnel-manager-mcp",
        "--transport",
        "streamable-http",
        "--port",
        "8000"
      ],
      "env": {
        "TRANSPORT": "streamable-http",
        "HOST": "127.0.0.1",
        "PORT": "8000",
        "MCP_TOOL_MODE": "intent",
        "FILETOOL": "True",
        "HOSTTOOL": "True",
        "INGESTTOOL": "True",
        "INVENTORYTOOL": "True",
        "OPERATIONSTOOL": "True",
        "REMOTETOOL": "True",
        "SECURITYTOOL": "True",
        "SYSTEMTOOL": "True",
        "TUNNEL_IDENTITY_FILE": "~/.ssh/id_ed25519",
        "TUNNEL_INVENTORY_GROUP": "all",
        "TUNNEL_KG_INGEST": "true",
        "TUNNEL_KNOWN_HOSTS": "~/.ssh/known_hosts",
        "TUNNEL_MANAGER_HEALTH_AGGREGATE_S": "3600",
        "TUNNEL_MANAGER_HEALTH_INGEST": "true",
        "TUNNEL_MANAGER_HEALTH_NOTIFY_URL": "",
        "TUNNEL_MANAGER_HOSTS": "r510,r710,r820,rw710",
        "TUNNEL_MAX_THREADS": "6",
        "TUNNEL_PARALLEL": "False",
        "TUNNEL_REMOTE_PORT": "22"
      }
    }
  }
}
```

Alternatively, connect to a pre-deployed Streamable-HTTP instance by `url`:

```json
{
  "mcpServers": {
    "tunnel-manager-mcp": {
      "url": "http://localhost:8000/tunnel-manager-mcp/mcp"
    }
  }
}
```

Run a reviewed container image as a least-privilege stdio child (no
listener or published port):

```bash
docker run -i --rm \
  --read-only \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --pids-limit=256 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=64m \
  -e TRANSPORT=stdio \
  -e MCP_TOOL_MODE=intent \
  -e FILETOOL=True \
  -e HOSTTOOL=True \
  -e INGESTTOOL=True \
  -e INVENTORYTOOL=True \
  -e OPERATIONSTOOL=True \
  -e REMOTETOOL=True \
  -e SECURITYTOOL=True \
  -e SYSTEMTOOL=True \
  -e TUNNEL_IDENTITY_FILE=~/.ssh/id_ed25519 \
  -e TUNNEL_INVENTORY_GROUP=all \
  -e TUNNEL_KG_INGEST=true \
  -e TUNNEL_KNOWN_HOSTS=~/.ssh/known_hosts \
  -e TUNNEL_MANAGER_HEALTH_AGGREGATE_S=3600 \
  -e TUNNEL_MANAGER_HEALTH_INGEST=true \
  -e TUNNEL_MANAGER_HEALTH_NOTIFY_URL="" \
  -e TUNNEL_MANAGER_HOSTS=r510,r710,r820,rw710 \
  -e TUNNEL_MAX_THREADS=6 \
  -e TUNNEL_PARALLEL=False \
  -e TUNNEL_REMOTE_PORT=22 \
  registry.example.invalid/tunnel-manager@sha256:<digest> tunnel-manager-mcp
```

For containerized network HTTP, supply an authenticated TLS ingress (or
direct server TLS), exact `MCP_ALLOWED_HOSTS`, and an exact trusted-proxy
CIDR policy through the operator-owned deployment profile. The generator
does not emit an unauthenticated non-loopback listener.

_Auto-generated from the code-read env surface (`MCP_TOOL_MODE` + package vars) — do not edit._
<!-- MCP-CONFIG-EXAMPLES:END -->

<!-- BEGIN GENERATED: additional-deployment-options -->
### Additional Deployment Options

`tunnel-manager` can run as a local stdio process or container, or behind a remote
network boundary. The
[Deployment guide](https://knuckles-team.github.io/tunnel-manager/deployment/) carries
the detailed transport contract.

- **Local container** — launch a reviewed immutable image as a least-privilege
  stdio child with no listener or published port.
- **Remote URL** — connect through an operator-supplied authenticated HTTPS
  ingress. Keep its URL, outbound identity references, trust profile, and exact
  `MCP_ALLOWED_HOSTS` in `AgentConfig`.
<!-- END GENERATED: additional-deployment-options -->

---

## Inventory

tunnel-manager works from a single shared YAML **inventory** that maps short host
aliases (e.g. `edge-node`) to their SSH connection details. Every ecosystem surface reads
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
| `HOST` | `127.0.0.1` | loopback bind by default; use an authenticated gateway for remote access |
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
| `TUNNEL_REMOTE_HOST` | — | default remote host (e.g. 198.51.100.10) |
| `TUNNEL_REMOTE_PORT` | `22` | default SSH port |
| `TUNNEL_USERNAME` | — | default SSH username |
| `TUNNEL_PASSWORD_REF` | — | runtime secret reference for SSH password auth; literal passwords are rejected |
| `TUNNEL_KNOWN_HOSTS` | `~/.ssh/known_hosts` | independently verified SSH server host keys |
| `TUNNEL_CERTIFICATE` | — | path to an SSH certificate file |
| `TUNNEL_PROXY_COMMAND` | — | SSH ProxyCommand for jump-host/bastion connections |
| `TUNNEL_INVENTORY` | — | path to the inventory file (defaults to XDG config path) |
| `TUNNEL_INVENTORY_GROUP` | `all` | inventory host group to target |
| `TUNNEL_PARALLEL` | `False` | run host operations in parallel |
| `TUNNEL_MAX_THREADS` | `6` | max worker threads when TUNNEL_PARALLEL=True |
| `TUNNEL_MAX_COMMAND_CHARS` | `65536` | maximum managed command size |
| `TUNNEL_MAX_OUTPUT_BYTES` | `1048576` | combined command-output cap |
| `TUNNEL_MAX_TRANSFER_BYTES` | `268435456` | file-transfer size cap |
| `TUNNEL_MAX_FLEET_HOSTS` | `1000` | inventory host cap |
| `TUNNEL_MAX_CONCURRENCY` | `64` | concurrent SSH operation cap |
| `XDG_CONFIG_HOME` | — | base config dir (defaults to ~/.config) for inventory resolution |
| `HOSTTOOL` | `True` | Grouped condensed-surface toggles, one per register_<tag>_tools registrar. |
| `REMOTETOOL` | `True` |  |
| `INVENTORYTOOL` | `True` |  |
| `OPERATIONSTOOL` | `True` |  |
| `SYSTEMTOOL` | `True` |  |
| `FILETOOL` | `True` |  |
| `SECURITYTOOL` | `True` |  |
| `INGESTTOOL` | `True` | KG-ingest tools (list the SSH inventory into epistemic-graph) |
| `TUNNEL_KG_INGEST` | `true` | default-on best-effort inventory ingest on `list` |
| `TUNNEL_MANAGER_HEALTH_INGEST` | `true` | default-on best-effort network-signal trend ingestion |
| `TUNNEL_MANAGER_HEALTH_AGGREGATE_S` | `3600` | window (s) over which samples distill to ONE :HealthTrend node/host/signal |
| `TUNNEL_MANAGER_HOSTS` | `r510,r710,r820,rw710` | comma-separated inventory aliases to probe/derive over (default: full inventory) |
| `TUNNEL_MANAGER_HEALTH_NOTIFY_URL` | — | best-effort webhook for network-anomaly notifications |

#### Inherited agent-utilities variables (apply to every connector)

| Variable | Example | Description |
|----------|---------|-------------|
| `MCP_TOOL_MODE` | `condensed` | Tool surface: `condensed` | `verbose` | `both` |
| `MCP_ENABLED_TOOLS` | — | Comma-separated tool allow-list |
| `MCP_DISABLED_TOOLS` | — | Comma-separated tool deny-list |
| `MCP_ENABLED_TAGS` | — | Comma-separated tag allow-list |
| `MCP_DISABLED_TAGS` | — | Comma-separated tag deny-list |
| `MCP_CLIENT_AUTH` | — | Outbound MCP child auth: `oidc-client-credentials` | `basic` | `none` |
| `OIDC_CLIENT_ID` | — | OIDC client id (service-account auth) |
| `OIDC_CLIENT_SECRET` | — | OIDC client secret (service-account auth) |
| `MCP_BASIC_AUTH_USERNAME` | — | HTTP Basic username (`MCP_CLIENT_AUTH=basic`) |
| `MCP_BASIC_AUTH_PASSWORD` | — | HTTP Basic password (`MCP_CLIENT_AUTH=basic`) |
| `MCP_URL` | `http://localhost:8000/mcp` | URL of the MCP server the agent connects to |
| `PROVIDER` | `openai` | LLM provider for the agent |
| `MODEL_ID` | `gpt-4o` | Model id for the agent |
| `ENABLE_WEB_UI` | `True` | Serve the AG-UI web interface |

_44 package + 14 inherited variable(s). Auto-generated from `.env.example` + the shared agent-utilities set — do not edit._
<!-- ENV-VARS-TABLE:END -->


Every variable the server reads, grouped by purpose. See [`.env.example`](.env.example)
for a copy-paste starting point.

### SSH connection & credentials
| Variable | Description | Default |
|----------|-------------|---------|
| `TUNNEL_IDENTITY_FILE` | Path to the SSH private key | `~/.ssh/id_ed25519` |
| `TUNNEL_USERNAME` | SSH username | — |
| `TUNNEL_PASSWORD_REF` | `env://`, `vault://`, `secret://`, or `sqlite://` SSH password reference | — |
| `TUNNEL_KNOWN_HOSTS` | Independently verified SSH server-key trust store | `~/.ssh/known_hosts` |
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
| `HOST` | Bind host (HTTP transports) | `127.0.0.1` |
| `PORT` | Bind port (HTTP transports) | `8000` |
| `MCP_TOOL_MODE` | Tool surface: `condensed`, `verbose`, or `both` | `condensed` |
| `MCP_ENABLED_TOOLS` / `MCP_DISABLED_TOOLS` | Comma-separated tool allow/deny list | — |
| `MCP_ENABLED_TAGS` / `MCP_DISABLED_TAGS` | Comma-separated tag allow/deny list | — |
| `DEBUG` | Verbose logging | `False` |
| `PYTHONUNBUFFERED` | Unbuffered stdout (recommended in containers) | `1` |

### Tool toggles
Each action-routed tool can be disabled individually via its toggle env var (set to `false`).
The full list is in the [Available MCP Tools](#available-mcp-tools) table above
(`HOSTTOOL`, `REMOTETOOL`, `INVENTORYTOOL`, `OPERATIONSTOOL`,
`SYSTEMTOOL`, `FILETOOL`, `SECURITYTOOL`).

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
    image: example/tunnel-manager:mcp
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
    image: example/tunnel-manager@sha256:<digest>
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

Detailed graph node architecture explanations, custom skill configurations, and agentic trace guides are available in [docs/deployment.md](docs/deployment.md).

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
| `tunnel-manager[mcp]` | Connector-focused MCP server (`agent-utilities[mcp]` — FastMCP/FastAPI + `epistemic-graph[full]`) | You only run the **MCP server** (smallest install / image) |
| `tunnel-manager[agent]` | Agent runtime (`agent-utilities[agent-runtime,logfire]` — model orchestration + `epistemic-graph[full]`) | You run the **integrated agent** |
| `tunnel-manager[all]` | Everything (`mcp` + `agent` + `logfire`) | Development / both surfaces |

```bash
# Connector-focused MCP server (includes the shared graph engine)
uv pip install "tunnel-manager[mcp]"

# Agent runtime (adds model orchestration to the shared graph engine)
uv pip install "tunnel-manager[agent]"

# Everything (development)
uv pip install "tunnel-manager[all]"      # or: python -m pip install "tunnel-manager[all]"
```

### Container images (`:mcp` vs `:agent`)

One multi-stage `docker/Dockerfile` builds two right-sized images, selected by `--target`:

| Image tag | Build target | Contents | Entrypoint |
|-----------|--------------|----------|------------|
| `example/tunnel-manager:mcp` | `--target mcp` | `tunnel-manager[mcp]` — **connector-focused**, includes `epistemic-graph[full]`; no model-orchestration stack | `tunnel-manager-mcp` |
| `example/tunnel-manager@sha256:<digest>` | `--target agent` (default) | `tunnel-manager[agent]` — **agent runtime**, model orchestration + `epistemic-graph[full]` | `tunnel-manager-agent` |

```bash
docker build --target mcp   -t example/tunnel-manager:mcp    docker/   # connector-focused MCP server
docker build --target agent -t example/tunnel-manager:agent-local docker/   # agent runtime
```

`docker/mcp.compose.yml` runs the connector-focused `:mcp` server; `docker/agent.compose.yml` runs the
agent (`immutable agent digest`) with a co-located `:mcp` sidecar.

### Knowledge-graph database (`epistemic-graph`)

Both `[mcp]` and `[agent]` carry the **epistemic-graph** engine through the required
Agent Utilities core dependency (`epistemic-graph[full]`). The `[mcp]` extra keeps
the server connector-focused; `[agent]` additionally enables model orchestration. Local
deployments can use the bundled engine. For production or shared state, run
**epistemic-graph as a dedicated database service** and configure the runtime to use it.
Deployment recipes (single-node + Raft HA), connection configuration, and architecture
diagrams are documented in the
[epistemic-graph deployment guide](https://knuckles-team.github.io/epistemic-graph/deployment/).

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

## Maintainers

Maintained by the project contributor team. Package metadata intentionally uses a
role address rather than personal identity.

---

## Contribute

Contributions are welcome! Please ensure code quality by executing local checks before submitting pull requests:
- Format code using `ruff format .`
- Lint code using `ruff check .`
- Validate type-safety with `mypy .`
- Execute test suites using `pytest`


<!-- BEGIN agent-utilities-deployment (generated; do not edit between markers) -->

## Deploy with `agent-utilities-deployment`

Provision this package with the consolidated **`agent-utilities-deployment`**
workflow. It selects an installed-package, editable-source, or immutable-container
path; records only runtime secret and TLS-profile references in `AgentConfig`; and
runs doctor, registration, policy, observability, and rollback gates. Ask your agent
to **"deploy `tunnel-manager` with agent-utilities-deployment"**.

| Install mode | Command |
|------|---------|
| Installed package | `uv tool install "tunnel-manager[mcp]"`, then run `tunnel-manager-mcp` |
| Editable source | `uv pip install -e ".[agent]"`, then run `tunnel-manager-mcp` |
| Immutable container | deploy `registry.example.invalid/tunnel-manager@sha256:<digest>` through the operator-selected orchestrator |

The repository embeds no deployment profile, credential value, certificate path, or
environment-specific endpoint. Supply those at runtime through `AgentConfig` and the
configured secret provider.

<!-- END agent-utilities-deployment -->

<!-- GOVERNED-CAPABILITY:START -->
## Governed capability contract

This package ships a compact canonical skill surface with specialist procedures
kept as referenced workflows. The current MCP tools, skill metadata,
`connector_manifest.yml`, ontology, mappings, shapes, fixtures, migrations,
tool-schema fingerprints, and certification metadata form one versioned
capability contract. Validate them together; do not rely on stale tool names or
historical per-task skill wrappers.

Runtime endpoints, credentials, certificate trust, tenant identity, retention,
and observability policy are deployment inputs and are never packaged values.
See [Configuration, trust, and privacy](docs/configuration.md) before enabling a
network transport, connector ingestion, GraphOS delegation, or trace export.
<!-- GOVERNED-CAPABILITY:END -->
