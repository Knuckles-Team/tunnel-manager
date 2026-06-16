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

*Version: 1.32.0*

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
| Tool Module | Toggle Env Var | Enabled by Default | Description & Nested Methods |
|-------------|----------------|--------------------|------------------------------|
| **Host** | `HOST_TOOL` | `True` | Register host inventory management tool. Action-routed methods: `add`, `list`, `remove`. |
| **Remote** | `REMOTE_TOOL` | `True` | Register single-host SSH operations tool. Action-routed methods: `check_ssh`, `copy_ssh_config`, `receive_file`, `remove_host_key`, `rotate_key`, `run_command`, `send_file`, `setup_passwordless`, `test_key_auth`. |
| **Inventory** | `INVENTORY_TOOL` | `True` | Register bulk inventory operations tool. Action-routed methods: `configure_key_auth`, `copy_ssh_config`, `mesh_bootstrap`, `receive_file`, `rotate_key`, `run_command`, `send_file`. |
| **Operations** | `OPERATIONS_TOOL` | `True` | Register operation lifecycle and session management tool. Action-routed methods: `cancel`, `get_metrics`, `get_progress`, `list_sessions`, `start`. |
| **System** | `SYSTEM_TOOL` | `True` | Register remote system intelligence tool. Action-routed methods: `analyze_logs`, `discover_services`, `get_info`, `network_topology`. |
| **File** | `FILE_TOOL` | `True` | Register advanced file operations tool. Action-routed methods: `backup`, `content_search`, `diff_compare`, `recursive_ops`, `watch`. |
| **Security** | `SECURITY_TOOL` | `True` | Register security scanning and compliance tool. Action-routed methods: `access_control_audit`, `compliance_check`, `security_audit`, `vulnerability_scan`. |

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

#### stdio Transport (Recommended for local IDEs e.g., Cursor, Claude Desktop)
Configure your IDE's `mcp.json` to launch the MCP server via `uvx`:

```json
{
  "mcpServers": {
    "tunnel-manager": {
      "command": "uvx",
      "args": [
        "--from",
        "tunnel-manager",
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
        "tunnel-manager",
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
  knucklessg1/tunnel-manager:latest
```

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
    image: knucklessg1/tunnel-manager:latest
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

Install the Python package locally:

```bash
# Using uv (highly recommended)
uv pip install tunnel-manager[all]

# Using standard pip
python -m pip install tunnel-manager[all]
```

---

## Documentation

The complete documentation is published as the
[official documentation site](https://knuckles-team.github.io/tunnel-manager/) and is
the recommended reference for installation, deployment, and day-to-day operation.

| Page | Contents |
|---|---|
| [Installation](https://knuckles-team.github.io/tunnel-manager/installation/) | pip, source, extras, prebuilt Docker image |
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
