# Installation

`tunnel-manager` is a standard Python package and a prebuilt container image. Pick the
path that matches how you want to run it.

## Requirements

- **Python 3.11 – 3.14**.
- SSH access to the hosts you intend to manage, and an SSH identity (key or password)
  available to the process — see [Deployment](deployment.md#configuration-environment)
  for the environment configuration.

## From PyPI (recommended)

```bash
pip install tunnel-manager
```

### Optional extras

The base install ships the SSH client layer and CLI. Install the extra for the
interface you need:

| Extra | Install | Pulls in |
|---|---|---|
| `mcp` | `pip install "tunnel-manager[mcp]"` | FastMCP MCP-server runtime (`agent-utilities[mcp]`) |
| `agent` | `pip install "tunnel-manager[agent]"` | Pydantic-AI agent + Logfire tracing (`agent-utilities[agent,logfire]`) |
| `all` | `pip install "tunnel-manager[all]"` | The MCP server, the agent, and tracing |
| `test` | `pip install "tunnel-manager[test]"` | `pytest`, `pytest-asyncio`, `pytest-cov`, `pytest-xdist` |

```bash
# Typical: run the MCP server and the agent together
pip install "tunnel-manager[all]"
```

## From source

```bash
git clone https://github.com/Knuckles-Team/tunnel-manager.git
cd tunnel-manager
pip install -e ".[all]"          # editable install with every interface
```

With [`uv`](https://docs.astral.sh/uv/):

```bash
uv pip install -e ".[all]"
uv run tunnel-manager-mcp
```

## Prebuilt Docker image

A multi-stage, slim image is published on every release (entrypoint
`tunnel-manager-mcp`):

```bash
docker pull knucklessg1/tunnel-manager:latest

docker run --rm -i \
  -e TUNNEL_IDENTITY_FILE=/root/.ssh/id_ed25519 \
  -v "$HOME/.ssh:/root/.ssh:ro" \
  knucklessg1/tunnel-manager:latest        # stdio transport (default)
```

For an HTTP server with a published port, and to run the agent alongside it, see
[Deployment](deployment.md).

## Verify the install

```bash
tunnel-manager-mcp --help
tunnel-manager --help
python -c "import tunnel_manager; print(tunnel_manager.__version__)"
```

## Next steps

- **[Deployment](deployment.md)** — run it as a long-lived MCP and agent server behind Caddy + DNS.
- **[Usage](usage.md)** — call the tools, the `HostManager` / `Tunnel` API, and the CLI.
- **[Configuration](deployment.md#configuration-environment)** — every environment variable.
