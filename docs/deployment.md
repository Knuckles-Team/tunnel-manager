# Deployment

This page covers running `tunnel-manager` as a long-lived server: the transports, a
Docker Compose stack, putting it behind a Caddy reverse proxy, and giving it a DNS
name with Technitium. `tunnel-manager` ships **both** an MCP server (console script
`tunnel-manager-mcp`) and a Pydantic-AI **agent server** (console script
`tunnel-manager-agent`); both are covered below.

## Run the MCP server

The transport is selected with `--transport` (or the `TRANSPORT` env var):

=== "stdio (default)"

    ```bash
    tunnel-manager-mcp
    ```
    For IDE / desktop MCP clients that launch the server as a subprocess.

=== "streamable-http"

    ```bash
    tunnel-manager-mcp --transport streamable-http --host 0.0.0.0 --port 8000
    ```
    A network server with a `/health` endpoint and `/mcp` route.

=== "sse"

    ```bash
    tunnel-manager-mcp --transport sse --host 0.0.0.0 --port 8000
    ```

Health check (HTTP transports):

```bash
curl -s http://localhost:8000/health
```

## Configuration (environment)

`tunnel-manager` is configured from the environment (or a sibling `.env` file). The
**required / commonly set** variables:

| Var | Default | Meaning |
|---|---|---|
| `HOST` | `0.0.0.0` | Bind address for HTTP transports |
| `PORT` | `8000` | Listen port for HTTP transports |
| `TRANSPORT` | `stdio` | `stdio`, `streamable-http`, or `sse` |
| `TUNNEL_IDENTITY_FILE` | `~/.ssh/id_ed25519` | SSH private key used to connect to hosts |
| `ENABLE_OTEL` | `True` | Emit OpenTelemetry traces |
| `EUNOMIA_TYPE` | `none` | Authorization mode — `none`, `embedded`, or `remote` |
| `DEBUG` | `False` | Verbose logging |

Each action-routed tool can be toggled independently:

| Var | Default | Tool |
|---|---|---|
| `TM_HOSTS_TOOL` | `True` | Host inventory management (`tm_hosts`) |
| `TM_REMOTE_TOOL` | `True` | Single-host SSH operations (`tm_remote`) |
| `TM_INVENTORY_TOOL` | `True` | Bulk inventory operations (`tm_inventory`) |
| `TM_OPERATIONS_TOOL` | `True` | Operation lifecycle / sessions (`tm_operations`) |
| `TM_SYSTEM_TOOL` | `True` | Remote system intelligence (`tm_system`) |
| `TM_FILES_TOOL` | `True` | Advanced file operations (`tm_files`) |
| `TM_SECURITY_TOOL` | `True` | Security and compliance auditing (`tm_security`) |

The complete set, including the OTEL and Eunomia connection settings, is documented in
[`.env.example`](https://github.com/Knuckles-Team/tunnel-manager/blob/main/.env.example).
Copy it to `.env` and populate only what you use.

## Docker Compose

The repo ships [`docker/mcp.compose.yml`](https://github.com/Knuckles-Team/tunnel-manager/blob/main/docker/mcp.compose.yml).
It reads a sibling `.env` and publishes the HTTP server on `:8000`:

```yaml
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
```

```bash
cp .env.example .env          # then edit TUNNEL_IDENTITY_FILE and toggles
docker compose -f docker/mcp.compose.yml up -d
docker compose -f docker/mcp.compose.yml logs -f
```

## Agent server

`tunnel-manager` includes a Pydantic-AI **graph agent** (console script
`tunnel-manager-agent`) that connects to the MCP server and exposes the Agent Control
Protocol plus an optional web UI. Run it standalone:

```bash
export MCP_URL=http://tunnel-manager-mcp:8000/mcp
export PROVIDER=openai
export MODEL_ID=gpt-4o
tunnel-manager-agent --host 0.0.0.0 --port 9002
```

The combined [`docker/agent.compose.yml`](https://github.com/Knuckles-Team/tunnel-manager/blob/main/docker/agent.compose.yml)
provisions the MCP server and the agent together; the agent reaches the MCP server by
container name through `MCP_URL` and is published on `:9002`:

```yaml
services:
  tunnel-manager-agent:
    image: knucklessg1/tunnel-manager:latest
    container_name: tunnel-manager-agent
    depends_on:
      - tunnel-manager-mcp
    env_file:
      - ../.env
    command: ["tunnel-manager-agent"]
    environment:
      - PYTHONUNBUFFERED=1
      - HOST=0.0.0.0
      - PORT=9002
      - MCP_URL=http://tunnel-manager-mcp:8000/mcp
      - PROVIDER=${PROVIDER:-openai}
      - MODEL_ID=${MODEL_ID:-gpt-4o}
      - ENABLE_WEB_UI=True
    ports:
      - "9002:9002"
```

```bash
docker compose -f docker/agent.compose.yml up -d
```

## Behind a Caddy reverse proxy

Expose the HTTP server on a hostname with automatic TLS. Add to your `Caddyfile`:

```caddy
# Internal (self-signed) — homelab .arpa zone
tunnel-manager.arpa {
    tls internal
    reverse_proxy tunnel-manager-mcp:8000
}
```

```caddy
# Public — automatic Let's Encrypt
tunnel-manager.example.com {
    reverse_proxy tunnel-manager-mcp:8000
}
```

Reload Caddy:

```bash
docker compose -f services/caddy/compose.yml exec caddy caddy reload --config /etc/caddy/Caddyfile
```

## DNS with Technitium

Point the hostname at the host running Caddy. Via the Technitium API:

```bash
curl -s "http://technitium.arpa:5380/api/zones/records/add" \
  --data-urlencode "token=$TECHNITIUM_DNS_TOKEN" \
  --data-urlencode "domain=tunnel-manager.arpa" \
  --data-urlencode "zone=arpa" \
  --data-urlencode "type=A" \
  --data-urlencode "ipAddress=10.0.0.10" \
  --data-urlencode "ttl=3600"
```

…or add an **A record** `tunnel-manager.arpa → <caddy-host-ip>` in the Technitium web
console (`http://technitium.arpa:5380`). The ecosystem
[`technitium-dns-mcp`](https://knuckles-team.github.io/technitium-dns-mcp/) automates
this as a tool.

## Register with an MCP client

Add to your client's `mcp_config.json` (multiplexer nickname `tun`):

```json
{
  "mcpServers": {
    "tunnel-manager": {
      "command": "uv",
      "args": ["run", "tunnel-manager-mcp"],
      "env": {
        "TUNNEL_IDENTITY_FILE": "~/.ssh/id_ed25519"
      }
    }
  }
}
```

For a remote HTTP server, point the client at `http://tunnel-manager.arpa/mcp` instead.
