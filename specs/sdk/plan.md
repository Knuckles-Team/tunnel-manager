# CONN-TUNNEL-MANAGER-SDK design and implementation plan

## Existing system and reuse

The SDK owns every capability named in the rows. tunnel-manager adds no module that repeats one. Each row deletes connector code and calls the SDK module.

## Live call path

`resolve_secret_ref` in `tunnel_manager/connection_security.py` calls `resolve_secret_reference`. The MCP tools in `tunnel_manager/mcp_server.py` call it for every `password_ref`

## Compatibility

Tool names, arguments, and results stay identical. The SDK floor is `agent-connector-sdk>=0.3.11`.
