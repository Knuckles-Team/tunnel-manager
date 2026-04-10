# MCP_AGENTS.md - Dynamic Agent Registry

This file tracks the generated agents from MCP servers. You can manually modify the 'Tools' list to customize agent expertise.

## Agent Mapping Table

| Name | Description | System Prompt | Tools | Tag | Source MCP |
|------|-------------|---------------|-------|-----|------------|
| Tunnel-Manager Host Management Specialist | Expert specialist for host_management domain tasks. | You are a Tunnel-Manager Host Management specialist. Help users manage and interact with Host Management functionality using the available tools. | tunnel-manager-mcp_host_management_toolset | host_management | tunnel-manager-mcp |
| Tunnel-Manager Misc Specialist | Expert specialist for misc domain tasks. | You are a Tunnel-Manager Misc specialist. Help users manage and interact with Misc functionality using the available tools. | tunnel-manager-mcp_misc_toolset | misc | tunnel-manager-mcp |
| Tunnel-Manager Remote Access Specialist | Expert specialist for remote_access domain tasks. | You are a Tunnel-Manager Remote Access specialist. Help users manage and interact with Remote Access functionality using the available tools. | tunnel-manager-mcp_remote_access_toolset | remote_access | tunnel-manager-mcp |

## Tool Inventory Table

| Tool Name | Description | Tag | Source |
|-----------|-------------|-----|--------|
| tunnel-manager-mcp_host_management_toolset | Static hint toolset for host_management based on config env. | host_management | tunnel-manager-mcp |
| tunnel-manager-mcp_misc_toolset | Static hint toolset for misc based on config env. | misc | tunnel-manager-mcp |
| tunnel-manager-mcp_remote_access_toolset | Static hint toolset for remote_access based on config env. | remote_access | tunnel-manager-mcp |
