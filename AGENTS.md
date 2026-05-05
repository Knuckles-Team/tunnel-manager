# AGENTS.md

## Tech Stack & Architecture
- Language/Version: Python 3.10+
- Core Libraries: `agent-utilities`, `fastmcp`, `paramiko`, `pydantic-ai`
- Key principles: Functional patterns, Pydantic for data validation, asynchronous tool execution.
- Architecture:
    - `mcp_server.py`: Main MCP server entry point and tool registration for SSH tunnel operations.
    - `agent_server.py`: Pydantic AI agent definition and logic for tunnel management.
    - `tunnel_manager.py`: Core SSH tunnel functionality including HostManager and Tunnel classes.
    - `operation_manager.py`: Enhanced operation tracking with streaming progress and cancellation.
    - `system_intelligence.py`: Remote system discovery and intelligence gathering.
    - `advanced_file_manager.py`: Advanced file operations including recursive ops, search, monitoring, and backup.
    - `security_auditor.py`: Security and compliance auditing capabilities.
    - `agent_data/`: Agent configuration, identity, and knowledge graph data.
    - `tests/`: Comprehensive test suite for tunnel management and MCP server functionality.

### Architecture Diagram
```mermaid
graph TD
    User([User/A2A]) --> Server[A2A Server / FastAPI]
    Server --> Agent[Pydantic AI Agent]
    Agent --> MCP[MCP Server / FastMCP]
    MCP --> Tunnel[Tunnel Manager]
    Tunnel --> SSH[SSH Connections]
    SSH --> RemoteHosts[Remote Hosts]
    MCP --> HostManager[Host Manager]
    HostManager --> Inventory[Inventory Files]
    MCP --> OperationManager[Operation Manager]
    MCP --> SystemIntelligence[System Intelligence]
    MCP --> AdvancedFileManager[Advanced File Manager]
    MCP --> SecurityAuditor[Security Auditor]
    OperationManager --> Tunnel
    SystemIntelligence --> Tunnel
    AdvancedFileManager --> Tunnel
    SecurityAuditor --> Tunnel
```

### Workflow Diagram
```mermaid
sequenceDiagram
    participant U as User
    participant S as Server
    participant A as Agent
    participant T as MCP Tool
    participant TM as Tunnel Manager
    participant SSH as SSH Connection
    participant RH as Remote Host

    U->>S: Request
    S->>A: Process Query
    A->>T: Invoke Tool
    T->>TM: Execute Operation
    TM->>SSH: Connect
    SSH->>RH: Execute Command/Transfer
    RH-->>SSH: Result
    SSH-->>TM: Output
    TM-->>T: Result
    T-->>A: Tool Result
    A-->>S: Final Response
    S-->>U: Output
```

## Commands (run these exactly)
# Installation
pip install .[all]

# Quality & Linting (run from project root)
pre-commit run --all-files

# Testing (run from project root)
pytest --cov=tunnel_manager --cov-report=term-missing

# Execution Commands
# tunnel-manager
tunnel_manager.tunnel_manager:tunnel_manager
# tunnel-manager-mcp
tunnel_manager.mcp:mcp_server
# tunnel-manager-agent
tunnel_manager.agent:agent_server

## Project Structure Quick Reference
- MCP Entry Point → `mcp_server.py`
- Agent Entry Point → `agent_server.py`
- Core Library → `tunnel_manager/tunnel_manager.py`
- Agent Data → `tunnel_manager/agent_data/`
- Tests → `tests/`

## Enhanced Capabilities

### Operation Manager (`operation_manager.py`)
Provides enhanced operation tracking and management for long-running operations:
- **Streaming Progress**: Real-time progress updates with cancellation support
- **Resource Monitoring**: Track CPU, memory, and disk usage during operations
- **Session Management**: Persistent SSH connection pooling and reuse
- **Operation Cancellation**: Graceful cancellation of in-progress operations
- **MCP Tools**: start_operation, get_operation_progress, cancel_operation, get_resource_metrics, list_active_sessions

### System Intelligence (`system_intelligence.py`)
Remote system discovery and intelligence gathering:
- **System Info**: OS version, hardware specs, installed packages, uptime
- **Service Discovery**: Running services, processes, and open ports
- **Log Analysis**: Pattern matching and statistics for log files
- **Network Topology**: Interfaces, routes, DNS, and active connections
- **MCP Tools**: get_system_info, discover_services, analyze_logs, network_topology

### Advanced File Manager (`advanced_file_manager.py`)
Advanced file operations for remote hosts:
- **Recursive Operations**: Copy, move, delete, list, chmod, chown on directories
- **Content Search**: Grep-like search across multiple directories
- **File Monitoring**: Real-time file/directory change detection
- **File Comparison**: Compare files across different hosts
- **Smart Backup**: Automated backups with compression and versioning
- **MCP Tools**: recursive_file_operations, file_content_search, file_watch_monitor, file_diff_compare, smart_backup

### Security Auditor (`security_auditor.py`)
Security and compliance auditing capabilities:
- **Security Audit**: Comprehensive security assessment with scoring
- **Compliance Checks**: CIS Benchmark, PCI DSS, HIPAA standard validation
- **Vulnerability Scanning**: Package and configuration vulnerability detection
- **Access Control Audit**: User, permission, sudo, and SSH access auditing
- **MCP Tools**: security_audit, compliance_check, vulnerability_scan, access_control_audit

### File Tree
```text
├── .bumpversion.cfg
├── .codespellignore
├── .dockerignore
├── .env
├── .gitattributes
├── .github
│   └── workflows
│       └── pipeline.yml
├── .gitignore
├── .pre-commit-config.yaml
├── AGENTS.md
├── Dockerfile
├── IMPLEMENTATION_PLAN.md
├── LICENSE
├── MANIFEST.in
├── README.md
├── compose.yml
├── debug.Dockerfile
├── mcp.compose.yml
├── pyproject.toml
├── pytest.ini
├── requirements.txt
├── scripts
│   ├── validate_a2a_agent_server.py
│   └── validate_agent_server.py
├── starship.toml
├── uv.lock
├── tests
│   ├── downloaded_inventory.txt
│   ├── downloaded_test.txt
│   ├── test_agent_server.py
│   ├── test_advanced_file_manager.py
│   ├── test_mcp_server.py
│   ├── test_operation_manager.py
│   ├── test_placeholder.py
│   ├── test_security_auditor.py
│   ├── test_system_intelligence.py
│   ├── test_tunnel.py
│   └── test_tunnel_manager.py
└── tunnel_manager
    ├── __init__.py
    ├── __main__.py
    ├── agent
    │   ├── AGENTS.md
    │   ├── CRON.md
    │   ├── CRON_LOG.md
    │   ├── HEARTBEAT.md
    │   ├── IDENTITY.md
    │   ├── MEMORY.md
    │   ├── USER.md
    │   ├── mcp_config.json
    │   └── templates.py
    ├── agent_data
    │   ├── CRON.md
    │   ├── CRON_LOG.md
    │   ├── HEARTBEAT.md
    │   ├── IDENTITY.md
    │   ├── MEMORY.md
    │   ├── NODE_AGENTS.md
    │   ├── USER.md
    │   ├── mcp_config.json
    │   ├── main_agent.md
    │   ├── icon.png
    │   ├── knowledge_graph.db
    │   └── chats
    ├── agent_server.py
    ├── advanced_file_manager.py
    ├── mcp_server.py
    ├── operation_manager.py
    ├── security_auditor.py
    ├── system_intelligence.py
    └── tunnel_manager.py
```

## Code Style & Conventions
**Always:**
- Use `agent-utilities` for common patterns (e.g., `create_mcp_server`, `create_agent`).
- Use `paramiko` for SSH operations with proper error handling.
- Define input/output models using Pydantic.
- Include descriptive docstrings for all tools (they are used as tool descriptions for LLMs).
- Check for optional dependencies using `try/except ImportError`.
- Use `ResponseBuilder` for consistent error responses in MCP tools.

**Good example:**
```python
from agent_utilities import create_mcp_server
from fastmcp import FastMCP
from pydantic import Field

mcp = create_mcp_server("my-agent")

@mcp.tool()
async def my_tool(
    param: str = Field(description="Parameter description"),
    ctx: Context = Field(default="")
) -> dict:
    """Description for LLM."""
    return ResponseBuilder.build(
        status=200,
        message="Success",
        details={"param": param}
    )
```

## Dos and Don'ts
**Do:**
- Run `pre-commit` before pushing changes.
- Use existing patterns from `agent-utilities`.
- Keep tools focused and idempotent where possible.

**Don't:**
- Use `cd` commands in scripts; use absolute paths or relative to project root.
- Add new dependencies to `dependencies` in `pyproject.toml` without checking `optional-dependencies` first.
- Hardcode secrets; use environment variables or `.env` files.

## Safety & Boundaries
**Always do:**
- Run lint/test via `pre-commit`.
- Use `agent-utilities` base classes.

**Ask first:**
- Major refactors of `mcp_server.py` or `agent_server.py`.
- Deleting or renaming public tool functions.

**Never do:**
- Commit `.env` files or secrets.
- Modify `agent-utilities` or `universal-skills` files from within this package.

## When Stuck
- Propose a plan first before making large changes.
- Check `agent-utilities` documentation for existing helpers.


## Testing with Timeout

To run tests with a timeout to prevent hanging, use the `pytest-timeout` plugin. You can combine it with the `-k` flag to run specific tests:

```bash
uv run pytest --timeout=60 -k "test_name_pattern"
```
