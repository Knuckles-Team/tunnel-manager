# Tunnel Manager

![PyPI - Version](https://img.shields.io/pypi/v/tunnel-manager)
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

*Version: 0.0.2*

This project provides a Python-based `Tunnel` class for secure SSH connections and file transfers, 
integrated with a FastMCP server (`tunnel_mcp.py`) to expose these capabilities as tools for AI-driven workflows. 
The implementation supports both standard SSH (e.g., for local networks) and 
Teleport's secure access platform, leveraging the `paramiko` library for SSH operations.

## Features

### Tunnel Class
- **Purpose**: Facilitates secure SSH connections and file transfers to remote hosts.
- **Key Functionality**:
    - **Run Remote Commands**: Execute shell commands on a remote host and retrieve output.
    - **File Upload/Download**: Transfer files to/from a remote host using SFTP.
    - **Teleport Support**: Seamlessly integrates with Teleport's certificate-based authentication and proxying.
    - **Configuration Flexibility**: Loads SSH settings from `~/.ssh/config` by default, with optional overrides for identity files, certificates, and proxy commands.
    - **Logging**: Optional file-based logging for debugging and auditing.

### FastMCP Server
- **Purpose**: Exposes `Tunnel` class functionality as a FastMCP server, enabling AI tools to perform remote operations programmatically.
- **Tools Provided**:
    - `run_remote_command`: Runs a shell command on a remote host and returns output.
    - `upload_file`: Uploads a file to a remote host via SFTP.
    - `download_file`: Downloads a file from a remote host via SFTP.
- **Transport Options**: Supports `stdio` (for local scripting) and `http` (for networked access) transport modes.
- **Progress Reporting**: Integrates with FastMCP's `Context` for progress updates during operations.
- **Logging**: Comprehensive logging to a file (`tunnel_mcp.log` by default).


<details>
  <summary><b>Usage:</b></summary>

## Tunnel Class
The `Tunnel` class can be used standalone for SSH operations. Example:

```python
from tunnel_manager import Tunnel

# Initialize with a remote host (assumes ~/.ssh/config or explicit params)
tunnel = Tunnel(
    remote_host="example.com",
    identity_file="/path/to/id_rsa",
    certificate_file="/path/to/cert",  # Optional for Teleport
    proxy_command="tsh proxy ssh %h",  # Optional for Teleport
    log_file="tunnel.log"
)

# Connect and run a command
tunnel.connect()
out, err = tunnel.run_command("ls -la /tmp")
print(f"Output: {out}\nError: {err}")

# Upload a file
tunnel.send_file("/local/file.txt", "/remote/file.txt")

# Download a file
tunnel.receive_file("/remote/file.txt", "/local/downloaded.txt")

# Close the connection
tunnel.close()
```


## FastMCP Server
The FastMCP server exposes the `Tunnel` functionality as AI-accessible tools. Start the server with:

```bash
python tunnel_mcp.py --transport stdio
```

Or for HTTP transport:
```bash
python tunnel_mcp.py --transport http --host 127.0.0.1 --port 8080
```

</details>

<details>
  <summary><b>Installation Instructions:</b></summary>

## Use with AI

Configure `mcp.json`
```json
{
  "mcpServers": {
    "tunnel_manager": {
      "command": "uv",
      "args": [
        "run",
        "--with",
        "tunnel-manager",
        "tunnel-manager-mcp"
      ],
      "env": {
        "TUNNEL_REMOTE_HOST": "user@192.168.1.12", // Optional
        "TUNNEL_REMOTE_PORT": "22",                // Optional
        "TUNNEL_IDENTITY_FILE": "",                // Optional
        "TUNNEL_CERTIFICATE": "",                  // Optional
        "TUNNEL_PROXY_COMMAND": "",                // Optional
        "TUNNEL_LOG_FILE": "~./tunnel_log.txt"     // Optional
      },
      "timeout": 200000
    }
  }
}
```

### Deploy MCP Server as a container
```bash
docker pull knucklessg1/tunnel-manager:latest
```

Modify the `compose.yml`

```compose
services:
  tunnel-manager:
    image: knucklessg1/tunnel-manager:latest
    environment:
      - HOST=0.0.0.0
      - PORT=8021
    ports:
      - 8021:8021
```

### Install Python Package

```bash
python -m pip install tunnel-manager
```

or

```bash
uv pip install --upgrade tunnel-manager
```


</details>

<details>
  <summary><b>Repository Owners:</b></summary>


<img width="100%" height="180em" src="https://github-readme-stats.vercel.app/api?username=Knucklessg1&show_icons=true&hide_border=true&&count_private=true&include_all_commits=true" />

![GitHub followers](https://img.shields.io/github/followers/Knucklessg1)
![GitHub User's stars](https://img.shields.io/github/stars/Knucklessg1)
</details>
