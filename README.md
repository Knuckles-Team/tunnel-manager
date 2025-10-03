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

*Version: 1.0.1*

This project provides a Python-based `Tunnel` class for secure SSH connections and file transfers, integrated with a FastMCP server (`tunnel_manager_mcp.py`) to expose these capabilities as tools for AI-driven workflows. The implementation supports both standard SSH (e.g., for local networks) and Teleport's secure access platform, leveraging the `paramiko` library for SSH operations.

## Features

### Tunnel Class
- **Purpose**: Facilitates secure SSH connections, file transfers, and key management for single or multiple hosts.
- **Key Functionality**:
    - **Run Remote Commands**: Execute shell commands on a remote host and retrieve output.
    - **File Upload/Download**: Transfer files to/from a single host or all hosts in an inventory group using SFTP.
    - **Passwordless SSH Setup**: Configure key-based authentication for secure, passwordless access.
    - **SSH Config Management**: Copy local SSH config files to remote hosts.
    - **Key Rotation**: Generate and deploy new SSH key pairs, updating `authorized_keys`.
    - **Inventory Support**: Operate on multiple hosts defined in an Ansible-style YAML inventory, with group targeting (e.g., `all`, `homelab`, `poweredge`).
    - **Teleport Support**: Seamlessly integrates with Teleport's certificate-based authentication and proxying.
    - **Configuration Flexibility**: Loads SSH settings from `~/.ssh/config` by default, with optional overrides for username, password, identity files, certificates, and proxy commands.
    - **Logging**: Optional file-based logging for debugging and auditing.
    - **Parallel Execution**: Support for parallel operations across multiple hosts with configurable thread limits.

### FastMCP Server
- **Purpose**: Exposes `Tunnel` class functionality as a FastMCP server, enabling AI tools to perform remote operations programmatically.
- **Tools Provided**:
    - `run_remote_command`: Runs a shell command on a single remote host.
    - `upload_file`: Uploads a file to a single remote host via SFTP.
    - `download_file`: Downloads a file from a single remote host via SFTP.
    - `check_ssh_server`: Checks if the SSH server is running and configured for key-based authentication.
    - `test_key_auth`: Tests key-based authentication for a host.
    - `setup_passwordless_ssh`: Sets up passwordless SSH for a single host.
    - `copy_ssh_config`: Copies an SSH config file to a single remote host.
    - `rotate_ssh_key`: Rotates SSH keys for a single host.
    - `remove_host_key`: Removes a host’s key from the local `known_hosts` file.
    - `setup_all_passwordless_ssh`: Sets up passwordless SSH for all hosts in an inventory group.
    - `run_command_on_all`: Runs a command on all hosts in an inventory group.
    - `copy_ssh_config_on_all`: Copies an SSH config file to all hosts in an inventory group.
    - `rotate_ssh_key_on_all`: Rotates SSH keys for all hosts in an inventory group.
- **Transport Options**: Supports `stdio` (for local scripting) and `http` (for networked access) transport modes.
- **Progress Reporting**: Integrates with FastMCP's `Context` for progress updates during operations.
- **Logging**: Comprehensive logging to a file (`tunnel_mcp.log` by default) or a user-specified file.

<details>
  <summary><b>Usage:</b></summary>

## Tunnel Class
The `Tunnel` class can be used standalone for SSH operations. Example:

```python
from tunnel_manager.tunnel_manager import Tunnel

# Initialize with a remote host (assumes ~/.ssh/config or explicit params)
tunnel = Tunnel(
    remote_host="192.168.1.10",
    username="admin",
    password="mypassword",
    identity_file="/path/to/id_rsa",
    certificate_file="/path/to/cert",  # Optional for Teleport
    proxy_command="tsh proxy ssh %h",  # Optional for Teleport
    ssh_config_file="~/.ssh/config",
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

# Setup passwordless SSH
tunnel.setup_passwordless_ssh(local_key_path="~/.ssh/id_rsa")

# Copy SSH config
tunnel.copy_ssh_config("/local/ssh_config", "~/.ssh/config")

# Rotate SSH key
tunnel.rotate_ssh_key("/path/to/new_key")

# Close the connection
tunnel.close()
```

## Tunnel Manager CLI Usage
The `tunnel_manager.py` script provides a CLI for managing SSH operations across hosts defined in an Ansible-style YAML inventory file. Below are examples for each command, targeting different inventory groups (`all`, `homelab`, `poweredge`).

**Inventory File Example (`inventory.yml`)**:
```yaml
all:
  hosts:
    r510:
      ansible_host: 192.168.1.10
      ansible_user: admin
      ansible_ssh_private_key_file: "~/.ssh/id_ed25519"
    r710:
      ansible_host: 192.168.1.11
      ansible_user: admin
      ansible_ssh_pass: mypassword
    gr1080:
      ansible_host: 192.168.1.14
      ansible_user: admin
      ansible_ssh_private_key_file: "~/.ssh/id_rsa"
homelab:
  hosts:
    r510:
      ansible_host: 192.168.1.10
      ansible_user: admin
      ansible_ssh_private_key_file: "~/.ssh/id_ed25519"
    r710:
      ansible_host: 192.168.1.11
      ansible_user: admin
      ansible_ssh_pass: mypassword
    gr1080:
      ansible_host: 192.168.1.14
      ansible_user: admin
      ansible_ssh_private_key_file: "~/.ssh/id_rsa"
poweredge:
  hosts:
    r510:
      ansible_host: 192.168.1.10
      ansible_user: admin
      ansible_ssh_private_key_file: "~/.ssh/id_ed25519"
    r710:
      ansible_host: 192.168.1.11
      ansible_user: admin
      ansible_ssh_pass: mypassword
```

Replace IPs, usernames, and passwords with your actual values.

### CLI Commands

#### 1. Setup Passwordless SSH
Set up passwordless SSH for hosts in the inventory, distributing a shared key.
- **Target `all` group (sequential)**:
  ```bash
  tunnel-manager setup-all --inventory inventory.yml --shared-key-path ~/.ssh/id_shared --log-file setup.log
  ```
- **Target `homelab` group (parallel, 3 threads)**:
  ```bash
  tunnel-manager setup-all --inventory inventory.yml --shared-key-path ~/.ssh/id_shared --group homelab --parallel --max-threads 3 --log-file setup_homelab.log
  ```
- **Target `poweredge` group (sequential)**:
  ```bash
  tunnel-manager setup-all --inventory inventory.yml --shared-key-path ~/.ssh/id_shared --group poweredge --log-file setup_poweredge.log
  ```

#### 2. Run a Command
Execute a shell command on all hosts in the specified group.
- **Run `uptime` on `all` group (sequential)**:
  ```bash
  tunnel-manager run-command --inventory inventory.yml --remote-command "uptime" --log-file uptime.log
  ```
- **Run `df -h` on `homelab` group (parallel, 5 threads)**:
  ```bash
  tunnel-manager run-command --inventory inventory.yml --remote-command "df -h" --group homelab --parallel --max-threads 5 --log-file df_homelab.log
  ```
- **Run `whoami` on `poweredge` group (sequential)**:
  ```bash
  tunnel-manager run-command --inventory inventory.yml --remote-command "whoami" --group poweredge --log-file whoami_poweredge.log
  ```

#### 3. Copy SSH Config
Copy a local SSH config file to the remote hosts’ `~/.ssh/config`.
- **Copy to `all` group (sequential)**:
  ```bash
  tunnel-manager copy-config --inventory inventory.yml --local-config-path ~/.ssh/config --log-file copy_config.log
  ```
- **Copy to `homelab` group (parallel, 4 threads)**:
  ```bash
  tunnel-manager copy-config --inventory inventory.yml --local-config-path ~/.ssh/config --group homelab --parallel --max-threads 4 --log-file copy_homelab.log
  ```
- **Copy to `poweredge` group with custom remote path**:
  ```bash
  tunnel-manager copy-config --inventory inventory.yml --local-config-path ~/.ssh/config --remote-config-path ~/.ssh/custom_config --group poweredge --log-file copy_poweredge.log
  ```

#### 4. Rotate SSH Keys
Rotate SSH keys for hosts, generating new keys with a prefix.
- **Rotate keys for `all` group (sequential)**:
  ```bash
  tunnel-manager rotate-key --inventory inventory.yml --key-prefix ~/.ssh/id_ --log-file rotate.log
  ```
- **Rotate keys for `homelab` group (parallel, 3 threads)**:
  ```bash
  tunnel-manager rotate-key --inventory inventory.yml --key-prefix ~/.ssh/id_ --group homelab --parallel --max-threads 3 --log-file rotate_homelab.log
  ```
- **Rotate keys for `poweredge` group (sequential)**:
  ```bash
  tunnel-manager rotate-key --inventory inventory.yml --key-prefix ~/.ssh/id_ --group poweredge --log-file rotate_poweredge.log
  ```

#### 5. Upload a File
Upload a local file to all hosts in the specified group.
- **Upload to `all` group (sequential)**:
  ```bash
  tunnel-manager send-file --inventory inventory.yml --local-path ./myfile.txt --remote-path /home/user/myfile.txt --log-file upload.log
  ```
- **Upload to `homelab` group (parallel, 3 threads)**:
  ```bash
  tunnel-manager send-file --inventory inventory.yml --local-path ./myfile.txt --remote-path /home/user/myfile.txt --group homelab --parallel --max-threads 3 --log-file upload_homelab.log
  ```
- **Upload to `poweredge` group (sequential)**:
  ```bash
  tunnel-manager send-file --inventory inventory.yml --local-path ./myfile.txt --remote-path /home/user/myfile.txt --group poweredge --log-file upload_poweredge.log
  ```

#### 6. Download a File
Download a file from all hosts in the specified group, saving to host-specific subdirectories (e.g., `downloads/R510/myfile.txt`).
- **Download from `all` group (sequential)**:
  ```bash
  tunnel-manager receive-file --inventory inventory.yml --remote-path /home/user/myfile.txt --local-path-prefix ./downloads --log-file download.log
  ```
- **Download from `homelab` group (parallel, 3 threads)**:
  ```bash
  tunnel-manager receive-file --inventory inventory.yml --remote-path /home/user/myfile.txt --local-path-prefix ./downloads --group homelab --parallel --max-threads 3 --log-file download_homelab.log
  ```
- **Download from `poweredge` group (sequential)**:
  ```bash
  tunnel-manager receive-file --inventory inventory.yml --remote-path /home/user/myfile.txt --local-path-prefix ./downloads --group poweredge --log-file download_poweredge.log
  ```

### CLI Command Table
| Short Flag | Long Flag            | Description                                              | Required | Default Value |
|------------|----------------------|----------------------------------------------------------|----------|---------------|
| -h         | --help               | Show usage for the script                                | No       | None          |
|            | --log-file           | Log to specified file (default: console output)           | No       | Console       |
|            | setup-all            | Setup passwordless SSH for all hosts in inventory         | Yes*     | None          |
|            | --inventory          | YAML inventory path                                      | Yes      | None          |
|            | --shared-key-path    | Path to shared private key                               | No       | ~/.ssh/id_shared |
|            | --group              | Inventory group to target                                 | No       | all           |
|            | --parallel           | Run operation in parallel                                | No       | False         |
|            | --max-threads        | Max threads for parallel execution                       | No       | 5             |
|            | run-command          | Run a shell command on all hosts in inventory            | Yes*     | None          |
|            | --remote-command     | Shell command to run                                     | Yes      | None          |
|            | copy-config          | Copy SSH config to all hosts in inventory                | Yes*     | None          |
|            | --local-config-path  | Local SSH config path                                    | Yes      | None          |
|            | --remote-config-path | Remote path for SSH config                               | No       | ~/.ssh/config |
|            | rotate-key           | Rotate SSH keys for all hosts in inventory               | Yes*     | None          |
|            | --key-prefix         | Prefix for new key paths (appends hostname)              | No       | ~/.ssh/id_    |
|            | send-file            | Upload a file to all hosts in inventory                  | Yes*     | None          |
|            | --local-path         | Local file path to upload                                | Yes      | None          |
|            | --remote-path        | Remote destination path                                  | Yes      | None          |
|            | receive-file         | Download a file from all hosts in inventory              | Yes*     | None          |
|            | --remote-path        | Remote file path to download                             | Yes      | None          |
|            | --local-path-prefix  | Local directory path prefix to save files                | Yes      | None          |

### Notes
One of the commands (`setup-all`, `run-command`, `copy-config`, `rotate-key`, `send-file`, `receive-file`) must be specified as the first argument to `tunnel_manager.py`. Each command has required arguments that must be specified with flags:
- `setup-all`: Requires `--inventory`.
- `run-command`: Requires `--inventory` and `--remote-command`.
- `copy-config`: Requires `--inventory` and `--local-config-path`.
- `rotate-key`: Requires `--inventory`.
- `send-file`: Requires `--inventory`, `--local-path`, and `--remote-path`.
- `receive-file`: Requires `--inventory`, `--remote-path`, and `--local-path-prefix`.

### Additional Notes
- Ensure `ansible_host` values in `inventory.yml` are resolvable IPs or hostnames.
- Update `ansible_ssh_private_key_file` in the inventory after running `rotate-key`.
- Use `--log-file` for file-based logging or omit for console output.
- The `--parallel` option speeds up operations but may overload resources; adjust `--max-threads` as needed.
- The `receive-file` command saves files to `local_path_prefix/<hostname>/<filename>` to preserve original filenames and avoid conflicts.

## FastMCP Server
The FastMCP server exposes the `Tunnel` functionality as AI-accessible tools. Start the server with:

```bash
python tunnel_manager_mcp.py --transport stdio
```

Or for HTTP transport:
```bash
python tunnel_manager_mcp.py --transport http --host 127.0.0.1 --port 8080
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
        "tunnel_manager_mcp"
      ],
      "env": {
        "TUNNEL_REMOTE_HOST": "user@192.168.1.12", // Optional
        "TUNNEL_USERNAME": "admin",                // Optional
        "TUNNEL_PASSWORD": "",                     // Optional
        "TUNNEL_REMOTE_PORT": "22",                // Optional
        "TUNNEL_IDENTITY_FILE": "",                // Optional
        "TUNNEL_INVENTORY": "~/inventory.yaml",    // Optional
        "TUNNEL_INVENTORY_GROUP": "all",           // Optional
        "TUNNEL_PARALLEL": "true",                 // Optional
        "TUNNEL_CERTIFICATE": "",                  // Optional
        "TUNNEL_PROXY_COMMAND": "",                // Optional
        "TUNNEL_LOG_FILE": "~/tunnel_log.txt",     // Optional
        "TUNNEL_MAX_THREADS": "6"                  // Optional
      },
      "timeout": 200000
    }
  }
}
```

### Deploy MCP Server as a Container
```bash
docker pull knucklessg1/tunnel-manager:latest
```

Modify the `compose.yml`
```yaml
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
