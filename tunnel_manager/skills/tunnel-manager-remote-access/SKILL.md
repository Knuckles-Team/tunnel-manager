---
name: tunnel-manager-remote-access
description: Tunnel Manager Remote Access capabilities for A2A Agent.
---
### Overview
This skill provides access to remote_access operations.

### Capabilities
- **run_command_on_remote_host**: Run shell command on remote host. Expected return object type: dict
- **send_file_to_remote_host**: Upload file to remote host. Expected return object type: dict
- **receive_file_from_remote_host**: Download file from remote host. Expected return object type: dict
- **check_ssh_server**: Check SSH server status. Expected return object type: dict
- **test_key_auth**: Test key-based auth. Expected return object type: dict
- **setup_passwordless_ssh**: Setup passwordless SSH. Expected return object type: dict
- **copy_ssh_config**: Copy SSH config to remote host. Expected return object type: dict
- **rotate_ssh_key**: Rotate SSH key on remote host. Expected return object type: dict
- **remove_host_key**: Remove host key from known_hosts. Expected return object type: dict
- **configure_key_auth_on_inventory**: Setup passwordless SSH for all hosts in group. Expected return object type: dict
- **run_command_on_inventory**: Run command on all hosts in group. Expected return object type: dict
- **copy_ssh_config_on_inventory**: Copy SSH config to all hosts in YAML group. Expected return object type: dict
- **rotate_ssh_key_on_inventory**: Rotate SSH keys for all hosts in YAML group. Expected return object type: dict
- **send_file_to_inventory**: Upload a file to all hosts in the specified inventory group. Expected return object type: dict
- **receive_file_from_inventory**: Download a file from all hosts in the specified inventory group. Expected return object type: dict

### Common Tools
- `run_command_on_remote_host`: Run shell command on remote host. Expected return object type: dict
- `send_file_to_remote_host`: Upload file to remote host. Expected return object type: dict
- `receive_file_from_remote_host`: Download file from remote host. Expected return object type: dict
- `check_ssh_server`: Check SSH server status. Expected return object type: dict
- `test_key_auth`: Test key-based auth. Expected return object type: dict
- `setup_passwordless_ssh`: Setup passwordless SSH. Expected return object type: dict
- `copy_ssh_config`: Copy SSH config to remote host. Expected return object type: dict
- `rotate_ssh_key`: Rotate SSH key on remote host. Expected return object type: dict
- `remove_host_key`: Remove host key from known_hosts. Expected return object type: dict
- `configure_key_auth_on_inventory`: Setup passwordless SSH for all hosts in group. Expected return object type: dict
- `run_command_on_inventory`: Run command on all hosts in group. Expected return object type: dict
- `copy_ssh_config_on_inventory`: Copy SSH config to all hosts in YAML group. Expected return object type: dict
- `rotate_ssh_key_on_inventory`: Rotate SSH keys for all hosts in YAML group. Expected return object type: dict
- `send_file_to_inventory`: Upload a file to all hosts in the specified inventory group. Expected return object type: dict
- `receive_file_from_inventory`: Download a file from all hosts in the specified inventory group. Expected return object type: dict

### Usage Rules
- Use these tools when the user requests actions related to **remote_access**.
- Always interpret the output of these tools to provide a concise summary to the user.

### Example Prompts
- "Please run command on remote host"
- "Please receive file from inventory"
- "Please remove host key"
- "Please copy ssh config"
- "Please run command on inventory"
