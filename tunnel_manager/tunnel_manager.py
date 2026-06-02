#!/usr/bin/env python


import argparse
import concurrent.futures
import logging
import os
import sys

import paramiko
import yaml

from .models import CommandResult, HostConfig

__version__ = "1.24.0"


class HostManager:
    def __init__(self, config_file: str = None):
        if config_file:
            self.config_file = config_file
        else:
            xdg_config = os.environ.get(
                "XDG_CONFIG_HOME", os.path.expanduser("~/.config")
            )
            self.config_file = os.path.join(
                xdg_config, "agent-utilities", "inventory.yaml"
            )

        self.logger = logging.getLogger(__name__)
        self.hosts = {}
        self.load_inventory()

    def load_inventory(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file) as f:
                    raw = yaml.safe_load(f) or {}

                # Check if it's an Ansible-style inventory
                if "all" in raw and isinstance(raw["all"], dict):
                    flattened = {}
                    all_group = raw["all"]
                    children = all_group.get("children", {})
                    all_hosts = all_group.get("hosts", {}) or {}
                    all_vars = all_group.get("vars", {}) or {}

                    # Parse hosts at 'all' level
                    for alias, hvars in all_hosts.items():
                        if not hvars:
                            hvars = {}
                        entry = {
                            "hostname": hvars.get("ansible_host", alias),
                            "user": hvars.get("ansible_user")
                            or all_vars.get("ansible_user", ""),
                            "password": hvars.get("ansible_ssh_pass")
                            or all_vars.get("ansible_ssh_pass"),
                            "port": int(
                                hvars.get("ansible_port")
                                or all_vars.get("ansible_port")
                                or 22
                            ),
                            "identity_file": hvars.get("ansible_ssh_private_key_file")
                            or all_vars.get("ansible_ssh_private_key_file"),
                            "proxy_command": hvars.get("ansible_ssh_common_args")
                            or all_vars.get("ansible_ssh_common_args"),
                            "key_path": hvars.get("key_path")
                            or all_vars.get("key_path")
                            or hvars.get("ansible_ssh_private_key_file")
                            or all_vars.get("ansible_ssh_private_key_file"),
                        }
                        flattened[alias] = entry

                    # Parse children groups
                    for group_data in children.values():
                        if not isinstance(group_data, dict):
                            continue
                        g_hosts = group_data.get("hosts", {}) or {}
                        g_vars = group_data.get("vars", {}) or {}

                        for alias, hvars in g_hosts.items():
                            if not hvars:
                                hvars = {}

                            user = (
                                hvars.get("ansible_user")
                                or g_vars.get("ansible_user")
                                or all_vars.get("ansible_user", "")
                            )
                            password = (
                                hvars.get("ansible_ssh_pass")
                                or g_vars.get("ansible_ssh_pass")
                                or all_vars.get("ansible_ssh_pass")
                            )
                            port = (
                                hvars.get("ansible_port")
                                or g_vars.get("ansible_port")
                                or all_vars.get("ansible_port", 22)
                            )
                            identity_file = (
                                hvars.get("ansible_ssh_private_key_file")
                                or g_vars.get("ansible_ssh_private_key_file")
                                or all_vars.get("ansible_ssh_private_key_file")
                            )
                            proxy_command = (
                                hvars.get("ansible_ssh_common_args")
                                or g_vars.get("ansible_ssh_common_args")
                                or all_vars.get("ansible_ssh_common_args")
                            )
                            key_path = (
                                hvars.get("key_path")
                                or g_vars.get("key_path")
                                or hvars.get("ansible_ssh_private_key_file")
                                or g_vars.get("ansible_ssh_private_key_file")
                            )

                            entry = {
                                "hostname": hvars.get("ansible_host", alias),
                                "user": user,
                                "password": password,
                                "port": int(port) if port else 22,
                                "identity_file": identity_file,
                                "proxy_command": proxy_command,
                                "key_path": key_path,
                            }
                            flattened[alias] = entry
                    self.hosts = flattened
                else:
                    self.hosts = raw
                self.logger.info(f"Loaded inventory from {self.config_file}")
            except Exception as e:
                self.logger.error(f"Failed to load inventory: {e}")
                self.hosts = {}
        else:
            self.logger.info(
                f"No inventory file found at {self.config_file}, starting empty."
            )
            self.hosts = {}

    def save_inventory(self):
        try:
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            if self.config_file.endswith("inventory.yaml") or self.config_file.endswith(
                "inventory.yml"
            ):
                existing_raw = {}
                if os.path.exists(self.config_file):
                    try:
                        with open(self.config_file) as f:
                            existing_raw = yaml.safe_load(f) or {}
                    except Exception:
                        pass

                if "all" not in existing_raw:
                    existing_raw = {
                        "all": {"children": {"homelab": {"hosts": {}, "vars": {}}}}
                    }

                group_name = "homelab"
                children = existing_raw["all"].setdefault("children", {})
                group_data = children.setdefault(group_name, {"hosts": {}, "vars": {}})
                g_hosts = group_data.setdefault("hosts", {})
                g_vars = group_data.setdefault("vars", {})

                for alias, entry in self.hosts.items():
                    if isinstance(entry, dict):
                        hostname = entry.get("hostname", alias)
                        user = entry.get("user")
                        password = entry.get("password")
                        port = entry.get("port", 22)
                        identity_file = entry.get("identity_file") or entry.get(
                            "key_path"
                        )

                        host_vars = g_hosts.setdefault(alias, {})
                        if not isinstance(host_vars, dict):
                            host_vars = {}
                            g_hosts[alias] = host_vars

                        host_vars["ansible_host"] = hostname
                        if user and user != g_vars.get("ansible_user"):
                            host_vars["ansible_user"] = user
                        if password and password != g_vars.get("ansible_ssh_pass"):
                            host_vars["ansible_ssh_pass"] = password
                        if port and port != g_vars.get("ansible_port", 22):
                            host_vars["ansible_port"] = port
                        if identity_file and identity_file != g_vars.get(
                            "ansible_ssh_private_key_file"
                        ):
                            host_vars["ansible_ssh_private_key_file"] = identity_file

                with open(self.config_file, "w") as f:
                    yaml.dump(existing_raw, f, default_flow_style=False)
            else:
                with open(self.config_file, "w") as f:
                    yaml.dump(self.hosts, f)
            self.logger.info(f"Saved inventory to {self.config_file}")
        except Exception as e:
            self.logger.error(f"Failed to save inventory: {e}")

    def add_host(
        self,
        alias: str,
        hostname: str,
        user: str,
        port: int = 22,
        identity_file: str = None,
        password: str = None,
        proxy_command: str = None,
        **kwargs,
    ):
        host_config = HostConfig(
            hostname=hostname,
            user=user,
            port=port,
            identity_file=identity_file,
            password=password,
            proxy_command=proxy_command,
            **kwargs,
        )
        self.hosts[alias] = host_config.model_dump(exclude_unset=True)
        self.save_inventory()
        self.logger.info(f"Added host: {alias}")

    def remove_host(self, alias: str):
        if alias in self.hosts:
            del self.hosts[alias]
            self.save_inventory()
            self.logger.info(f"Removed host: {alias}")
        else:
            self.logger.warning(f"Host not found: {alias}")

    def list_hosts(self) -> dict[str, HostConfig]:
        return {k: HostConfig(**v) for k, v in self.hosts.items()}

    def get_host(self, alias: str) -> HostConfig | None:
        data = self.hosts.get(alias)
        return HostConfig(**data) if data else None


class Tunnel:
    def __init__(
        self,
        config: HostConfig = None,
        remote_host: str = None,
        username: str = None,
        password: str = None,
        port: int = 22,
        identity_file: str = None,
        certificate_file: str = None,
        proxy_command: str = None,
        ssh_config_file: str = os.path.expanduser("~/.ssh/config"),
        connect_timeout: int = 10,
        banner_timeout: int = 10,
        auth_timeout: int = 15,
        keepalive_interval: int = 30,
        connect_retries: int = 2,
        retry_backoff: float = 1.0,
    ):
        """
        Initialize the Tunnel class using either a Pydantic HostConfig model or legacy kwargs.

        :param config: HostConfig object containing connection details.
        :param ssh_config_file: Optional path to a custom SSH config file (defaults to ~/.ssh/config).
        """
        if config:
            self.remote_host = config.hostname
            self.username = config.user
            self.password = config.password
            self.port = config.port
            self.identity_file = config.identity_file or config.key_path
            self.proxy_command = config.proxy_command
            self.certificate_file = config.extra_config.get("certificate_file")
        else:
            self.remote_host = remote_host
            self.username = username
            self.password = password
            self.port = port
            self.identity_file = identity_file
            self.proxy_command = proxy_command
            self.certificate_file = certificate_file

        self.ssh_client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)

        # Connection hardening tunables (stability fixes for flaky SSH).
        # Bounded timeouts prevent indefinite hangs; a small retry/backoff
        # absorbs transient auth/banner failures on otherwise-reachable hosts.
        self.connect_timeout = connect_timeout
        self.banner_timeout = banner_timeout
        self.auth_timeout = auth_timeout
        self.keepalive_interval = keepalive_interval
        self.connect_retries = max(1, connect_retries)
        self.retry_backoff = retry_backoff

        self.ssh_config = paramiko.SSHConfig()
        if os.path.exists(ssh_config_file) and os.path.isfile(ssh_config_file):
            with open(ssh_config_file) as f:
                self.ssh_config.parse(f)
            self.logger.info(f"Loaded SSH config from: {ssh_config_file}")
        else:
            self.logger.warning(f"No SSH config found at: {ssh_config_file}")

        host_config_ssh = self.ssh_config.lookup(self.remote_host) or {}

        self.username = self.username or host_config_ssh.get("user")
        self.identity_file = self.identity_file or (
            host_config_ssh.get("identityfile")[0]
            if host_config_ssh.get("identityfile")
            else None
        )
        self.certificate_file = self.certificate_file or host_config_ssh.get(
            "certificatefile"
        )
        self.proxy_command = self.proxy_command or host_config_ssh.get("proxycommand")

        if not self.username:
            raise ValueError("Username must be provided via parameter or SSH config.")
        if not self.identity_file and not self.password:
            self.logger.info(
                "Neither identity_file nor password was explicitly provided. "
                "Will attempt authentication using local SSH Agent and default keys."
            )

    def connect(self, timeout=None):
        if (
            self.ssh_client
            and self.ssh_client.get_transport()
            and self.ssh_client.get_transport().is_active()
        ):
            return

        import time

        connect_timeout = timeout or self.connect_timeout

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )  # nosec B507

        # 1. Path Expansion & Normalization (Linux & Windows)
        expanded_identity = None
        if self.identity_file:
            expanded_identity = os.path.abspath(os.path.expanduser(self.identity_file))
            self.logger.info(f"Resolved identity path: {expanded_identity}")

        expanded_cert = None
        if self.certificate_file:
            expanded_cert = os.path.abspath(os.path.expanduser(self.certificate_file))
            self.logger.info(f"Resolved certificate path: {expanded_cert}")

        # 2. Proxy Command Token Expansion & Platform Resolution (Linux & Windows)
        proxy = None
        if self.proxy_command:
            cmd_str = self.proxy_command
            cmd_str = cmd_str.replace("%h", self.remote_host)
            cmd_str = cmd_str.replace("%p", str(self.port))
            cmd_str = cmd_str.replace("%r", self.username or "")

            import shlex
            import shutil

            try:
                parts = shlex.split(cmd_str)
                if parts:
                    resolved_exec = shutil.which(parts[0])
                    if resolved_exec:
                        parts[0] = resolved_exec
                        cmd_str = " ".join(parts)
            except Exception as e:
                self.logger.warning(
                    f"Failed to parse proxy command '{cmd_str}': {str(e)}"
                )

            proxy = paramiko.ProxyCommand(cmd_str)
            self.logger.info(f"Using proxy command: {cmd_str}")

        private_key = None
        if expanded_identity:
            try:
                private_key = paramiko.Ed25519Key.from_private_key_file(
                    expanded_identity
                )
                self.logger.info(f"Loaded ED25519 key from: {expanded_identity}")
            except paramiko.ssh_exception.SSHException:
                private_key = paramiko.RSAKey.from_private_key_file(expanded_identity)
                self.logger.info(f"Loaded RSA key from: {expanded_identity}")

            if expanded_cert:
                private_key.load_certificate(expanded_cert)
                self.logger.info(f"Loaded certificate: {expanded_cert}")

        # 3. Connection with bounded timeouts + retry/backoff. SSH Agent and
        # default key discovery stay enabled for zero-burden RSA fallback.
        last_exc = None
        for attempt in range(1, self.connect_retries + 1):
            try:
                self.ssh_client.connect(
                    self.remote_host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    pkey=private_key,
                    sock=proxy,
                    timeout=connect_timeout,
                    banner_timeout=self.banner_timeout,
                    auth_timeout=self.auth_timeout,
                    look_for_keys=True,
                    allow_agent=True,
                )
                transport = self.ssh_client.get_transport()
                if transport is not None:
                    # Detect silently-dropped idle connections.
                    transport.set_keepalive(self.keepalive_interval)
                self.logger.info(
                    f"Connected to {self.remote_host} (attempt {attempt})"
                )
                return
            except Exception as e:
                last_exc = e
                self.logger.warning(
                    f"Connection attempt {attempt}/{self.connect_retries} to "
                    f"{self.remote_host} failed: {str(e)}"
                )
                if attempt < self.connect_retries:
                    time.sleep(self.retry_backoff * attempt)

        self.logger.error(
            f"Connection to {self.remote_host} failed after "
            f"{self.connect_retries} attempts: {str(last_exc)}"
        )
        raise last_exc

    def run_command(self, command, timeout=None) -> CommandResult:
        """
        Run a shell command on the remote host.

        :param command: The command to execute.
        :param timeout: Optional command execution timeout in seconds.
        :return: CommandResult object.
        """
        self.connect(timeout=timeout)
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(
                command, timeout=timeout
            )  # nosec B601
            channel = stdout.channel
            if timeout:
                channel.settimeout(timeout)
            out = stdout.read().decode("utf-8").strip()
            err = stderr.read().decode("utf-8").strip()
            # Bound the exit-status wait: paramiko's recv_exit_status() is an
            # unbounded blocking read, so a stalled remote process would hang
            # the call forever. Gate it on the channel's status_event instead.
            if timeout and not channel.status_event.wait(timeout):
                raise TimeoutError(
                    f"Timed out after {timeout}s waiting for command to exit: {command}"
                )
            exit_status = channel.recv_exit_status()
            self.logger.info(
                f"Command executed: {command}\nOutput: {out}\nError: {err}"
            )
            return CommandResult(
                success=(exit_status == 0), stdout=out, stderr=err, command=command
            )
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            return CommandResult(
                success=False, error_message=str(e), stderr=str(e), command=command
            )

    def send_file(self, local_path, remote_path):
        """
        Send (upload) a file to the remote host.
        :param local_path: Path to the local file.
        :param remote_path: Path on the remote host.
        """
        self.connect()
        try:
            local_path = os.path.abspath(os.path.expanduser(local_path))
            remote_path = os.path.expanduser(remote_path)

            self.logger.debug(
                f"send_file: local_path='{local_path}', remote_path='{remote_path}'"
            )
            self.logger.debug(f"send_file: CWD={os.getcwd()}")

            if not os.path.exists(local_path):
                err_msg = f"Local file does not exist: {local_path}"
                self.logger.error(err_msg)
                raise OSError(err_msg)
            if not os.path.isfile(local_path):
                err_msg = (
                    f"Local path is not a regular file (dir/symlink?): {local_path}"
                )
                self.logger.error(err_msg)
                raise OSError(err_msg)
            if not os.access(local_path, os.R_OK):
                err_msg = f"No read permission for local file: {local_path}"
                self.logger.error(err_msg)
                raise PermissionError(err_msg)

            try:
                with open(local_path, "rb") as f:
                    sample = f.read(1024)
                    self.logger.debug(
                        f"Binary open successful for {local_path}, sample size: {len(sample)} bytes"
                    )
            except Exception as open_err:
                err_msg = f"Failed to open {local_path} in binary mode: {str(open_err)}"
                self.logger.error(err_msg)
                raise OSError(err_msg) from open_err

            if not self.sftp:
                self.sftp = self.ssh_client.open_sftp()
                self.sftp.get_channel().settimeout(self.connect_timeout)
            self.logger.debug(f"Opening SFTP for put: {local_path} -> {remote_path}")
            self.sftp.put(local_path, remote_path)
            self.logger.info(f"File sent: {local_path} -> {remote_path}")
        except Exception as e:
            self.logger.error(f"File send failed: {str(e)} (type: {type(e).__name__})")
            import traceback

            self.logger.error(traceback.format_exc())
            raise
        finally:
            if self.sftp:
                self.sftp.close()
                self.sftp = None

    def receive_file(self, remote_path, local_path):
        """
        Receive (download) a file from the remote host.

        :param remote_path: Path on the remote host.
        :param local_path: Path to save the local file.
        """
        self.connect()
        try:
            if not self.sftp:
                self.sftp = self.ssh_client.open_sftp()
                self.sftp.get_channel().settimeout(self.connect_timeout)
            self.sftp.get(remote_path, local_path)
            self.logger.info(f"File received: {remote_path} -> {local_path}")
        except Exception as e:
            self.logger.error(f"File receive failed: {str(e)}")
            raise
        finally:
            if self.sftp:
                self.sftp.close()
                self.sftp = None

    def check_ssh_server(self):
        """
        Check if the SSH server is running and configured for key-based auth on the remote host.
        :return: Tuple (bool, str) indicating if SSH server is running and any error message.
        """
        try:
            self.connect()
            out, err = self.run_command(
                "systemctl status sshd || ps aux | grep '[s]shd'"
            )
            if "running" in out.lower() or "sshd" in out.lower():
                out, err = self.run_command(
                    "grep '^PubkeyAuthentication' /etc/ssh/sshd_config"
                )
                if "PubkeyAuthentication yes" in out:
                    return True, "SSH server running with key-based auth enabled."
                return False, "SSH server running but key-based auth not enabled."
            return False, "SSH server not running."
        except Exception as e:
            self.logger.error(f"Failed to check SSH server: {str(e)}")
            return False, f"Failed to check SSH server: {str(e)}"
        finally:
            self.close()

    def test_key_auth(self, local_key_path):
        """
        Test if key-based authentication works for the remote host.
        :param local_key_path: Path to the private key to test.
        :return: Tuple (bool, str) indicating success and any error message.
        """
        local_key_path = os.path.expanduser(local_key_path)
        try:
            temp_tunnel = Tunnel(
                config=HostConfig(
                    hostname=self.remote_host,
                    user=self.username,
                    key_path=local_key_path,
                )
            )
            temp_tunnel.connect()
            temp_tunnel.close()
            return True, "Key-based authentication successful."
        except Exception as e:
            self.logger.error(f"Key auth test failed: {str(e)}")
            return False, f"Key auth test failed: {str(e)}"

    def close(self):
        """
        Close the SSH connection.
        """
        if self.ssh_client:
            self.ssh_client.close()
            self.logger.info(f"Connection closed for {self.remote_host}")
            self.ssh_client = None

    def setup_passwordless_ssh(
        self, local_key_path=os.path.expanduser("~/.ssh/id_rsa"), key_type="ed25519"
    ):
        """
        Set up passwordless SSH by copying a public key to the remote host.
        Requires password-based authentication to be configured.

        :param local_key_path: Path to the local private key (public key is assumed to be .pub).
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        """
        if not self.password:
            raise ValueError("Password-based authentication required for setup.")

        local_key_path = os.path.expanduser(local_key_path)
        pub_key_path = local_key_path + ".pub"

        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(pub_key_path):
            import subprocess

            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        local_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            else:
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        local_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            self.logger.info(
                f"Generated {key_type} key pair: {local_key_path}, {pub_key_path}"
            )

        with open(pub_key_path) as f:
            pub_key = f.read().strip()

        try:
            self.connect()
            self.run_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
            self.run_command(f"echo '{pub_key}' >> ~/.ssh/authorized_keys")
            self.run_command("chmod 600 ~/.ssh/authorized_keys")
            self.logger.info(
                f"Set up passwordless SSH for {self.username}@{self.remote_host} with {key_type} key"
            )
        except Exception as e:
            self.logger.error(f"Failed to set up passwordless SSH: {str(e)}")
            raise
        finally:
            self.close()

    @staticmethod
    def execute_on_inventory(
        inventory, func, group="all", parallel=False, max_threads=5
    ):
        """
        Execute a function on all hosts in the specified group of the YAML inventory, sequentially or in parallel.
        :param inventory: Path to the YAML inventory file.
        :param func: Function to execute, takes host dict as argument.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Whether to run in parallel using threads.
        :param max_threads: Maximum number of threads if parallel.
        """
        logger = logging.getLogger("Tunnel")
        logger.info(f"Processing inventory '{inventory}' for group '{group}'")
        print(
            f"Loading inventory '{inventory}' for group '{group}'...", file=sys.stderr
        )

        try:
            with open(inventory) as f:
                inventory_data = yaml.safe_load(f) or {}
            logger.debug(f"Loaded inventory data: {inventory_data}")
        except FileNotFoundError:
            logger.error(f"Inventory file not found: {inventory}")
            print(f"Error: Inventory file not found: {inventory}", file=sys.stderr)
            raise
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse inventory file: {str(e)}")
            print(f"Error: Failed to parse inventory file: {str(e)}", file=sys.stderr)
            raise

        hosts = []

        # Check if it's an Ansible-style inventory
        if "all" in inventory_data and isinstance(inventory_data["all"], dict):
            all_group = inventory_data["all"]
            all_vars = all_group.get("vars", {}) or {}
            all_hosts = all_group.get("hosts", {}) or {}
            children = all_group.get("children", {}) or {}

            # We need to collect hosts belonging to the target group
            hosts_to_parse = {}  # alias -> (hvars, g_vars)

            if group == "all":
                # Add direct hosts from 'all'
                for alias, hvars in all_hosts.items():
                    hosts_to_parse[alias] = (hvars or {}, {})
                # Add hosts from all children
                for child_data in children.values():
                    if isinstance(child_data, dict):
                        g_hosts = child_data.get("hosts", {}) or {}
                        g_vars = child_data.get("vars", {}) or {}
                        for alias, hvars in g_hosts.items():
                            hosts_to_parse[alias] = (hvars or {}, g_vars)
            elif group in children:
                child_data = children[group]
                if isinstance(child_data, dict):
                    g_hosts = child_data.get("hosts", {}) or {}
                    g_vars = child_data.get("vars", {}) or {}
                    for alias, hvars in g_hosts.items():
                        hosts_to_parse[alias] = (hvars or {}, g_vars)
            else:
                # Group not found in children. Check if defined as a top-level key outside children
                if (
                    group in inventory_data
                    and isinstance(inventory_data[group], dict)
                    and "hosts" in inventory_data[group]
                ):
                    legacy_hosts = inventory_data[group]["hosts"] or {}
                    legacy_vars = inventory_data[group].get("vars", {}) or {}
                    for alias, hvars in legacy_hosts.items():
                        hosts_to_parse[alias] = (hvars or {}, legacy_vars)
                else:
                    logger.error(
                        f"Group '{group}' not found in inventory or invalid (hosts not a dict)"
                    )
                    print(
                        f"Error: Group '{group}' not found in inventory or invalid (hosts not a dict)",
                        file=sys.stderr,
                    )
                    raise ValueError(
                        f"Group '{group}' not found in inventory or invalid"
                    )

            # Now build the host entries
            for alias, (hvars, g_vars) in hosts_to_parse.items():
                username = (
                    hvars.get("ansible_user")
                    or hvars.get("user")
                    or g_vars.get("ansible_user")
                    or g_vars.get("user")
                    or all_vars.get("ansible_user")
                    or all_vars.get("user")
                    or ""
                )
                password = (
                    hvars.get("ansible_ssh_pass")
                    or hvars.get("password")
                    or g_vars.get("ansible_ssh_pass")
                    or g_vars.get("password")
                    or all_vars.get("ansible_ssh_pass")
                    or all_vars.get("password")
                )
                key_path = (
                    hvars.get("key_path")
                    or hvars.get("identity_file")
                    or hvars.get("ansible_ssh_private_key_file")
                    or g_vars.get("key_path")
                    or g_vars.get("identity_file")
                    or g_vars.get("ansible_ssh_private_key_file")
                    or all_vars.get("key_path")
                    or all_vars.get("identity_file")
                    or all_vars.get("ansible_ssh_private_key_file")
                )
                port = (
                    hvars.get("ansible_port")
                    or hvars.get("port")
                    or g_vars.get("ansible_port")
                    or g_vars.get("port")
                    or all_vars.get("ansible_port")
                    or all_vars.get("port")
                    or 22
                )

                host_entry = {
                    "hostname": hvars.get("ansible_host")
                    or hvars.get("hostname")
                    or alias,
                    "username": username,
                    "password": password,
                    "key_path": key_path,
                    "port": int(port) if port else 22,
                }
                if not host_entry["username"]:
                    logger.error(
                        f"No username specified for host {host_entry['hostname']}"
                    )
                    print(
                        f"Error: No username specified for host {host_entry['hostname']}",
                        file=sys.stderr,
                    )
                    continue
                logger.debug(f"Added host: {host_entry['hostname']}")
                hosts.append(host_entry)

        else:
            # Legacy non-Ansible flat inventory (or key-value flat structure)
            if group == "all":
                # Treat the entire inventory_data as flat hosts
                for alias, hvars in inventory_data.items():
                    if isinstance(hvars, dict):
                        username = (
                            hvars.get("user")
                            or hvars.get("username")
                            or hvars.get("ansible_user")
                            or ""
                        )
                        password = hvars.get("password") or hvars.get(
                            "ansible_ssh_pass"
                        )
                        key_path = (
                            hvars.get("key_path")
                            or hvars.get("identity_file")
                            or hvars.get("ansible_ssh_private_key_file")
                        )
                        port = hvars.get("port") or hvars.get("ansible_port") or 22
                        host_entry = {
                            "hostname": hvars.get("hostname")
                            or hvars.get("ansible_host")
                            or alias,
                            "username": username,
                            "password": password,
                            "key_path": key_path,
                            "port": int(port) if port else 22,
                        }
                        if not host_entry["username"]:
                            logger.error(
                                f"No username specified for host {host_entry['hostname']}"
                            )
                            continue
                        hosts.append(host_entry)
            elif (
                group in inventory_data
                and isinstance(inventory_data[group], dict)
                and "hosts" in inventory_data[group]
                and isinstance(inventory_data[group]["hosts"], dict)
            ):
                # Legacy style with group as a top-level key containing 'hosts'
                for host, vars in inventory_data[group]["hosts"].items():
                    hvars = vars or {}
                    host_entry = {
                        "hostname": hvars.get("ansible_host")
                        or hvars.get("hostname")
                        or host,
                        "username": hvars.get("ansible_user")
                        or hvars.get("user")
                        or hvars.get("username"),
                        "password": hvars.get("ansible_ssh_pass")
                        or hvars.get("password"),
                        "key_path": hvars.get("ansible_ssh_private_key_file")
                        or hvars.get("key_path")
                        or hvars.get("identity_file"),
                        "port": int(
                            hvars.get("ansible_port") or hvars.get("port") or 22
                        ),
                    }
                    if not host_entry["username"]:
                        logger.error(
                            f"No username specified for host {host_entry['hostname']}"
                        )
                        continue
                    hosts.append(host_entry)
            else:
                logger.error(
                    f"Group '{group}' not found in inventory or invalid (hosts not a dict)"
                )
                print(
                    f"Error: Group '{group}' not found in inventory or invalid (hosts not a dict)",
                    file=sys.stderr,
                )
                raise ValueError(f"Group '{group}' not found in inventory or invalid")

        logger.info(f"Found {len(hosts)} hosts in group '{group}'")
        print(f"Found {len(hosts)} hosts in group '{group}'", file=sys.stderr)

        if not hosts:
            logger.warning(f"No valid hosts found in group '{group}'")
            print(f"Warning: No valid hosts found in group '{group}'", file=sys.stderr)
            return

        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [executor.submit(func, host) for host in hosts]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error in parallel execution: {str(e)}")
                        print(f"Error in parallel execution: {str(e)}", file=sys.stderr)
        else:
            for host in hosts:
                func(host)
        print(f"Completed processing group '{group}'", file=sys.stderr)

    def remove_host_key(
        self, known_hosts_path=os.path.expanduser("~/.ssh/known_hosts")
    ) -> str:
        """
        Remove the host key for the remote host from the known_hosts file.
        :param known_hosts_path: Path to the known_hosts file (default: ~/.ssh/known_hosts).
        """
        known_hosts_path = os.path.expanduser(known_hosts_path)
        kh = paramiko.HostKeys()
        if os.path.exists(known_hosts_path):
            kh.load(known_hosts_path)
            if self.remote_host in kh:
                del kh[self.remote_host]
                kh.save(known_hosts_path)
                self.logger.info(
                    f"Removed host key for {self.remote_host} from {known_hosts_path}"
                )
                return (
                    f"Removed host key for {self.remote_host} from {known_hosts_path}"
                )
            else:
                self.logger.warning(
                    f"No host key found for {self.remote_host} in {known_hosts_path}"
                )
                return f"No host key found for {self.remote_host} in {known_hosts_path}"
        else:
            self.logger.warning(f"No known_hosts file at {known_hosts_path}")
            return f"No known_hosts file at {known_hosts_path}"

    def copy_ssh_config(
        self, local_config_path, remote_config_path=os.path.expanduser("~/.ssh/config")
    ):
        """
        Copy a local SSH config to the remote host’s ~/.ssh/config.
        :param local_config_path: Path to the local config file.
        :param remote_config_path: Path on remote (default ~/.ssh/config).
        """
        self.connect()
        self.run_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
        self.send_file(local_config_path, remote_config_path)
        self.run_command(f"chmod 600 {remote_config_path}")
        self.logger.info(
            f"Copied SSH config to {remote_config_path} on {self.remote_host}"
        )

    def rotate_ssh_key(self, new_key_path, key_type="ed25519"):
        """
        Rotate the SSH key by generating a new pair and updating authorized_keys.
        :param new_key_path: Path for the new private key.
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        """
        new_key_path = os.path.expanduser(new_key_path)
        new_pub_path = new_key_path + ".pub"
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(new_key_path):
            import subprocess

            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        new_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            else:
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        new_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            self.logger.info(f"Generated new {key_type} key pair: {new_key_path}")

        with open(new_pub_path) as f:
            new_pub = f.read().strip()

        old_pub = None
        if self.identity_file:
            old_key_path = os.path.expanduser(self.identity_file)
            old_pub_path = old_key_path + ".pub"
            if os.path.exists(old_pub_path):
                with open(old_pub_path) as f:
                    old_pub = f.read().strip()

        self.connect()
        out, err = self.run_command("cat ~/.ssh/authorized_keys")
        auth_keys = out.splitlines()
        new_auth = [
            line
            for line in auth_keys
            if line.strip() and (old_pub is None or line.strip() != old_pub)
        ]
        new_auth.append(new_pub)

        temp_file = "/tmp/authorized_keys.new"  # nosec B108
        new_auth_joined = "\n".join(new_auth)
        self.run_command(f"echo '{new_auth_joined}' > {temp_file}")
        self.run_command(f"mv {temp_file} ~/.ssh/authorized_keys")
        self.run_command("chmod 600 ~/.ssh/authorized_keys")

        self.identity_file = new_key_path
        self.password = None
        self.logger.info(
            f"Rotated {key_type} key to {new_key_path} on {self.remote_host}"
        )
        logging.info(
            f"Please update SSH config for {self.remote_host} IdentityFile to {new_key_path}"
        )

    @staticmethod
    def setup_all_passwordless_ssh(
        inventory,
        shared_key_path=os.path.expanduser("~/.ssh/id_shared"),
        key_type="ed25519",
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Set up passwordless SSH for all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param shared_key_path: Path to a shared private key (optional, generates if missing).
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """
        shared_key_path = os.path.expanduser(shared_key_path)
        shared_pub_key_path = shared_key_path + ".pub"
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(shared_key_path):
            import subprocess

            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        shared_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            else:
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "ed25519",
                        "-f",
                        shared_key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            logging.info(
                f"Generated shared {key_type} key pair: {shared_key_path}, {shared_pub_key_path}"
            )

        with open(shared_pub_key_path) as f:
            shared_pub_key = f.read().strip()

        def setup_host(host):
            hostname = host["hostname"]
            username = host["username"]
            password = host["password"]
            key_path = host.get("key_path", shared_key_path)

            logging.info(f"\nSetting up {username}@{hostname}...")

            tunnel = Tunnel(
                remote_host=hostname,
                username=username,
                password=password,
            )
            tunnel.remove_host_key()
            tunnel.setup_passwordless_ssh(local_key_path=key_path, key_type=key_type)

            try:
                tunnel.connect()
                tunnel.run_command(f"echo '{shared_pub_key}' >> ~/.ssh/authorized_keys")
                tunnel.run_command("chmod 600 ~/.ssh/authorized_keys")
                logging.info(f"Added shared {key_type} key to {username}@{hostname}")
            except Exception as e:
                logging.error(
                    f"Failed to add shared key to {username}@{hostname}: {str(e)}"
                )
            finally:
                tunnel.close()

            result, msg = tunnel.test_key_auth(key_path)
            logging.info(f"Key auth test for {username}@{hostname}: {msg}")

        Tunnel.execute_on_inventory(inventory, setup_host, group, parallel, max_threads)

    @staticmethod
    def setup_full_mesh_ssh(
        inventory,
        key_path=os.path.expanduser("~/.ssh/id_ed25519"),
        key_type="ed25519",
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Set up full-mesh passwordless SSH for all hosts in the specified group.
        Ensures every host can SSH to every other host, including the local machine,
        without password prompts. Supports POSIX and Windows remotes.
        """
        import subprocess

        logger = logging.getLogger("Tunnel")
        logger.info(
            f"Starting native full-mesh SSH bootstrap for group '{group}' using inventory '{inventory}'"
        )

        # 1. Local key generation
        key_path = os.path.expanduser(key_path)
        pub_key_path = key_path + ".pub"
        if key_type not in ["rsa", "ed25519"]:
            raise ValueError("key_type must be 'rsa' or 'ed25519'")

        if not os.path.exists(key_path):
            os.makedirs(os.path.dirname(key_path), exist_ok=True)
            if key_type == "rsa":
                subprocess.run(
                    [
                        "/usr/bin/ssh-keygen",
                        "-t",
                        "rsa",
                        "-b",
                        "4096",
                        "-f",
                        key_path,
                        "-N",
                        "",
                    ],
                    check=True,
                )
            else:
                subprocess.run(
                    ["/usr/bin/ssh-keygen", "-t", "ed25519", "-f", key_path, "-N", ""],
                    check=True,
                )
            logger.info(f"Generated local {key_type} key pair: {key_path}")

        with open(pub_key_path) as f:
            local_pub_key = f.read().strip()

        # 2. Parse inventory hosts
        try:
            with open(inventory) as f:
                inventory_data = yaml.safe_load(f)
        except Exception as e:
            logger.error(f"Failed to read inventory file: {e}")
            raise

        hosts = []
        if (
            group in inventory_data
            and isinstance(inventory_data[group], dict)
            and "hosts" in inventory_data[group]
            and isinstance(inventory_data[group]["hosts"], dict)
        ):
            for host_name, vars in inventory_data[group]["hosts"].items():
                host_entry = {
                    "name": host_name,
                    "hostname": vars.get("ansible_host", host_name),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file") or key_path,
                }
                if host_entry["username"]:
                    hosts.append(host_entry)
        else:
            raise ValueError(f"Group '{group}' not found in inventory or invalid")

        if not hosts:
            logger.warning(f"No valid hosts found in group '{group}'")
            return {"status": "success", "host_results": [], "errors": []}

        # First pass - setup passwordless access, detect remote OS, ensure keygen and read pubkey
        host_results = {}

        def process_first_pass(host):
            hostname = host["hostname"]
            username = host["username"]
            password = host["password"]
            kpath = host["key_path"]

            tunnel = Tunnel(
                remote_host=hostname,
                username=username,
                password=password,
                identity_file=kpath,
            )

            # Test key auth
            res, _ = tunnel.test_key_auth(kpath)
            if not res:
                if not password:
                    raise ValueError(
                        f"Key authentication failed and no password provided for {username}@{hostname}"
                    )
                logger.info(
                    f"Key auth failed for {username}@{hostname}, attempting passwordless setup..."
                )
                tunnel.remove_host_key()
                tunnel.setup_passwordless_ssh(local_key_path=kpath, key_type=key_type)

            # Re-connect to perform remote generation and detection
            tunnel.connect()
            try:
                # Detect OS
                is_windows = False
                res_os = tunnel.run_command("uname -s")
                if (
                    not res_os.success
                    or "uname" in res_os.stderr.lower()
                    or not res_os.stdout
                ):
                    is_windows = True

                # Check / generate key on remote
                if is_windows:
                    tunnel.run_command(
                        'if not exist "%USERPROFILE%\\.ssh" mkdir "%USERPROFILE%\\.ssh"'
                    )
                    gen_cmd = f'if not exist "%USERPROFILE%\\.ssh\\id_{key_type}" (ssh-keygen -t {key_type} -N "" -f "%USERPROFILE%\\.ssh\\id_{key_type}")'
                else:
                    tunnel.run_command("mkdir -p ~/.ssh && chmod 700 ~/.ssh")
                    gen_cmd = f"if [ ! -f ~/.ssh/id_{key_type} ]; then ssh-keygen -t {key_type} -N '' -f ~/.ssh/id_{key_type}; fi"

                res_gen = tunnel.run_command(gen_cmd)
                if not res_gen.success:
                    raise RuntimeError(
                        f"Failed to generate key on remote host: {res_gen.stderr or res_gen.error_message}"
                    )

                # Read remote public key
                if is_windows:
                    read_cmd = f'type "%USERPROFILE%\\.ssh\\id_{key_type}.pub"'
                else:
                    read_cmd = f"cat ~/.ssh/id_{key_type}.pub"

                res_pub = tunnel.run_command(read_cmd)
                if not res_pub.success or not res_pub.stdout:
                    raise RuntimeError(
                        f"Failed to read public key from remote: {res_pub.stderr or res_pub.error_message}"
                    )
                remote_pub_key = res_pub.stdout.strip()

                # Extract local-perceived IP via SSH_CONNECTION
                if is_windows:
                    ip_cmd = "echo %SSH_CONNECTION%"
                else:
                    ip_cmd = "echo $SSH_CONNECTION"

                res_ip = tunnel.run_command(ip_cmd)
                client_ip = None
                if res_ip.success and res_ip.stdout:
                    parts = res_ip.stdout.strip().split()
                    if parts:
                        client_ip = parts[0]

                # Ensure local pub key is explicitly inside remote authorized_keys
                if is_windows:
                    tunnel.run_command(
                        f'echo {local_pub_key} >> "%USERPROFILE%\\.ssh\\authorized_keys"'
                    )
                else:
                    tunnel.run_command(
                        f"echo '{local_pub_key}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
                    )

                host_results[hostname] = {
                    "name": host["name"],
                    "hostname": hostname,
                    "username": username,
                    "password": password,
                    "key_path": kpath,
                    "is_windows": is_windows,
                    "remote_pub_key": remote_pub_key,
                    "client_ip": client_ip,
                    "status": "success",
                    "errors": [],
                }
            except Exception as e:
                host_results[hostname] = {
                    "name": host["name"],
                    "hostname": hostname,
                    "username": username,
                    "status": "failed",
                    "errors": [str(e)],
                }
            finally:
                tunnel.close()

        # Run first pass (parallel or sequential)
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [executor.submit(process_first_pass, h) for h in hosts]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error in first pass: {e}")
        else:
            for h in hosts:
                try:
                    process_first_pass(h)
                except Exception as e:
                    logger.error(f"Error in first pass: {e}")

        # Filter out failed hosts from second pass
        successful_hosts = [
            r for r in host_results.values() if r["status"] == "success"
        ]

        # Second pass - distribute other hosts' public keys and run ssh-keyscan
        def process_second_pass(host):
            hostname = host["hostname"]
            username = host["username"]
            kpath = host["key_path"]
            is_windows = host["is_windows"]
            client_ip = host["client_ip"]

            tunnel = Tunnel(
                remote_host=hostname, username=username, identity_file=kpath
            )
            tunnel.connect()
            try:
                # Read existing authorized_keys
                if is_windows:
                    cat_cmd = 'type "%USERPROFILE%\\.ssh\\authorized_keys"'
                else:
                    cat_cmd = "cat ~/.ssh/authorized_keys"

                res_auth = tunnel.run_command(cat_cmd)
                existing_keys = res_auth.stdout if res_auth.success else ""

                # Collect and append keys
                keys_to_add = []
                if local_pub_key not in existing_keys:
                    keys_to_add.append(local_pub_key)

                for other_host in successful_hosts:
                    if other_host["hostname"] != hostname:
                        other_pub = other_host["remote_pub_key"]
                        if other_pub not in existing_keys:
                            keys_to_add.append(other_pub)

                if keys_to_add:
                    for key_to_add in keys_to_add:
                        if is_windows:
                            tunnel.run_command(
                                f'echo {key_to_add} >> "%USERPROFILE%\\.ssh\\authorized_keys"'
                            )
                        else:
                            tunnel.run_command(
                                f"echo '{key_to_add}' >> ~/.ssh/authorized_keys"
                            )
                    if not is_windows:
                        tunnel.run_command("chmod 600 ~/.ssh/authorized_keys")

                # Setup keyscan for all targets
                scan_targets = set()
                if client_ip:
                    scan_targets.add(client_ip)
                for other_host in successful_hosts:
                    if other_host["hostname"] != hostname:
                        scan_targets.add(other_host["hostname"])
                        if (
                            other_host.get("name")
                            and other_host["name"] != other_host["hostname"]
                        ):
                            scan_targets.add(other_host["name"])

                for target in scan_targets:
                    if is_windows:
                        keyscan_cmd = f'ssh-keyscan -H {target} >> "%USERPROFILE%\\.ssh\\known_hosts"'
                    else:
                        tunnel.run_command(
                            "touch ~/.ssh/known_hosts && chmod 600 ~/.ssh/known_hosts"
                        )
                        keyscan_cmd = f"ssh-keyscan -H {target} >> ~/.ssh/known_hosts"
                    tunnel.run_command(keyscan_cmd)

            except Exception as e:
                host_results[hostname]["status"] = "failed"
                host_results[hostname]["errors"].append(str(e))
            finally:
                tunnel.close()

        # Run second pass (parallel or sequential)
        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [
                    executor.submit(process_second_pass, h) for h in successful_hosts
                ]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                    except Exception as e:
                        logger.error(f"Error in second pass: {e}")
        else:
            for h in successful_hosts:
                try:
                    process_second_pass(h)
                except Exception as e:
                    logger.error(f"Error in second pass: {e}")

        # Local updates (local authorized_keys and local known_hosts)
        try:
            local_auth_path = os.path.expanduser("~/.ssh/authorized_keys")
            local_existing_keys = ""
            if os.path.exists(local_auth_path):
                with open(local_auth_path) as f:
                    local_existing_keys = f.read()

            with open(local_auth_path, "a") as f:
                for h in successful_hosts:
                    if h["remote_pub_key"] not in local_existing_keys:
                        f.write("\n" + h["remote_pub_key"] + "\n")

            local_known_hosts = os.path.expanduser("~/.ssh/known_hosts")
            os.makedirs(os.path.dirname(local_known_hosts), exist_ok=True)
            with open(local_known_hosts, "a"):
                pass

            for h in successful_hosts:
                for target in [h["hostname"], h.get("name")]:
                    if target:
                        try:
                            res = subprocess.run(
                                ["ssh-keyscan", "-H", target],
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            if res.returncode == 0 and res.stdout.strip():
                                with open(local_known_hosts, "a") as f:
                                    f.write("\n" + res.stdout.strip() + "\n")
                        except Exception as e:
                            logger.warning(f"Local keyscan failed for {target}: {e}")
        except Exception as e:
            logger.error(f"Failed to update local authorized_keys / known_hosts: {e}")

        # Assemble final result
        final_results = list(host_results.values())
        errors = []
        for r in final_results:
            errors.extend(r["errors"])

        return {
            "status": "success" if not errors else "failed",
            "host_results": final_results,
            "errors": errors,
        }

    @staticmethod
    def run_command_on_inventory(
        inventory, command, group="all", parallel=False, max_threads=5, timeout=None
    ):
        """
        Run a shell command on all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param command: The shell command to run.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        :param timeout: Optional command execution timeout in seconds.
        """
        logger = logging.getLogger("Tunnel")
        logger.info(
            f"Running command '{command}' on group '{group}' with timeout {timeout}"
        )
        print(f"Executing command '{command}' on group '{group}'...", file=sys.stderr)

        def run_host(host):
            try:
                tunnel = Tunnel(
                    config=HostConfig(
                        hostname=host["hostname"],
                        user=host["username"],
                        password=host.get("password"),
                        key_path=host.get("key_path"),
                    )
                )
                out, err = tunnel.run_command(command, timeout=timeout)
                logger.info(
                    f"Host {host['hostname']}: In: {command}, Out: {out}, Err: {err}"
                )
                print(
                    f"Host {host['hostname']}:\nInput: {command}\nOutput: {out}\nError: {err}",
                    file=sys.stderr,
                )
                tunnel.close()
            except Exception as e:
                logger.error(f"Failed to run command on {host['hostname']}: {str(e)}")
                print(f"Error on {host['hostname']}: {str(e)}", file=sys.stderr)

        try:
            Tunnel.execute_on_inventory(
                inventory, run_host, group, parallel, max_threads
            )
            print(f"Completed command execution on group '{group}'", file=sys.stderr)
        except Exception as e:
            logger.error(f"Failed to execute command on group '{group}': {str(e)}")
            print(
                f"Error executing command on group '{group}': {str(e)}", file=sys.stderr
            )
            raise

    @staticmethod
    def copy_ssh_config_on_inventory(
        inventory,
        local_config_path,
        remote_config_path=os.path.expanduser("~/.ssh/config"),
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Copy local SSH config to all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param local_config_path: Local SSH config path.
        :param remote_config_path: Remote path (default ~/.ssh/config).
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """

        def copy_host(host):
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password=host.get("password"),
                    key_path=host.get("key_path"),
                )
            )
            tunnel.copy_ssh_config(local_config_path, remote_config_path)
            tunnel.close()

        Tunnel.execute_on_inventory(inventory, copy_host, group, parallel, max_threads)

    @staticmethod
    def rotate_ssh_key_on_inventory(
        inventory,
        key_prefix=os.path.expanduser("~/.ssh/id_"),
        key_type="ed25519",
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Rotate SSH keys for all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param key_prefix: Prefix for new key paths (appends hostname).
        :param key_type: Type of key to generate ('rsa' or 'ed25519', default: 'rsa').
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """

        def rotate_host(host):
            new_key_path = os.path.expanduser(key_prefix + host["hostname"])
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password=host.get("password"),
                    key_path=host.get("key_path"),
                )
            )
            tunnel.rotate_ssh_key(new_key_path, key_type=key_type)
            logging.info(
                f"Rotated {key_type} key for {host['hostname']}. Update inventory key_path to {new_key_path} if needed."
            )
            tunnel.close()

        Tunnel.execute_on_inventory(
            inventory, rotate_host, group, parallel, max_threads
        )

    @staticmethod
    def send_file_on_inventory(
        inventory,
        local_path,
        remote_path,
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Upload a file to all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param local_path: Path to the local file to upload.
        :param remote_path: Path on the remote hosts to save the file.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel execution.
        """

        def send_host(host):
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password=host.get("password"),
                    key_path=host.get("key_path"),
                )
            )
            tunnel.send_file(local_path, remote_path)
            logging.info(f"Host {host['hostname']}: File uploaded to {remote_path}")
            tunnel.close()

        if not os.path.exists(local_path):
            raise ValueError(f"Local file does not exist: {local_path}")

        Tunnel.execute_on_inventory(inventory, send_host, group, parallel, max_threads)

    @staticmethod
    def receive_file_on_inventory(
        inventory,
        remote_path: str,
        local_path_prefix,
        group="all",
        parallel=False,
        max_threads=5,
    ):
        """
        Download a file from all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param remote_path: Path on the remote hosts to download the file from.
        :param local_path_prefix: Local directory path prefix to save files (creates host-specific subdirectories).
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel execution.
        """

        def receive_host(host):
            host_dir = os.path.join(local_path_prefix, host["hostname"])
            os.makedirs(host_dir, exist_ok=True)
            local_path = os.path.join(f"{host_dir}", os.path.basename(remote_path))
            tunnel = Tunnel(
                config=HostConfig(
                    hostname=host["hostname"],
                    user=host["username"],
                    password=host.get("password"),
                    key_path=host.get("key_path"),
                )
            )
            tunnel.receive_file(remote_path, local_path)
            logging.info(f"Host {host['hostname']}: File downloaded to {local_path}")
            tunnel.close()

        os.makedirs(local_path_prefix, exist_ok=True)
        Tunnel.execute_on_inventory(
            inventory, receive_host, group, parallel, max_threads
        )


def tunnel_manager():
    print(f"tunnel_manager v{__version__}", file=sys.stderr)
    parser = argparse.ArgumentParser(description="Tunnel Manager CLI")
    parser.add_argument("--log-file", help="Log to this file (default: console output)")

    xdg_config = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    default_inventory = os.path.join(xdg_config, "agent-utilities", "inventory.yaml")

    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup-all", help="Setup passwordless for all")
    setup_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    setup_parser.add_argument(
        "--shared-key-path",
        default="~/.ssh/id_shared",
        help="Path to shared private key",
    )
    setup_parser.add_argument(
        "--key-type",
        choices=["rsa", "ed25519"],
        default="ed25519",
        help="Key type to generate (rsa or ed25519, default: ed25519)",
    )
    setup_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    setup_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    setup_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    run_parser = subparsers.add_parser("run-command", help="Run command on all")
    run_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    run_parser.add_argument("--remote-command", help="Shell command to run")
    run_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    run_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    run_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )
    run_parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Command timeout in seconds (default: 60)",
    )

    copy_parser = subparsers.add_parser("copy-config", help="Copy SSH config to all")
    copy_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    copy_parser.add_argument(
        "--local-config-path", default="~/.ssh/config", help="Local SSH config path"
    )
    copy_parser.add_argument(
        "--remote-config-path",
        default="~/.ssh/config",
        help="Remote path (default ~/.ssh/config)",
    )
    copy_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    copy_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    copy_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    rotate_parser = subparsers.add_parser("rotate-key", help="Rotate keys for all")
    rotate_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    rotate_parser.add_argument(
        "--key-prefix",
        default="~/.ssh/id_",
        help="Prefix for new key paths (appends hostname)",
    )
    rotate_parser.add_argument(
        "--key-type",
        choices=["rsa", "ed25519"],
        default="ed25519",
        help="Key type to generate (rsa or ed25519, default: ed25519)",
    )
    rotate_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    rotate_parser.add_argument(
        "--parallel", action="store_true", help="Run in parallel"
    )
    rotate_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    send_parser = subparsers.add_parser(
        "send-file", help="Upload file to all hosts in inventory"
    )
    send_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    send_parser.add_argument("--local-path", help="Local file path to upload")
    send_parser.add_argument("--remote-path", help="Remote destination path")
    send_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    send_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    send_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    receive_parser = subparsers.add_parser(
        "receive-file", help="Download file from all hosts in inventory"
    )
    receive_parser.add_argument(
        "--inventory", default=default_inventory, help="YAML inventory path"
    )
    receive_parser.add_argument("--remote-path", help="Remote file path to download")
    receive_parser.add_argument(
        "--local-path-prefix", help="Local directory path prefix to save files"
    )
    receive_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    receive_parser.add_argument(
        "--parallel", action="store_true", help="Run in parallel"
    )
    receive_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.log_file:
        log_dir = (
            os.path.dirname(os.path.abspath(args.log_file))
            if os.path.dirname(args.log_file)
            else os.getcwd()
        )
        os.makedirs(log_dir, exist_ok=True)
        try:
            logging.basicConfig(
                filename=args.log_file,
                level=logging.DEBUG,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            )
        except PermissionError as e:
            print(
                f"Error: Cannot write to log file '{args.log_file}': {str(e)}",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )

    logger = logging.getLogger("Tunnel")
    logger.debug(
        f"Starting Tunnel Automation with command: {args.command}, args: {vars(args)}"
    )
    print(f"Starting Tunnel Automation with command: {args.command}", file=sys.stderr)

    try:
        if args.command == "setup-all":
            Tunnel.setup_all_passwordless_ssh(
                args.inventory,
                args.shared_key_path,
                args.key_type,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "run-command":
            Tunnel.run_command_on_inventory(
                args.inventory,
                args.remote_command,
                args.group,
                args.parallel,
                args.max_threads,
                timeout=args.timeout,
            )
        elif args.command == "copy-config":
            Tunnel.copy_ssh_config_on_inventory(
                args.inventory,
                args.local_config_path,
                args.remote_config_path,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "rotate-key":
            Tunnel.rotate_ssh_key_on_inventory(
                args.inventory,
                args.key_prefix,
                args.key_type,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "send-file":
            Tunnel.send_file_on_inventory(
                args.inventory,
                args.local_path,
                args.remote_path,
                args.group,
                args.parallel,
                args.max_threads,
            )
        elif args.command == "receive-file":
            Tunnel.receive_file_on_inventory(
                args.inventory,
                args.remote_path,
                args.local_path_prefix,
                args.group,
                args.parallel,
                args.max_threads,
            )
        logger.debug("Automation Complete")
        print("Automation Complete", file=sys.stderr)
    except Exception as e:
        logger.error(f"Automation failed: {str(e)}")
        print(f"Error: Automation failed: {str(e)}", file=sys.stderr)
        sys.exit(1)


def main():
    tunnel_manager()


if __name__ == "__main__":
    tunnel_manager()
