#!/usr/bin/env python
# coding: utf-8

import sys
import argparse
import concurrent.futures
import logging
import os
import paramiko
import yaml

__version__ = "1.1.10"


class HostManager:
    def __init__(self, config_file: str = None):
        if config_file:
            self.config_file = config_file
        else:
            self.config_file = os.path.expanduser("~/.tunnel_manager/hosts.yaml")

        self.logger = logging.getLogger(__name__)
        self.hosts = {}
        self.load_inventory()

    def load_inventory(self):
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r") as f:
                    self.hosts = yaml.safe_load(f) or {}
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
        self.hosts[alias] = {
            "hostname": hostname,
            "user": user,
            "port": port,
            "identity_file": identity_file,
            "password": password,
            "proxy_command": proxy_command,
            **kwargs,
        }
        self.save_inventory()
        self.logger.info(f"Added host: {alias}")

    def remove_host(self, alias: str):
        if alias in self.hosts:
            del self.hosts[alias]
            self.save_inventory()
            self.logger.info(f"Removed host: {alias}")
        else:
            self.logger.warning(f"Host not found: {alias}")

    def list_hosts(self):
        return self.hosts

    def get_host(self, alias: str):
        return self.hosts.get(alias)


class Tunnel:
    def __init__(
        self,
        remote_host: str,
        username: str = None,
        password: str = None,
        port: int = 22,
        identity_file: str = None,
        certificate_file: str = None,
        proxy_command: str = None,
        ssh_config_file: str = os.path.expanduser("~/.ssh/config"),
    ):
        """
        Initialize the Tunnel class.

        :param remote_host: The hostname or IP of the remote host.
        :param username: The username for authentication (overrides config).
        :param password: The password for authentication (if no identity_file).
        :param port: The SSH port (default: 22).
        :param identity_file: Optional path to the private key file (overrides config).
        :param certificate_file: Optional path to the certificate file (overrides config).
        :param proxy_command: Optional proxy command string (overrides config).
        :param log_file: Optional path to a log file for recording operations.
        :param ssh_config_file: Optional path to a custom SSH config file (defaults to ~/.ssh/config).
        """
        self.remote_host = remote_host
        self.username = username
        self.password = password
        self.port = port
        self.ssh_client = None
        self.sftp = None
        self.logger = logging.getLogger(__name__)

        self.ssh_config = paramiko.SSHConfig()
        if os.path.exists(ssh_config_file) and os.path.isfile(ssh_config_file):
            with open(ssh_config_file, "r") as f:
                self.ssh_config.parse(f)
            self.logger.info(f"Loaded SSH config from: {ssh_config_file}")
        else:
            self.logger.warning(f"No SSH config found at: {ssh_config_file}")
        host_config = self.ssh_config.lookup(remote_host) or {}

        self.username = username or host_config.get("user")
        self.identity_file = identity_file or (
            host_config.get("identityfile")[0]
            if host_config.get("identityfile")
            else None
        )
        self.certificate_file = certificate_file or host_config.get("certificatefile")
        self.proxy_command = proxy_command or host_config.get("proxycommand")

        if not self.username:
            raise ValueError("Username must be provided via parameter or SSH config.")
        if not self.identity_file and not self.password:
            raise ValueError("Either identity_file or password must be provided.")

    def connect(self):
        if (
            self.ssh_client
            and self.ssh_client.get_transport()
            and self.ssh_client.get_transport().is_active()
        ):
            return

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        proxy = None
        if self.proxy_command:
            proxy = paramiko.ProxyCommand(self.proxy_command)
            self.logger.info(f"Using proxy command: {self.proxy_command}")

        try:
            if self.identity_file:
                try:
                    private_key = paramiko.Ed25519Key.from_private_key_file(
                        self.identity_file
                    )
                    self.logger.info(f"Loaded ED25519 key from: {self.identity_file}")
                except paramiko.ssh_exception.SSHException:
                    private_key = paramiko.RSAKey.from_private_key_file(
                        self.identity_file
                    )
                    self.logger.info(f"Loaded RSA key from: {self.identity_file}")
                if self.certificate_file:
                    private_key.load_certificate(self.certificate_file)
                    self.logger.info(f"Loaded certificate: {self.certificate_file}")
                self.ssh_client.connect(
                    self.remote_host,
                    port=self.port,
                    username=self.username,
                    pkey=private_key,
                    sock=proxy,
                    auth_timeout=30,
                    look_for_keys=False,
                    allow_agent=False,
                )
            else:
                self.ssh_client.connect(
                    self.remote_host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    sock=proxy,
                    auth_timeout=30,
                    look_for_keys=False,
                    allow_agent=False,
                )
            self.logger.info(f"Connected to {self.remote_host}")
        except Exception as e:
            self.logger.error(f"Connection failed: {str(e)}")
            raise

    def run_command(self, command):
        """
        Run a shell command on the remote host.

        :param command: The command to execute.
        :return: Tuple of (stdout, stderr) as strings.
        """
        self.connect()
        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)
            out = stdout.read().decode("utf-8").strip()
            err = stderr.read().decode("utf-8").strip()
            self.logger.info(
                f"Command executed: {command}\nOutput: {out}\nError: {err}"
            )
            return out, err
        except Exception as e:
            self.logger.error(f"Command execution failed: {str(e)}")
            raise

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
                raise IOError(err_msg)
            if not os.path.isfile(local_path):
                err_msg = (
                    f"Local path is not a regular file (dir/symlink?): {local_path}"
                )
                self.logger.error(err_msg)
                raise IOError(err_msg)
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
                raise IOError(err_msg)

            if not self.sftp:
                self.sftp = self.ssh_client.open_sftp()
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
                remote_host=self.remote_host,
                username=self.username,
                identity_file=local_key_path,
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
            if key_type == "rsa":
                os.system(f"ssh-keygen -t rsa -b 4096 -f {local_key_path} -N ''")
            else:
                os.system(f"ssh-keygen -t ed25519 -f {local_key_path} -N ''")
            self.logger.info(
                f"Generated {key_type} key pair: {local_key_path}, {pub_key_path}"
            )

        with open(pub_key_path, "r") as f:
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
        print(f"Loading inventory '{inventory}' for group '{group}'...")

        try:
            with open(inventory, "r") as f:
                inventory_data = yaml.safe_load(f)
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
        if (
            group in inventory_data
            and isinstance(inventory_data[group], dict)
            and "hosts" in inventory_data[group]
            and isinstance(inventory_data[group]["hosts"], dict)
        ):
            for host, vars in inventory_data[group]["hosts"].items():
                host_entry = {
                    "hostname": vars.get("ansible_host", host),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file"),
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
            logger.error(
                f"Group '{group}' not found in inventory or invalid (hosts not a dict)"
            )
            print(
                f"Error: Group '{group}' not found in inventory or invalid (hosts not a dict)",
                file=sys.stderr,
            )
            raise ValueError(f"Group '{group}' not found in inventory or invalid")

        logger.info(f"Found {len(hosts)} hosts in group '{group}'")
        print(f"Found {len(hosts)} hosts in group '{group}'")

        if not hosts:
            logger.warning(f"No valid hosts found in group '{group}'")
            print(f"Warning: No valid hosts found in group '{group}'")
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
        print(f"Completed processing group '{group}'")

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
            if key_type == "rsa":
                os.system(f"ssh-keygen -t rsa -b 4096 -f {new_key_path} -N ''")
            else:
                os.system(f"ssh-keygen -t ed25519 -f {new_key_path} -N ''")
            self.logger.info(f"Generated new {key_type} key pair: {new_key_path}")

        with open(new_pub_path, "r") as f:
            new_pub = f.read().strip()

        old_pub = None
        if self.identity_file:
            old_key_path = os.path.expanduser(self.identity_file)
            old_pub_path = old_key_path + ".pub"
            if os.path.exists(old_pub_path):
                with open(old_pub_path, "r") as f:
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

        temp_file = "/tmp/authorized_keys.new"
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
            if key_type == "rsa":
                os.system(f"ssh-keygen -t rsa -b 4096 -f {shared_key_path} -N ''")
            else:
                os.system(f"ssh-keygen -t ed25519 -f {shared_key_path} -N ''")
            logging.info(
                f"Generated shared {key_type} key pair: {shared_key_path}, {shared_pub_key_path}"
            )

        with open(shared_pub_key_path, "r") as f:
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
    def run_command_on_inventory(
        inventory, command, group="all", parallel=False, max_threads=5
    ):
        """
        Run a shell command on all hosts in the specified group of the YAML inventory.
        :param inventory: Path to the YAML inventory file.
        :param command: The shell command to run.
        :param group: Inventory group to target (default: 'all').
        :param parallel: Run in parallel.
        :param max_threads: Max threads for parallel.
        """
        logger = logging.getLogger("Tunnel")
        logger.info(f"Running command '{command}' on group '{group}'")
        print(f"Executing command '{command}' on group '{group}'...")

        def run_host(host):
            try:
                tunnel = Tunnel(
                    remote_host=host["hostname"],
                    username=host["username"],
                    password=host.get("password"),
                    identity_file=host.get("key_path"),
                )
                out, err = tunnel.run_command(command)
                logger.info(
                    f"Host {host['hostname']}: In: {command}, Out: {out}, Err: {err}"
                )
                print(
                    f"Host {host['hostname']}:\nInput: {command}\nOutput: {out}\nError: {err}"
                )
                tunnel.close()
            except Exception as e:
                logger.error(f"Failed to run command on {host['hostname']}: {str(e)}")
                print(f"Error on {host['hostname']}: {str(e)}", file=sys.stderr)

        try:
            Tunnel.execute_on_inventory(
                inventory, run_host, group, parallel, max_threads
            )
            print(f"Completed command execution on group '{group}'")
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
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
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
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
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
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
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
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
            )
            tunnel.receive_file(remote_path, local_path)
            logging.info(f"Host {host['hostname']}: File downloaded to {local_path}")
            tunnel.close()

        os.makedirs(local_path_prefix, exist_ok=True)
        Tunnel.execute_on_inventory(
            inventory, receive_host, group, parallel, max_threads
        )


def tunnel_manager():
    print(f"tunnel_manager v{__version__}")
    parser = argparse.ArgumentParser(add_help=False, description="Tunnel Manager CLI")
    parser.add_argument("--log-file", help="Log to this file (default: console output)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    setup_parser = subparsers.add_parser("setup-all", help="Setup passwordless for all")
    setup_parser.add_argument("--inventory", help="YAML inventory path")
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
    run_parser.add_argument("--inventory", help="YAML inventory path")
    run_parser.add_argument("--remote-command", help="Shell command to run")
    run_parser.add_argument(
        "--group", default="all", help="Inventory group to target (default: all)"
    )
    run_parser.add_argument("--parallel", action="store_true", help="Run in parallel")
    run_parser.add_argument(
        "--max-threads", type=int, default=5, help="Max threads for parallel execution"
    )

    copy_parser = subparsers.add_parser("copy-config", help="Copy SSH config to all")
    copy_parser.add_argument("--inventory", help="YAML inventory path")
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
    rotate_parser.add_argument("--inventory", help="YAML inventory path")
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
    send_parser.add_argument("--inventory", help="YAML inventory path")
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
    receive_parser.add_argument("--inventory", help="YAML inventory path")
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

    parser.add_argument("--help", action="store_true", help="Show usage")

    args = parser.parse_args()

    if hasattr(args, "help") and args.help:

        usage()

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
    print(f"Starting Tunnel Automation with command: {args.command}")

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
        print("Automation Complete")
    except Exception as e:
        logger.error(f"Automation failed: {str(e)}")
        print(f"Error: Automation failed: {str(e)}", file=sys.stderr)
        sys.exit(1)


def usage():
    print(
        f"Tunnel Manager ({__version__}): Tunnel Manager CLI\n\n"
        "Usage:\n"
        "--log-file              [ Log to this file (default: console output) ]\n"
        "--inventory             [ YAML inventory path ]\n"
        "--shared-key-path       [ Path to shared private key ]\n"
        "--key-type              [ Key type to generate (rsa or ed25519, default: ed25519) ]\n"
        "--group                 [ Inventory group to target (default: all) ]\n"
        "--parallel              [ Run in parallel ]\n"
        "--max-threads           [ Max threads for parallel execution ]\n"
        "--inventory             [ YAML inventory path ]\n"
        "--remote-command        [ Shell command to run ]\n"
        "--group                 [ Inventory group to target (default: all) ]\n"
        "--parallel              [ Run in parallel ]\n"
        "--max-threads           [ Max threads for parallel execution ]\n"
        "--inventory             [ YAML inventory path ]\n"
        "--local-config-path     [ Local SSH config path ]\n"
        "--remote-config-path    [ Remote path (default ~/.ssh/config) ]\n"
        "--group                 [ Inventory group to target (default: all) ]\n"
        "--parallel              [ Run in parallel ]\n"
        "--max-threads           [ Max threads for parallel execution ]\n"
        "--inventory             [ YAML inventory path ]\n"
        "--key-prefix            [ Prefix for new key paths (appends hostname) ]\n"
        "--key-type              [ Key type to generate (rsa or ed25519, default: ed25519) ]\n"
        "--group                 [ Inventory group to target (default: all) ]\n"
        "--parallel              [ Run in parallel ]\n"
        "--max-threads           [ Max threads for parallel execution ]\n"
        "--inventory             [ YAML inventory path ]\n"
        "--local-path            [ Local file path to upload ]\n"
        "--remote-path           [ Remote destination path ]\n"
        "--group                 [ Inventory group to target (default: all) ]\n"
        "--parallel              [ Run in parallel ]\n"
        "--max-threads           [ Max threads for parallel execution ]\n"
        "--inventory             [ YAML inventory path ]\n"
        "--remote-path           [ Remote file path to download ]\n"
        "--local-path-prefix     [ Local directory path prefix to save files ]\n"
        "--group                 [ Inventory group to target (default: all) ]\n"
        "--parallel              [ Run in parallel ]\n"
        "--max-threads           [ Max threads for parallel execution ]\n"
        "\n"
        "Examples:\n"
        "  [Simple]  tunnel-manager \n"
        '  [Complex] tunnel-manager --log-file "value" --inventory "value" --shared-key-path "value" --key-type "value" --group "value" --parallel --max-threads "value" --inventory "value" --remote-command "value" --group "value" --parallel --max-threads "value" --inventory "value" --local-config-path "value" --remote-config-path "value" --group "value" --parallel --max-threads "value" --inventory "value" --key-prefix "value" --key-type "value" --group "value" --parallel --max-threads "value" --inventory "value" --local-path "value" --remote-path "value" --group "value" --parallel --max-threads "value" --inventory "value" --remote-path "value" --local-path-prefix "value" --group "value" --parallel --max-threads "value"\n'
    )


if __name__ == "__main__":
    tunnel_manager()
