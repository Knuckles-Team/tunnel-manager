import logging
import os
import paramiko


class Tunnel:
    def __init__(
        self,
        remote_host: str,
        port: int = 22,
        identity_file: str = None,
        certificate_file: str = None,
        proxy_command: str = None,
        log_file: str = None,
    ):
        """
        Initialize the Tunnel class.

        :param remote_host: The hostname or IP of the remote host.
        :param identity_file: Optional path to the private key file (overrides config).
        :param certificate_file: Optional path to the certificate file (overrides config, used for Teleport).
        :param proxy_command: Optional proxy command string (overrides config, used for Teleport proxying).
        :param log_file: Optional path to a log file for recording operations.
        """
        self.remote_host = remote_host
        self.port = port
        self.ssh_client = None
        self.sftp = None
        self.logger = None

        # Load from ~/.ssh/config if not overridden
        ssh_config_path = os.path.expanduser("~/.ssh/config")
        self.ssh_config = paramiko.SSHConfig()
        if os.path.exists(ssh_config_path):
            with open(ssh_config_path) as f:
                self.ssh_config.parse(f)
        host_config = self.ssh_config.lookup(remote_host) or {}

        self.identity_file = identity_file or (
            host_config.get("identityfile", [None])[0]
            if "identityfile" in host_config
            else None
        )
        self.certificate_file = certificate_file or host_config.get("certificatefile")
        self.proxy_command = proxy_command or host_config.get("proxycommand")

        if not self.identity_file:
            raise ValueError(
                "Identity file must be provided either via parameter or in ~/.ssh/config."
            )

        if log_file:
            logging.basicConfig(
                filename=log_file,
                level=logging.INFO,
                format="%(asctime)s - %(levelname)s - %(message)s",
            )
            self.logger = logging.getLogger(__name__)
            self.logger.info(f"Tunnel initialized for host: {remote_host}")

    def connect(self):
        """
        Establish the SSH connection if not already connected.
        """
        if (
            self.ssh_client
            and self.ssh_client.get_transport()
            and self.ssh_client.get_transport().is_active()
        ):
            return  # Already connected

        self.ssh_client = paramiko.SSHClient()
        self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        proxy = None
        if self.proxy_command:
            proxy = paramiko.ProxyCommand(self.proxy_command)
            if self.logger:
                self.logger.info(f"Using proxy command: {self.proxy_command}")

        private_key = paramiko.RSAKey.from_private_key_file(self.identity_file)
        if self.certificate_file:
            private_key.load_certificate(self.certificate_file)
            if self.logger:
                self.logger.info(f"Loaded certificate: {self.certificate_file}")

        try:
            self.ssh_client.connect(
                self.remote_host,
                port=self.port,
                pkey=private_key,
                sock=proxy,
                auth_timeout=30,
                look_for_keys=False,
                allow_agent=False,
            )
            if self.logger:
                self.logger.info(f"Connected to {self.remote_host}")
        except Exception as e:
            if self.logger:
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
            if self.logger:
                self.logger.info(
                    f"Command executed: {command}\nOutput: {out}\nError: {err}"
                )
            return out, err
        except Exception as e:
            if self.logger:
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
            if not self.sftp:
                self.sftp = self.ssh_client.open_sftp()
            self.sftp.put(local_path, remote_path)
            if self.logger:
                self.logger.info(f"File sent: {local_path} -> {remote_path}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"File send failed: {str(e)}")
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
            if self.logger:
                self.logger.info(f"File received: {remote_path} -> {local_path}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"File receive failed: {str(e)}")
            raise
        finally:
            if self.sftp:
                self.sftp.close()
                self.sftp = None

    def close(self):
        """
        Close the SSH connection.
        """
        if self.ssh_client:
            self.ssh_client.close()
            if self.logger:
                self.logger.info(f"Connection closed for {self.remote_host}")
            self.ssh_client = None


# Example usage (commented out):
# tunnel = Tunnel("your-remote-host.example.com", log_file="tunnel.log")
# tunnel.connect()
# out, err = tunnel.run_command("ls -la")
# print(out)
# tunnel.send_file("/local/file.txt", "/remote/file.txt")
# tunnel.receive_file("/remote/file.txt", "/local/downloaded.txt")
# tunnel.close()
