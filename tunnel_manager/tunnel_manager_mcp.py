import os
import sys
import argparse
import logging
import concurrent.futures
import yaml
import asyncio
from typing import Optional
from tunnel_manager.tunnel_manager import Tunnel
from fastmcp import FastMCP, Context
from pydantic import Field

# Initialize FastMCP
mcp = FastMCP(name="TunnelServer")

# Configure default logging
logging.basicConfig(
    filename="tunnel_mcp.log",
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


# Updated and New MCP Tools
@mcp.tool(
    annotations={
        "title": "Run Remote Command",
        "readOnlyHint": True,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def run_remote_command(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication (if no identity_file).",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    command: str = Field(
        description="The shell command to run on the remote host.",
        default=None,
    ),
    identity_file: Optional[str] = Field(
        description="Path to the private key file.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate_file: Optional[str] = Field(
        description="Path to the certificate file (for Teleport).",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy_command: Optional[str] = Field(
        description="Proxy command (for Teleport).",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Runs a shell command on a remote host via SSH or Teleport."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting run_remote_command for host: {remote_host}, command: {command}"
    )

    if not remote_host or not command:
        raise ValueError("remote_host and command must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            identity_file=identity_file,
            certificate_file=certificate_file,
            proxy_command=proxy_command,
            ssh_config_file=ssh_config_file,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        tunnel.connect()
        out, err = tunnel.run_command(command)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"Command output: {out}, error: {err}")
        return f"Output:\n{out}\nError:\n{err}"
    except Exception as e:
        logger.error(f"Failed to run command: {str(e)}")
        raise RuntimeError(f"Failed to run command: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Upload File",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def upload_file(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication (if no identity_file).",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    local_path: str = Field(description="Local file path to upload.", default=None),
    remote_path: str = Field(description="Remote destination path.", default=None),
    identity_file: Optional[str] = Field(
        description="Path to the private key file.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate_file: Optional[str] = Field(
        description="Path to the certificate file (for Teleport).",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy_command: Optional[str] = Field(
        description="Proxy command (for Teleport).",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Uploads a file to a remote host via SSH or Teleport."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting upload_file for host: {remote_host}, local: {local_path}, remote: {remote_path}"
    )

    if not remote_host or not local_path or not remote_path:
        raise ValueError("remote_host, local_path, and remote_path must be provided.")

    if not os.path.exists(local_path):
        raise ValueError(f"Local file does not exist: {local_path}")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            identity_file=identity_file,
            certificate_file=certificate_file,
            proxy_command=proxy_command,
            ssh_config_file=ssh_config_file,
        )
        tunnel.connect()

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        sftp = tunnel.ssh_client.open_sftp()
        file_size = os.path.getsize(local_path)
        transferred = 0

        def progress_callback(transf, total):
            nonlocal transferred
            transferred = transf
            if ctx:
                asyncio.ensure_future(ctx.report_progress(progress=transf, total=total))

        sftp.put(local_path, remote_path, callback=progress_callback)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        sftp.close()
        logger.debug(f"File uploaded: {local_path} -> {remote_path}")
        return f"File uploaded successfully to {remote_path}"
    except Exception as e:
        logger.error(f"Failed to upload file: {str(e)}")
        raise RuntimeError(f"Failed to upload file: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Download File",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def download_file(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication (if no identity_file).",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    remote_path: str = Field(description="Remote file path to download.", default=None),
    local_path: str = Field(description="Local destination path.", default=None),
    identity_file: Optional[str] = Field(
        description="Path to the private key file.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate_file: Optional[str] = Field(
        description="Path to the certificate file (for Teleport).",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy_command: Optional[str] = Field(
        description="Proxy command (for Teleport).",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Downloads a file from a remote host via SSH or Teleport."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting download_file for host: {remote_host}, remote: {remote_path}, local: {local_path}"
    )

    if not remote_host or not remote_path or not local_path:
        raise ValueError("remote_host, remote_path, and local_path must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            identity_file=identity_file,
            certificate_file=certificate_file,
            proxy_command=proxy_command,
            ssh_config_file=ssh_config_file,
        )
        tunnel.connect()

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        sftp = tunnel.ssh_client.open_sftp()
        remote_attr = sftp.stat(remote_path)
        file_size = remote_attr.st_size
        transferred = 0

        def progress_callback(transf, total):
            nonlocal transferred
            transferred = transf
            if ctx:
                asyncio.ensure_future(ctx.report_progress(progress=transf, total=total))

        sftp.get(remote_path, local_path, callback=progress_callback)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        sftp.close()
        logger.debug(f"File downloaded: {remote_path} -> {local_path}")
        return f"File downloaded successfully to {local_path}"
    except Exception as e:
        logger.error(f"Failed to download file: {str(e)}")
        raise RuntimeError(f"Failed to download file: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Check SSH Server",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def check_ssh_server(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication (if no identity_file).",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    identity_file: Optional[str] = Field(
        description="Path to the private key file.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate_file: Optional[str] = Field(
        description="Path to the certificate file (for Teleport).",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy_command: Optional[str] = Field(
        description="Proxy command (for Teleport).",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Check if the SSH server is running and configured for key-based authentication."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(f"Starting check_ssh_server for host: {remote_host}")

    if not remote_host:
        raise ValueError("remote_host must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            identity_file=identity_file,
            certificate_file=certificate_file,
            proxy_command=proxy_command,
            ssh_config_file=ssh_config_file,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        success, message = tunnel.check_ssh_server()

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"SSH server check result: {message}")
        return f"SSH server check: {message}"
    except Exception as e:
        logger.error(f"Failed to check SSH server: {str(e)}")
        raise RuntimeError(f"Failed to check SSH server: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Test Key Authentication",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def test_key_auth(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    local_key_path: str = Field(
        description="Path to the private key to test.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Test if key-based authentication works for the remote host."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting test_key_auth for host: {remote_host}, key: {local_key_path}"
    )

    if not remote_host or not local_key_path:
        raise ValueError("remote_host and local_key_path must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            port=port,
            ssh_config_file=ssh_config_file,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        success, message = tunnel.test_key_auth(local_key_path)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"Key auth test result: {message}")
        return f"Key auth test: {message}"
    except Exception as e:
        logger.error(f"Failed to test key auth: {str(e)}")
        raise RuntimeError(f"Failed to test key auth: {str(e)}")


@mcp.tool(
    annotations={
        "title": "Setup Passwordless SSH",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def setup_passwordless_ssh(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication.",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    local_key_path: str = Field(
        description="Path to the private key (public key is assumed to be .pub).",
        default=os.path.expanduser("~/.ssh/id_rsa"),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Set up passwordless SSH by copying a public key to the remote host."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting setup_passwordless_ssh for host: {remote_host}, key: {local_key_path}"
    )

    if not remote_host or not password:
        raise ValueError("remote_host and password must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            ssh_config_file=ssh_config_file,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        tunnel.setup_passwordless_ssh(local_key_path)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"Passwordless SSH setup for {username}@{remote_host}")
        return f"Passwordless SSH setup completed for {username}@{remote_host}"
    except Exception as e:
        logger.error(f"Failed to setup passwordless SSH: {str(e)}")
        raise RuntimeError(f"Failed to setup passwordless SSH: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Copy SSH Config",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def copy_ssh_config(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication (if no identity_file).",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    local_config_path: str = Field(
        description="Local SSH config file path.",
        default=None,
    ),
    remote_config_path: str = Field(
        description="Remote destination path for SSH config.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    identity_file: Optional[str] = Field(
        description="Path to the private key file.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate_file: Optional[str] = Field(
        description="Path to the certificate file (for Teleport).",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy_command: Optional[str] = Field(
        description="Proxy command (for Teleport).",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Copy a local SSH config to the remote host’s ~/.ssh/config."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting copy_ssh_config for host: {remote_host}, local: {local_config_path}, remote: {remote_config_path}"
    )

    if not remote_host or not local_config_path:
        raise ValueError("remote_host and local_config_path must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            identity_file=identity_file,
            certificate_file=certificate_file,
            proxy_command=proxy_command,
            ssh_config_file=ssh_config_file,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        tunnel.copy_ssh_config(local_config_path, remote_config_path)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"Copied SSH config to {remote_config_path} on {remote_host}")
        return f"SSH config copied to {remote_config_path} on {remote_host}"
    except Exception as e:
        logger.error(f"Failed to copy SSH config: {str(e)}")
        raise RuntimeError(f"Failed to copy SSH config: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Rotate SSH Key",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def rotate_ssh_key(
    remote_host: str = Field(
        description="The remote host to connect to.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    username: Optional[str] = Field(
        description="Username for authentication.",
        default=os.environ.get("TUNNEL_USERNAME", None),
    ),
    password: Optional[str] = Field(
        description="Password for authentication (if no identity_file).",
        default=os.environ.get("TUNNEL_PASSWORD", None),
    ),
    port: int = Field(
        description="The remote host's port to connect to.",
        default=int(os.environ.get("TUNNEL_REMOTE_PORT", 22)),
    ),
    new_key_path: str = Field(
        description="Path for the new private key.",
        default=None,
    ),
    identity_file: Optional[str] = Field(
        description="Path to the current private key file.",
        default=os.environ.get("TUNNEL_IDENTITY_FILE", None),
    ),
    certificate_file: Optional[str] = Field(
        description="Path to the certificate file (for Teleport).",
        default=os.environ.get("TUNNEL_CERTIFICATE", None),
    ),
    proxy_command: Optional[str] = Field(
        description="Proxy command (for Teleport).",
        default=os.environ.get("TUNNEL_PROXY_COMMAND", None),
    ),
    ssh_config_file: str = Field(
        description="Path to SSH config file.",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Rotate the SSH key by generating a new pair and updating authorized_keys."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting rotate_ssh_key for host: {remote_host}, new key: {new_key_path}"
    )

    if not remote_host or not new_key_path:
        raise ValueError("remote_host and new_key_path must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
            username=username,
            password=password,
            port=port,
            identity_file=identity_file,
            certificate_file=certificate_file,
            proxy_command=proxy_command,
            ssh_config_file=ssh_config_file,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        tunnel.rotate_ssh_key(new_key_path)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"Rotated key to {new_key_path} on {remote_host}")
        return f"SSH key rotated to {new_key_path} on {remote_host}. Update SSH config IdentityFile to {new_key_path}."
    except Exception as e:
        logger.error(f"Failed to rotate SSH key: {str(e)}")
        raise RuntimeError(f"Failed to rotate SSH key: {str(e)}")
    finally:
        if "tunnel" in locals():
            tunnel.close()


@mcp.tool(
    annotations={
        "title": "Remove Host Key",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def remove_host_key(
    remote_host: str = Field(
        description="The remote host to remove from known_hosts.",
        default=os.environ.get("TUNNEL_REMOTE_HOST", None),
    ),
    known_hosts_path: str = Field(
        description="Path to the known_hosts file.",
        default=os.path.expanduser("~/.ssh/known_hosts"),
    ),
    log_file: Optional[str] = Field(
        description="Path to log file for this operation.",
        default=os.environ.get("TUNNEL_LOG_FILE", None),
    ),
    ctx: Context = Field(
        description="MCP context for progress reporting.",
        default=None,
    ),
) -> str:
    """Remove the host key for the remote host from the known_hosts file."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting remove_host_key for host: {remote_host}, known_hosts: {known_hosts_path}"
    )

    if not remote_host:
        raise ValueError("remote_host must be provided.")

    try:
        tunnel = Tunnel(
            remote_host=remote_host,
        )

        if ctx:
            await ctx.report_progress(progress=0, total=100)
            logger.debug("Reported initial progress: 0/100")

        tunnel.remove_host_key(known_hosts_path)

        if ctx:
            await ctx.report_progress(progress=100, total=100)
            logger.debug("Reported final progress: 100/100")

        logger.debug(f"Removed host key for {remote_host} from {known_hosts_path}")
        return f"Removed host key for {remote_host} from {known_hosts_path}"
    except Exception as e:
        logger.error(f"Failed to remove host key: {str(e)}")
        raise RuntimeError(f"Failed to remove host key: {str(e)}")


@mcp.tool(
    annotations={
        "title": "Setup Passwordless SSH for All",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def setup_all_passwordless_ssh(
    inventory_path: str = Field(
        description="Path to the YAML inventory file.", default=None
    ),
    shared_key_path: str = Field(
        description="Path to shared private key.",
        default=os.path.expanduser("~/.ssh/id_shared"),
    ),
    group: str = Field(description="Inventory group to target.", default="all"),
    parallel: bool = Field(description="Run in parallel.", default=False),
    max_threads: int = Field(
        description="Max threads for parallel execution.", default=5
    ),
    log_file: Optional[str] = Field(description="Path to log file.", default=None),
    ctx: Context = Field(
        description="MCP context for progress reporting.", default=None
    ),
) -> str:
    """Set up passwordless SSH for all hosts in the specified group of the YAML inventory."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting setup_all_passwordless_ssh for inventory: {inventory_path}, group: {group}"
    )

    if not inventory_path:
        raise ValueError("inventory_path must be provided.")

    try:
        shared_key_path = os.path.expanduser(shared_key_path)
        shared_pub_key_path = shared_key_path + ".pub"
        if not os.path.exists(shared_key_path):
            os.system(f"ssh-keygen -t rsa -b 4096 -f {shared_key_path} -N ''")
            logger.info(
                f"Generated shared key pair: {shared_key_path}, {shared_pub_key_path}"
            )

        with open(shared_pub_key_path, "r") as f:
            shared_pub_key = f.read().strip()

        async def setup_host(host, ctx):
            hostname = host["hostname"]
            username = host["username"]
            password = host["password"]
            key_path = host.get("key_path", shared_key_path)
            logger.info(f"Setting up {username}@{hostname}...")
            tunnel = Tunnel(
                remote_host=hostname,
                username=username,
                password=password,
            )
            tunnel.remove_host_key()
            tunnel.setup_passwordless_ssh(local_key_path=key_path)
            try:
                tunnel.connect()
                tunnel.run_command(f"echo '{shared_pub_key}' >> ~/.ssh/authorized_keys")
                tunnel.run_command("chmod 600 ~/.ssh/authorized_keys")
                logger.info(f"Added shared key to {username}@{hostname}")
            except Exception as e:
                logger.error(
                    f"Failed to add shared key to {username}@{hostname}: {str(e)}"
                )
            finally:
                tunnel.close()
            result, msg = tunnel.test_key_auth(shared_key_path)
            logger.info(f"Key auth test for {username}@{hostname}: {msg}")

        with open(inventory_path, "r") as f:
            inventory = yaml.safe_load(f)

        hosts = []
        if (
            group in inventory
            and isinstance(inventory[group], dict)
            and "hosts" in inventory[group]
        ):
            for host, vars in inventory[group]["hosts"].items():
                host_entry = {
                    "hostname": vars.get("ansible_host", host),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file"),
                }
                hosts.append(host_entry)
        else:
            raise ValueError(f"Group '{group}' not found in inventory or invalid.")

        total_hosts = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total_hosts)
            logger.debug(f"Reported initial progress: 0/{total_hosts}")

        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [
                    executor.submit(lambda h: asyncio.run(setup_host(h, ctx)), host)
                    for host in hosts
                ]
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        completed += 1
                        if ctx:
                            await ctx.report_progress(
                                progress=completed, total=total_hosts
                            )
                            logger.debug(
                                f"Reported progress: {completed}/{total_hosts}"
                            )
                    except Exception as e:
                        logger.error(f"Error: {e}")
        else:
            for i, host in enumerate(hosts):
                await setup_host(host, ctx)
                if ctx:
                    await ctx.report_progress(progress=i + 1, total=total_hosts)
                    logger.debug(f"Reported progress: {i + 1}/{total_hosts}")

        logger.debug(f"Completed passwordless SSH setup for group {group}")
        return f"Passwordless SSH setup completed for group {group}"
    except Exception as e:
        logger.error(f"Failed to setup passwordless SSH for all: {str(e)}")
        raise RuntimeError(f"Failed to setup passwordless SSH for all: {str(e)}")


@mcp.tool(
    annotations={
        "title": "Run Command on All Hosts",
        "readOnlyHint": True,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def run_command_on_all(
    inventory_path: str = Field(
        description="Path to the YAML inventory file.", default=None
    ),
    command: str = Field(
        description="Shell command to run on all hosts.", default=None
    ),
    group: str = Field(description="Inventory group to target.", default="all"),
    parallel: bool = Field(description="Run in parallel.", default=False),
    max_threads: int = Field(
        description="Max threads for parallel execution.", default=5
    ),
    log_file: Optional[str] = Field(description="Path to log file.", default=None),
    ctx: Context = Field(
        description="MCP context for progress reporting.", default=None
    ),
) -> str:
    """Run a shell command on all hosts in the specified group of the YAML inventory."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting run_command_on_all for inventory: {inventory_path}, group: {group}, command: {command}"
    )

    if not inventory_path or not command:
        raise ValueError("inventory_path and command must be provided.")

    try:

        async def run_host(host, ctx):
            tunnel = Tunnel(
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
            )
            out, err = tunnel.run_command(command)
            logger.info(f"Host {host['hostname']}: Out: {out}, Err: {err}")
            tunnel.close()

        with open(inventory_path, "r") as f:
            inventory = yaml.safe_load(f)

        hosts = []
        if (
            group in inventory
            and isinstance(inventory[group], dict)
            and "hosts" in inventory[group]
        ):
            for host, vars in inventory[group]["hosts"].items():
                host_entry = {
                    "hostname": vars.get("ansible_host", host),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file"),
                }
                hosts.append(host_entry)
        else:
            raise ValueError(f"Group '{group}' not found in inventory or invalid.")

        total_hosts = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total_hosts)
            logger.debug(f"Reported initial progress: 0/{total_hosts}")

        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [
                    executor.submit(lambda h: asyncio.run(run_host(h, ctx)), host)
                    for host in hosts
                ]
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        completed += 1
                        if ctx:
                            await ctx.report_progress(
                                progress=completed, total=total_hosts
                            )
                            logger.debug(
                                f"Reported progress: {completed}/{total_hosts}"
                            )
                    except Exception as e:
                        logger.error(f"Error: {e}")
        else:
            for i, host in enumerate(hosts):
                await run_host(host, ctx)
                if ctx:
                    await ctx.report_progress(progress=i + 1, total=total_hosts)
                    logger.debug(f"Reported progress: {i + 1}/{total_hosts}")

        logger.debug(f"Completed command execution for group {group}")
        return f"Command '{command}' executed on group {group}"
    except Exception as e:
        logger.error(f"Failed to run command on all: {str(e)}")
        raise RuntimeError(f"Failed to run command on all: {str(e)}")


@mcp.tool(
    annotations={
        "title": "Copy SSH Config to All Hosts",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def copy_ssh_config_on_all(
    inventory_path: str = Field(
        description="Path to the YAML inventory file.", default=None
    ),
    local_config_path: str = Field(description="Local SSH config path.", default=None),
    remote_config_path: str = Field(
        description="Remote path (default ~/.ssh/config).",
        default=os.path.expanduser("~/.ssh/config"),
    ),
    group: str = Field(description="Inventory group to target.", default="all"),
    parallel: bool = Field(description="Run in parallel.", default=False),
    max_threads: int = Field(
        description="Max threads for parallel execution.", default=5
    ),
    log_file: Optional[str] = Field(description="Path to log file.", default=None),
    ctx: Context = Field(
        description="MCP context for progress reporting.", default=None
    ),
) -> str:
    """Copy local SSH config to all hosts in the specified group of the YAML inventory."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting copy_ssh_config_on_all for inventory: {inventory_path}, group: {group}"
    )

    if not inventory_path or not local_config_path:
        raise ValueError("inventory_path and local_config_path must be provided.")

    try:

        async def copy_host(host, ctx):
            tunnel = Tunnel(
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
            )
            tunnel.copy_ssh_config(local_config_path, remote_config_path)
            tunnel.close()

        with open(inventory_path, "r") as f:
            inventory = yaml.safe_load(f)

        hosts = []
        if (
            group in inventory
            and isinstance(inventory[group], dict)
            and "hosts" in inventory[group]
        ):
            for host, vars in inventory[group]["hosts"].items():
                host_entry = {
                    "hostname": vars.get("ansible_host", host),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file"),
                }
                hosts.append(host_entry)
        else:
            raise ValueError(f"Group '{group}' not found in inventory or invalid.")

        total_hosts = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total_hosts)
            logger.debug(f"Reported initial progress: 0/{total_hosts}")

        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [
                    executor.submit(lambda h: asyncio.run(copy_host(h, ctx)), host)
                    for host in hosts
                ]
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        completed += 1
                        if ctx:
                            await ctx.report_progress(
                                progress=completed, total=total_hosts
                            )
                            logger.debug(
                                f"Reported progress: {completed}/{total_hosts}"
                            )
                    except Exception as e:
                        logger.error(f"Error: {e}")
        else:
            for i, host in enumerate(hosts):
                await copy_host(host, ctx)
                if ctx:
                    await ctx.report_progress(progress=i + 1, total=total_hosts)
                    logger.debug(f"Reported progress: {i + 1}/{total_hosts}")

        logger.debug(f"Completed SSH config copy for group {group}")
        return f"SSH config copied to group {group}"
    except Exception as e:
        logger.error(f"Failed to copy SSH config to all: {str(e)}")
        raise RuntimeError(f"Failed to copy SSH config to all: {str(e)}")


@mcp.tool(
    annotations={
        "title": "Rotate SSH Keys for All Hosts",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": False,
        "openWorldHint": False,
    },
    tags={"remote_access"},
)
async def rotate_ssh_key_on_all(
    inventory_path: str = Field(
        description="Path to the YAML inventory file.", default=None
    ),
    key_prefix: str = Field(
        description="Prefix for new key paths (appends hostname).",
        default=os.path.expanduser("~/.ssh/id_"),
    ),
    group: str = Field(description="Inventory group to target.", default="all"),
    parallel: bool = Field(description="Run in parallel.", default=False),
    max_threads: int = Field(
        description="Max threads for parallel execution.", default=5
    ),
    log_file: Optional[str] = Field(description="Path to log file.", default=None),
    ctx: Context = Field(
        description="MCP context for progress reporting.", default=None
    ),
) -> str:
    """Rotate SSH keys for all hosts in the specified group of the YAML inventory."""
    logger = logging.getLogger("TunnelServer")
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        )
    logger.debug(
        f"Starting rotate_ssh_key_on_all for inventory: {inventory_path}, group: {group}"
    )

    if not inventory_path:
        raise ValueError("inventory_path must be provided.")

    try:

        async def rotate_host(host, ctx):
            new_key_path = os.path.expanduser(key_prefix + host["hostname"])
            tunnel = Tunnel(
                remote_host=host["hostname"],
                username=host["username"],
                password=host.get("password"),
                identity_file=host.get("key_path"),
            )
            tunnel.rotate_ssh_key(new_key_path)
            logger.info(
                f"Rotated key for {host['hostname']}. Update inventory key_path to {new_key_path} if needed."
            )
            tunnel.close()

        with open(inventory_path, "r") as f:
            inventory = yaml.safe_load(f)

        hosts = []
        if (
            group in inventory
            and isinstance(inventory[group], dict)
            and "hosts" in inventory[group]
        ):
            for host, vars in inventory[group]["hosts"].items():
                host_entry = {
                    "hostname": vars.get("ansible_host", host),
                    "username": vars.get("ansible_user"),
                    "password": vars.get("ansible_ssh_pass"),
                    "key_path": vars.get("ansible_ssh_private_key_file"),
                }
                hosts.append(host_entry)
        else:
            raise ValueError(f"Group '{group}' not found in inventory or invalid.")

        total_hosts = len(hosts)
        if ctx:
            await ctx.report_progress(progress=0, total=total_hosts)
            logger.debug(f"Reported initial progress: 0/{total_hosts}")

        if parallel:
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_threads
            ) as executor:
                futures = [
                    executor.submit(lambda h: asyncio.run(rotate_host(h, ctx)), host)
                    for host in hosts
                ]
                completed = 0
                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        completed += 1
                        if ctx:
                            await ctx.report_progress(
                                progress=completed, total=total_hosts
                            )
                            logger.debug(
                                f"Reported progress: {completed}/{total_hosts}"
                            )
                    except Exception as e:
                        logger.error(f"Error: {e}")
        else:
            for i, host in enumerate(hosts):
                await rotate_host(host, ctx)
                if ctx:
                    await ctx.report_progress(progress=i + 1, total=total_hosts)
                    logger.debug(f"Reported progress: {i + 1}/{total_hosts}")

        logger.debug(f"Completed SSH key rotation for group {group}")
        return f"SSH keys rotated for group {group}"
    except Exception as e:
        logger.error(f"Failed to rotate SSH keys for all: {str(e)}")
        raise RuntimeError(f"Failed to rotate SSH keys for all: {str(e)}")


def tunnel_manager_mcp():
    parser = argparse.ArgumentParser(
        description="Tunnel MCP Server for remote SSH and file operations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--transport",
        default="stdio",
        choices=["stdio", "http", "sse"],
        help="Transport method: 'stdio', 'http', or 'sse' [legacy] (default: stdio)",
    )
    parser.add_argument(
        "-s",
        "--host",
        default="0.0.0.0",
        help="Host address for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=8000,
        help="Port number for HTTP transport (default: 8000)",
    )

    args = parser.parse_args()

    if args.port < 0 or args.port > 65535:
        print(f"Error: Port {args.port} is out of valid range (0-65535).")
        sys.exit(1)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "http":
        mcp.run(transport="http", host=args.host, port=args.port)
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    else:
        logger = logging.getLogger("TunnelServer")
        logger.error("Transport not supported")
        sys.exit(1)


if __name__ == "__main__":
    tunnel_manager_mcp()
