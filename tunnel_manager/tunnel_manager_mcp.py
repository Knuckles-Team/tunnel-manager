#!/usr/bin/python
# coding: utf-8
import argparse
import os
import sys
import logging
from typing import Optional
from tunnel_manager.tunnel_manager import Tunnel
from fastmcp import FastMCP, Context
from pydantic import Field

logging.basicConfig(filename="tunnel_mcp.log", level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

mcp = FastMCP(name="TunnelServer")

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
        remote_host: str = Field(description="The remote host to connect to.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)),
        remote_port: str = Field(description="The remote host's port to connect to.", default=os.environ.get("TUNNEL_REMOTE_PORT", None)),
        command: str = Field(description="The shell command to run on the remote host.", default=None),
        identity_file: Optional[str] = Field(description="Path to the private key file.", default=os.environ.get("TUNNEL_IDENTITY_FILE", None)),
        certificate_file: Optional[str] = Field(description="Path to the certificate file (for Teleport).", default=os.environ.get("TUNNEL_CERTIFICATE", None)),
        proxy_command: Optional[str] = Field(description="Proxy command (for Teleport).", default=os.environ.get("TUNNEL_PROXY_COMMAND", None)),
        log_file: Optional[str] = Field(description="Path to log file for this operation.", default=os.environ.get("TUNNEL_LOG_FILE", None)),
        ctx: Context = Field(description="MCP context for progress reporting.", default=None),
) -> str:
    """Runs a shell command on a remote host via SSH or Teleport."""
    logger = logging.getLogger("TunnelServer")
    logger.debug(f"Starting run_remote_command for host: {remote_host}, command: {command}")

    if not remote_host or not command:
        raise ValueError("remote_host and command must be provided.")

    try:
        tunnel = Tunnel(remote_host, identity_file, certificate_file, proxy_command, log_file)

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
        if 'tunnel' in locals():
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
        remote_host: str = Field(description="The remote host to connect to.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)),
        remote_port: str = Field(description="The remote host's port to connect to.", default=os.environ.get("TUNNEL_REMOTE_PORT", None)),
        local_path: str = Field(description="Local file path to upload.", default=None),
        remote_path: str = Field(description="Remote destination path.", default=None),
        identity_file: Optional[str] = Field(description="Path to the private key file.", default=os.environ.get("TUNNEL_IDENTITY_FILE", None)),
        certificate_file: Optional[str] = Field(description="Path to the certificate file (for Teleport).", default=os.environ.get("TUNNEL_CERTIFICATE", None)),
        proxy_command: Optional[str] = Field(description="Proxy command (for Teleport).", default=os.environ.get("TUNNEL_PROXY_COMMAND", None)),
        log_file: Optional[str] = Field(description="Path to log file for this operation.", default=os.environ.get("TUNNEL_LOG_FILE", None)),
        ctx: Context = Field(description="MCP context for progress reporting.", default=None),
) -> str:
    """Uploads a file to a remote host via SSH or Teleport."""
    logger = logging.getLogger("TunnelServer")
    logger.debug(f"Starting upload_file for host: {remote_host}, local: {local_path}, remote: {remote_path}")

    if not remote_host or not local_path or not remote_path:
        raise ValueError("remote_host, local_path, and remote_path must be provided.")

    if not os.path.exists(local_path):
        raise ValueError(f"Local file does not exist: {local_path}")

    try:
        tunnel = Tunnel(remote_host, identity_file, certificate_file, proxy_command, log_file)
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
        if 'tunnel' in locals():
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
        remote_host: str = Field(description="The remote host to connect to.", default=os.environ.get("TUNNEL_REMOTE_HOST", None)),
        remote_port: str = Field(description="The remote host's port to connect to.", default=os.environ.get("TUNNEL_REMOTE_PORT", None)),
        remote_path: str = Field(description="Remote file path to download.", default=None),
        local_path: str = Field(description="Local destination path.", default=None),
        identity_file: Optional[str] = Field(description="Path to the private key file.", default=os.environ.get("TUNNEL_IDENTITY_FILE", None)),
        certificate_file: Optional[str] = Field(description="Path to the certificate file (for Teleport).", default=os.environ.get("TUNNEL_CERTIFICATE", None)),
        proxy_command: Optional[str] = Field(description="Proxy command (for Teleport).", default=os.environ.get("TUNNEL_PROXY_COMMAND", None)),
        log_file: Optional[str] = Field(description="Path to log file for this operation.", default=os.environ.get("TUNNEL_LOG_FILE", None)),
        ctx: Context = Field(description="MCP context for progress reporting.", default=None),
) -> str:
    """Downloads a file from a remote host via SSH or Teleport."""
    logger = logging.getLogger("TunnelServer")
    logger.debug(f"Starting download_file for host: {remote_host}, remote: {remote_path}, local: {local_path}")

    if not remote_host or not remote_path or not local_path:
        raise ValueError("remote_host, remote_path, and local_path must be provided.")

    try:
        tunnel = Tunnel(remote_host, identity_file, certificate_file, proxy_command, log_file)
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
        if 'tunnel' in locals():
            tunnel.close()

def tunnel_mcp():
    parser = argparse.ArgumentParser(
        description="Tunnel MCP Server for remote SSH and file operations",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-t", "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport method for the MCP server (stdio or http)."
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host address for HTTP transport."
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=8000,
        help="Port for HTTP transport (0-65535)."
    )

    args = parser.parse_args()

    if args.port < 0 or args.port > 65535:
        print(f"Error: Port {args.port} is out of valid range (0-65535).")
        sys.exit(1)

    logger = logging.getLogger("TunnelServer")
    if args.transport == "stdio":
        logger.info("Starting MCP server with stdio transport")
        mcp.run(transport="stdio")
    elif args.transport == "http":
        logger.info(f"Starting MCP server with HTTP transport on {args.host}:{args.port}")
        mcp.run(transport="http", host=args.host, port=args.port)
    else:
        logger.error("Transport not supported")
        sys.exit(1)

if __name__ == "__main__":
    tunnel_mcp()