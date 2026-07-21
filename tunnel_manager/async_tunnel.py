import asyncio
import logging
import os

import asyncssh
import yaml
from agent_utilities.core.config import setting

from .connection_security import (
    ConnectionPolicyError,
    max_fleet_hosts,
    max_output_bytes,
    validate_command,
    validate_timeout,
    validated_known_hosts_path,
)
from .connection_security import (
    max_concurrency as configured_max_concurrency,
)
from .models import CommandResult, HostConfig
from .proxy_security import proxy_command_argv
from .tunnel_manager import _known_hosts_file, _password_ref

logger = logging.getLogger(__name__)


class AsyncTunnelManager:
    """
    Handles massively parallel SSH connections using asyncssh.
    Designed to scale to 10,000+ hosts without blocking the OS thread pool.
    """

    @staticmethod
    async def async_run_command_on_host(
        host_config: HostConfig, command: str, timeout: int = 60
    ) -> CommandResult:
        """
        Connects to a single host asynchronously and executes the command.
        """
        try:
            # 1. Path Expansion & Normalization (Linux & Windows)
            key_path = host_config.identity_file or host_config.key_path
            if key_path:
                key_path = os.path.abspath(os.path.expanduser(key_path))

            certificate_file = host_config.extra_config.get(
                "certificate_file"
            ) or host_config.extra_config.get("certificatefile")
            if certificate_file:
                certificate_file = os.path.abspath(os.path.expanduser(certificate_file))

            command = validate_command(command)
            command_timeout = validate_timeout(timeout, default=60)
            connect_kwargs = {
                "host": host_config.hostname,
                "port": host_config.port,
                "username": host_config.user,
                "known_hosts": validated_known_hosts_path(
                    host_config.known_hosts_file or setting("TUNNEL_KNOWN_HOSTS")
                ),
                "connect_timeout": 10,
                "login_timeout": 15,
                "keepalive_interval": 30,
            }

            password = host_config.resolved_password()
            if password:
                connect_kwargs["password"] = password

            # Client keys and certificates pairing
            if key_path:
                if certificate_file:
                    connect_kwargs["client_keys"] = [(key_path, certificate_file)]
                else:
                    connect_kwargs["client_keys"] = [key_path]

            # 2. Proxy Command Token Expansion & Platform Resolution (Linux & Windows)
            if host_config.proxy_command:
                connect_kwargs["proxy_command"] = proxy_command_argv(
                    host_config.proxy_command,
                    hostname=host_config.hostname,
                    port=host_config.port,
                    username=host_config.user or "",
                )

            async with asyncssh.connect(**connect_kwargs) as conn:
                process = await conn.create_process(command, encoding=None)
                output_limit = max_output_bytes()
                output_total = 0
                output_lock = asyncio.Lock()

                async def _drain(stream) -> bytes:
                    nonlocal output_total
                    chunks: list[bytes] = []
                    while True:
                        chunk = await stream.read(65_536)
                        if not chunk:
                            break
                        encoded = chunk if isinstance(chunk, bytes) else chunk.encode()
                        async with output_lock:
                            output_total += len(encoded)
                            if output_total > output_limit:
                                raise ConnectionPolicyError(
                                    "Managed command output limit exceeded"
                                )
                        chunks.append(encoded)
                    return b"".join(chunks)

                try:
                    stdout_data, stderr_data = await asyncio.wait_for(
                        asyncio.gather(
                            _drain(process.stdout),
                            _drain(process.stderr),
                        ),
                        timeout=command_timeout,
                    )
                    await asyncio.wait_for(process.wait(), timeout=1)
                except BaseException:
                    process.terminate()
                    try:
                        await asyncio.wait_for(process.wait(), timeout=1)
                    except (TimeoutError, asyncssh.Error):
                        process.kill()
                    raise
                stdout_text = stdout_data.decode("utf-8", errors="replace").strip()
                stderr_text = stderr_data.decode("utf-8", errors="replace").strip()
                return CommandResult(
                    success=(process.exit_status == 0),
                    stdout=stdout_text,
                    stderr=stderr_text,
                )

        except asyncssh.Error as e:
            logger.error("Operation failed: error_type=%s", type(e).__name__)
            return CommandResult(success=False, error_message="ManagedConnectionError")
        except Exception as e:
            logger.error("Unexpected remote execution failure: %s", type(e).__name__)
            return CommandResult(success=False, error_message="ManagedConnectionError")

    @staticmethod
    async def run_command_on_fleet_async(
        inventory_file: str,
        command: str,
        group: str = "all",
        max_concurrent: int = 64,
        timeout: int = 60,
    ) -> dict:
        """
        Loads the inventory, executes the command across the fleet in parallel,
        and aggregates the results using a MapReduce pattern.
        """
        logger.info("Loading configured fleet inventory")
        try:
            with open(inventory_file) as f:
                inventory_data = yaml.safe_load(f)
        except Exception as e:
            return {"error": f"Failed to load inventory: {type(e).__name__}"}

        if not isinstance(inventory_data, dict):
            return {"error": "Configured inventory is invalid."}
        if group not in inventory_data or "hosts" not in inventory_data[group]:
            return {"error": "Configured inventory group is invalid."}

        hosts = []
        for host, vars in inventory_data[group]["hosts"].items():
            hosts.append(
                HostConfig(
                    hostname=vars.get("ansible_host", host),
                    user=vars.get("ansible_user"),
                    password_ref=_password_ref(vars),
                    key_path=vars.get("ansible_ssh_private_key_file"),
                    known_hosts_file=_known_hosts_file(vars),
                )
            )

        if not hosts:
            return {"error": "No valid hosts found in inventory."}
        if len(hosts) > max_fleet_hosts():
            return {"error": "Configured inventory exceeds the fleet limit."}

        if isinstance(max_concurrent, bool):
            return {"error": "Configured concurrency is invalid."}
        max_concurrent = max(
            1,
            min(int(max_concurrent), configured_max_concurrency(), len(hosts)),
        )
        timeout = validate_timeout(timeout, default=60)

        logger.info("Executing managed operation across host_count=%d", len(hosts))

        # We use a semaphore to limit concurrent connections
        sem = asyncio.Semaphore(max_concurrent)

        async def _bounded_execution(host: HostConfig):
            async with sem:
                return (
                    host.hostname,
                    await AsyncTunnelManager.async_run_command_on_host(
                        host, command, timeout=timeout
                    ),
                )

        tasks = [_bounded_execution(host) for host in hosts]
        results = await asyncio.gather(*tasks)

        # MapReduce Payload Aggregation
        summary_map = {}
        successful = 0
        failed = 0

        for hostname, result in results:
            if result.success:
                successful += 1
                # Group by output to compress identical responses (e.g., "Ubuntu 24.04")
                out = result.stdout
                if out not in summary_map:
                    summary_map[out] = []
                summary_map[out].append(hostname)
            else:
                failed += 1
                err = result.error_message or result.stderr
                if err not in summary_map:
                    summary_map[err] = []
                summary_map[err].append(hostname)

        # Build the final aggregated payload
        compressed_output = []
        for output_signature, nodes in summary_map.items():
            compressed_output.append(
                f"[{len(nodes)} hosts returned]:\n{output_signature}"
            )

        return {
            "total_hosts": len(hosts),
            "successful": successful,
            "failed": failed,
            "summary": "\n\n---\n\n".join(compressed_output),
        }
