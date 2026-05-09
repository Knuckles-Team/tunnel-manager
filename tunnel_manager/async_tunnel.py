import asyncio
import logging
import os

import asyncssh
import yaml

from .models import CommandResult, HostConfig

logger = logging.getLogger(__name__)


class AsyncTunnelManager:
    """
    Handles massively parallel SSH connections using asyncssh.
    Designed to scale to 10,000+ hosts without blocking the OS thread pool.
    """

    @staticmethod
    async def async_run_command_on_host(
        host_config: HostConfig, command: str
    ) -> CommandResult:
        """
        Connects to a single host asynchronously and executes the command.
        """
        try:
            connect_kwargs = {
                "host": host_config.hostname,
                "port": host_config.port,
                "username": host_config.user,
                "known_hosts": None,
            }

            if host_config.password:
                connect_kwargs["password"] = host_config.password
            elif host_config.identity_file or host_config.key_path:
                key_path = host_config.identity_file or host_config.key_path
                connect_kwargs["client_keys"] = [os.path.expanduser(key_path)]
            else:
                return CommandResult(
                    success=False,
                    error_message=f"No authentication method provided for {host_config.hostname}",
                    command=command,
                )

            async with asyncssh.connect(**connect_kwargs) as conn:
                result = await conn.run(command)
                return CommandResult(
                    success=(result.exit_status == 0),
                    stdout=result.stdout.strip() if result.stdout else "",
                    stderr=result.stderr.strip() if result.stderr else "",
                    command=command,
                )

        except asyncssh.Error as e:
            logger.error(f"SSH connection failed on {host_config.hostname}: {str(e)}")
            return CommandResult(success=False, error_message=str(e), command=command)
        except Exception as e:
            logger.error(
                f"Unexpected error executing on {host_config.hostname}: {str(e)}"
            )
            return CommandResult(success=False, error_message=str(e), command=command)

    @staticmethod
    async def run_command_on_fleet_async(
        inventory_file: str,
        command: str,
        group: str = "all",
        max_concurrent: int = 1000,
    ) -> dict:
        """
        Loads the inventory, executes the command across the fleet in parallel,
        and aggregates the results using a MapReduce pattern.
        """
        logger.info(f"Loading fleet inventory from {inventory_file}")
        try:
            with open(inventory_file) as f:
                inventory_data = yaml.safe_load(f)
        except Exception as e:
            return {"error": f"Failed to load inventory: {str(e)}"}

        if group not in inventory_data or "hosts" not in inventory_data[group]:
            return {"error": f"Group '{group}' not found or invalid in inventory."}

        hosts = []
        for host, vars in inventory_data[group]["hosts"].items():
            hosts.append(
                HostConfig(
                    hostname=vars.get("ansible_host", host),
                    user=vars.get("ansible_user"),
                    password=vars.get("ansible_ssh_pass"),
                    key_path=vars.get("ansible_ssh_private_key_file"),
                )
            )

        if not hosts:
            return {"error": "No valid hosts found in inventory."}

        logger.info(f"Executing '{command}' across {len(hosts)} hosts concurrently.")

        # We use a semaphore to limit concurrent connections
        sem = asyncio.Semaphore(max_concurrent)

        async def _bounded_execution(host: HostConfig):
            async with sem:
                return (
                    host.hostname,
                    await AsyncTunnelManager.async_run_command_on_host(host, command),
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
