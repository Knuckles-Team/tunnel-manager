#!/usr/bin/env python
"""
System Intelligence module for remote system discovery and analysis.

This module provides capabilities for:
- Gathering comprehensive system information
- Discovering running services and processes
- Analyzing system and application logs
- Mapping network topology and connections
"""

import logging
import re
from dataclasses import dataclass
from typing import Any

from tunnel_manager.advanced_file_manager import (
    _bounded_paths,
    _remote_path,
    _search_pattern,
)
from tunnel_manager.connection_security import ConnectionPolicyError
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger(__name__)


@dataclass
class SystemInfo:
    """Comprehensive system information."""

    os: dict
    kernel: dict
    hardware: dict
    packages: dict
    uptime: str


@dataclass
class ServiceInfo:
    """Information about running services."""

    services: dict
    processes: list
    ports: list


@dataclass
class LogAnalysis:
    """Results from log analysis."""

    log_file: str
    total_lines: int
    matches: list
    recent_errors: list
    summary: dict


@dataclass
class NetworkTopology:
    """Network topology information."""

    interfaces: list
    routes: list
    connections: list
    dns_servers: list
    hostname: str


class SystemIntelligence:
    """
    Provides system intelligence and discovery capabilities for remote hosts.
    """

    def __init__(self, tunnel: Tunnel):
        """
        Initialize SystemIntelligence with a Tunnel instance.

        Args:
            tunnel: Tunnel instance for SSH connections
        """
        self.tunnel = tunnel
        self.logger = logging.getLogger(__name__)

    def _run(self, command: str) -> tuple[str, str, int]:
        """Normalize bounded Tunnel results for the typed discovery helpers."""

        result = self.tunnel.run_command(command)
        if hasattr(result, "success"):
            return result.stdout, result.stderr, 0 if result.success else 1
        if isinstance(result, (tuple, list)) and len(result) == 3:
            return str(result[0]), str(result[1]), int(result[2])
        raise ConnectionPolicyError("Managed remote command failed")

    def get_system_info(self) -> dict:
        """
        Gather comprehensive system information.

        Returns:
            Dictionary with OS, kernel, hardware, packages, and uptime information
        """
        try:
            self.logger.info("Gathering managed-host system information")

            # Get OS information
            os_info = self._get_os_info()

            # Get kernel information
            kernel_info = self._get_kernel_info()

            # Get hardware information
            hardware_info = self._get_hardware_info()

            # Get package information
            packages_info = self._get_packages_info()

            # Get uptime
            uptime = self._get_uptime()

            system_info = {
                "host": self.tunnel.remote_host,
                "os": os_info,
                "kernel": kernel_info,
                "hardware": hardware_info,
                "packages": packages_info,
                "uptime": uptime,
            }

            self.logger.info("Managed-host system information gathered")
            return system_info

        except Exception:
            self.logger.error("Failed to gather system info")
            return {
                "host": self.tunnel.remote_host,
                "error": "Operation failed",
                "os": {"name": "Unknown", "version": "Unknown", "arch": "Unknown"},
                "kernel": {"version": "Unknown", "type": "Unknown"},
                "hardware": {
                    "cpu": {"cores": 0, "model": "Unknown"},
                    "memory": {"total": "Unknown", "available": "Unknown"},
                    "disk": [],
                },
                "packages": {},
                "uptime": "unknown",
            }

    def _get_os_info(self) -> dict:
        """Get operating system information."""
        try:
            # Try lsb_release first (Debian/Ubuntu)
            stdout, stderr, exit_code = self._run("lsb_release -a")
            if exit_code == 0:
                os_name = self._parse_lsb_release(stdout)
                if os_name:
                    return os_name

            # Fallback to /etc/os-release
            stdout, stderr, exit_code = self._run("cat /etc/os-release")
            if exit_code == 0:
                return self._parse_os_release(stdout)

            # Fallback to uname
            stdout, stderr, exit_code = self._run("uname -a")
            if exit_code == 0:
                return {
                    "name": "Unknown",
                    "version": "Unknown",
                    "arch": stdout.split()[-1],
                }

            return {"name": "Unknown", "version": "Unknown", "arch": "Unknown"}

        except Exception:
            self.logger.error("Failed to get OS info")
            return {"name": "Unknown", "version": "Unknown", "arch": "Unknown"}

    def _parse_lsb_release(self, output: str) -> dict:
        """Parse lsb_release output."""
        info = {}
        for line in output.split("\n"):
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower().replace(" ", "_")
                value = value.strip()
                info[key] = value
        return {
            "name": info.get("distributor_id", "Unknown"),
            "version": info.get("release", "Unknown"),
            "arch": info.get("architecture", "Unknown"),
        }

    def _parse_os_release(self, output: str) -> dict:
        """Parse /etc/os-release output."""
        info = {}
        for line in output.split("\n"):
            if "=" in line and not line.startswith("#"):
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"')
                info[key] = value
        return {
            "name": info.get("NAME", "Unknown"),
            "version": info.get("VERSION", "Unknown"),
            "arch": info.get("architecture", "Unknown"),
        }

    def _get_kernel_info(self) -> dict:
        """Get kernel information."""
        try:
            stdout, stderr, exit_code = self._run("uname -r")
            if exit_code != 0:
                return {"version": "Unknown", "type": "Unknown"}

            version = stdout.strip()
            stdout, stderr, exit_code = self._run("uname -s")
            kernel_type = stdout.strip() if exit_code == 0 else "Unknown"

            return {"version": version, "type": kernel_type}

        except Exception:
            self.logger.error("Failed to get kernel info")
            return {"version": "Unknown", "type": "Unknown"}

    def _get_hardware_info(self) -> dict:
        """Get hardware information."""
        try:
            # Get CPU info
            cpu_info = self._get_cpu_info()

            # Get memory info
            memory_info = self._get_memory_info()

            # Get disk info
            disk_info = self._get_disk_info()

            return {
                "cpu": cpu_info,
                "memory": memory_info,
                "disk": disk_info,
            }

        except Exception:
            self.logger.error("Failed to get hardware info")
            return {"cpu": {}, "memory": {}, "disk": []}

    def _get_cpu_info(self) -> dict:
        """Get CPU information."""
        try:
            stdout, stderr, exit_code = self._run("nproc")
            cores = int(stdout.strip()) if exit_code == 0 else 0

            stdout, stderr, exit_code = self._run(
                "cat /proc/cpuinfo | grep 'model name' | head -1"
            )
            model = (
                stdout.split(":")[1].strip()
                if exit_code == 0 and ":" in stdout
                else "Unknown"
            )

            return {"cores": cores, "model": model}

        except Exception:
            self.logger.error("Failed to get CPU info")
            return {"cores": 0, "model": "Unknown"}

    def _get_memory_info(self) -> dict:
        """Get memory information."""
        try:
            stdout, stderr, exit_code = self._run("free -h")
            if exit_code != 0:
                return {"total": "Unknown", "available": "Unknown"}

            lines = stdout.split("\n")
            if len(lines) >= 2:
                mem_line = lines[1].split()
                return {
                    "total": mem_line[1],
                    "available": mem_line[6] if len(mem_line) > 6 else "Unknown",
                }

            return {"total": "Unknown", "available": "Unknown"}

        except Exception:
            self.logger.error("Failed to get memory info")
            return {"total": "Unknown", "available": "Unknown"}

    def _get_disk_info(self) -> list:
        """Get disk information."""
        try:
            stdout, stderr, exit_code = self._run("df -h")
            if exit_code != 0:
                return []

            disks = []
            lines = stdout.split("\n")
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 6:
                        disks.append(
                            {
                                "filesystem": parts[0],
                                "size": parts[1],
                                "used": parts[2],
                                "available": parts[3],
                                "use_percent": parts[4],
                                "mount": parts[5],
                            }
                        )

            return disks

        except Exception:
            self.logger.error("Failed to get disk info")
            return []

    def _get_packages_info(self) -> dict:
        """Get installed packages information."""
        try:
            packages = {}

            # Try to get Python version
            stdout, stderr, exit_code = self._run("python3 --version 2>&1")
            if exit_code == 0:
                packages["python"] = stdout.strip().replace("Python ", "")

            # Try to get Docker version
            stdout, stderr, exit_code = self._run("docker --version 2>&1")
            if exit_code == 0:
                packages["docker"] = stdout.strip().replace("Docker version ", "")

            # Try to get git version
            stdout, stderr, exit_code = self._run("git --version 2>&1")
            if exit_code == 0:
                packages["git"] = stdout.strip().replace("git version ", "")

            return packages

        except Exception:
            self.logger.error("Failed to get packages info")
            return {}

    def _get_uptime(self) -> str:
        """Get system uptime."""
        try:
            stdout, stderr, exit_code = self._run("uptime -p")
            if exit_code == 0:
                return stdout.strip()

            # Fallback to uptime
            stdout, stderr, exit_code = self._run("uptime")
            if exit_code == 0:
                return stdout.strip()

            return "unknown"

        except Exception as e:
            self.logger.error("Failed to get uptime: error_type=%s", type(e).__name__)
            return "unknown"

    def discover_services(self) -> dict:
        """
        Discover running services, open ports, and processes.

        Returns:
            Dictionary with service status and process information
        """
        try:
            self.logger.info("Discovering managed-host services")

            # Get service information (systemctl if available)
            services = self._get_services()

            # Get process information
            processes = self._get_processes()

            # Get open ports
            ports = self._get_open_ports()

            service_info = {
                "host": self.tunnel.remote_host,
                "services": services,
                "processes": processes,
                "ports": ports,
            }

            self.logger.info("Managed-host services discovered")
            return service_info

        except Exception as e:
            self.logger.error(
                "Failed to discover services: error_type=%s", type(e).__name__
            )
            return {
                "host": self.tunnel.remote_host,
                "error": "Operation failed",
                "services": {},
                "processes": [],
                "ports": [],
            }

    def _get_services(self) -> dict:
        """Get running services using systemctl."""
        try:
            stdout, stderr, exit_code = self._run(
                "systemctl list-units --type=service --state=running"
            )
            if exit_code != 0:
                return {}

            services = {}
            lines = stdout.split("\n")
            for line in lines[1:]:  # Skip header
                if line.strip() and ".service" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        service_name = parts[0].replace(".service", "")
                        status = parts[3]
                        services[service_name] = {"status": status, "ports": []}

            return services

        except Exception as e:
            self.logger.error("Failed to get services: error_type=%s", type(e).__name__)
            return {}

    def _get_processes(self) -> list:
        """Get running processes."""
        try:
            stdout, stderr, exit_code = self._run("ps aux --sort=-%cpu | head -10")
            if exit_code != 0:
                return []

            processes = []
            lines = stdout.split("\n")
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 11:
                        processes.append(
                            {
                                "user": parts[0],
                                "pid": int(parts[1]) if parts[1].isdigit() else 0,
                                "cpu": parts[2],
                                "mem": parts[3],
                                "command": " ".join(parts[10:]),
                            }
                        )

            return processes

        except Exception as e:
            self.logger.error(
                "Failed to get processes: error_type=%s", type(e).__name__
            )
            return []

    def _get_open_ports(self) -> list:
        """Get open ports and listening services."""
        try:
            stdout, stderr, exit_code = self._run("ss -tulpn")
            if exit_code != 0:
                return []

            ports = []
            lines = stdout.split("\n")
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 6:
                        ports.append(
                            {
                                "protocol": parts[0],
                                "state": parts[1],
                                "local": parts[4],
                                "process": parts[6] if len(parts) > 6 else "unknown",
                            }
                        )

            return ports

        except Exception:
            self.logger.error("Failed to get open ports")
            return []

    def analyze_logs(self, log_paths: list[str], patterns: list[str]) -> dict:
        """
        Analyze log files for specified patterns.

        Args:
            log_paths: List of log file paths to analyze
            patterns: List of patterns to search for

        Returns:
            Dictionary with log analysis results
        """
        try:
            _bounded_paths(log_paths)
            if not isinstance(patterns, list) or not 1 <= len(patterns) <= 64:
                raise ConnectionPolicyError("Invalid managed log pattern list")
            for pattern in patterns:
                _search_pattern(pattern)
            self.logger.info("Analyzing managed-host logs")

            all_results = []

            for log_path in log_paths:
                result = self._analyze_single_log(log_path, patterns)
                all_results.append(result)

            # Combine results
            total_matches = sum(r["match_count"] for r in all_results)
            total_errors = sum(len(r["recent_errors"]) for r in all_results)

            analysis = {
                "host": self.tunnel.remote_host,
                "log_files": all_results,
                "total_matches": total_matches,
                "total_errors": total_errors,
                "patterns_searched": patterns,
            }

            self.logger.info("Managed-host logs analyzed")
            return analysis

        except Exception:
            self.logger.error("Failed to analyze logs")
            return {
                "host": self.tunnel.remote_host,
                "error": "Operation failed",
                "log_files": [],
                "total_matches": 0,
                "total_errors": 0,
            }

    def _analyze_single_log(self, log_path: str, patterns: list[str]) -> dict:
        """Analyze a single log file."""
        try:
            log_path_arg = _remote_path(log_path)
            # Check if file exists
            stdout, stderr, exit_code = self._run(
                f"test -f {log_path_arg} && echo 'exists'"
            )
            if exit_code != 0 or "exists" not in stdout:
                return {
                    "log_file": log_path,
                    "exists": False,
                    "error": "File not found",
                    "match_count": 0,
                    "recent_errors": [],
                }

            # Get total line count
            stdout, stderr, exit_code = self._run(f"wc -l -- {log_path_arg}")
            total_lines = int(stdout.split()[0]) if exit_code == 0 else 0

            # Search for patterns
            matches: list[dict[str, Any]] = []
            recent_errors: list[dict[str, Any]] = []
            total_pattern_matches = 0

            for pattern in patterns:
                pattern_arg = _search_pattern(pattern)
                stdout, stderr, exit_code = self._run(
                    f"grep -c -- {pattern_arg} {log_path_arg} 2>/dev/null || echo '0'"
                )
                count = int(stdout.strip()) if stdout.strip().isdigit() else 0
                total_pattern_matches += count

                # Get recent matches (last 5)
                stdout, stderr, exit_code = self._run(
                    f"grep -- {pattern_arg} {log_path_arg} 2>/dev/null | tail -n 5"
                )
                recent_matches = stdout.strip().split("\n") if exit_code == 0 else []

                matches.append(
                    {
                        "pattern": pattern,
                        "count": count,
                        "recent_matches": recent_matches,
                    }
                )

                # If pattern looks like an error, collect recent errors
                if "error" in pattern.lower() or "fail" in pattern.lower():
                    recent_errors.extend(recent_matches)

            return {
                "log_file": log_path,
                "exists": True,
                "total_lines": total_lines,
                "matches": matches,
                "recent_errors": recent_errors[-10:],  # Last 10 errors
                "match_count": total_pattern_matches,
            }

        except Exception:
            self.logger.error("Failed to analyze configured log")
            return {
                "log_file": log_path,
                "exists": False,
                "error": "Operation failed",
                "match_count": 0,
                "recent_errors": [],
            }

    def network_topology(self) -> dict:
        """
        Map network interfaces, routes, and active connections.

        Returns:
            Dictionary with network topology information
        """
        try:
            self.logger.info("Mapping managed-host network topology")

            # Get network interfaces
            interfaces = self._get_network_interfaces()

            # Get routing table
            routes = self._get_routes()

            # Get active connections
            connections = self._get_connections()

            # Get DNS servers
            dns_servers = self._get_dns_servers()

            # Get hostname
            hostname = self._get_hostname()

            topology = {
                "host": self.tunnel.remote_host,
                "hostname": hostname,
                "interfaces": interfaces,
                "routes": routes,
                "connections": connections,
                "dns_servers": dns_servers,
            }

            self.logger.info("Managed-host network topology mapped")
            return topology

        except Exception:
            self.logger.error("Failed to map network topology")
            return {
                "host": self.tunnel.remote_host,
                "error": "Operation failed",
                "hostname": "unknown",
                "interfaces": [],
                "routes": [],
                "connections": [],
                "dns_servers": [],
            }

    def _get_network_interfaces(self) -> list:
        """Get network interfaces."""
        try:
            stdout, stderr, exit_code = self._run("ip addr show")
            if exit_code != 0:
                return []

            interfaces = []
            current_interface = None

            for line in stdout.split("\n"):
                if line.strip().startswith("inet "):
                    if current_interface:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            ip_info = parts[1].split("/")
                            current_interface["ip"] = ip_info[0]
                            current_interface["netmask"] = (
                                ip_info[1] if len(ip_info) > 1 else ""
                            )
                elif line.strip().startswith("inet6 "):
                    if current_interface:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            current_interface["ipv6"] = parts[1].split("/")[0]
                elif re.match(r"^\d+:", line):
                    if current_interface:
                        interfaces.append(current_interface)
                    parts = line.split()
                    if len(parts) >= 2:
                        interface_name = parts[1].rstrip(":")
                        # Extract state from the flags (e.g., <LOOPBACK,UP,LOWER_UP>)
                        state = "unknown"
                        if len(parts) >= 3:
                            flags = parts[2].strip("<>")
                            if "UP" in flags.upper():
                                state = "UP"
                            elif "DOWN" in flags.upper():
                                state = "DOWN"
                        current_interface = {
                            "name": interface_name,
                            "state": state,
                            "ip": "",
                            "ipv6": "",
                        }
                elif "state " in line.lower() and current_interface:
                    # Also check for state on separate line (some systems format differently)
                    state_match = re.search(r"state (\w+)", line, re.IGNORECASE)
                    if state_match:
                        current_interface["state"] = state_match.group(1).upper()

            if current_interface:
                interfaces.append(current_interface)

            return interfaces

        except Exception:
            self.logger.error("Failed to get network interfaces")
            return []

    def _get_routes(self) -> list:
        """Get routing table."""
        try:
            stdout, stderr, exit_code = self._run("ip route show")
            if exit_code != 0:
                return []

            routes = []
            for line in stdout.split("\n"):
                if line.strip():
                    parts = line.strip().split()
                    route = {"raw": line.strip()}
                    if "via" in parts:
                        via_index = parts.index("via")
                        if via_index + 1 < len(parts):
                            route["gateway"] = parts[via_index + 1]
                    if "dev" in parts:
                        dev_index = parts.index("dev")
                        if dev_index + 1 < len(parts):
                            route["interface"] = parts[dev_index + 1]
                    routes.append(route)

            return routes

        except Exception as e:
            self.logger.error("Failed to get routes: error_type=%s", type(e).__name__)
            return []

    def _get_connections(self) -> list:
        """Get active network connections."""
        try:
            stdout, stderr, exit_code = self._run("ss -tn")
            if exit_code != 0:
                return []

            connections = []
            for line in stdout.split("\n")[1:]:  # Skip header
                if line.strip():
                    parts = re.split(r"\s+", line.strip())
                    if len(parts) >= 5:
                        connections.append(
                            {
                                "protocol": parts[0],
                                "state": parts[1],
                                "local": parts[3] if len(parts) > 3 else "",
                                "remote": parts[4] if len(parts) > 4 else "",
                            }
                        )

            return connections

        except Exception:
            self.logger.error("Failed to get connections")
            return []

    def _get_dns_servers(self) -> list:
        """Get DNS servers."""
        try:
            stdout, stderr, exit_code = self._run("cat /etc/resolv.conf")
            if exit_code != 0:
                return []

            dns_servers = []
            for line in stdout.split("\n"):
                if line.strip().startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        dns_servers.append(parts[1])

            return dns_servers

        except Exception as e:
            self.logger.error(
                "Failed to get DNS servers: error_type=%s", type(e).__name__
            )
            return []

    def _get_hostname(self) -> str:
        """Get system hostname."""
        try:
            stdout, stderr, exit_code = self._run("hostname")
            if exit_code == 0:
                return stdout.strip()
            return "unknown"

        except Exception as e:
            self.logger.error("Failed to get hostname: error_type=%s", type(e).__name__)
            return "unknown"
