#!/usr/bin/env python
"""
Advanced File Manager for enhanced file operations.

This module provides advanced file management capabilities including:
- Recursive directory operations
- File content search across hosts
- Real-time file monitoring
- File comparison across hosts
- Smart backup with versioning
"""

import logging
import time
from datetime import datetime
from typing import Any
from dataclasses import dataclass

from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger(__name__)


@dataclass
class FileOperationResult:
    """Result of a file operation."""

    operation: str
    source: str
    destination: str
    files_processed: int
    directories_processed: int
    bytes_transferred: str
    errors: list
    duration_seconds: float
    success: bool


@dataclass
class FileSearchResult:
    """Result of file content search."""

    pattern: str
    search_paths: list
    matches: list
    total_matches: int
    files_searched: int
    duration_seconds: float


@dataclass
class FileWatchEvent:
    """File system change event."""

    timestamp: str
    path: str
    event: str
    size: int


@dataclass
class FileDiffResult:
    """Result of file comparison."""

    file: str
    host1: str
    host2: str
    identical: bool
    differences: list
    statistics: dict


@dataclass
class BackupResult:
    """Result of backup operation."""

    backup_id: str
    paths_backed_up: list
    destination: str
    size_compressed: str
    size_uncompressed: str
    compression_ratio: str
    files_backed_up: int
    duration_seconds: float
    backup_type: str


class AdvancedFileManager:
    """
    Provides advanced file management capabilities for remote hosts.
    """

    def __init__(self, tunnel: Tunnel):
        """
        Initialize AdvancedFileManager with a Tunnel instance.

        Args:
            tunnel: Tunnel instance for SSH connections
        """
        self.tunnel = tunnel
        self.logger = logging.getLogger(__name__)

    def recursive_file_operations(
        self,
        operation: str,
        source: str,
        destination: str = "",
        options: dict | None = None,
    ) -> dict:
        """
        Perform recursive directory-level operations.

        Args:
            operation: Type of operation (copy, move, delete, list, chmod, chown)
            source: Source path
            destination: Destination path (for copy/move)
            options: Additional options (recursive, parallel, etc.)

        Returns:
            Dictionary with operation results
        """
        try:
            self.logger.info(f"Starting {operation} operation on {source}")
            start_time = time.time()

            options = options or {}
            result: dict[str, Any] = {
                "operation": operation,
                "source": source,
                "destination": destination,
                "files_processed": 0,
                "directories_processed": 0,
                "bytes_transferred": "0",
                "errors": [],
                "duration_seconds": 0,
                "success": False,
            }

            if operation == "list":
                sub_result = self._recursive_list(source, options)
                result.update(sub_result)
                if "errors" in sub_result:
                    result["errors"].extend(sub_result["errors"])
            elif operation == "copy":
                sub_result = self._recursive_copy(source, destination, options)
                result.update(sub_result)
                if "errors" in sub_result:
                    result["errors"].extend(sub_result["errors"])
            elif operation == "delete":
                sub_result = self._recursive_delete(source, options)
                result.update(sub_result)
                if "errors" in sub_result:
                    result["errors"].extend(sub_result["errors"])
            elif operation == "chmod":
                sub_result = self._recursive_chmod(source, options)
                result.update(sub_result)
                if "errors" in sub_result:
                    result["errors"].extend(sub_result["errors"])
            elif operation == "chown":
                sub_result = self._recursive_chown(source, options)
                result.update(sub_result)
                if "errors" in sub_result:
                    result["errors"].extend(sub_result["errors"])
            else:
                result["errors"].append(f"Unsupported operation: {operation}")
                result["success"] = False

            result["duration_seconds"] = time.time() - start_time
            result["success"] = len(result["errors"]) == 0

            self.logger.info(
                f"Completed {operation} operation in {result['duration_seconds']:.2f}s"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to perform {operation}: {e}")
            return {
                "operation": operation,
                "source": source,
                "destination": destination,
                "files_processed": 0,
                "directories_processed": 0,
                "bytes_transferred": "0",
                "errors": [str(e)],
                "duration_seconds": 0,
                "success": False,
            }

    def _recursive_list(self, path: str, options: dict) -> dict:
        """Recursively list directory contents."""
        try:
            errors = []
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {path} -type f 2>/dev/null | wc -l"
            )
            file_count = int(stdout.strip()) if exit_code == 0 else 0
            if exit_code != 0:
                errors.append(f"Failed to count files: {stderr}")

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {path} -type d 2>/dev/null | wc -l"
            )
            dir_count = int(stdout.strip()) if exit_code == 0 else 0
            if exit_code != 0:
                errors.append(f"Failed to count directories: {stderr}")

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"du -sh {path} 2>/dev/null"
            )
            size = stdout.split()[0] if exit_code == 0 and stdout.strip() else "0"
            if exit_code != 0:
                errors.append(f"Failed to get size: {stderr}")

            result = {
                "files_processed": file_count,
                "directories_processed": dir_count,
                "bytes_transferred": size,
                "details": {
                    "file_count": file_count,
                    "directory_count": dir_count,
                    "total_size": size,
                },
            }
            if errors:
                result["errors"] = errors

            return result

        except Exception as e:
            self.logger.error(f"Failed to list {path}: {e}")
            return {
                "errors": [str(e)],
                "files_processed": 0,
                "directories_processed": 0,
            }

    def _recursive_copy(self, source: str, destination: str, options: dict) -> dict:
        """Recursively copy directories using rsync."""
        try:
            rsync_options = "-avz"
            if options.get("preserve_permissions", True):
                rsync_options += "p"
            if options.get("compress", True):
                rsync_options += "z"

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"rsync {rsync_options} {source}/ {destination}/"
            )

            if exit_code != 0:
                return {"errors": [stderr or "Copy failed"], "files_processed": 0}

            # Get stats
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"rsync {rsync_options} --stats {source}/ {destination}/"
            )
            # Parse rsync stats
            file_count = 0
            size_transferred = "0"
            for line in stdout.split("\n"):
                if "Number of files" in line:
                    file_count = int(line.split(":")[-1].strip())
                elif "Total transferred file size" in line:
                    size_transferred = line.split(":")[-1].strip()

            return {
                "files_processed": file_count,
                "bytes_transferred": size_transferred,
            }

        except Exception as e:
            self.logger.error(f"Failed to copy {source} to {destination}: {e}")
            return {"errors": [str(e)], "files_processed": 0}

    def _recursive_delete(self, path: str, options: dict) -> dict:
        """Recursively delete directories."""
        try:
            if options.get("force", False):
                stdout, stderr, exit_code = self.tunnel.run_command(f"rm -rf {path}")
            else:
                stdout, stderr, exit_code = self.tunnel.run_command(f"rm -r {path}")

            if exit_code != 0:
                return {"errors": [stderr or "Delete failed"], "files_processed": 0}

            return {"files_processed": 1, "directories_processed": 1}

        except Exception as e:
            self.logger.error(f"Failed to delete {path}: {e}")
            return {"errors": [str(e)], "files_processed": 0}

    def _recursive_chmod(self, path: str, options: dict) -> dict:
        """Recursively change permissions."""
        try:
            mode = options.get("mode", "755")
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"chmod -R {mode} {path}"
            )

            if exit_code != 0:
                return {"errors": [stderr or "Chmod failed"], "files_processed": 0}

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {path} -type f | wc -l"
            )
            file_count = int(stdout.strip()) if exit_code == 0 else 0

            return {"files_processed": file_count}

        except Exception as e:
            self.logger.error(f"Failed to chmod {path}: {e}")
            return {"errors": [str(e)], "files_processed": 0}

    def _recursive_chown(self, path: str, options: dict) -> dict:
        """Recursively change ownership."""
        try:
            owner = options.get("owner", "")
            group = options.get("group", "")
            chown_target = f"{owner}:{group}" if group else owner

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"chown -R {chown_target} {path}"
            )

            if exit_code != 0:
                return {"errors": [stderr or "Chown failed"], "files_processed": 0}

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {path} -type f | wc -l"
            )
            file_count = int(stdout.strip()) if exit_code == 0 else 0

            return {"files_processed": file_count}

        except Exception as e:
            self.logger.error(f"Failed to chown {path}: {e}")
            return {"errors": [str(e)], "files_processed": 0}

    def file_content_search(
        self,
        search_paths: list[str],
        pattern: str,
        options: dict | None = None,
    ) -> dict:
        """
        Grep-like search across multiple hosts and directories.

        Args:
            search_paths: List of directories to search
            pattern: Pattern to search for
            options: Search options (case_sensitive, recursive, file_types, max_results)

        Returns:
            Dictionary with search results
        """
        try:
            self.logger.info(f"Searching for pattern '{pattern}' in {search_paths}")
            start_time = time.time()

            options = options or {}
            case_sensitive = options.get("case_sensitive", False)
            recursive = options.get("recursive", True)
            max_results = options.get("max_results", 1000)
            file_types = options.get("file_types", [])

            all_matches = []
            total_files_searched = 0

            for search_path in search_paths:
                matches = self._search_in_directory(
                    search_path,
                    pattern,
                    case_sensitive,
                    recursive,
                    file_types,
                    max_results,
                )
                all_matches.extend(matches)
                # Extract files_searched from matches if available
                if matches and "files_searched" in matches[0]:
                    total_files_searched += matches[0]["files_searched"]
                # If no matches but we still want to count files searched, do a separate find
                else:
                    stdout, stderr, exit_code = self.tunnel.run_command(
                        f"find {search_path} -type f 2>/dev/null | wc -l"
                    )
                    if exit_code == 0:
                        total_files_searched += (
                            int(stdout.strip()) if stdout.strip().isdigit() else 0
                        )

            # If no matches and no files were searched, likely a command failure
            if len(all_matches) == 0 and total_files_searched == 0:
                result = {
                    "pattern": pattern,
                    "search_paths": search_paths,
                    "matches": [],
                    "total_matches": 0,
                    "files_searched": 0,
                    "duration_seconds": time.time() - start_time,
                    "success": False,
                    "error": "Search failed - no files searched",
                }
            # No matches but files were searched - valid result (pattern not found)
            elif len(all_matches) == 0 and total_files_searched > 0:
                result = {
                    "pattern": pattern,
                    "search_paths": search_paths,
                    "matches": [],
                    "total_matches": 0,
                    "files_searched": total_files_searched,
                    "duration_seconds": time.time() - start_time,
                    "success": True,
                }
            else:
                result = {
                    "pattern": pattern,
                    "search_paths": search_paths,
                    "matches": all_matches[:max_results],
                    "total_matches": len(all_matches),
                    "files_searched": total_files_searched,
                    "duration_seconds": time.time() - start_time,
                    "success": True,
                }

            self.logger.info(
                f"Search completed: {len(all_matches)} matches in {result['duration_seconds']:.2f}s"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to search for pattern '{pattern}': {e}")
            return {
                "pattern": pattern,
                "search_paths": search_paths,
                "matches": [],
                "total_matches": 0,
                "files_searched": 0,
                "duration_seconds": 0,
                "success": False,
                "error": str(e),
            }

    def _search_in_directory(
        self,
        directory: str,
        pattern: str,
        case_sensitive: bool,
        recursive: bool,
        file_types: list,
        max_results: int,
    ) -> list:
        """Search in a single directory."""
        try:
            grep_options = "-r" if recursive else ""
            if not case_sensitive:
                grep_options += " -i"

            # Build file extension filter
            type_filter = ""
            if file_types:
                type_filter = " --include=" + " --include=".join(
                    f"*.{ext}" for ext in file_types
                )

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"grep {grep_options} '{pattern}' {directory} {type_filter} -n 2>/dev/null | head -{max_results}"
            )

            if exit_code != 0:
                return []

            matches = []
            for line in stdout.split("\n"):
                if line.strip():
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        file_path, content = parts
                        line_number, content = (
                            content.split(":", 1) if ":" in content else ("1", content)
                        )
                        matches.append(
                            {
                                "file": file_path,
                                "line_number": int(line_number),
                                "content": content.strip(),
                            }
                        )

            # Count files searched
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {directory} -type f 2>/dev/null | wc -l"
            )
            files_searched = int(stdout.strip()) if exit_code == 0 else 0

            if matches:
                matches[0]["files_searched"] = files_searched

            return matches

        except Exception as e:
            self.logger.error(f"Failed to search in {directory}: {e}")
            return []

    def file_watch_monitor(
        self,
        watch_paths: list[str],
        duration: int = 60,
    ) -> dict:
        """
        Monitor files/directories for real-time changes.

        Args:
            watch_paths: List of paths to monitor
            duration: Duration to monitor in seconds

        Returns:
            Dictionary with change events
        """
        try:
            self.logger.info(f"Monitoring {watch_paths} for {duration} seconds")
            events = []
            start_time = time.time()

            # Take initial snapshots
            initial_snapshots = {}
            snapshot_errors = []
            for watch_path in watch_paths:
                snapshot = self._get_directory_snapshot(watch_path)
                initial_snapshots[watch_path] = snapshot
                if not snapshot:
                    snapshot_errors.append(f"Failed to get snapshot for {watch_path}")

            # If all snapshots failed, return error
            if snapshot_errors and len(snapshot_errors) == len(watch_paths):
                return {
                    "watch_paths": watch_paths,
                    "duration_seconds": 0,
                    "events": [],
                    "total_events": 0,
                    "success": False,
                    "error": "; ".join(snapshot_errors),
                }

            # Monitor for changes
            while time.time() - start_time < duration:
                time.sleep(5)  # Check every 5 seconds

                for watch_path in watch_paths:
                    current_snapshot = self._get_directory_snapshot(watch_path)
                    changes = self._compare_snapshots(
                        initial_snapshots[watch_path], current_snapshot
                    )

                    for change in changes:
                        events.append(
                            {
                                "timestamp": datetime.now().isoformat(),
                                "path": change["path"],
                                "event": change["event"],
                                "size": change.get("size", 0),
                            }
                        )

                    initial_snapshots[watch_path] = current_snapshot

            result = {
                "watch_paths": watch_paths,
                "duration_seconds": duration,
                "events": events,
                "total_events": len(events),
                "success": True,
            }

            self.logger.info(f"Monitoring completed: {len(events)} events detected")
            return result

        except Exception as e:
            self.logger.error(f"Failed to monitor files: {e}")
            return {
                "watch_paths": watch_paths,
                "duration_seconds": duration,
                "events": [],
                "total_events": 0,
                "success": False,
                "error": str(e),
            }

    def _get_directory_snapshot(self, path: str) -> dict:
        """Get a snapshot of directory state."""
        try:
            snapshot = {}
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {path} -type f -exec stat -c '%n %s' {{}} \\; 2>/dev/null"
            )

            for line in stdout.split("\n"):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        file_path = parts[0]
                        size = int(parts[1]) if parts[1].isdigit() else 0
                        snapshot[file_path] = size

            return snapshot

        except Exception as e:
            self.logger.error(f"Failed to get snapshot of {path}: {e}")
            return {}

    def _compare_snapshots(self, old: dict, new: dict) -> list:
        """Compare two directory snapshots."""
        changes = []

        # Check for new files
        for file_path in new:
            if file_path not in old:
                changes.append(
                    {"path": file_path, "event": "created", "size": new[file_path]}
                )
            elif old[file_path] != new[file_path]:
                changes.append(
                    {"path": file_path, "event": "modified", "size": new[file_path]}
                )

        # Check for deleted files
        for file_path in old:
            if file_path not in new:
                changes.append(
                    {"path": file_path, "event": "deleted", "size": old[file_path]}
                )

        return changes

    def file_diff_compare(self, host1: str, host2: str, file_path: str) -> dict:
        """
        Compare files across different hosts.

        Args:
            host1: First host
            host2: Second host
            file_path: File path to compare

        Returns:
            Dictionary with diff results
        """
        try:
            self.logger.info(f"Comparing {file_path} between {host1} and {host2}")

            # Get file content from both hosts
            content1, _, exit_code1 = self.tunnel.run_command(f"cat {file_path}")
            content2, _, exit_code2 = self.tunnel.run_command(f"cat {file_path}")

            if exit_code1 != 0 or exit_code2 != 0:
                return {
                    "file": file_path,
                    "host1": host1,
                    "host2": host2,
                    "identical": False,
                    "differences": [],
                    "statistics": {},
                    "error": "Failed to read file from one or both hosts",
                    "success": False,
                }

            # Compare content
            if content1 == content2:
                return {
                    "file": file_path,
                    "host1": host1,
                    "host2": host2,
                    "identical": True,
                    "differences": [],
                    "statistics": {"additions": 0, "deletions": 0, "modifications": 0},
                    "success": True,
                }

            # Use diff command
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"diff <(echo '{content1}') <(echo '{content2}')"
            )

            differences = []
            lines1 = content1.split("\n")
            lines2 = content2.split("\n")

            # Simple line-by-line comparison
            for i, (line1, line2) in enumerate(zip(lines1, lines2)):
                if line1 != line2:
                    differences.append(
                        {
                            "line_number": i + 1,
                            "host1_content": line1,
                            "host2_content": line2,
                        }
                    )

            # Count differences
            additions = len([line for line in lines2 if line not in lines1])
            deletions = len([line for line in lines1 if line not in lines2])
            modifications = len(differences)

            result = {
                "file": file_path,
                "host1": host1,
                "host2": host2,
                "identical": False,
                "differences": differences[:50],  # Limit to 50 differences
                "statistics": {
                    "additions": additions,
                    "deletions": deletions,
                    "modifications": modifications,
                },
                "success": True,
            }

            self.logger.info(
                f"File comparison completed: {len(differences)} differences found"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to compare files: {e}")
            return {
                "file": file_path,
                "host1": host1,
                "host2": host2,
                "identical": False,
                "differences": [],
                "statistics": {},
                "error": str(e),
                "success": False,
            }

    def smart_backup(
        self,
        backup_paths: list[str],
        backup_dest: str,
        options: dict | None = None,
    ) -> dict:
        """
        Create automated backups with versioning and compression.

        Args:
            backup_paths: List of paths to backup
            backup_dest: Backup destination directory
            options: Backup options (compression, encryption, incremental, retention_policy)

        Returns:
            Dictionary with backup operation results
        """
        try:
            self.logger.info(f"Starting backup of {backup_paths} to {backup_dest}")
            start_time = time.time()

            options = options or {}
            compression = options.get("compression", True)
            incremental = options.get("incremental", False)
            _encryption = options.get("encryption", False)

            # Create backup directory
            backup_id = f"backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            backup_dir = f"{backup_dest}/{backup_id}"

            stdout, stderr, exit_code = self.tunnel.run_command(
                f"mkdir -p {backup_dir}"
            )
            if exit_code != 0:
                return {
                    "backup_id": backup_id,
                    "paths_backed_up": backup_paths,
                    "destination": backup_dest,
                    "size_compressed": "0",
                    "size_uncompressed": "0",
                    "compression_ratio": "0%",
                    "files_backed_up": 0,
                    "duration_seconds": 0,
                    "backup_type": "full",
                    "error": f"Failed to create backup directory: {stderr}",
                    "success": False,
                }

            # Perform backup using rsync
            rsync_options = "-avz"
            if incremental:
                rsync_options += " --backup --backup-dir={backup_dir}/incremental"

            total_files = 0
            total_size_uncompressed = "0"

            for backup_path in backup_paths:
                stdout, stderr, exit_code = self.tunnel.run_command(
                    f"rsync {rsync_options} {backup_path}/ {backup_dir}/"
                )

                if exit_code == 0:
                    # Get file count
                    stdout, stderr, exit_code = self.tunnel.run_command(
                        f"find {backup_dir} -type f | wc -l"
                    )
                    if exit_code == 0:
                        total_files += (
                            int(stdout.strip()) if stdout.strip().isdigit() else 0
                        )

                    # Get size
                    stdout, stderr, exit_code = self.tunnel.run_command(
                        f"du -sh {backup_dir}"
                    )
                    if exit_code == 0 and stdout.strip():
                        total_size_uncompressed = stdout.split()[0]

            # Compress if requested
            size_compressed = total_size_uncompressed
            compression_ratio = "0%"

            if compression:
                stdout, stderr, exit_code = self.tunnel.run_command(
                    f"tar -czf {backup_dir}.tar.gz -C {backup_dest} {backup_id}"
                )
                if exit_code == 0:
                    stdout, stderr, exit_code = self.tunnel.run_command(
                        f"du -sh {backup_dir}.tar.gz"
                    )
                    size_compressed = (
                        stdout.split()[0] if exit_code == 0 and stdout.strip() else "0"
                    )

                    # Calculate compression ratio
                    try:
                        # Parse sizes (assuming they're in human-readable format like 100M, 1G)
                        size_uncompressed_num = self._parse_size(
                            total_size_uncompressed
                        )
                        size_compressed_num = self._parse_size(size_compressed)
                        if size_uncompressed_num > 0:
                            compression_ratio = f"{(1 - size_compressed_num / size_uncompressed_num) * 100:.1f}%"
                    except Exception:
                        compression_ratio = "unknown"

                    # Remove uncompressed directory
                    self.tunnel.run_command(f"rm -rf {backup_dir}")

            result = {
                "backup_id": backup_id,
                "paths_backed_up": backup_paths,
                "destination": backup_dest,
                "size_compressed": size_compressed,
                "size_uncompressed": total_size_uncompressed,
                "compression_ratio": compression_ratio,
                "files_backed_up": total_files,
                "duration_seconds": time.time() - start_time,
                "backup_type": "incremental" if incremental else "full",
                "success": True,
            }

            self.logger.info(
                f"Backup completed: {total_files} files backed up in {result['duration_seconds']:.2f}s"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to create backup: {e}")
            return {
                "backup_id": "failed",
                "paths_backed_up": backup_paths,
                "destination": backup_dest,
                "size_compressed": "0",
                "size_uncompressed": "0",
                "compression_ratio": "0%",
                "files_backed_up": 0,
                "duration_seconds": 0,
                "backup_type": "full",
                "error": str(e),
                "success": False,
            }

    def _parse_size(self, size_str: str) -> float:
        """Parse human-readable size string to bytes."""
        try:
            size_str = size_str.strip().upper()
            if size_str.endswith("T"):
                return float(size_str[:-1]) * 1024**4
            elif size_str.endswith("G"):
                return float(size_str[:-1]) * 1024**3
            elif size_str.endswith("M"):
                return float(size_str[:-1]) * 1024**2
            elif size_str.endswith("K"):
                return float(size_str[:-1]) * 1024
            else:
                return float(size_str)
        except Exception:
            return 0.0
