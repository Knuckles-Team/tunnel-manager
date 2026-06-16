"""MCP tools for file operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import logging

from agent_utilities.mcp_utilities import ctx_log, run_blocking
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.advanced_file_manager import AdvancedFileManager
from tunnel_manager.mcp_server import ResponseBuilder
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger("tunnel-manager-mcp")


def register_file_tools(mcp: FastMCP):
    """Register advanced file operations tool."""

    @mcp.tool(
        annotations={
            "title": "Advanced File Operations",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"advanced_file_operations"},
    )
    async def tm_files(
        action: str = Field(
            description="Action: 'recursive_ops', 'content_search', 'watch', 'diff_compare', 'backup'"
        ),
        remote_host: str = Field(default="", description="Remote host."),
        username: str = Field(default="", description="SSH username."),
        password: str = Field(default="", description="SSH password."),
        identity_file: str = Field(default="", description="SSH identity file path."),
        operation: str = Field(
            default="",
            description="Operation type: copy, move, delete, list, chmod, chown (recursive_ops).",
        ),
        source: str = Field(default="", description="Source path (recursive_ops)."),
        destination: str = Field(
            default="", description="Destination path (recursive_ops/copy/move)."
        ),
        mode: str = Field(
            default="755", description="Permission mode (recursive_ops/chmod)."
        ),
        owner: str = Field(default="", description="Owner (recursive_ops/chown)."),
        group: str = Field(default="", description="Group (recursive_ops/chown)."),
        search_paths: list[str] = Field(
            default=[], description="Directories to search (content_search)."
        ),
        pattern: str = Field(
            default="", description="Search pattern (content_search)."
        ),
        case_sensitive: bool = Field(
            default=False, description="Case-sensitive (content_search)."
        ),
        recursive: bool = Field(
            default=True, description="Recursive search (content_search)."
        ),
        max_results: int = Field(
            default=1000, description="Max results (content_search)."
        ),
        watch_paths: list[str] = Field(
            default=[], description="Paths to monitor (watch)."
        ),
        duration: int = Field(default=60, description="Monitor duration secs (watch)."),
        file_path: str = Field(
            default="", description="File path to compare (diff_compare)."
        ),
        host1: str = Field(default="", description="First host (diff_compare)."),
        host2: str = Field(default="", description="Second host (diff_compare)."),
        backup_paths: list[str] = Field(
            default=[], description="Paths to backup (backup)."
        ),
        backup_dest: str = Field(
            default="", description="Backup destination (backup)."
        ),
        compression: bool = Field(
            default=True, description="Enable compression (backup)."
        ),
        incremental: bool = Field(
            default=False, description="Incremental backup (backup)."
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Advanced file operations on remote hosts."""
        if action == "recursive_ops":
            if not remote_host or not operation or not source:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, operation, source",
                    {"action": action},
                    errors=["Need remote_host, operation, source"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                options = {}
                if operation == "chmod":
                    options["mode"] = mode
                elif operation == "chown":
                    options["owner"] = owner
                    options["group"] = group
                result = await run_blocking(
                    fm.recursive_file_operations,
                    operation,
                    source,
                    destination,
                    options,
                )
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Recursive {operation} completed",
                    {"host": remote_host, "operation": operation, "result": result},
                    error=result.get("error", ""),
                    errors=result.get("errors", []),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Recursive file ops fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "Recursive file ops fail",
                    {"host": remote_host, "operation": operation},
                    str(e),
                )

        elif action == "content_search":
            if not remote_host or not search_paths or not pattern:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, search_paths, pattern",
                    {"action": action},
                    errors=["Need remote_host, search_paths, pattern"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                options = {
                    "case_sensitive": case_sensitive,
                    "recursive": recursive,
                    "max_results": max_results,
                }
                result = await run_blocking(
                    fm.file_content_search, search_paths, pattern, options
                )
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    "File content search completed",
                    {"host": remote_host, "pattern": pattern, "result": result},
                    error=result.get("error", ""),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"File content search fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "File content search fail",
                    {"host": remote_host, "pattern": pattern},
                    str(e),
                )

        elif action == "watch":
            if not remote_host or not watch_paths:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, watch_paths",
                    {"action": action},
                    errors=["Need remote_host, watch_paths"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                result = await run_blocking(
                    fm.file_watch_monitor, watch_paths, duration
                )
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    "File monitoring completed",
                    {"host": remote_host, "watch_paths": watch_paths, "result": result},
                    error=result.get("error", ""),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"File watch fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "File watch fail",
                    {"host": remote_host, "watch_paths": watch_paths},
                    str(e),
                )

        elif action == "diff_compare":
            if not file_path or not host1 or not host2:
                return ResponseBuilder.build(
                    400,
                    "Need file_path, host1, host2",
                    {"action": action},
                    errors=["Need file_path, host1, host2"],
                )
            try:
                tunnel1 = Tunnel(
                    remote_host=host1,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel1)
                result = await run_blocking(
                    fm.file_diff_compare, host1, host2, file_path
                )
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    "File comparison completed",
                    {
                        "file": file_path,
                        "host1": host1,
                        "host2": host2,
                        "result": result,
                    },
                    error=result.get("error", ""),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"File diff fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "File diff fail",
                    {"file": file_path, "host1": host1, "host2": host2},
                    str(e),
                )

        elif action == "backup":
            if not remote_host or not backup_paths or not backup_dest:
                return ResponseBuilder.build(
                    400,
                    "Need remote_host, backup_paths, backup_dest",
                    {"action": action},
                    errors=["Need remote_host, backup_paths, backup_dest"],
                )
            try:
                tunnel = Tunnel(
                    remote_host=remote_host,
                    username=username or None,
                    password=password or None,
                    identity_file=identity_file or None,
                )
                fm = AdvancedFileManager(tunnel)
                options = {"compression": compression, "incremental": incremental}
                result = await run_blocking(
                    fm.smart_backup, backup_paths, backup_dest, options
                )
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    "Backup completed",
                    {
                        "host": remote_host,
                        "backup_paths": backup_paths,
                        "result": result,
                    },
                    error=result.get("error", ""),
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Backup fail: {e}")
                return ResponseBuilder.build(
                    500,
                    "Backup fail",
                    {"host": remote_host, "backup_paths": backup_paths},
                    str(e),
                )
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: recursive_ops, content_search, watch, diff_compare, backup"
                ],
            )
