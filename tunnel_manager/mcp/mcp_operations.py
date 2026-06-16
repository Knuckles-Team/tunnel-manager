"""MCP tools for operations operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import logging

from agent_utilities.mcp_utilities import (
    ctx_confirm_destructive,
    ctx_log,
    ctx_progress,
    run_blocking,
)
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.mcp_server import ResponseBuilder
from tunnel_manager.operation_manager import operation_manager

logger = logging.getLogger("tunnel-manager-mcp")


def register_operations_tools(mcp: FastMCP):
    """Register operation lifecycle and session management tool."""

    @mcp.tool(
        annotations={
            "title": "Operation Management",
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": False,
        },
        tags={"operation_management"},
    )
    async def tm_operations(
        action: str = Field(
            description="Action: 'start', 'get_progress', 'cancel', 'get_metrics', 'list_sessions'"
        ),
        operation_id: str = Field(
            default="", description="Operation ID (get_progress/cancel/get_metrics)."
        ),
        operation_type: str = Field(
            default="", description="Type of operation (start)."
        ),
        total_steps: int = Field(default=0, description="Total steps (start)."),
        details: dict = Field(
            description="Additional details (start).", default_factory=dict
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Operation lifecycle and session management."""
        if action == "start":
            if not operation_type:
                return ResponseBuilder.build(
                    400,
                    "Need operation_type",
                    {"action": action},
                    errors=["Need operation_type"],
                )
            try:
                op_id = await run_blocking(
                    operation_manager.create_operation,
                    operation_type=operation_type,
                    total_steps=total_steps,
                    details=details,
                )
                return ResponseBuilder.build(
                    200,
                    "Operation started",
                    {"operation_id": op_id, "operation_type": operation_type},
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Failed to start operation: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to start operation",
                    {"operation_type": operation_type},
                    str(e),
                )

        elif action == "get_progress":
            if not operation_id:
                return ResponseBuilder.build(
                    400,
                    "Need operation_id",
                    {"action": action},
                    errors=["Need operation_id"],
                )
            try:
                status = await run_blocking(
                    operation_manager.get_operation_status, operation_id
                )
                if status is None:
                    return ResponseBuilder.build(
                        404,
                        "Operation not found",
                        {"operation_id": operation_id},
                        errors=["Operation not found"],
                    )
                return ResponseBuilder.build(
                    200,
                    "Operation progress retrieved",
                    {"operation_id": operation_id, "status": status},
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Failed to get operation progress: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to get operation progress",
                    {"operation_id": operation_id},
                    str(e),
                )

        elif action == "cancel":
            if not operation_id:
                return ResponseBuilder.build(
                    400,
                    "Need operation_id",
                    {"action": action},
                    errors=["Need operation_id"],
                )
            if not await ctx_confirm_destructive(ctx, "cancel operation"):
                return {"status": "cancelled", "message": "Operation cancelled by user"}
            await ctx_progress(ctx, 0, 100)
            try:
                success = await run_blocking(
                    operation_manager.request_cancellation, operation_id
                )
                if success:
                    return ResponseBuilder.build(
                        200,
                        "Operation cancellation requested",
                        {"operation_id": operation_id},
                    )
                else:
                    return ResponseBuilder.build(
                        400,
                        "Failed to cancel",
                        {"operation_id": operation_id},
                        errors=["Operation not found or already completed"],
                    )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Failed to cancel operation: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to cancel operation",
                    {"operation_id": operation_id},
                    str(e),
                )

        elif action == "get_metrics":
            if not operation_id:
                return ResponseBuilder.build(
                    400,
                    "Need operation_id",
                    {"action": action},
                    errors=["Need operation_id"],
                )
            try:
                metrics = await run_blocking(
                    operation_manager.get_resource_metrics, operation_id
                )
                return ResponseBuilder.build(
                    200,
                    "Resource metrics retrieved",
                    {
                        "operation_id": operation_id,
                        "metrics": metrics,
                        "metric_count": len(metrics),
                    },
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Failed to get resource metrics: {e}")
                return ResponseBuilder.build(
                    500,
                    "Failed to get resource metrics",
                    {"operation_id": operation_id},
                    str(e),
                )

        elif action == "list_sessions":
            try:
                sessions = await run_blocking(operation_manager.list_active_sessions)
                return ResponseBuilder.build(
                    200,
                    "Active sessions listed",
                    {
                        "sessions": sessions["sessions"],
                        "total_sessions": sessions["total_sessions"],
                    },
                )
            except Exception as e:
                ctx_log(ctx, logger, "error", f"Failed to list active sessions: {e}")
                return ResponseBuilder.build(
                    500, "Failed to list active sessions", {}, str(e)
                )
        else:
            return ResponseBuilder.build(
                400,
                f"Unknown action: {action}",
                {"action": action},
                errors=[
                    "Valid: start, get_progress, cancel, get_metrics, list_sessions"
                ],
            )
