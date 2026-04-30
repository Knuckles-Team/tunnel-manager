#!/usr/bin/env python
"""
Operation Manager for enhanced MCP capabilities.

This module provides advanced operation management including:
- Streaming progress updates with cancellation support
- Resource monitoring during operations
- Session management for persistent connections
- Operation cancellation capabilities
"""

import asyncio
import logging
import uuid
from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class OperationState:
    """State tracking for ongoing operations."""

    operation_id: str
    operation_type: str
    status: str = "pending"  # pending, in_progress, completed, cancelled, failed
    progress: int = 0
    current_step: str = ""
    total_steps: int = 0
    current_step_index: int = 0
    estimated_remaining_seconds: int = 0
    details: dict = field(default_factory=dict)
    error: str = ""
    start_time: datetime | None = None
    end_time: datetime | None = None


@dataclass
class ResourceMetrics:
    """Resource usage metrics."""

    operation_id: str
    timestamp: datetime
    local_resources: dict = field(default_factory=dict)
    remote_resources: dict = field(default_factory=dict)


@dataclass
class SessionInfo:
    """Information about a persistent SSH session."""

    session_id: str
    host: str
    status: str = "active"
    last_used: datetime | None = None
    age_seconds: int = 0
    connection: Any = None


class OperationManager:
    """
    Manages operations with streaming progress, resource monitoring, and cancellation support.
    """

    def __init__(self):
        self.operations: dict[str, OperationState] = {}
        self.sessions: dict[str, dict[str, SessionInfo]] = {}
        self.resource_history: dict[str, list[ResourceMetrics]] = {}
        self.cancellation_requests: set[str] = set()
        self.logger = logging.getLogger(__name__)

    def create_operation(
        self,
        operation_type: str,
        total_steps: int = 0,
        details: dict | None = None,
    ) -> str:
        """
        Create a new operation and return its ID.

        Args:
            operation_type: Type of operation being performed
            total_steps: Total number of steps in the operation
            details: Additional operation details

        Returns:
            Operation ID
        """
        operation_id = f"op_{uuid.uuid4().hex[:8]}"
        operation = OperationState(
            operation_id=operation_id,
            operation_type=operation_type,
            total_steps=total_steps,
            details=details or {},
            start_time=datetime.now(),
        )
        self.operations[operation_id] = operation
        self.logger.info(f"Created operation {operation_id} of type {operation_type}")
        return operation_id

    def update_operation_progress(
        self,
        operation_id: str,
        progress: int,
        current_step: str = "",
        current_step_index: int = 0,
        estimated_remaining_seconds: int = 0,
        details: dict | None = None,
    ) -> bool:
        """
        Update operation progress.

        Args:
            operation_id: Operation to update
            progress: Progress percentage (0-100)
            current_step: Description of current step
            current_step_index: Index of current step
            estimated_remaining_seconds: Estimated time remaining
            details: Additional details to update

        Returns:
            True if update successful, False if operation not found or cancelled
        """
        if operation_id not in self.operations:
            self.logger.warning(f"Operation {operation_id} not found")
            return False

        if operation_id in self.cancellation_requests:
            self.logger.info(f"Operation {operation_id} marked for cancellation")
            return False

        operation = self.operations[operation_id]
        operation.progress = progress
        operation.status = "in_progress"
        operation.current_step = current_step
        operation.current_step_index = current_step_index
        operation.estimated_remaining_seconds = estimated_remaining_seconds

        if details:
            operation.details.update(details)

        self.logger.debug(
            f"Updated operation {operation_id}: {progress}% - {current_step}"
        )
        return True

    def complete_operation(
        self, operation_id: str, status: str = "completed", error: str = ""
    ) -> bool:
        """
        Mark an operation as complete.

        Args:
            operation_id: Operation to complete
            status: Final status (completed, failed, cancelled)
            error: Error message if failed

        Returns:
            True if successful, False if operation not found
        """
        if operation_id not in self.operations:
            self.logger.warning(f"Operation {operation_id} not found")
            return False

        operation = self.operations[operation_id]
        operation.status = status
        operation.end_time = datetime.now()
        operation.error = error

        if operation_id in self.cancellation_requests:
            self.cancellation_requests.remove(operation_id)

        self.logger.info(f"Completed operation {operation_id} with status {status}")
        return True

    def request_cancellation(self, operation_id: str) -> bool:
        """
        Request cancellation of an operation.

        Args:
            operation_id: Operation to cancel

        Returns:
            True if cancellation requested, False if operation not found or already completed
        """
        if operation_id not in self.operations:
            self.logger.warning(f"Operation {operation_id} not found")
            return False

        operation = self.operations[operation_id]
        if operation.status in ["completed", "failed", "cancelled"]:
            self.logger.warning(f"Operation {operation_id} already {operation.status}")
            return False

        self.cancellation_requests.add(operation_id)
        self.logger.info(f"Requested cancellation for operation {operation_id}")
        return True

    def get_operation_status(self, operation_id: str) -> dict | None:
        """
        Get current status of an operation.

        Args:
            operation_id: Operation to query

        Returns:
            Operation status dict or None if not found
        """
        if operation_id not in self.operations:
            return None

        operation = self.operations[operation_id]
        return {
            "operation_id": operation.operation_id,
            "operation_type": operation.operation_type,
            "status": operation.status,
            "progress": operation.progress,
            "current_step": operation.current_step,
            "total_steps": operation.total_steps,
            "current_step_index": operation.current_step_index,
            "estimated_remaining_seconds": operation.estimated_remaining_seconds,
            "details": operation.details,
            "error": operation.error,
            "start_time": (
                operation.start_time.isoformat() if operation.start_time else None
            ),
            "end_time": operation.end_time.isoformat() if operation.end_time else None,
        }

    async def streaming_progress(
        self, operation_id: str, update_callback: Callable | None = None
    ) -> AsyncGenerator[dict, None]:
        """
        Stream progress updates for an operation.

        Args:
            operation_id: Operation to stream progress for
            update_callback: Optional callback for progress updates

        Yields:
            Progress update dictionaries
        """
        if operation_id not in self.operations:
            yield {
                "operation_id": operation_id,
                "status": "error",
                "error": "Operation not found",
            }
            return

        operation = self.operations[operation_id]

        while operation.status in ["pending", "in_progress"]:
            # Check for cancellation
            if operation_id in self.cancellation_requests:
                operation.status = "cancelled"
                operation.end_time = datetime.now()
                self.cancellation_requests.remove(operation_id)
                yield {
                    "operation_id": operation_id,
                    "status": "cancelled",
                    "progress": operation.progress,
                    "message": "Operation cancelled by user",
                }
                return

            # Yield current progress
            progress_data = {
                "operation_id": operation_id,
                "status": operation.status,
                "progress": operation.progress,
                "current_step": operation.current_step,
                "total_steps": operation.total_steps,
                "current_step_index": operation.current_step_index,
                "estimated_remaining_seconds": operation.estimated_remaining_seconds,
                "details": operation.details,
            }

            if update_callback:
                await update_callback(progress_data)

            yield progress_data

            # Wait a bit before next update
            await asyncio.sleep(0.5)

        # Final status update
        yield {
            "operation_id": operation_id,
            "status": operation.status,
            "progress": operation.progress,
            "error": operation.error,
        }

    def record_resource_metrics(
        self, operation_id: str, local_resources: dict, remote_resources: dict
    ) -> None:
        """
        Record resource usage metrics for an operation.

        Args:
            operation_id: Operation to record metrics for
            local_resources: Local system resource metrics
            remote_resources: Remote system resource metrics
        """
        if operation_id not in self.resource_history:
            self.resource_history[operation_id] = []

        metrics = ResourceMetrics(
            operation_id=operation_id,
            timestamp=datetime.now(),
            local_resources=local_resources,
            remote_resources=remote_resources,
        )

        self.resource_history[operation_id].append(metrics)
        self.logger.debug(f"Recorded resource metrics for operation {operation_id}")

    def get_resource_metrics(self, operation_id: str) -> list[dict]:
        """
        Get resource metrics for an operation.

        Args:
            operation_id: Operation to get metrics for

        Returns:
            List of resource metric dictionaries
        """
        if operation_id not in self.resource_history:
            return []

        return [
            {
                "operation_id": m.operation_id,
                "timestamp": m.timestamp.isoformat(),
                "local_resources": m.local_resources,
                "remote_resources": m.remote_resources,
            }
            for m in self.resource_history[operation_id]
        ]

    def register_session(self, session_id: str, host: str, connection: Any) -> str:
        """
        Register a persistent SSH session.

        Args:
            session_id: Unique session identifier
            host: Remote host
            connection: SSH connection object

        Returns:
            Session ID
        """
        if host not in self.sessions:
            self.sessions[host] = {}

        session_info = SessionInfo(
            session_id=session_id,
            host=host,
            status="active",
            last_used=datetime.now(),
            age_seconds=0,
            connection=connection,
        )

        self.sessions[host][session_id] = session_info
        self.logger.info(f"Registered session {session_id} for host {host}")
        return session_id

    def update_session_usage(self, session_id: str, host: str) -> bool:
        """
        Update last used time for a session.

        Args:
            session_id: Session to update
            host: Host the session is connected to

        Returns:
            True if successful, False if session not found
        """
        if host not in self.sessions or session_id not in self.sessions[host]:
            self.logger.warning(f"Session {session_id} not found for host {host}")
            return False

        session = self.sessions[host][session_id]
        session.last_used = datetime.now()
        session.age_seconds = int(
            (datetime.now() - session.last_used.replace(microsecond=0)).total_seconds()
        )
        return True

    def get_session(self, session_id: str, host: str) -> Any | None:
        """
        Get a session connection.

        Args:
            session_id: Session to retrieve
            host: Host the session is connected to

        Returns:
            Connection object or None if not found
        """
        if host not in self.sessions or session_id not in self.sessions[host]:
            return None

        return self.sessions[host][session_id].connection

    def close_session(self, session_id: str, host: str) -> bool:
        """
        Close and remove a session.

        Args:
            session_id: Session to close
            host: Host the session is connected to

        Returns:
            True if successful, False if session not found
        """
        if host not in self.sessions or session_id not in self.sessions[host]:
            self.logger.warning(f"Session {session_id} not found for host {host}")
            return False

        session = self.sessions[host][session_id]
        if session.connection:
            # Close the connection if it has a close method
            if hasattr(session.connection, "close"):
                session.connection.close()

        del self.sessions[host][session_id]
        self.logger.info(f"Closed session {session_id} for host {host}")
        return True

    def list_active_sessions(self) -> dict:
        """
        List all active sessions.

        Returns:
            Dictionary of session information
        """
        active_sessions = {}
        for host, sessions in self.sessions.items():
            host_sessions = []
            for session_id, session_info in sessions.items():
                if session_info.status == "active":
                    age_seconds = (
                        int((datetime.now() - session_info.last_used).total_seconds())
                        if session_info.last_used
                        else 0
                    )
                    host_sessions.append(
                        {
                            "session_id": session_id,
                            "status": session_info.status,
                            "last_used": (
                                session_info.last_used.isoformat()
                                if session_info.last_used
                                else None
                            ),
                            "age_seconds": age_seconds,
                        }
                    )
            if host_sessions:
                active_sessions[host] = host_sessions

        return {
            "sessions": active_sessions,
            "total_sessions": sum(len(s) for s in self.sessions.values()),
        }

    def cleanup_old_sessions(self, max_age_seconds: int = 3600) -> int:
        """
        Clean up sessions older than specified age.

        Args:
            max_age_seconds: Maximum age in seconds before cleanup

        Returns:
            Number of sessions cleaned up
        """
        cleaned_count = 0
        current_time = datetime.now()

        for host in list(self.sessions.keys()):
            for session_id in list(self.sessions[host].keys()):
                session = self.sessions[host][session_id]
                if session.last_used:
                    age = (current_time - session.last_used).total_seconds()
                    if age > max_age_seconds:
                        self.close_session(session_id, host)
                        cleaned_count += 1

        self.logger.info(f"Cleaned up {cleaned_count} old sessions")
        return cleaned_count

    def list_operations(self, status: str | None = None) -> list[dict]:
        """
        List operations, optionally filtered by status.

        Args:
            status: Optional status filter

        Returns:
            List of operation dictionaries
        """
        operations = []
        for operation in self.operations.values():
            if status is None or operation.status == status:
                op_status = self.get_operation_status(operation.operation_id)
                if op_status is not None:
                    operations.append(op_status)

        return operations

    def cleanup_old_operations(self, max_age_hours: int = 24) -> int:
        """
        Clean up completed operations older than specified age.

        Args:
            max_age_hours: Maximum age in hours before cleanup

        Returns:
            Number of operations cleaned up
        """
        cleaned_count = 0
        current_time = datetime.now()

        for operation_id in list(self.operations.keys()):
            operation = self.operations[operation_id]
            if (
                operation.status in ["completed", "failed", "cancelled"]
                and operation.end_time
            ):
                age_hours = (current_time - operation.end_time).total_seconds() / 3600
                if age_hours > max_age_hours:
                    del self.operations[operation_id]
                    if operation_id in self.resource_history:
                        del self.resource_history[operation_id]
                    cleaned_count += 1

        self.logger.info(f"Cleaned up {cleaned_count} old operations")
        return cleaned_count


# Global operation manager instance
operation_manager = OperationManager()
