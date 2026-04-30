#!/usr/bin/env python
"""
Tests for OperationManager class.
"""

import asyncio
from datetime import datetime, timedelta

import pytest

from tunnel_manager.operation_manager import (
    OperationManager,
    OperationState,
    ResourceMetrics,
    SessionInfo,
    operation_manager,
)


class TestOperationManager:
    """Test suite for OperationManager class."""

    def test_create_operation(self):
        """Test creating a new operation."""
        manager = OperationManager()
        operation_id = manager.create_operation(
            operation_type="test_operation",
            total_steps=5,
            details={"param": "value"},
        )

        assert operation_id.startswith("op_")
        assert len(operation_id) == 11  # "op_" + 8 hex chars
        assert operation_id in manager.operations

        operation = manager.operations[operation_id]
        assert operation.operation_type == "test_operation"
        assert operation.total_steps == 5
        assert operation.status == "pending"
        assert operation.progress == 0
        assert operation.details == {"param": "value"}
        assert operation.start_time is not None

    def test_update_operation_progress(self):
        """Test updating operation progress."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation", total_steps=10)

        success = manager.update_operation_progress(
            operation_id=operation_id,
            progress=50,
            current_step="Processing files",
            current_step_index=5,
            estimated_remaining_seconds=120,
            details={"files_processed": 5},
        )

        assert success is True
        operation = manager.operations[operation_id]
        assert operation.progress == 50
        assert operation.current_step == "Processing files"
        assert operation.current_step_index == 5
        assert operation.estimated_remaining_seconds == 120
        assert operation.details == {"files_processed": 5}
        assert operation.status == "in_progress"

    def test_update_nonexistent_operation(self):
        """Test updating a non-existent operation."""
        manager = OperationManager()
        success = manager.update_operation_progress(
            operation_id="nonexistent", progress=50
        )
        assert success is False

    def test_update_cancelled_operation(self):
        """Test updating an operation marked for cancellation."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")
        manager.request_cancellation(operation_id)

        success = manager.update_operation_progress(
            operation_id=operation_id, progress=50
        )
        assert success is False

    def test_complete_operation(self):
        """Test completing an operation successfully."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")

        success = manager.complete_operation(
            operation_id=operation_id, status="completed"
        )

        assert success is True
        operation = manager.operations[operation_id]
        assert operation.status == "completed"
        assert operation.end_time is not None

    def test_complete_operation_with_error(self):
        """Test completing an operation with error."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")

        success = manager.complete_operation(
            operation_id=operation_id, status="failed", error="Connection timeout"
        )

        assert success is True
        operation = manager.operations[operation_id]
        assert operation.status == "failed"
        assert operation.error == "Connection timeout"

    def test_complete_nonexistent_operation(self):
        """Test completing a non-existent operation."""
        manager = OperationManager()
        success = manager.complete_operation(operation_id="nonexistent")
        assert success is False

    def test_request_cancellation(self):
        """Test requesting operation cancellation."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")

        success = manager.request_cancellation(operation_id)

        assert success is True
        assert operation_id in manager.cancellation_requests

    def test_request_cancellation_nonexistent(self):
        """Test requesting cancellation for non-existent operation."""
        manager = OperationManager()
        success = manager.request_cancellation("nonexistent")
        assert success is False

    def test_request_cancellation_already_completed(self):
        """Test requesting cancellation for already completed operation."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")
        manager.complete_operation(operation_id)

        success = manager.request_cancellation(operation_id)
        assert success is False

    def test_get_operation_status(self):
        """Test getting operation status."""
        manager = OperationManager()
        operation_id = manager.create_operation(
            "test_operation", total_steps=10, details={"test": "data"}
        )
        manager.update_operation_progress(
            operation_id, progress=50, current_step="Step 5"
        )

        status = manager.get_operation_status(operation_id)

        assert status is not None
        assert status["operation_id"] == operation_id
        assert status["operation_type"] == "test_operation"
        assert status["status"] == "in_progress"
        assert status["progress"] == 50
        assert status["current_step"] == "Step 5"
        assert status["total_steps"] == 10
        assert status["details"] == {"test": "data"}
        assert status["start_time"] is not None

    def test_get_nonexistent_operation_status(self):
        """Test getting status for non-existent operation."""
        manager = OperationManager()
        status = manager.get_operation_status("nonexistent")
        assert status is None

    @pytest.mark.asyncio
    async def test_streaming_progress(self):
        """Test streaming progress updates."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation", total_steps=3)

        # Simulate progress updates
        updates = []

        async def simulate_progress():
            for i in range(1, 4):
                manager.update_operation_progress(
                    operation_id,
                    progress=i * 33,
                    current_step=f"Step {i}",
                    current_step_index=i,
                )
                await asyncio.sleep(0.1)
            manager.complete_operation(operation_id)

        # Start progress simulation
        asyncio.create_task(simulate_progress())

        # Collect streaming updates
        progress_count = 0
        async for update in manager.streaming_progress(operation_id):
            updates.append(update)
            progress_count += 1
            if progress_count > 5:  # Limit collection for test
                break

        assert len(updates) > 0
        assert updates[0]["operation_id"] == operation_id
        assert updates[0]["status"] in ["pending", "in_progress"]

    @pytest.mark.asyncio
    async def test_streaming_progress_cancellation(self):
        """Test streaming progress with cancellation."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")

        # Request cancellation
        manager.request_cancellation(operation_id)

        updates = []
        async for update in manager.streaming_progress(operation_id):
            updates.append(update)

        assert len(updates) > 0
        assert updates[-1]["status"] == "cancelled"

    @pytest.mark.asyncio
    async def test_streaming_progress_nonexistent(self):
        """Test streaming progress for non-existent operation."""
        manager = OperationManager()

        updates = []
        async for update in manager.streaming_progress("nonexistent"):
            updates.append(update)

        assert len(updates) == 1
        assert updates[0]["status"] == "error"

    def test_record_resource_metrics(self):
        """Test recording resource metrics."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")

        local_resources = {"cpu_percent": 25.5, "memory_percent": 45.2}
        remote_resources = {"cpu_percent": 35.8, "memory_percent": 55.1}

        manager.record_resource_metrics(operation_id, local_resources, remote_resources)

        assert operation_id in manager.resource_history
        assert len(manager.resource_history[operation_id]) == 1

        metrics = manager.resource_history[operation_id][0]
        assert metrics.operation_id == operation_id
        assert metrics.local_resources == local_resources
        assert metrics.remote_resources == remote_resources

    def test_get_resource_metrics(self):
        """Test getting resource metrics."""
        manager = OperationManager()
        operation_id = manager.create_operation("test_operation")

        local_resources = {"cpu_percent": 25.5}
        remote_resources = {"cpu_percent": 35.8}

        manager.record_resource_metrics(operation_id, local_resources, remote_resources)

        metrics = manager.get_resource_metrics(operation_id)

        assert len(metrics) == 1
        assert metrics[0]["operation_id"] == operation_id
        assert metrics[0]["local_resources"] == local_resources
        assert metrics[0]["remote_resources"] == remote_resources
        assert "timestamp" in metrics[0]

    def test_get_resource_metrics_nonexistent(self):
        """Test getting resource metrics for non-existent operation."""
        manager = OperationManager()
        metrics = manager.get_resource_metrics("nonexistent")
        assert metrics == []

    def test_register_session(self):
        """Test registering a session."""
        manager = OperationManager()
        mock_connection = {"type": "mock_connection"}

        session_id = manager.register_session(
            session_id="test_session", host="example.com", connection=mock_connection
        )

        assert session_id == "test_session"
        assert "example.com" in manager.sessions
        assert "test_session" in manager.sessions["example.com"]

        session = manager.sessions["example.com"]["test_session"]
        assert session.session_id == "test_session"
        assert session.host == "example.com"
        assert session.status == "active"
        assert session.connection == mock_connection
        assert session.last_used is not None

    def test_update_session_usage(self):
        """Test updating session usage."""
        manager = OperationManager()
        mock_connection = {"type": "mock_connection"}

        session_id = manager.register_session(
            session_id="test_session", host="example.com", connection=mock_connection
        )

        # Wait a bit
        import time

        time.sleep(0.1)

        success = manager.update_session_usage(session_id, "example.com")

        assert success is True
        session = manager.sessions["example.com"]["test_session"]
        assert session.last_used is not None

    def test_update_nonexistent_session(self):
        """Test updating non-existent session."""
        manager = OperationManager()
        success = manager.update_session_usage("nonexistent", "example.com")
        assert success is False

    def test_get_session(self):
        """Test getting a session connection."""
        manager = OperationManager()
        mock_connection = {"type": "mock_connection"}

        session_id = manager.register_session(
            session_id="test_session", host="example.com", connection=mock_connection
        )

        connection = manager.get_session(session_id, "example.com")

        assert connection == mock_connection

    def test_get_nonexistent_session(self):
        """Test getting non-existent session."""
        manager = OperationManager()
        connection = manager.get_session("nonexistent", "example.com")
        assert connection is None

    def test_close_session(self):
        """Test closing a session."""
        manager = OperationManager()
        mock_connection = {"type": "mock_connection", "close": lambda: None}

        session_id = manager.register_session(
            session_id="test_session", host="example.com", connection=mock_connection
        )

        success = manager.close_session(session_id, "example.com")

        assert success is True
        assert "test_session" not in manager.sessions["example.com"]

    def test_close_nonexistent_session(self):
        """Test closing non-existent session."""
        manager = OperationManager()
        success = manager.close_session("nonexistent", "example.com")
        assert success is False

    def test_list_active_sessions(self):
        """Test listing active sessions."""
        manager = OperationManager()

        # Register multiple sessions
        manager.register_session(session_id="session1", host="host1.com", connection={})
        manager.register_session(session_id="session2", host="host1.com", connection={})
        manager.register_session(session_id="session3", host="host2.com", connection={})

        sessions = manager.list_active_sessions()

        assert "sessions" in sessions
        assert "total_sessions" in sessions
        assert sessions["total_sessions"] == 3
        assert "host1.com" in sessions["sessions"]
        assert "host2.com" in sessions["sessions"]
        assert len(sessions["sessions"]["host1.com"]) == 2
        assert len(sessions["sessions"]["host2.com"]) == 1

    def test_list_active_sessions_empty(self):
        """Test listing active sessions when none exist."""
        manager = OperationManager()
        sessions = manager.list_active_sessions()

        assert sessions["sessions"] == {}
        assert sessions["total_sessions"] == 0

    def test_cleanup_old_sessions(self):
        """Test cleaning up old sessions."""
        manager = OperationManager()

        # Register a session
        manager.register_session(
            session_id="old_session", host="example.com", connection={}
        )

        # Manually set last_used to be old
        old_time = datetime.now() - timedelta(seconds=3700)
        manager.sessions["example.com"]["old_session"].last_used = old_time

        # Clean up sessions older than 1 hour
        cleaned = manager.cleanup_old_sessions(max_age_seconds=3600)

        assert cleaned == 1
        assert "old_session" not in manager.sessions["example.com"]

    def test_cleanup_old_sessions_none_to_clean(self):
        """Test cleanup when no sessions are old enough."""
        manager = OperationManager()

        # Register a recent session
        manager.register_session(
            session_id="recent_session", host="example.com", connection={}
        )

        cleaned = manager.cleanup_old_sessions(max_age_seconds=3600)

        assert cleaned == 0
        assert "recent_session" in manager.sessions["example.com"]

    def test_list_operations(self):
        """Test listing operations."""
        manager = OperationManager()

        # Create multiple operations
        op1 = manager.create_operation("operation1")
        op2 = manager.create_operation("operation2")
        manager.complete_operation(op1)

        operations = manager.list_operations()

        assert len(operations) == 2
        assert any(op["operation_id"] == op1 for op in operations)
        assert any(op["operation_id"] == op2 for op in operations)

    def test_list_operations_filtered(self):
        """Test listing operations with status filter."""
        manager = OperationManager()

        op1 = manager.create_operation("operation1")
        op2 = manager.create_operation("operation2")
        manager.complete_operation(op1)

        completed_ops = manager.list_operations(status="completed")
        pending_ops = manager.list_operations(status="pending")

        assert len(completed_ops) == 1
        assert completed_ops[0]["operation_id"] == op1
        assert len(pending_ops) == 1
        assert pending_ops[0]["operation_id"] == op2

    def test_cleanup_old_operations(self):
        """Test cleaning up old operations."""
        manager = OperationManager()

        # Create and complete an operation
        op1 = manager.create_operation("operation1")
        manager.complete_operation(op1)

        # Manually set end_time to be old
        old_time = datetime.now() - timedelta(hours=25)
        manager.operations[op1].end_time = old_time

        # Clean up operations older than 24 hours
        cleaned = manager.cleanup_old_operations(max_age_hours=24)

        assert cleaned == 1
        assert op1 not in manager.operations

    def test_cleanup_old_operations_none_to_clean(self):
        """Test cleanup when no operations are old enough."""
        manager = OperationManager()

        # Create and complete a recent operation
        op1 = manager.create_operation("operation1")
        manager.complete_operation(op1)

        cleaned = manager.cleanup_old_operations(max_age_hours=24)

        assert cleaned == 0
        assert op1 in manager.operations

    def test_global_operation_manager(self):
        """Test that global operation manager instance exists."""

        assert operation_manager is not None
        assert isinstance(operation_manager, OperationManager)


class TestOperationState:
    """Test suite for OperationState dataclass."""

    def test_operation_state_creation(self):
        """Test creating an OperationState."""
        state = OperationState(
            operation_id="op_test",
            operation_type="test_type",
            total_steps=5,
        )

        assert state.operation_id == "op_test"
        assert state.operation_type == "test_type"
        assert state.status == "pending"
        assert state.progress == 0
        assert state.total_steps == 5


class TestResourceMetrics:
    """Test suite for ResourceMetrics dataclass."""

    def test_resource_metrics_creation(self):
        """Test creating ResourceMetrics."""
        metrics = ResourceMetrics(
            operation_id="op_test",
            timestamp=datetime.now(),
            local_resources={"cpu": 50},
            remote_resources={"cpu": 60},
        )

        assert metrics.operation_id == "op_test"
        assert metrics.local_resources == {"cpu": 50}
        assert metrics.remote_resources == {"cpu": 60}


class TestSessionInfo:
    """Test suite for SessionInfo dataclass."""

    def test_session_info_creation(self):
        """Test creating SessionInfo."""
        session = SessionInfo(
            session_id="sess_test",
            host="example.com",
            status="active",
        )

        assert session.session_id == "sess_test"
        assert session.host == "example.com"
        assert session.status == "active"
        assert session.age_seconds == 0
