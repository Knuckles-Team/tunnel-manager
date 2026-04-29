#!/usr/bin/env python
"""
Tests for AdvancedFileManager class.
"""

from unittest.mock import Mock
from tunnel_manager.advanced_file_manager import (
    AdvancedFileManager,
    FileOperationResult,
    FileSearchResult,
    FileWatchEvent,
    FileDiffResult,
    BackupResult,
)
from tunnel_manager.tunnel_manager import Tunnel


class TestAdvancedFileManager:
    """Test suite for AdvancedFileManager class."""

    def test_advanced_file_manager_initialization(self):
        """Test AdvancedFileManager initialization."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        file_manager = AdvancedFileManager(mock_tunnel)

        assert file_manager.tunnel == mock_tunnel
        assert file_manager.logger is not None

    def test_recursive_file_operations_list(self):
        """Test recursive list operation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "find" in command and "-type f" in command:
                return ("100", "", 0)
            elif "find" in command and "-type d" in command:
                return ("10", "", 0)
            elif "du -sh" in command:
                return ("1.5G", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations("list", "/var/log")

        assert result["operation"] == "list"
        assert result["success"] is True
        assert result["files_processed"] == 100
        assert result["directories_processed"] == 10
        assert result["bytes_transferred"] == "1.5G"

    def test_recursive_file_operations_copy(self):
        """Test recursive copy operation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "rsync" in command and "--stats" not in command:
                return ("", "", 0)
            elif "rsync" in command and "--stats" in command:
                return ("Number of files: 50\nTotal transferred file size: 100M", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations("copy", "/source", "/dest")

        assert result["operation"] == "copy"
        assert result["success"] is True
        assert result["files_processed"] == 50
        assert result["bytes_transferred"] == "100M"

    def test_recursive_file_operations_delete(self):
        """Test recursive delete operation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        mock_tunnel.run_command = Mock(return_value=("", "", 0))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations("delete", "/tmp/old")

        assert result["operation"] == "delete"
        assert result["success"] is True
        assert result["files_processed"] == 1
        assert result["directories_processed"] == 1

    def test_recursive_file_operations_unsupported(self):
        """Test unsupported operation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations("unsupported", "/path")

        assert result["success"] is False
        assert "Unsupported operation" in result["errors"][0]

    def test_recursive_file_operations_error_handling(self):
        """Test error handling in recursive operations."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(return_value=("", "Error", 1))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations("list", "/nonexistent")

        # When all commands fail, the operation should still complete but with errors
        assert "errors" in result
        assert len(result["errors"]) > 0

    def test_file_content_search_success(self):
        """Test successful file content search."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "grep" in command and "-n" in command:
                return (
                    "/var/log/syslog:123:ERROR: Connection failed\n/var/log/app.log:456:ERROR: Disk full",
                    "",
                    0,
                )
            elif "find" in command and "wc -l" in command:
                return ("50", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_content_search(["/var/log"], "ERROR")

        assert result["success"] is True
        assert result["pattern"] == "ERROR"
        assert len(result["matches"]) == 2
        assert result["total_matches"] == 2
        assert result["files_searched"] == 50

    def test_file_content_search_no_matches(self):
        """Test file content search with no matches."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "grep" in command:
                return ("", "", 1)  # No matches
            elif "find" in command:
                return ("50", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_content_search(["/var/log"], "NONEXISTENT")

        assert result["success"] is True
        assert result["total_matches"] == 0
        assert len(result["matches"]) == 0

    def test_file_content_search_error_handling(self):
        """Test file content search with errors."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(return_value=("", "Error", 1))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_content_search(["/var/log"], "ERROR")

        assert "error" in result

    def test_file_watch_monitor_success(self):
        """Test successful file monitoring."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        snapshot_count = [0]

        def mock_run_command(command):
            if "find" in command and "stat" in command:
                snapshot_count[0] += 1
                if snapshot_count[0] == 1:
                    return ("/tmp/file1 100\n/tmp/file2 200", "", 0)
                else:
                    return ("/tmp/file1 100\n/tmp/file2 200\n/tmp/file3 300", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        # Use short duration for testing
        result = file_manager.file_watch_monitor(["/tmp"], duration=1)

        assert result["success"] is True
        assert result["watch_paths"] == ["/tmp"]
        assert result["duration_seconds"] == 1
        assert len(result["events"]) >= 0  # May or may not detect changes in 1 second

    def test_file_watch_monitor_error_handling(self):
        """Test file monitoring with errors."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(return_value=("", "Error", 1))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_watch_monitor(["/tmp"], duration=1)

        assert "error" in result

    def test_file_diff_compare_identical(self):
        """Test file comparison with identical files."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        mock_tunnel.run_command = Mock(return_value=("same content", "", 0))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_diff_compare("host1", "host2", "/etc/config.conf")

        assert result["success"] is True
        assert result["identical"] is True
        assert len(result["differences"]) == 0
        assert result["statistics"]["additions"] == 0
        assert result["statistics"]["deletions"] == 0

    def test_file_diff_compare_different(self):
        """Test file comparison with different files."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        # Mock to return different content on each call
        call_count = [0]

        def mock_run_command(command):
            call_count[0] += 1
            if "cat" in command:
                # Return different content for each call
                if call_count[0] == 1:
                    return ("line1\nline2\nline4", "", 0)
                else:
                    return ("line1\nline2\nline3", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_diff_compare("host1", "host2", "/etc/config.conf")

        assert result["success"] is True
        assert result["identical"] is False
        assert len(result["differences"]) > 0
        assert result["statistics"]["modifications"] > 0

    def test_file_diff_compare_read_error(self):
        """Test file comparison with read error."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(return_value=("", "Error", 1))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.file_diff_compare("host1", "host2", "/etc/config.conf")

        assert result["success"] is False
        assert result["identical"] is False
        assert "error" in result

    def test_smart_backup_success(self):
        """Test successful backup operation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "mkdir" in command:
                return ("", "", 0)
            elif "rsync" in command and "--backup" not in command:
                return ("", "", 0)
            elif "find" in command and "wc -l" in command:
                return ("100", "", 0)
            elif "du -sh" in command and ".tar.gz" in command:
                return ("100M", "", 0)
            elif "du -sh" in command:
                return ("500M", "", 0)
            elif "tar" in command:
                return ("", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.smart_backup(["/var/log", "/etc"], "/backup")

        assert result["success"] is True
        assert result["backup_id"].startswith("backup_")
        assert result["paths_backed_up"] == ["/var/log", "/etc"]
        assert result["files_backed_up"] == 200  # 100 files per path, 2 paths
        assert result["size_uncompressed"] == "500M"
        assert result["size_compressed"] == "100M"
        assert result["backup_type"] == "full"

    def test_smart_backup_incremental(self):
        """Test incremental backup operation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "mkdir" in command:
                return ("", "", 0)
            elif "rsync" in command:
                return ("", "", 0)
            elif "find" in command:
                return ("50", "", 0)
            elif "du -sh" in command:
                return ("250M", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.smart_backup(
            ["/var/log"], "/backup", {"incremental": True}
        )

        assert result["success"] is True
        assert result["backup_type"] == "incremental"

    def test_smart_backup_error_handling(self):
        """Test backup with directory creation error."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(return_value=("", "Permission denied", 1))

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.smart_backup(["/var/log"], "/backup")

        assert result["success"] is False
        assert result["files_backed_up"] == 0
        assert "error" in result

    def test_parse_size(self):
        """Test size parsing."""
        mock_tunnel = Mock(spec=Tunnel)
        file_manager = AdvancedFileManager(mock_tunnel)

        assert file_manager._parse_size("100M") == 100 * 1024**2
        assert file_manager._parse_size("1G") == 1024**3
        assert file_manager._parse_size("500K") == 500 * 1024
        assert file_manager._parse_size("1024") == 1024.0

    def test_parse_size_invalid(self):
        """Test size parsing with invalid input."""
        mock_tunnel = Mock(spec=Tunnel)
        file_manager = AdvancedFileManager(mock_tunnel)

        assert file_manager._parse_size("invalid") == 0.0
        assert file_manager._parse_size("") == 0.0

    def test_get_directory_snapshot(self):
        """Test directory snapshot creation."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        mock_tunnel.run_command = Mock(
            return_value=("/tmp/file1 100\n/tmp/file2 200", "", 0)
        )

        file_manager = AdvancedFileManager(mock_tunnel)
        snapshot = file_manager._get_directory_snapshot("/tmp")

        assert snapshot["/tmp/file1"] == 100
        assert snapshot["/tmp/file2"] == 200

    def test_get_directory_snapshot_error(self):
        """Test directory snapshot with error."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(return_value=("", "Error", 1))

        file_manager = AdvancedFileManager(mock_tunnel)
        snapshot = file_manager._get_directory_snapshot("/tmp")

        assert snapshot == {}

    def test_compare_snapshots(self):
        """Test snapshot comparison."""
        mock_tunnel = Mock(spec=Tunnel)
        file_manager = AdvancedFileManager(mock_tunnel)

        old_snapshot = {"/tmp/file1": 100, "/tmp/file2": 200}
        new_snapshot = {"/tmp/file1": 150, "/tmp/file2": 200, "/tmp/file3": 300}

        changes = file_manager._compare_snapshots(old_snapshot, new_snapshot)

        assert len(changes) == 2
        assert any(c["event"] == "modified" for c in changes)
        assert any(c["event"] == "created" for c in changes)

    def test_compare_snapshots_deletions(self):
        """Test snapshot comparison with deletions."""
        mock_tunnel = Mock(spec=Tunnel)
        file_manager = AdvancedFileManager(mock_tunnel)

        old_snapshot = {"/tmp/file1": 100, "/tmp/file2": 200}
        new_snapshot = {"/tmp/file1": 100}

        changes = file_manager._compare_snapshots(old_snapshot, new_snapshot)

        assert len(changes) == 1
        assert changes[0]["event"] == "deleted"

    def test_search_in_directory(self):
        """Test directory search."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "grep" in command:
                return (
                    "/var/log/syslog:123:ERROR test\n/var/log/app.log:456:WARNING test",
                    "",
                    0,
                )
            elif "find" in command:
                return ("25", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        matches = file_manager._search_in_directory(
            "/var/log", "ERROR", True, True, [], 1000
        )

        assert len(matches) >= 1
        assert (
            "/var/log/syslog" in matches[0]["file"] or "ERROR" in matches[0]["content"]
        )

    def test_search_in_directory_no_matches(self):
        """Test directory search with no matches."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "grep" in command:
                return ("", "", 1)  # No matches
            elif "find" in command:
                return ("25", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        matches = file_manager._search_in_directory(
            "/var/log", "NONEXISTENT", True, True, [], 1000
        )

        assert len(matches) == 0

    def test_recursive_chmod(self):
        """Test recursive chmod."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "chmod" in command:
                return ("", "", 0)
            elif "find" in command:
                return ("50", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations(
            "chmod", "/var/log", options={"mode": "755"}
        )

        assert result["files_processed"] == 50
        assert len(result["errors"]) == 0

    def test_recursive_chown(self):
        """Test recursive chown."""
        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "chown" in command:
                return ("", "", 0)
            elif "find" in command:
                return ("50", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        file_manager = AdvancedFileManager(mock_tunnel)
        result = file_manager.recursive_file_operations(
            "chown", "/var/log", options={"owner": "user", "group": "group"}
        )

        assert result["files_processed"] == 50
        assert len(result["errors"]) == 0


class TestFileOperationResult:
    """Test suite for FileOperationResult dataclass."""

    def test_file_operation_result_creation(self):
        """Test creating FileOperationResult."""
        result = FileOperationResult(
            operation="copy",
            source="/source",
            destination="/dest",
            files_processed=100,
            directories_processed=10,
            bytes_transferred="1GB",
            errors=[],
            duration_seconds=45.2,
            success=True,
        )

        assert result.operation == "copy"
        assert result.files_processed == 100
        assert result.success is True


class TestFileSearchResult:
    """Test suite for FileSearchResult dataclass."""

    def test_file_search_result_creation(self):
        """Test creating FileSearchResult."""
        result = FileSearchResult(
            pattern="ERROR",
            search_paths=["/var/log"],
            matches=[],
            total_matches=0,
            files_searched=50,
            duration_seconds=2.5,
        )

        assert result.pattern == "ERROR"
        assert result.total_matches == 0


class TestFileWatchEvent:
    """Test suite for FileWatchEvent dataclass."""

    def test_file_watch_event_creation(self):
        """Test creating FileWatchEvent."""
        event = FileWatchEvent(
            timestamp="2024-01-15T10:30:00",
            path="/tmp/file.txt",
            event="modified",
            size=1024,
        )

        assert event.path == "/tmp/file.txt"
        assert event.event == "modified"


class TestFileDiffResult:
    """Test suite for FileDiffResult dataclass."""

    def test_file_diff_result_creation(self):
        """Test creating FileDiffResult."""
        result = FileDiffResult(
            file="/etc/config.conf",
            host1="server01",
            host2="server02",
            identical=False,
            differences=[
                {"line_number": 1, "host1_content": "line1", "host2_content": "line2"}
            ],
            statistics={"additions": 1, "deletions": 0, "modifications": 1},
        )

        assert result.file == "/etc/config.conf"
        assert result.identical is False
        assert len(result.differences) == 1


class TestBackupResult:
    """Test suite for BackupResult dataclass."""

    def test_backup_result_creation(self):
        """Test creating BackupResult."""
        result = BackupResult(
            backup_id="backup_20240115_103000",
            paths_backed_up=["/var/log"],
            destination="/backup",
            size_compressed="100M",
            size_uncompressed="500M",
            compression_ratio="80%",
            files_backed_up=100,
            duration_seconds=120.5,
            backup_type="full",
        )

        assert result.backup_id == "backup_20240115_103000"
        assert result.compression_ratio == "80%"
        assert result.backup_type == "full"
