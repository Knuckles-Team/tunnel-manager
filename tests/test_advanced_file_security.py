"""Adversarial tests for typed remote file and log operations."""

import shlex

from tunnel_manager.advanced_file_manager import AdvancedFileManager
from tunnel_manager.models import CommandResult
from tunnel_manager.security_auditor import SecurityAuditor
from tunnel_manager.system_intelligence import SystemIntelligence


class RecordingTunnel:
    remote_host = "managed.example.invalid"

    def __init__(self):
        self.commands: list[str] = []

    def run_command(self, command: str) -> CommandResult:
        self.commands.append(command)
        stdout = "exists" if command.startswith("test -f ") else "0"
        return CommandResult(success=True, stdout=stdout)


def test_recursive_path_is_one_shell_argument():
    tunnel = RecordingTunnel()
    manager = AdvancedFileManager(tunnel)
    path = "/var/tmp/data; touch /tmp/owned"

    result = manager.recursive_file_operations("list", path)

    assert result["success"] is True
    assert tunnel.commands
    assert all(shlex.quote(path) in command for command in tunnel.commands)


def test_permission_mode_injection_is_rejected_before_execution():
    tunnel = RecordingTunnel()
    manager = AdvancedFileManager(tunnel)

    result = manager.recursive_file_operations(
        "chmod",
        "/srv/data",
        options={"mode": "755; touch /tmp/owned"},
    )

    assert result["success"] is False
    assert tunnel.commands == []


def test_search_caps_and_quotes_untrusted_inputs():
    tunnel = RecordingTunnel()
    manager = AdvancedFileManager(tunnel)
    path = "/var/log; touch /tmp/path-owned"
    pattern = "failed'; touch /tmp/pattern-owned; #"

    result = manager.file_content_search(
        [path], pattern, {"max_results": 10, "recursive": True}
    )

    assert result["success"] is False
    assert tunnel.commands
    assert shlex.quote(path) in tunnel.commands[0]
    assert shlex.quote(pattern) in tunnel.commands[0]

    tunnel.commands.clear()
    rejected = manager.file_content_search(
        ["/var/log"], "error", {"max_results": 10_001}
    )
    assert rejected["success"] is False
    assert tunnel.commands == []


def test_log_analysis_quotes_paths_and_patterns():
    tunnel = RecordingTunnel()
    manager = SystemIntelligence(tunnel)
    path = "/var/log/app; touch /tmp/path-owned"
    pattern = "error'; touch /tmp/pattern-owned; #"

    manager.analyze_logs([path], [pattern])

    assert tunnel.commands
    assert all(shlex.quote(path) in command for command in tunnel.commands)
    assert any(shlex.quote(pattern) in command for command in tunnel.commands)


def test_file_watch_rejects_unbounded_duration_without_sleeping():
    tunnel = RecordingTunnel()
    manager = AdvancedFileManager(tunnel)

    result = manager.file_watch_monitor(["/var/log"], duration=3_601)

    assert result["success"] is False
    assert tunnel.commands == []


def test_auditor_rejects_unsupported_profiles_without_false_assurance():
    tunnel = RecordingTunnel()
    auditor = SecurityAuditor(tunnel)

    compliance = auditor.compliance_check("unsupported")
    vulnerability = auditor.vulnerability_scan("unsupported")

    assert compliance["success"] is False
    assert compliance["compliant"] is False
    assert vulnerability["success"] is False
    assert tunnel.commands == []
