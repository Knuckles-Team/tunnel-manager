#!/usr/bin/env python
"""
Tests for SecurityAuditor module.
"""

from unittest.mock import Mock


class TestSecurityAuditor:
    """Test suite for SecurityAuditor class."""

    def test_security_auditor_initialization(self):
        """Test SecurityAuditor initialization."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        auditor = SecurityAuditor(mock_tunnel)

        assert auditor.tunnel == mock_tunnel
        assert auditor.logger is not None

    def test_security_audit_comprehensive(self):
        """Test comprehensive security audit."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "apt list" in command:
                return ("0", "", 0)
            elif "sshd_config" in command:
                return ("PermitRootLogin no\nPasswordAuthentication no", "", 0)
            elif "ufw status" in command:
                return ("Status: active", "", 0)
            elif "passwd" in command:
                return ("root:x:0:0:root:/root:/bin/bash", "", 0)
            elif "shadow" in command and "awk" in command:
                return ("", "", 0)
            elif "stat" in command:
                return ("600", "", 0)
            elif "systemctl" in command:
                return ("", "", 0)
            elif "journalctl" in command:
                return ("", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.security_audit()

        assert result["success"] is True
        assert result["audit_type"] == "comprehensive"
        assert result["host"] == "testhost.example.com"
        assert "findings" in result
        assert "severity_counts" in result
        assert "score" in result
        assert "recommendations" in result

    def test_security_audit_with_scope(self):
        """Test security audit with specific scope."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "apt list" in command:
                return ("5", "", 0)
            elif "sshd_config" in command:
                return ("PermitRootLogin yes", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.security_audit(scope=["system_updates", "ssh_config"])

        assert result["success"] is True
        assert len(result["findings"]) >= 1

    def test_security_audit_error_handling(self):
        """Test security audit error handling."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(side_effect=Exception("Connection failed"))

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.security_audit()

        assert result["success"] is False
        assert "audit_errors" in result

    def test_check_system_updates(self):
        """Test system updates check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "apt list" in command:
                return ("10", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_system_updates()

        assert len(findings) >= 1
        assert findings[0]["category"] == "system_updates"

    def test_check_ssh_config(self):
        """Test SSH configuration check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "sshd_config" in command:
                return (
                    "PermitRootLogin yes\nPasswordAuthentication yes\nProtocol 1",
                    "",
                    0,
                )
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_ssh_config()

        assert len(findings) >= 1
        assert findings[0]["category"] == "ssh_config"

    def test_check_firewall(self):
        """Test firewall check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "ufw" in command:
                return ("Status: inactive", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_firewall()

        assert len(findings) >= 1
        assert findings[0]["category"] == "firewall"

    def test_check_user_accounts(self):
        """Test user accounts check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "passwd" in command:
                return (
                    "root:x:0:0:root:/root:/bin/bash\nadmin:x:0:0:admin:/home/admin:/bin/bash",
                    "",
                    0,
                )
            elif "shadow" in command and "awk" in command:
                return ("testuser", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_user_accounts()

        assert len(findings) >= 1
        assert findings[0]["category"] == "user_accounts"

    def test_check_file_permissions(self):
        """Test file permissions check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "shadow" in command and "stat" in command:
                return ("644", "", 0)
            else:
                return ("600", "", 0)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_file_permissions()

        assert len(findings) >= 1
        assert findings[0]["category"] == "file_permissions"

    def test_check_services(self):
        """Test services check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "systemctl" in command:
                return ("ssh.service\n telnet.service", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_services()

        assert len(findings) >= 1
        assert findings[0]["category"] == "services"

    def test_check_logs(self):
        """Test logs check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "journalctl" in command:
                error_lines = "\n".join(["error"] * 15)
                return (error_lines, "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        findings = auditor._check_logs()

        assert len(findings) >= 1
        assert findings[0]["category"] == "logs"

    def test_calculate_security_score(self):
        """Test security score calculation."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        auditor = SecurityAuditor(mock_tunnel)

        # Test with no findings
        score = auditor._calculate_security_score({})
        assert score == 100

        # Test with some findings
        severity_counts = {"critical": 1, "high": 1, "medium": 1}
        score = auditor._calculate_security_score(severity_counts)
        assert score == 55  # 100 - 25 - 15 - 5

    def test_compliance_check_cis_benchmark(self):
        """Test CIS benchmark compliance check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "apt list" in command:
                return ("0", "", 0)
            elif "PermitRootLogin" in command:
                return ("PermitRootLogin no", "", 0)
            elif "ufw status" in command:
                return ("Status: active", "", 0)
            elif "shadow" in command and "stat" in command:
                return ("600", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.compliance_check(standard="cis_benchmark")

        assert result["success"] is True
        assert result["standard"] == "cis_benchmark"
        assert "passed_checks" in result
        assert "failed_checks" in result
        assert "violations" in result

    def test_compliance_check_pci_dss(self):
        """Test PCI DSS compliance check."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "ufw" in command:
                return ("Status: active", "", 0)
            elif "shadow" in command and "awk" in command:
                return ("", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.compliance_check(standard="pci_dss")

        assert result["success"] is True
        assert result["standard"] == "pci_dss"

    def test_compliance_check_error_handling(self):
        """Test compliance check error handling."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(side_effect=Exception("Connection failed"))

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.compliance_check(standard="cis_benchmark")

        assert result["success"] is False
        assert "check_errors" in result

    def test_vulnerability_scan_basic(self):
        """Test basic vulnerability scan."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "apt list" in command:
                return ("package1/updates 1.0-1", "", 0)
            elif "TLSv1" in command:
                return ("TLSv1", "", 0)
            elif "find" in command and "perm" in command:
                return ("/etc/test.conf", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.vulnerability_scan(scan_type="basic")

        assert result["success"] is True
        assert result["scan_type"] == "basic"
        assert "vulnerabilities" in result
        assert "severity_counts" in result

    def test_vulnerability_scan_package(self):
        """Test package vulnerability scan."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "apt list" in command:
                return ("package1/updates 1.0-1\npackage2/updates 2.0-1", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.vulnerability_scan(scan_type="package")

        assert result["success"] is True
        assert result["scan_type"] == "package"
        assert len(result["vulnerabilities"]) >= 1

    def test_vulnerability_scan_error_handling(self):
        """Test vulnerability scan error handling."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(side_effect=Exception("Connection failed"))

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.vulnerability_scan(scan_type="basic")

        assert result["success"] is False
        assert "scan_errors" in result

    def test_access_control_audit(self):
        """Test access control audit."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "passwd" in command and "cat" in command:
                return (
                    "root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000:Test:/home/test:/bin/bash",
                    "",
                    0,
                )
            elif "find" in command and "perm" in command:
                return ("/etc/test.conf", "", 0)
            elif "sudoers" in command:
                return ("root ALL=(ALL:ALL) ALL", "", 0)
            elif "sshd_config" in command:
                return (
                    "PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes",
                    "",
                    0,
                )
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.access_control_audit()

        assert result["success"] is True
        assert result["audit_type"] == "access_control"
        assert "users_audited" in result
        assert "permission_issues" in result
        assert "sudo_config" in result
        assert "ssh_config" in result

    def test_access_control_audit_error_handling(self):
        """Test access control audit error handling."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"
        mock_tunnel.run_command = Mock(side_effect=Exception("Connection failed"))

        auditor = SecurityAuditor(mock_tunnel)
        result = auditor.access_control_audit()

        assert result["success"] is False
        assert "audit_errors" in result

    def test_audit_users(self):
        """Test user audit."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "passwd" in command:
                return (
                    "root:x:0:0:root:/root:/bin/bash\ntestuser:x:1000:1000:Test:/home/test:/bin/bash",
                    "",
                    0,
                )
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        users = auditor._audit_users()

        assert len(users) >= 1
        assert users[0]["username"] == "root"

    def test_audit_permissions(self):
        """Test permissions audit."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "find" in command and "perm" in command:
                return ("/etc/test.conf", "", 0)
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        issues = auditor._audit_permissions()

        assert len(issues) >= 1
        assert issues[0]["issue"] == "world-writable"

    def test_audit_sudo(self):
        """Test sudo audit."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "sudoers" in command:
                return (
                    "root ALL=(ALL:ALL) ALL\ntestuser ALL=(ALL) NOPASSWD: ALL",
                    "",
                    0,
                )
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        config = auditor._audit_sudo()

        assert config["has_sudoers_file"] is True
        assert "passwordless_sudo" in config

    def test_audit_ssh_access(self):
        """Test SSH access audit."""
        from tunnel_manager.security_auditor import SecurityAuditor
        from tunnel_manager.tunnel_manager import Tunnel

        mock_tunnel = Mock(spec=Tunnel)
        mock_tunnel.remote_host = "testhost.example.com"

        def mock_run_command(command):
            if "sshd_config" in command:
                return (
                    "PermitRootLogin no\nPasswordAuthentication no\nPubkeyAuthentication yes",
                    "",
                    0,
                )
            else:
                return ("", "", 1)

        mock_tunnel.run_command = mock_run_command

        auditor = SecurityAuditor(mock_tunnel)
        config = auditor._audit_ssh_access()

        assert config["has_ssh_config"] is True
        assert config["permit_root_login"] is False
        assert config["password_auth"] is False


class TestSecurityAuditResult:
    """Test suite for SecurityAuditResult dataclass."""

    def test_security_audit_result_creation(self):
        """Test SecurityAuditResult creation."""
        from tunnel_manager.security_auditor import SecurityAuditResult

        result = SecurityAuditResult(
            audit_type="comprehensive",
            host="testhost.example.com",
            timestamp="2024-01-01T00:00:00",
            findings=[],
            severity_counts={},
            score=100,
            recommendations=[],
            success=True,
        )

        assert result.audit_type == "comprehensive"
        assert result.host == "testhost.example.com"
        assert result.score == 100
        assert result.success is True


class TestComplianceCheckResult:
    """Test suite for ComplianceCheckResult dataclass."""

    def test_compliance_check_result_creation(self):
        """Test ComplianceCheckResult creation."""
        from tunnel_manager.security_auditor import ComplianceCheckResult

        result = ComplianceCheckResult(
            standard="cis_benchmark",
            host="testhost.example.com",
            timestamp="2024-01-01T00:00:00",
            compliant=True,
            passed_checks=10,
            failed_checks=0,
            violations=[],
            details={},
        )

        assert result.standard == "cis_benchmark"
        assert result.compliant is True
        assert result.passed_checks == 10


class TestVulnerabilityScanResult:
    """Test suite for VulnerabilityScanResult dataclass."""

    def test_vulnerability_scan_result_creation(self):
        """Test VulnerabilityScanResult creation."""
        from tunnel_manager.security_auditor import VulnerabilityScanResult

        result = VulnerabilityScanResult(
            scan_type="basic",
            host="testhost.example.com",
            timestamp="2024-01-01T00:00:00",
            vulnerabilities=[],
            severity_counts={},
            scan_duration=10.5,
            success=True,
        )

        assert result.scan_type == "basic"
        assert result.scan_duration == 10.5
        assert result.success is True


class TestAccessControlAuditResult:
    """Test suite for AccessControlAuditResult dataclass."""

    def test_access_control_audit_result_creation(self):
        """Test AccessControlAuditResult creation."""
        from tunnel_manager.security_auditor import AccessControlAuditResult

        result = AccessControlAuditResult(
            audit_type="access_control",
            host="testhost.example.com",
            timestamp="2024-01-01T00:00:00",
            users_audited=10,
            permission_issues=[],
            sudo_config={},
            ssh_config={},
            success=True,
        )

        assert result.audit_type == "access_control"
        assert result.users_audited == 10
        assert result.success is True
