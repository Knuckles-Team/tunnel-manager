#!/usr/bin/env python
"""
Security Auditor for security and compliance automation.

This module provides security and compliance capabilities including:
- Comprehensive security assessments
- Compliance checks against standards
- Vulnerability scanning
- Access control audits
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger(__name__)


@dataclass
class SecurityAuditResult:
    """Result of a security audit."""

    audit_type: str
    host: str
    timestamp: str
    findings: list
    severity_counts: dict
    score: int
    recommendations: list
    success: bool


@dataclass
class ComplianceCheckResult:
    """Result of a compliance check."""

    standard: str
    host: str
    timestamp: str
    compliant: bool
    passed_checks: int
    failed_checks: int
    violations: list
    details: dict


@dataclass
class VulnerabilityScanResult:
    """Result of a vulnerability scan."""

    scan_type: str
    host: str
    timestamp: str
    vulnerabilities: list
    severity_counts: dict
    scan_duration: float
    success: bool


@dataclass
class AccessControlAuditResult:
    """Result of an access control audit."""

    audit_type: str
    host: str
    timestamp: str
    users_audited: int
    permission_issues: list
    sudo_config: dict
    ssh_config: dict
    success: bool


class SecurityAuditor:
    """
    Provides security and compliance auditing capabilities for remote hosts.
    """

    def __init__(self, tunnel: Tunnel):
        """
        Initialize SecurityAuditor with a Tunnel instance.

        Args:
            tunnel: Tunnel instance for SSH connections
        """
        self.tunnel = tunnel
        self.logger = logging.getLogger(__name__)

    def security_audit(self, scope: list[str] | None = None) -> dict:
        """
        Perform comprehensive security assessment.

        Args:
            scope: List of security areas to audit (default: all)

        Returns:
            Dictionary with security audit results
        """
        try:
            self.logger.info("Starting comprehensive security audit")
            start_time = datetime.now()

            scope = scope or [
                "system_updates",
                "ssh_config",
                "firewall",
                "user_accounts",
                "file_permissions",
                "services",
                "logs",
            ]

            findings = []
            severity_counts = {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            }
            recommendations = []
            audit_errors = []

            # System updates check
            if "system_updates" in scope:
                try:
                    update_findings = self._check_system_updates()
                    findings.extend(update_findings)
                    for f in update_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"System updates check failed: {e}")

            # SSH configuration check
            if "ssh_config" in scope:
                try:
                    ssh_findings = self._check_ssh_config()
                    findings.extend(ssh_findings)
                    for f in ssh_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"SSH config check failed: {e}")

            # Firewall check
            if "firewall" in scope:
                try:
                    firewall_findings = self._check_firewall()
                    findings.extend(firewall_findings)
                    for f in firewall_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"Firewall check failed: {e}")

            # User accounts check
            if "user_accounts" in scope:
                try:
                    user_findings = self._check_user_accounts()
                    findings.extend(user_findings)
                    for f in user_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"User accounts check failed: {e}")

            # File permissions check
            if "file_permissions" in scope:
                try:
                    perm_findings = self._check_file_permissions()
                    findings.extend(perm_findings)
                    for f in perm_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"File permissions check failed: {e}")

            # Services check
            if "services" in scope:
                try:
                    service_findings = self._check_services()
                    findings.extend(service_findings)
                    for f in service_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"Services check failed: {e}")

            # Log monitoring check
            if "logs" in scope:
                try:
                    log_findings = self._check_logs()
                    findings.extend(log_findings)
                    for f in log_findings:
                        severity_counts[f["severity"]] = (
                            severity_counts.get(f["severity"], 0) + 1
                        )
                except Exception as e:
                    audit_errors.append(f"Logs check failed: {e}")

            # Generate recommendations
            recommendations = self._generate_recommendations(findings)

            # Calculate security score (0-100)
            score = self._calculate_security_score(severity_counts)

            result = {
                "audit_type": "comprehensive",
                "host": self.tunnel.remote_host,
                "timestamp": start_time.isoformat(),
                "findings": findings,
                "severity_counts": severity_counts,
                "score": score,
                "recommendations": recommendations,
                "audit_errors": audit_errors,
                "success": len(audit_errors) == 0,
            }

            self.logger.info(f"Security audit completed with score: {score}/100")
            return result

        except Exception as e:
            self.logger.error(f"Failed to perform security audit: {e}")
            return {
                "audit_type": "comprehensive",
                "host": self.tunnel.remote_host,
                "timestamp": datetime.now().isoformat(),
                "findings": [],
                "severity_counts": {},
                "score": 0,
                "recommendations": [],
                "success": False,
                "error": str(e),
            }

    def _check_system_updates(self) -> list:
        """Check for pending system updates."""
        findings = []
        stdout, stderr, exit_code = self.tunnel.run_command(
            "apt list --upgradable 2>/dev/null | wc -l"
        )
        if exit_code == 0:
            update_count = int(stdout.strip()) if stdout.strip().isdigit() else 0
            if update_count > 0:
                findings.append(
                    {
                        "category": "system_updates",
                        "severity": "medium",
                        "message": f"{update_count} packages available for update",
                        "recommendation": "Apply security updates promptly",
                    }
                )
        return findings

    def _check_ssh_config(self) -> list:
        """Check SSH configuration for security issues."""
        findings = []
        stdout, stderr, exit_code = self.tunnel.run_command(
            "cat /etc/ssh/sshd_config 2>/dev/null"
        )
        if exit_code == 0:
            config = stdout
            if "PermitRootLogin yes" in config:
                findings.append(
                    {
                        "category": "ssh_config",
                        "severity": "high",
                        "message": "Root login is permitted",
                        "recommendation": "Disable root login: PermitRootLogin no",
                    }
                )
            if "PasswordAuthentication yes" in config:
                findings.append(
                    {
                        "category": "ssh_config",
                        "severity": "medium",
                        "message": "Password authentication is enabled",
                        "recommendation": "Use key-based authentication: PasswordAuthentication no",
                    }
                )
            if "Protocol 1" in config:
                findings.append(
                    {
                        "category": "ssh_config",
                        "severity": "critical",
                        "message": "SSH protocol 1 is enabled (deprecated)",
                        "recommendation": "Use SSH protocol 2 only: Protocol 2",
                    }
                )
        return findings

    def _check_firewall(self) -> list:
        """Check firewall configuration."""
        findings = []
        stdout, stderr, exit_code = self.tunnel.run_command("ufw status 2>/dev/null")
        if exit_code == 0:
            if "inactive" in stdout:
                findings.append(
                    {
                        "category": "firewall",
                        "severity": "high",
                        "message": "Firewall is inactive",
                        "recommendation": "Enable firewall: ufw enable",
                    }
                )
        else:
            # Try iptables
            stdout, stderr, exit_code = self.tunnel.run_command(
                "iptables -L -n 2>/dev/null"
            )
            if exit_code == 0 and len(stdout.split("\n")) < 10:
                findings.append(
                    {
                        "category": "firewall",
                        "severity": "medium",
                        "message": "Minimal firewall rules detected",
                        "recommendation": "Review and strengthen firewall rules",
                    }
                )
        return findings

    def _check_user_accounts(self) -> list:
        """Check user account security."""
        findings = []
        # Check for users with UID 0 (root)
        stdout, stderr, exit_code = self.tunnel.run_command(
            "cat /etc/passwd | grep ':0:' 2>/dev/null"
        )
        if exit_code == 0:
            root_users = [
                line.split(":")[0] for line in stdout.split("\n") if line.strip()
            ]
            if len(root_users) > 1:
                findings.append(
                    {
                        "category": "user_accounts",
                        "severity": "critical",
                        "message": f"Multiple users with UID 0: {root_users}",
                        "recommendation": "Review and remove unnecessary root-equivalent users",
                    }
                )

        # Check for users without passwords
        stdout, stderr, exit_code = self.tunnel.run_command(
            "cat /etc/shadow | awk -F: '($2 == \"\") {print $1}' 2>/dev/null"
        )
        if exit_code == 0 and stdout.strip():
            findings.append(
                {
                    "category": "user_accounts",
                    "severity": "critical",
                    "message": "Users without passwords detected",
                    "recommendation": "Set passwords for all user accounts",
                }
            )
        return findings

    def _check_file_permissions(self) -> list:
        """Check critical file permissions."""
        findings = []
        critical_files = [
            "/etc/shadow",
            "/etc/passwd",
            "/etc/sudoers",
            "/etc/ssh/sshd_config",
        ]
        for file_path in critical_files:
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"stat -c '%a' {file_path} 2>/dev/null"
            )
            if exit_code == 0:
                perms = stdout.strip()
                if file_path == "/etc/shadow" and perms != "600" and perms != "000":
                    findings.append(
                        {
                            "category": "file_permissions",
                            "severity": "high",
                            "message": f"Insecure permissions on {file_path}: {perms}",
                            "recommendation": f"Set restrictive permissions: chmod 600 {file_path}",
                        }
                    )
        return findings

    def _check_services(self) -> list:
        """Check running services for security issues."""
        findings = []
        stdout, stderr, exit_code = self.tunnel.run_command(
            "systemctl list-units --type=service --state=running 2>/dev/null"
        )
        if exit_code == 0:
            services = [
                line.split()[0] for line in stdout.split("\n") if ".service" in line
            ]
            # Check for potentially dangerous services
            dangerous_services = ["telnet", "rsh", "rlogin", "ftp"]
            for service in dangerous_services:
                if any(service in s for s in services):
                    findings.append(
                        {
                            "category": "services",
                            "severity": "high",
                            "message": f"Insecure service running: {service}",
                            "recommendation": f"Disable {service} service",
                        }
                    )
        return findings

    def _check_logs(self) -> list:
        """Check system logs for security events."""
        findings = []
        stdout, stderr, exit_code = self.tunnel.run_command(
            "journalctl -n 100 --priority=err..alert 2>/dev/null"
        )
        if exit_code == 0:
            error_count = len([line for line in stdout.split("\n") if line.strip()])
            if error_count > 10:
                findings.append(
                    {
                        "category": "logs",
                        "severity": "medium",
                        "message": f"High number of error/alert log entries: {error_count}",
                        "recommendation": "Review system logs for potential issues",
                    }
                )
        return findings

    def _generate_recommendations(self, findings: list) -> list:
        """Generate security recommendations based on findings."""
        recommendations = []
        seen = set()
        for finding in findings:
            rec = finding.get("recommendation", "")
            if rec and rec not in seen:
                recommendations.append(rec)
                seen.add(rec)
        return recommendations

    def _calculate_security_score(self, severity_counts: dict) -> int:
        """Calculate security score based on severity counts."""
        # Base score of 100, deduct points based on severity
        deductions = {
            "critical": 25,
            "high": 15,
            "medium": 5,
            "low": 1,
            "info": 0,
        }
        total_deduction = sum(
            severity_counts.get(sev, 0) * deduction
            for sev, deduction in deductions.items()
        )
        return max(0, 100 - total_deduction)

    def compliance_check(self, standard: str = "cis_benchmark") -> dict:
        """
        Check compliance against security standards.

        Args:
            standard: Compliance standard to check (cis_benchmark, pci_dss, hipaa)

        Returns:
            Dictionary with compliance check results
        """
        try:
            self.logger.info(f"Starting compliance check against {standard}")
            start_time = datetime.now()

            checks = self._get_compliance_checks(standard)
            passed = 0
            failed = 0
            violations = []
            check_errors = []

            for check in checks:
                try:
                    result = self._run_compliance_check(check)
                    if result["passed"]:
                        passed += 1
                    else:
                        failed += 1
                        violations.append(
                            {
                                "check_id": check["id"],
                                "description": check["description"],
                                "severity": check["severity"],
                                "finding": result["finding"],
                                "remediation": check["remediation"],
                            }
                        )
                except Exception as e:
                    check_errors.append(f"Check {check['id']} failed: {e}")

            compliant = failed == 0 and len(check_errors) == 0

            result = {
                "standard": standard,
                "host": self.tunnel.remote_host,
                "timestamp": start_time.isoformat(),
                "compliant": compliant,
                "passed_checks": passed,
                "failed_checks": failed,
                "violations": violations,
                "check_errors": check_errors,
                "details": {
                    "total_checks": len(checks),
                    "compliance_percentage": (
                        (passed / len(checks) * 100) if checks else 0
                    ),
                },
                "success": len(check_errors) == 0,
            }

            self.logger.info(
                f"Compliance check completed: {passed}/{len(checks)} checks passed"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to perform compliance check: {e}")
            return {
                "standard": standard,
                "host": self.tunnel.remote_host,
                "timestamp": datetime.now().isoformat(),
                "compliant": False,
                "passed_checks": 0,
                "failed_checks": 0,
                "violations": [],
                "details": {},
                "success": False,
                "error": str(e),
            }

    def _get_compliance_checks(self, standard: str) -> list:
        """Get compliance checks for the specified standard."""
        if standard == "cis_benchmark":
            return [
                {
                    "id": "CIS-1.1.1",
                    "description": "Ensure system updates are applied",
                    "severity": "high",
                    "command": "apt list --upgradable 2>/dev/null | wc -l",
                    "expected": "0",
                    "remediation": "Apply all security updates",
                },
                {
                    "id": "CIS-1.2.1",
                    "description": "Ensure SSH root login is disabled",
                    "severity": "critical",
                    "command": "grep 'PermitRootLogin' /etc/ssh/sshd_config",
                    "expected_pattern": "no",
                    "remediation": "Set PermitRootLogin no in sshd_config",
                },
                {
                    "id": "CIS-1.3.1",
                    "description": "Ensure firewall is enabled",
                    "severity": "high",
                    "command": "ufw status",
                    "expected_pattern": "active",
                    "remediation": "Enable firewall with ufw enable",
                },
                {
                    "id": "CIS-2.1.1",
                    "description": "Ensure /etc/shadow permissions are 600",
                    "severity": "critical",
                    "command": "stat -c '%a' /etc/shadow",
                    "expected": "600",
                    "remediation": "chmod 600 /etc/shadow",
                },
            ]
        elif standard == "pci_dss":
            return [
                {
                    "id": "PCI-1.1",
                    "description": "Ensure firewall is configured",
                    "severity": "critical",
                    "command": "ufw status",
                    "expected_pattern": "active",
                    "remediation": "Configure and enable firewall",
                },
                {
                    "id": "PCI-2.1",
                    "description": "Ensure default passwords are changed",
                    "severity": "critical",
                    "command": "cat /etc/shadow | awk -F: '($2 == \"\") {print $1}'",
                    "expected": "",
                    "remediation": "Set passwords for all accounts",
                },
            ]
        else:
            return []

    def _run_compliance_check(self, check: dict) -> dict:
        """Run a single compliance check."""
        stdout, stderr, exit_code = self.tunnel.run_command(check["command"])
        output = stdout.strip()

        if "expected" in check:
            passed = output == check["expected"]
            finding = f"Expected '{check['expected']}', got '{output}'"
        elif "expected_pattern" in check:
            passed = check["expected_pattern"] in output.lower()
            finding = f"Pattern '{check['expected_pattern']}' not found in output"
        else:
            passed = exit_code == 0
            finding = "Command failed" if exit_code != 0 else ""

        return {"passed": passed, "finding": finding if not passed else ""}

    def vulnerability_scan(self, scan_type: str = "basic") -> dict:
        """
        Scan for known vulnerabilities.

        Args:
            scan_type: Type of scan (basic, package, config)

        Returns:
            Dictionary with vulnerability scan results
        """
        try:
            self.logger.info(f"Starting vulnerability scan ({scan_type})")
            start_time = datetime.now()

            vulnerabilities = []
            severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            scan_errors = []

            if scan_type in ["basic", "package"]:
                try:
                    pkg_vulns = self._scan_package_vulnerabilities()
                    vulnerabilities.extend(pkg_vulns)
                    for v in pkg_vulns:
                        severity_counts[v["severity"]] = (
                            severity_counts.get(v["severity"], 0) + 1
                        )
                except Exception as e:
                    scan_errors.append(f"Package vulnerability scan failed: {e}")

            if scan_type in ["basic", "config"]:
                try:
                    config_vulns = self._scan_config_vulnerabilities()
                    vulnerabilities.extend(config_vulns)
                    for v in config_vulns:
                        severity_counts[v["severity"]] = (
                            severity_counts.get(v["severity"], 0) + 1
                        )
                except Exception as e:
                    scan_errors.append(f"Config vulnerability scan failed: {e}")

            duration = (datetime.now() - start_time).total_seconds()

            result = {
                "scan_type": scan_type,
                "host": self.tunnel.remote_host,
                "timestamp": start_time.isoformat(),
                "vulnerabilities": vulnerabilities,
                "severity_counts": severity_counts,
                "scan_duration": duration,
                "scan_errors": scan_errors,
                "success": len(scan_errors) == 0,
            }

            self.logger.info(
                f"Vulnerability scan completed: {len(vulnerabilities)} vulnerabilities found"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to perform vulnerability scan: {e}")
            return {
                "scan_type": scan_type,
                "host": self.tunnel.remote_host,
                "timestamp": datetime.now().isoformat(),
                "vulnerabilities": [],
                "severity_counts": {},
                "scan_duration": 0,
                "success": False,
                "error": str(e),
            }

    def _scan_package_vulnerabilities(self) -> list:
        """Scan for package vulnerabilities."""
        vulnerabilities = []
        stdout, stderr, exit_code = self.tunnel.run_command(
            "apt list --upgradable 2>/dev/null"
        )
        if exit_code == 0:
            for line in stdout.split("\n"):
                if line.strip() and "/" in line:
                    vulnerabilities.append(
                        {
                            "type": "package",
                            "package": line.split("/")[0],
                            "severity": "medium",
                            "description": "Package update available",
                            "fix": "Update package with apt upgrade",
                        }
                    )
        return vulnerabilities

    def _scan_config_vulnerabilities(self) -> list:
        """Scan for configuration vulnerabilities."""
        vulnerabilities = []
        # Check for weak SSL/TLS configurations
        stdout, stderr, exit_code = self.tunnel.run_command(
            "grep -r 'TLSv1' /etc/ssl /etc/nginx 2>/dev/null"
        )
        if exit_code == 0 and stdout.strip():
            vulnerabilities.append(
                {
                    "type": "configuration",
                    "severity": "high",
                    "description": "Legacy TLS version detected",
                    "location": "SSL/TLS configuration",
                    "fix": "Disable TLSv1 and use TLSv1.2+",
                }
            )

        # Check for world-writable files in system directories
        stdout, stderr, exit_code = self.tunnel.run_command(
            "find /etc /usr /bin -perm -o+w 2>/dev/null"
        )
        if exit_code == 0 and stdout.strip():
            vulnerabilities.append(
                {
                    "type": "configuration",
                    "severity": "medium",
                    "description": "World-writable files in system directories",
                    "location": "System directories",
                    "fix": "Remove world-write permissions",
                }
            )
        return vulnerabilities

    def access_control_audit(self) -> dict:
        """
        Audit access controls and permissions.

        Returns:
            Dictionary with access control audit results
        """
        try:
            self.logger.info("Starting access control audit")
            start_time = datetime.now()

            # Audit users
            audit_errors = []
            users_audited = []
            permission_issues = []
            sudo_config = {}
            ssh_config = {}

            try:
                users_audited = self._audit_users()
            except Exception as e:
                audit_errors.append(f"User audit failed: {e}")

            try:
                permission_issues = self._audit_permissions()
            except Exception as e:
                audit_errors.append(f"Permission audit failed: {e}")

            try:
                sudo_config = self._audit_sudo()
            except Exception as e:
                audit_errors.append(f"Sudo audit failed: {e}")

            try:
                ssh_config = self._audit_ssh_access()
            except Exception as e:
                audit_errors.append(f"SSH access audit failed: {e}")

            result = {
                "audit_type": "access_control",
                "host": self.tunnel.remote_host,
                "timestamp": start_time.isoformat(),
                "users_audited": len(users_audited),
                "permission_issues": permission_issues,
                "sudo_config": sudo_config,
                "ssh_config": ssh_config,
                "audit_errors": audit_errors,
                "success": len(audit_errors) == 0,
            }

            self.logger.info(
                f"Access control audit completed: {len(users_audited)} users audited"
            )
            return result

        except Exception as e:
            self.logger.error(f"Failed to perform access control audit: {e}")
            return {
                "audit_type": "access_control",
                "host": self.tunnel.remote_host,
                "timestamp": datetime.now().isoformat(),
                "users_audited": 0,
                "permission_issues": [],
                "sudo_config": {},
                "ssh_config": {},
                "success": False,
                "error": str(e),
            }

    def _audit_users(self) -> list:
        """Audit user accounts."""
        users = []
        stdout, stderr, exit_code = self.tunnel.run_command("cat /etc/passwd")
        if exit_code == 0:
            for line in stdout.split("\n"):
                if line.strip():
                    parts = line.split(":")
                    if len(parts) >= 7:
                        users.append(
                            {
                                "username": parts[0],
                                "uid": parts[2],
                                "gid": parts[3],
                                "home": parts[5],
                                "shell": parts[6],
                            }
                        )
        return users

    def _audit_permissions(self) -> list:
        """Audit file and directory permissions."""
        issues = []
        # Check for world-writable files in sensitive directories
        sensitive_dirs = ["/etc", "/root", "/home"]
        for dir_path in sensitive_dirs:
            stdout, stderr, exit_code = self.tunnel.run_command(
                f"find {dir_path} -perm -o+w 2>/dev/null"
            )
            if exit_code == 0 and stdout.strip():
                for file_path in stdout.split("\n"):
                    if file_path.strip():
                        issues.append(
                            {
                                "path": file_path.strip(),
                                "issue": "world-writable",
                                "severity": "high",
                            }
                        )
        return issues

    def _audit_sudo(self) -> dict[str, Any]:
        """Audit sudo configuration."""
        config: dict[str, Any] = {}
        stdout, stderr, exit_code = self.tunnel.run_command(
            "cat /etc/sudoers 2>/dev/null"
        )
        if exit_code == 0:
            config["has_sudoers_file"] = True
            config["sudoers_lines"] = len(stdout.split("\n"))
            config["passwordless_sudo"] = "NOPASSWD" in stdout
        else:
            config["has_sudoers_file"] = False
        return config

    def _audit_ssh_access(self) -> dict:
        """Audit SSH access configuration."""
        config = {}
        stdout, stderr, exit_code = self.tunnel.run_command(
            "cat /etc/ssh/sshd_config 2>/dev/null"
        )
        if exit_code == 0:
            config["has_ssh_config"] = True
            config["permit_root_login"] = "PermitRootLogin yes" in stdout
            config["password_auth"] = "PasswordAuthentication yes" in stdout
            config["pubkey_auth"] = "PubkeyAuthentication yes" in stdout
        else:
            config["has_ssh_config"] = False
        return config
