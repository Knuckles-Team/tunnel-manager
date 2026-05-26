"""MCP tools for security operations.

Auto-generated from mcp_server.py during ecosystem standardization.
"""

import logging

from agent_utilities.mcp_utilities import ctx_log
from fastmcp import Context, FastMCP
from pydantic import Field

from tunnel_manager.mcp_server import ResponseBuilder
from tunnel_manager.security_auditor import SecurityAuditor
from tunnel_manager.tunnel_manager import Tunnel

logger = logging.getLogger("tunnel-manager-mcp")


def register_security_tools(mcp: FastMCP):
    """Register security scanning and compliance tool."""

    @mcp.tool(
        annotations={
            "title": "Security Auditing",
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
        },
        tags={"security_auditing"},
    )
    async def tm_security(
        action: str = Field(
            description="Action: 'security_audit', 'compliance_check', 'vulnerability_scan', 'access_control_audit'"
        ),
        remote_host: str = Field(description="Remote host to audit."),
        username: str = Field(default="", description="SSH username."),
        password: str = Field(default="", description="SSH password."),
        identity_file: str = Field(default="", description="SSH identity file path."),
        scope: list[str] = Field(
            default=[], description="Security areas to audit (security_audit)."
        ),
        standard: str = Field(
            default="cis_benchmark",
            description="Compliance standard: cis_benchmark, pci_dss, hipaa (compliance_check).",
        ),
        scan_type: str = Field(
            default="basic",
            description="Scan type: basic, package, config (vulnerability_scan).",
        ),
        ctx: Context = Field(description="MCP context.", default=None),
    ) -> dict:
        """Security scanning and compliance."""
        try:
            tunnel = Tunnel(
                remote_host=remote_host,
                username=username or None,
                password=password or None,
                identity_file=identity_file or None,
            )
            auditor = SecurityAuditor(tunnel)

            if action == "security_audit":
                result = auditor.security_audit(scope if scope else None)
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Security audit completed with score: {result['score']}/100",
                    {"host": remote_host, "audit_result": result},
                    error=result.get("error", ""),
                    errors=result.get("audit_errors", []),
                )

            elif action == "compliance_check":
                result = auditor.compliance_check(standard)
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Compliance check completed: {result['compliance_percentage']:.1f}% compliant",
                    {
                        "host": remote_host,
                        "standard": standard,
                        "compliance_result": result,
                    },
                    error=result.get("error", ""),
                    errors=result.get("check_errors", []),
                )

            elif action == "vulnerability_scan":
                result = auditor.vulnerability_scan(scan_type)
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Vulnerability scan completed: {len(result['vulnerabilities'])} vulnerabilities found",
                    {
                        "host": remote_host,
                        "scan_type": scan_type,
                        "scan_result": result,
                    },
                    error=result.get("error", ""),
                    errors=result.get("scan_errors", []),
                )

            elif action == "access_control_audit":
                result = auditor.access_control_audit()
                return ResponseBuilder.build(
                    200 if result["success"] else 500,
                    f"Access control audit completed: {result['users_audited']} users audited",
                    {"host": remote_host, "audit_result": result},
                    error=result.get("error", ""),
                    errors=result.get("audit_errors", []),
                )
            else:
                return ResponseBuilder.build(
                    400,
                    f"Unknown action: {action}",
                    {"action": action},
                    errors=[
                        "Valid: security_audit, compliance_check, vulnerability_scan, access_control_audit"
                    ],
                )
        except Exception as e:
            ctx_log(ctx, logger, "error", f"Security audit fail ({action}): {e}")
            return ResponseBuilder.build(
                500, f"Security audit fail ({action})", {"host": remote_host}, str(e)
            )
