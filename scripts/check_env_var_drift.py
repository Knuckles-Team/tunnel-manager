#!/usr/bin/env python3
"""Run the shared env-drift gate with Tunnel Manager's security contract.

TUNNEL_PASSWORD is intentionally read once by security_posture to detect the
forbidden legacy plaintext-password input. It is a security sentinel, not
deployable configuration, so it must not be added to .env.example merely to
appease the generic documentation checker. This wrapper accepts that one
evidence-backed finding and leaves every other drift finding fatal.
"""

from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path
from typing import Any

from deployment_policy import DeploymentPolicyError, load_policy
from run_agent_utilities_gate import _agent_utilities_root

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PASSWORD_ENV = "TUNNEL_PASSWORD"


def _shared_checker() -> Any:
    framework_root = _agent_utilities_root(REPOSITORY_ROOT)
    sys.path.insert(0, str(framework_root))
    from agent_utilities.mcp import check_env_var_drift

    return check_env_var_drift


def _has_authorized_password_sentinel(root: Path) -> bool:
    """Prove the forbidden variable is read only by the posture sentinel."""

    reads = 0
    source = root / "tunnel_manager" / "connection_security.py"
    try:
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, SyntaxError, UnicodeDecodeError):
        return False
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            if not (
                isinstance(inner.func, ast.Attribute)
                and inner.func.attr == "get"
                and isinstance(inner.func.value, ast.Attribute)
                and inner.func.value.attr == "environ"
                and isinstance(inner.func.value.value, ast.Name)
                and inner.func.value.value.id == "os"
            ):
                continue
            if (
                inner.args
                and isinstance(inner.args[0], ast.Constant)
                and inner.args[0].value == FORBIDDEN_PASSWORD_ENV
            ):
                reads += 1
                if node.name != "security_posture":
                    return False
    return reads == 1


def _unexpected_findings(report: dict[str, Any], root: Path) -> list[dict[str, Any]]:
    accepted = _password_sentinel_accepted(report, root)
    return [
        finding
        for finding in report["findings"]
        if not (
            accepted
            and finding["type"] == "UNDOCUMENTED"
            and finding["var"] == FORBIDDEN_PASSWORD_ENV
        )
    ]


def _password_sentinel_accepted(report: dict[str, Any], root: Path) -> bool:
    password_findings = [
        (finding["type"], finding["var"])
        for finding in report["findings"]
        if finding["var"] == FORBIDDEN_PASSWORD_ENV
    ]
    return (
        _has_authorized_password_sentinel(root)
        and set(password_findings) == {("UNDOCUMENTED", FORBIDDEN_PASSWORD_ENV)}
        and len(password_findings) == 1
    )


def _runtime_reads(checker: Any, root: Path) -> set[str]:
    """Return Python/runtime reads, excluding Compose interpolation itself."""

    reads = set(checker._scan_setting_calls(root)) | set(
        checker._agent_utilities_reads()
    )
    for helper_name in ("_script_reads", "_derive_toggle_vars"):
        helper = getattr(checker, helper_name, None)
        if helper is not None:
            reads.update(helper(root))
    family_reader = getattr(checker, "_scan_dynamic_family_reads", None)
    family_scanner = getattr(checker, "_scan_dynamic_families", None)
    framework_families = getattr(checker, "_agent_utilities_dynamic_families", None)
    if family_reader is not None and family_scanner is not None:
        families = dict(framework_families() if framework_families else {})
        families.update(family_scanner(root))
        reads.update(family_reader(root, families))
    return reads


def _reconcile_deployment_authority(
    report: dict[str, Any], root: Path, checker: Any
) -> tuple[dict[str, Any], tuple[str, ...]]:
    """Apply only explicit deployment projections to shared-scanner findings.

    ``.env.example`` is temporarily owned by the inventory-authority lane. The
    deployment page therefore owns two narrow projections here: retired raw OTLP
    declarations are no longer accepted configuration, and Compose image inputs
    are documented there because Compose resolves them outside Python. Every
    finding outside those exact source/name pairs remains fatal.
    """

    policy = load_policy(root)
    retired = set(policy["retired_environment"])
    runtime_reads = _runtime_reads(checker, root)
    live_retired = retired & runtime_reads
    if live_retired:
        names = ", ".join(sorted(live_retired))
        raise DeploymentPolicyError(
            f"retired environment names still have runtime readers: {names}"
        )

    image_inputs = set(policy["compose_image_inputs"])
    runtime_image_reads = image_inputs & runtime_reads
    if runtime_image_reads:
        names = ", ".join(sorted(runtime_image_reads))
        raise DeploymentPolicyError(
            f"deployment image inputs have Python/runtime readers: {names}"
        )

    reconciled: list[dict[str, Any]] = []
    accepted: list[str] = []
    for finding in report["findings"]:
        var = finding.get("var")
        source_set = set(finding.get("sources", []))
        if (
            finding.get("type") == "DEAD"
            and var in retired
            and source_set == {".env.example"}
        ):
            accepted.append(f"retired {var}")
            continue
        if (
            finding.get("type") == "UNDOCUMENTED"
            and var in image_inputs
            and source_set == {"(code)"}
        ):
            accepted.append(f"Compose input {var}")
            continue
        reconciled.append(finding)
    return dict(report, findings=reconciled, drift=len(reconciled)), tuple(accepted)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Tunnel Manager env drift.")
    parser.add_argument("root", nargs="?", default=str(REPOSITORY_ROOT))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    checker = _shared_checker()
    try:
        report, reconciled = _reconcile_deployment_authority(
            checker.analyze(root), root, checker
        )
    except DeploymentPolicyError as error:
        print(f"deployment authority invalid: {error}", file=sys.stderr)
        return 1
    unexpected = _unexpected_findings(report, root)
    rendered = dict(
        report,
        findings=unexpected,
        drift=len(unexpected),
        deployment_authority_reconciled=list(reconciled),
    )
    if args.json:
        import json

        print(json.dumps(rendered, indent=2))
    else:
        print(checker._format(rendered))
        if _password_sentinel_accepted(report, root):
            print(
                "  ✓ TUNNEL_PASSWORD is accepted only as the security posture "
                "forbidden-input sentinel"
            )
        for item in reconciled:
            print(f"  ✓ deployment authority: {item}")
    if args.check and unexpected:
        print(
            "\nenv-var drift detected — unexpected configuration drift remains.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
