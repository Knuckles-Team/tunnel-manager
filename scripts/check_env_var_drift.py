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

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PASSWORD_ENV = "TUNNEL_PASSWORD"


def _shared_checker() -> Any:
    from scion_sdk.mcp import env_drift as check_env_var_drift

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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check Tunnel Manager env drift.")
    parser.add_argument("root", nargs="?", default=str(REPOSITORY_ROOT))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    root = Path(args.root).resolve()
    checker = _shared_checker()
    report = checker.analyze(root)
    unexpected = _unexpected_findings(report, root)
    rendered = dict(
        report,
        findings=unexpected,
        drift=len(unexpected),
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
    if args.check and unexpected:
        print(
            "\nenv-var drift detected — unexpected configuration drift remains.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
