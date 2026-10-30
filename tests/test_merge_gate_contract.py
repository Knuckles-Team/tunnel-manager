"""Focused tests for the env-drift merge-gate reconciliation (the deployment-authority harness is retired)."""

from __future__ import annotations

import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import check_env_var_drift  # noqa: E402


def test_resource_limit_family_is_visible_to_env_drift_scanner() -> None:
    from scion_sdk.mcp import env_drift as drift

    root = REPOSITORY_ROOT
    families = drift._scan_dynamic_families(root)
    reads = drift._scan_dynamic_family_reads(root, families)

    assert {
        "TUNNEL_MAX_COMMAND_CHARS",
        "TUNNEL_MAX_OUTPUT_BYTES",
        "TUNNEL_MAX_TRANSFER_BYTES",
        "TUNNEL_MAX_FLEET_HOSTS",
        "TUNNEL_MAX_CONCURRENCY",
    } <= reads


def test_forbidden_password_sentinel_is_evidence_backed() -> None:
    assert check_env_var_drift._has_authorized_password_sentinel(REPOSITORY_ROOT)
    report = {
        "findings": [
            {"type": "UNDOCUMENTED", "var": "TUNNEL_PASSWORD"},
        ]
    }

    assert check_env_var_drift._unexpected_findings(report, REPOSITORY_ROOT) == []


def test_unrelated_env_drift_is_not_accepted() -> None:
    report = {
        "findings": [
            {"type": "UNDOCUMENTED", "var": "TUNNEL_PASSWORD"},
            {"type": "DEAD", "var": "STALE_SETTING"},
        ]
    }

    unexpected = check_env_var_drift._unexpected_findings(report, REPOSITORY_ROOT)

    assert unexpected == [{"type": "DEAD", "var": "STALE_SETTING"}]
