"""Focused tests for deterministic, non-secret merge-gate prerequisites."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from subprocess import CompletedProcess

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT / "scripts"))

import check_env_var_drift  # noqa: E402
import deployment_policy  # noqa: E402
import validate_compose  # noqa: E402


def test_compose_fixture_contains_only_immutable_managed_images() -> None:
    values = validate_compose._fixture_values()

    assert set(values) == validate_compose.REQUIRED_IMAGE_VARIABLES
    for variable, value in values.items():
        validate_compose._require_immutable_image(value, variable)
        assert "password" not in variable.lower()
        assert "secret" not in variable.lower()


def test_compose_files_declare_expected_image_inputs() -> None:
    assert validate_compose._compose_image_variables(
        REPOSITORY_ROOT / "docker" / "mcp.compose.yml"
    ) == frozenset({"TUNNEL_MANAGER_MCP_IMAGE"})
    assert (
        validate_compose._compose_image_variables(
            REPOSITORY_ROOT / "docker" / "agent.compose.yml"
        )
        == validate_compose.REQUIRED_IMAGE_VARIABLES
    )


def test_deployment_authority_declares_immutable_image_inputs() -> None:
    policy = deployment_policy.load_policy(REPOSITORY_ROOT)

    assert set(policy["compose_image_inputs"]) == {
        "TUNNEL_MANAGER_MCP_IMAGE",
        "TUNNEL_MANAGER_AGENT_IMAGE",
    }
    for spec in policy["compose_image_inputs"].values():
        assert deployment_policy.IMMUTABLE_IMAGE.fullmatch(spec["example"])


def test_deployment_authority_proves_raw_otlp_names_are_retired() -> None:
    policy = deployment_policy.load_policy(REPOSITORY_ROOT)
    assert set(policy["retired_environment"]) == {
        "OTEL_EXPORTER_OTLP_PUBLIC_KEY",
        "OTEL_EXPORTER_OTLP_SECRET_KEY",
    }
    from agent_utilities.mcp import check_env_var_drift as drift

    runtime_reads = set(drift._scan_setting_calls(REPOSITORY_ROOT)) | set(
        drift._agent_utilities_reads()
    )
    assert not runtime_reads & set(policy["retired_environment"])


def test_deployment_authority_reconciles_only_exact_known_findings() -> None:
    from agent_utilities.mcp import check_env_var_drift as drift

    report = {
        "findings": [
            {
                "type": "DEAD",
                "var": "OTEL_EXPORTER_OTLP_PUBLIC_KEY",
                "sources": [".env.example"],
            },
            {
                "type": "DEAD",
                "var": "OTEL_EXPORTER_OTLP_SECRET_KEY",
                "sources": [".env.example"],
            },
            {
                "type": "UNDOCUMENTED",
                "var": "TUNNEL_MANAGER_MCP_IMAGE",
                "sources": ["(code)"],
            },
            {
                "type": "UNDOCUMENTED",
                "var": "TUNNEL_MANAGER_AGENT_IMAGE",
                "sources": ["(code)"],
            },
            {"type": "DEAD", "var": "UNRELATED_SETTING", "sources": [".env.example"]},
        ]
    }

    reconciled, accepted = check_env_var_drift._reconcile_deployment_authority(
        report, REPOSITORY_ROOT, drift
    )

    assert {item["var"] for item in reconciled["findings"]} == {"UNRELATED_SETTING"}
    assert len(accepted) == 4


def test_deployment_authority_rejects_a_defaulted_image_substitution(tmp_path) -> None:
    compose = tmp_path / "mcp.compose.yml"
    compose.write_text(
        "services:\n  app:\n    image: ${TUNNEL_MANAGER_MCP_IMAGE:-fallback}\n",
        encoding="utf-8",
    )

    assert validate_compose._compose_image_variables(compose) == frozenset(
        {"TUNNEL_MANAGER_MCP_IMAGE"}
    )
    assert validate_compose._compose_required_image_variables(compose) == frozenset()


def test_deployment_authority_rejects_a_live_retired_reader() -> None:
    class FakeChecker:
        @staticmethod
        def _scan_setting_calls(_root):
            return {"OTEL_EXPORTER_OTLP_PUBLIC_KEY"}

        @staticmethod
        def _agent_utilities_reads():
            return set()

        @staticmethod
        def _compose_subst_reads(_root):
            return set(validate_compose.REQUIRED_IMAGE_VARIABLES)

    with pytest.raises(
        deployment_policy.DeploymentPolicyError, match="runtime readers"
    ):
        check_env_var_drift._reconcile_deployment_authority(
            {"findings": []}, REPOSITORY_ROOT, FakeChecker()
        )


def test_deployment_authority_rejects_a_python_image_reader() -> None:
    class FakeChecker:
        @staticmethod
        def _scan_setting_calls(_root):
            return {"TUNNEL_MANAGER_MCP_IMAGE"}

        @staticmethod
        def _agent_utilities_reads():
            return set()

    with pytest.raises(
        deployment_policy.DeploymentPolicyError, match="Python/runtime readers"
    ):
        check_env_var_drift._reconcile_deployment_authority(
            {"findings": []}, REPOSITORY_ROOT, FakeChecker()
        )


def _raw_deployment_policy() -> dict:
    return json.loads(deployment_policy._policy_block(REPOSITORY_ROOT))


def test_deployment_authority_rejects_a_non_compose_policy_path() -> None:
    policy = _raw_deployment_policy()
    policy["compose_image_inputs"]["TUNNEL_MANAGER_MCP_IMAGE"]["files"] = ["README.md"]

    with pytest.raises(
        deployment_policy.DeploymentPolicyError, match="Compose manifest universe"
    ):
        deployment_policy.validate_policy(REPOSITORY_ROOT, policy)


def test_deployment_authority_rejects_a_missing_variable_in_declared_file() -> None:
    policy = _raw_deployment_policy()
    policy["compose_image_inputs"]["TUNNEL_MANAGER_AGENT_IMAGE"]["files"] = [
        "docker/mcp.compose.yml"
    ]

    with pytest.raises(
        deployment_policy.DeploymentPolicyError, match="Compose image mapping"
    ):
        deployment_policy.validate_policy(REPOSITORY_ROOT, policy)


def test_deployment_authority_rejects_an_undeclared_compose_manifest() -> None:
    policy = _raw_deployment_policy()
    policy["compose_image_inputs"]["TUNNEL_MANAGER_MCP_IMAGE"]["files"] = [
        "docker/agent.compose.yml"
    ]

    with pytest.raises(
        deployment_policy.DeploymentPolicyError, match="Compose manifest universe"
    ):
        deployment_policy.validate_policy(REPOSITORY_ROOT, policy)


def test_compose_gate_avoids_runtime_env_file(monkeypatch) -> None:
    observed: list[list[str]] = []

    def fake_run(command, **kwargs):
        observed.append(command)
        assert kwargs["cwd"] == REPOSITORY_ROOT
        assert kwargs["timeout"] == 30
        compose_file = Path(command[command.index("-f") + 1])
        values = validate_compose._fixture_values()
        images = "\n".join(
            values[name]
            for name in validate_compose._compose_image_variables(compose_file)
        )
        return CompletedProcess(command, 0, stdout=f"{images}\n", stderr="")

    monkeypatch.setattr(validate_compose.subprocess, "run", fake_run)

    assert validate_compose.main() == 0
    assert observed
    assert all("--no-env-resolution" in command for command in observed)
    assert all("../.env" not in command for command in observed)


def test_resource_limit_family_is_visible_to_env_drift_scanner() -> None:
    from agent_utilities.mcp import check_env_var_drift as drift

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
