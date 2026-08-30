"""Load the checked-in deployment authority used by the local merge gates.

The deployment page owns deployment-only inputs that are not Python settings.  A
small machine-readable block keeps the Compose image contract and retired-name
decisions in the same document as the operator instructions.  This module only
parses and validates that block; it does not provide a runtime configuration
fallback.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

POLICY_START = "<!-- BEGIN: deployment-env-policy -->"
POLICY_END = "<!-- END: deployment-env-policy -->"
EXPECTED_SCHEMA_VERSION = 1
RETIRED_ENVIRONMENT = frozenset(
    {
        "OTEL_EXPORTER_OTLP_PUBLIC_KEY",
        "OTEL_EXPORTER_OTLP_SECRET_KEY",
    }
)
REQUIRED_IMAGE_VARIABLES = frozenset(
    {
        "TUNNEL_MANAGER_MCP_IMAGE",
        "TUNNEL_MANAGER_AGENT_IMAGE",
    }
)
IMMUTABLE_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}\Z")
_ENV_NAME = re.compile(r"^[A-Z][A-Z0-9_]*\Z")
_IMAGE_KEY = re.compile(r"^\s*image\s*:")
IMAGE_SUBSTITUTION = re.compile(r"\$\{([A-Z][A-Z0-9_]*)(?:(:?[-?])[^}]*)?\}")


class DeploymentPolicyError(ValueError):
    """Raised when the checked-in deployment authority is malformed."""


def compose_manifest_files(root: Path) -> tuple[Path, ...]:
    """Return the complete Compose manifest universe for this package."""

    candidates = {*root.glob("*compose*.y*ml"), *root.glob("docker/*compose*.y*ml")}
    return tuple(sorted(path for path in candidates if path.is_file()))


def _image_substitutions(compose_file: Path) -> tuple[tuple[str, str | None], ...]:
    """Return ``(variable, operator)`` pairs from this file's ``image:`` scalars."""

    try:
        lines = compose_file.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise DeploymentPolicyError(
            f"cannot read Compose manifest: {compose_file}"
        ) from error
    substitutions: list[tuple[str, str | None]] = []
    for line in lines:
        if not _IMAGE_KEY.match(line):
            continue
        substitutions.extend(
            (match.group(1), match.group(2))
            for match in IMAGE_SUBSTITUTION.finditer(line)
        )
    return tuple(substitutions)


def compose_image_variables(compose_file: Path) -> frozenset[str]:
    """Return variables interpolated by ``image:`` values in one manifest."""

    return frozenset(name for name, _operator in _image_substitutions(compose_file))


def compose_required_image_variables(compose_file: Path) -> frozenset[str]:
    """Return image variables using Compose's required ``:?`` operator."""

    return frozenset(
        name
        for name, operator in _image_substitutions(compose_file)
        if operator == ":?"
    )


def _policy_block(root: Path) -> str:
    path = root / "docs" / "deployment.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as error:
        raise DeploymentPolicyError(
            f"cannot read deployment authority: {path}"
        ) from error
    if POLICY_START not in text or POLICY_END not in text:
        raise DeploymentPolicyError(
            f"deployment authority is missing {POLICY_START} / {POLICY_END}"
        )
    block = text.split(POLICY_START, 1)[1].split(POLICY_END, 1)[0]
    if not block.strip().startswith("```json") or "```" not in block[7:]:
        raise DeploymentPolicyError("deployment authority policy must be a JSON fence")
    payload = block.split("```json", 1)[1].split("```", 1)[0].strip()
    return payload


def _require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeploymentPolicyError(f"{label} must be a non-empty string")
    return value


def _validate_retired(data: Any) -> dict[str, dict[str, str]]:
    if not isinstance(data, dict) or set(data) != RETIRED_ENVIRONMENT:
        raise DeploymentPolicyError(
            "deployment authority must list exactly the two retired raw OTLP names"
        )
    out: dict[str, dict[str, str]] = {}
    expected_replacements = {
        "OTEL_EXPORTER_OTLP_PUBLIC_KEY": "OTEL_EXPORTER_OTLP_PUBLIC_KEY_REF",
        "OTEL_EXPORTER_OTLP_SECRET_KEY": "OTEL_EXPORTER_OTLP_SECRET_KEY_REF",
    }
    for name, raw_spec in data.items():
        if not _ENV_NAME.fullmatch(name):
            raise DeploymentPolicyError(f"invalid retired environment name: {name}")
        if not isinstance(raw_spec, dict):
            raise DeploymentPolicyError(f"retired policy for {name} must be an object")
        if set(raw_spec) != {"replacement", "reason"}:
            raise DeploymentPolicyError(
                f"retired policy for {name} must contain replacement and reason"
            )
        replacement = _require_string(
            raw_spec["replacement"], f"replacement for {name}"
        )
        if replacement != expected_replacements[name]:
            raise DeploymentPolicyError(f"unexpected replacement for {name}")
        out[name] = {
            "replacement": replacement,
            "reason": _require_string(raw_spec["reason"], f"reason for {name}"),
        }
    return out


def _validate_images(root: Path, data: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(data, dict) or set(data) != REQUIRED_IMAGE_VARIABLES:
        raise DeploymentPolicyError(
            "deployment authority must list exactly the two managed image inputs"
        )
    out: dict[str, dict[str, Any]] = {}
    for name, raw_spec in data.items():
        if not _ENV_NAME.fullmatch(name):
            raise DeploymentPolicyError(f"invalid image environment name: {name}")
        if not isinstance(raw_spec, dict) or set(raw_spec) != {"example", "files"}:
            raise DeploymentPolicyError(
                f"image policy for {name} must contain example and files"
            )
        example = _require_string(raw_spec["example"], f"example for {name}")
        if not IMMUTABLE_IMAGE.fullmatch(example):
            raise DeploymentPolicyError(
                f"example for {name} must be an immutable sha256 image"
            )
        if ":latest" in example:
            raise DeploymentPolicyError(f"mutable latest tag is forbidden for {name}")
        files = raw_spec["files"]
        if (
            not isinstance(files, list)
            or not files
            or not all(isinstance(item, str) and item for item in files)
        ):
            raise DeploymentPolicyError(f"files for {name} must be a non-empty list")
        for relative in files:
            candidate = (root / relative).resolve()
            try:
                candidate.relative_to(root.resolve())
            except ValueError as error:
                raise DeploymentPolicyError(
                    f"image policy path escapes repository: {relative}"
                ) from error
            if not candidate.is_file():
                raise DeploymentPolicyError(
                    f"image policy file does not exist: {relative}"
                )
        out[name] = {"example": example, "files": tuple(files)}

    manifests = compose_manifest_files(root)
    manifest_names = {path.relative_to(root.resolve()).as_posix() for path in manifests}
    policy_names = {relative for spec in out.values() for relative in spec["files"]}
    if policy_names != manifest_names:
        missing = ", ".join(sorted(manifest_names - policy_names)) or "(none)"
        extra = ", ".join(sorted(policy_names - manifest_names)) or "(none)"
        raise DeploymentPolicyError(
            "deployment image policy must cover exactly the Compose manifest universe; "
            f"missing={missing}; non-Compose-or-extra={extra}"
        )

    for compose_file in manifests:
        relative = compose_file.relative_to(root.resolve()).as_posix()
        expected = {name for name, spec in out.items() if relative in spec["files"]}
        actual = set(compose_image_variables(compose_file))
        if actual != expected:
            raise DeploymentPolicyError(
                f"Compose image mapping for {relative} is not exact: "
                f"expected={sorted(expected)}; actual={sorted(actual)}"
            )
        required = set(compose_required_image_variables(compose_file))
        if required != actual:
            raise DeploymentPolicyError(
                f"Compose image inputs in {relative} must all use required :? substitutions"
            )
    return out


def validate_policy(root: Path, data: Any) -> dict[str, Any]:
    """Validate raw policy data against the current Compose manifests."""

    if not isinstance(data, dict) or set(data) != {
        "schema_version",
        "retired_environment",
        "compose_image_inputs",
    }:
        raise DeploymentPolicyError(
            "deployment authority has an unexpected top-level shape"
        )
    if data["schema_version"] != EXPECTED_SCHEMA_VERSION:
        raise DeploymentPolicyError(
            f"unsupported deployment authority schema: {data['schema_version']}"
        )
    return {
        "schema_version": EXPECTED_SCHEMA_VERSION,
        "retired_environment": _validate_retired(data["retired_environment"]),
        "compose_image_inputs": _validate_images(root, data["compose_image_inputs"]),
    }


def load_policy(root: Path) -> dict[str, Any]:
    """Return the validated deployment policy from ``docs/deployment.md``."""

    try:
        data = json.loads(_policy_block(root))
    except json.JSONDecodeError as error:
        raise DeploymentPolicyError("deployment authority JSON is invalid") from error
    return validate_policy(root, data)
