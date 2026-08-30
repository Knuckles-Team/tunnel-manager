#!/usr/bin/env python3
"""Validate Compose structure with tracked, non-secret inputs.

The deployment ``.env`` is intentionally not part of this check: it contains
runtime credentials and is not present in a clean checkout.  Compose's
``--no-env-resolution`` mode still validates interpolation and emits the image
set without reading ``env_file`` contents or contacting a registry.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

from deployment_policy import (
    compose_image_variables,
    compose_manifest_files,
    compose_required_image_variables,
    load_policy,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_PATH = REPOSITORY_ROOT / "scripts" / "fixtures" / "precommit-compose.env"
COMPOSE_FILES = compose_manifest_files(REPOSITORY_ROOT)
DEPLOYMENT_POLICY = load_policy(REPOSITORY_ROOT)
REQUIRED_IMAGE_VARIABLES = frozenset(DEPLOYMENT_POLICY["compose_image_inputs"])
IMMUTABLE_IMAGE = re.compile(r"[^@\s]+@sha256:[0-9a-f]{64}\Z")


def _fixture_values() -> dict[str, str]:
    """Load the allowlisted image-only validation fixture."""

    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        FIXTURE_PATH.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        name, separator, value = line.partition("=")
        if not separator or not name or not value:
            raise ValueError(f"malformed validation fixture line {line_number}")
        if name in values:
            raise ValueError(f"duplicate validation fixture variable {name}")
        values[name] = value
    if set(values) != REQUIRED_IMAGE_VARIABLES:
        raise ValueError(
            "validation fixture must contain exactly the managed image variables"
        )
    expected = {
        name: spec["example"]
        for name, spec in DEPLOYMENT_POLICY["compose_image_inputs"].items()
    }
    if values != expected:
        raise ValueError("validation fixture must mirror deployment authority examples")
    return values


def _require_immutable_image(value: str, source: str) -> None:
    if not IMMUTABLE_IMAGE.fullmatch(value):
        raise ValueError(
            f"{source} must end with @sha256:<64 lowercase hexadecimal digits>"
        )


def _compose_image_variables(compose_file: Path) -> frozenset[str]:
    return compose_image_variables(compose_file)


def _compose_required_image_variables(compose_file: Path) -> frozenset[str]:
    return compose_required_image_variables(compose_file)


def _compose_images(compose_file: Path, fixture: Path) -> set[str]:
    command = [
        "docker",
        "compose",
        "--env-file",
        str(fixture),
        "-f",
        str(compose_file),
        "config",
        "--no-env-resolution",
        "--images",
    ]
    try:
        result = subprocess.run(
            command,
            cwd=REPOSITORY_ROOT,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(
            f"unable to run Docker Compose for {compose_file}"
        ) from error
    if result.returncode:
        detail = result.stderr.strip()
        suffix = f": {detail}" if detail else ""
        raise RuntimeError(f"Compose config failed for {compose_file}{suffix}")
    images = {line.strip() for line in result.stdout.splitlines() if line.strip()}
    if not images:
        raise RuntimeError(f"Compose rendered no images for {compose_file}")
    return images


def main() -> int:
    try:
        values = _fixture_values()
        for variable, value in values.items():
            _require_immutable_image(value, variable)
        if not COMPOSE_FILES:
            raise RuntimeError("no Compose files found for validation")
        for compose_file in COMPOSE_FILES:
            variables = _compose_image_variables(compose_file)
            relative = compose_file.relative_to(REPOSITORY_ROOT).as_posix()
            expected_variables = {
                variable
                for variable, spec in DEPLOYMENT_POLICY["compose_image_inputs"].items()
                if relative in spec["files"]
            }
            unknown = variables - REQUIRED_IMAGE_VARIABLES
            missing = expected_variables - variables
            if unknown:
                raise ValueError(
                    f"{compose_file} uses undeclared image inputs: "
                    f"{', '.join(sorted(unknown))}"
                )
            if missing:
                raise ValueError(
                    f"{compose_file} is missing managed image inputs: "
                    f"{', '.join(sorted(missing))}"
                )
            non_required = expected_variables - _compose_required_image_variables(
                compose_file
            )
            if non_required:
                raise ValueError(
                    f"{compose_file} must require image inputs with :? substitution: "
                    f"{', '.join(sorted(non_required))}"
                )
            rendered = _compose_images(compose_file, FIXTURE_PATH)
            expected = {values[variable] for variable in variables}
            if not expected <= rendered:
                absent = ", ".join(sorted(expected - rendered))
                raise RuntimeError(
                    f"Compose did not render configured image(s) for {compose_file}: {absent}"
                )
            for image in rendered:
                _require_immutable_image(image, f"{compose_file} rendered image")
    except (OSError, RuntimeError, ValueError) as error:
        print(f"Compose validation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
