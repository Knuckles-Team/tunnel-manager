"""Fail-closed validation and resource limits for SSH connections.

The helpers in this module deliberately return generic errors and never include
hosts, users, paths, commands, or secret references in exception text.  That
keeps validation failures safe for MCP responses and observability backends.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import stat
from pathlib import Path

from agent_utilities.core.config import setting

_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?\Z")
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
_SECRET_REF_RE = re.compile(
    r"(?:env|secret|sqlite|vault)://[^\s\x00-\x1f\x7f]{1,2048}\Z"
)
_PUBLIC_KEY_RE = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) "
    r"[A-Za-z0-9+/]{32,16384}={0,3}\Z"
)
_ENV_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}\Z")

DEFAULT_KNOWN_HOSTS = "~/.ssh/known_hosts"
LOOPBACK_BIND_HOST = "127.0.0.1"


class ConnectionPolicyError(ValueError):
    """Raised when a connection request violates the local security policy."""


def _bounded_env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = str(setting(name, "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConnectionPolicyError("Invalid SSH resource-limit configuration") from exc
    if isinstance(value, bool) or not minimum <= value <= maximum:
        raise ConnectionPolicyError("Invalid SSH resource-limit configuration")
    return value


def max_command_chars() -> int:
    return _bounded_env_int("TUNNEL_MAX_COMMAND_CHARS", 65_536, 1, 262_144)


def max_output_bytes() -> int:
    return _bounded_env_int("TUNNEL_MAX_OUTPUT_BYTES", 1_048_576, 1_024, 16_777_216)


def max_transfer_bytes() -> int:
    return _bounded_env_int(
        "TUNNEL_MAX_TRANSFER_BYTES", 268_435_456, 1_024, 2_147_483_648
    )


def max_fleet_hosts() -> int:
    return _bounded_env_int("TUNNEL_MAX_FLEET_HOSTS", 1_000, 1, 10_000)


def max_concurrency() -> int:
    return _bounded_env_int("TUNNEL_MAX_CONCURRENCY", 64, 1, 256)


def validate_host(value: str) -> str:
    """Validate an IP address, DNS name, or conservative SSH-config alias."""

    if not isinstance(value, str):
        raise ConnectionPolicyError("Invalid SSH host")
    host = value.strip()
    if not host or host != value or len(host) > 253:
        raise ConnectionPolicyError("Invalid SSH host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if (
        not _HOST_RE.fullmatch(host)
        or ".." in host
        or host.startswith(("-", "."))
        or host.endswith(("-", "."))
    ):
        raise ConnectionPolicyError("Invalid SSH host")
    return host


def validate_username(value: str) -> str:
    if not isinstance(value, str) or not _USER_RE.fullmatch(value):
        raise ConnectionPolicyError("Invalid SSH username")
    return value


def validate_port(value: int) -> int:
    if isinstance(value, bool):
        raise ConnectionPolicyError("Invalid SSH port")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectionPolicyError("Invalid SSH port") from exc
    if not 1 <= port <= 65_535:
        raise ConnectionPolicyError("Invalid SSH port")
    return port


def validate_forward_target(host: str, port: int) -> tuple[str, int]:
    """Validate a forward destination without broadening the local bind."""

    return validate_host(host), validate_port(port)


def validate_local_bind(host: str | None = None) -> str:
    """Require loopback for local forwarding.

    Tunnel Manager intentionally has no public-bind escape hatch.  Deployments
    which need remote listeners must put an authenticated, policy-enforcing
    gateway in front of a loopback listener.
    """

    candidate = (host or LOOPBACK_BIND_HOST).strip()
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ConnectionPolicyError("Local SSH forwards must bind to loopback") from exc
    if not address.is_loopback:
        raise ConnectionPolicyError("Local SSH forwards must bind to loopback")
    return candidate


def validate_secret_ref(value: str | None, *, required: bool = False) -> str | None:
    """Accept an opaque runtime secret reference and reject literal values."""

    if value is None or value == "":
        if required:
            raise ConnectionPolicyError("An SSH password secret reference is required")
        return None
    if not isinstance(value, str) or not _SECRET_REF_RE.fullmatch(value):
        raise ConnectionPolicyError(
            "SSH passwords must be supplied through a supported secret reference"
        )
    return value


def resolve_secret_ref(value: str | None) -> str | None:
    """Resolve a validated reference only at the connection boundary."""

    reference = validate_secret_ref(value)
    if reference is None:
        return None
    if reference.startswith("env://"):
        variable = reference.removeprefix("env://")
        if not _ENV_NAME_RE.fullmatch(variable):
            raise ConnectionPolicyError("SSH credential resolution failed")
        resolved = setting(variable)
    else:
        from agent_utilities.security.secrets_client import create_secrets_client

        resolved = create_secrets_client().resolve_ref(reference)
    if resolved is None or not isinstance(resolved, str) or not resolved:
        raise ConnectionPolicyError("SSH credential resolution failed")
    if len(resolved) > 65_536 or "\x00" in resolved:
        raise ConnectionPolicyError("SSH credential resolution failed")
    return resolved


def validate_timeout(
    value: int | float | None,
    *,
    default: int,
    maximum: int = 3_600,
) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ConnectionPolicyError("Invalid SSH timeout")
    try:
        timeout = int(value)
    except (TypeError, ValueError) as exc:
        raise ConnectionPolicyError("Invalid SSH timeout") from exc
    if timeout != value or not 1 <= timeout <= maximum:
        raise ConnectionPolicyError("Invalid SSH timeout")
    return timeout


def validate_command(command: str) -> str:
    if (
        not isinstance(command, str)
        or not command
        or len(command) > max_command_chars()
        or "\x00" in command
    ):
        raise ConnectionPolicyError("Invalid managed command")
    return command


def validate_remote_path(value: str) -> str:
    """Validate one bounded remote path without applying shell semantics."""

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 4_096
        or any(ord(char) < 32 or ord(char) == 127 for char in value)
    ):
        raise ConnectionPolicyError("Invalid managed remote path")
    return value


def quote_remote_path(value: str) -> str:
    """Validate and quote one POSIX remote path, including ``~/`` expansion."""

    value = validate_remote_path(value)
    if value == "~":
        return '"$HOME"'
    if value.startswith("~/"):
        suffix = value[2:]
        return '"$HOME"' if not suffix else f'"$HOME"/{shlex.quote(suffix)}'
    return shlex.quote(value)


def validate_public_key(value: str) -> str:
    """Return a comment-free public key safe for an authorized_keys append."""

    if not isinstance(value, str):
        raise ConnectionPolicyError("Invalid SSH public key")
    parts = value.strip().split()
    if len(parts) < 2:
        raise ConnectionPolicyError("Invalid SSH public key")
    key = " ".join(parts[:2])
    if not _PUBLIC_KEY_RE.fullmatch(key):
        raise ConnectionPolicyError("Invalid SSH public key")
    return key


def validated_known_hosts_path(value: str | None = None) -> str:
    """Return a regular, non-writable known-hosts file owned by this user."""

    candidate = Path(value or DEFAULT_KNOWN_HOSTS).expanduser()
    try:
        path = candidate.resolve(strict=True)
        info = path.stat()
    except OSError as exc:
        raise ConnectionPolicyError(
            "A trusted SSH known-hosts file is required"
        ) from exc
    if not path.is_file() or stat.S_ISLNK(candidate.lstat().st_mode):
        raise ConnectionPolicyError("A trusted SSH known-hosts file is required")
    if os.name != "nt":
        if info.st_uid not in {0, os.getuid()} or info.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            raise ConnectionPolicyError(
                "The SSH known-hosts file is not securely owned"
            )
    return str(path)


def validate_identity_path(value: str | None) -> str | None:
    if not value:
        return None
    candidate = Path(value).expanduser()
    try:
        path = candidate.resolve(strict=True)
        info = path.stat()
    except OSError as exc:
        raise ConnectionPolicyError("Configured SSH identity is unavailable") from exc
    if not path.is_file() or stat.S_ISLNK(candidate.lstat().st_mode):
        raise ConnectionPolicyError("Configured SSH identity is unavailable")
    if os.name != "nt" and info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConnectionPolicyError("Configured SSH identity permissions are unsafe")
    return str(path)


def security_posture() -> dict[str, bool | int]:
    """Return metadata-only doctor facts; never expose configured values."""

    known_hosts_ok = True
    try:
        validated_known_hosts_path(setting("TUNNEL_KNOWN_HOSTS") or None)
    except ConnectionPolicyError:
        known_hosts_ok = False
    return {
        "known_hosts_ready": known_hosts_ok,
        # Deliberately NOT `setting("TUNNEL_PASSWORD") is None`: `setting()`
        # normalizes an empty-string env var to its default (None), so it
        # cannot distinguish "unset" from "set but empty" — and a
        # `TUNNEL_PASSWORD=` left in an env file is exactly the legacy
        # plaintext-password footgun this check exists to flag. Read the raw
        # environment directly to preserve that distinction.
        "plaintext_password_env_absent": os.environ.get("TUNNEL_PASSWORD") is None,
        "password_ref_configured": bool(setting("TUNNEL_PASSWORD_REF")),
        "local_forward_loopback_only": validate_local_bind() == LOOPBACK_BIND_HOST,
        "max_command_chars": max_command_chars(),
        "max_output_bytes": max_output_bytes(),
        "max_transfer_bytes": max_transfer_bytes(),
        "max_fleet_hosts": max_fleet_hosts(),
        "max_concurrency": max_concurrency(),
    }
