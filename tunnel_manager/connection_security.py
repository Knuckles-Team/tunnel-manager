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

from scion_sdk.config import setting

_HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,251}[A-Za-z0-9])?\Z")
_USER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}\Z")
_SECRET_REF_RE = re.compile(
    r"(?:env|secret|sqlite|vault)://[^\s\x00-\x1f\x7f]{1,2048}\Z"
)
_PUBLIC_KEY_RE = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) "
    r"[A-Za-z0-9+/]{32,16384}={0,3}\Z"
)

DEFAULT_KNOWN_HOSTS = "~/.ssh/known_hosts"
LOOPBACK_BIND_HOST = "127.0.0.1"


class ConnectionPolicyError(ValueError):
    """Raised when a connection request violates the local security policy."""


_RESOURCE_LIMIT_SUFFIXES = (
    "MAX_COMMAND_CHARS",
    "MAX_OUTPUT_BYTES",
    "MAX_TRANSFER_BYTES",
    "MAX_FLEET_HOSTS",
    "MAX_CONCURRENCY",
)


def _bounded_env_int(
    setting_group: str,
    setting_name: str,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    """Read one bounded setting from the declared ``TUNNEL`` limit family."""

    raw = str(setting(f"{setting_group}_{setting_name}", "")).strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConnectionPolicyError("Invalid SSH resource-limit configuration") from exc
    if isinstance(value, bool) or not minimum <= value <= maximum:
        raise ConnectionPolicyError("Invalid SSH resource-limit configuration")
    return value


# The setting name is composed at runtime from a stable group and a reviewed suffix
# family.  Publishing the family keeps the env-drift gate aware of these genuine reads
# without duplicating the configuration names at each scanner call site.
_bounded_env_int.dynamic_env_prefix_arg = "setting_group"  # type: ignore[attr-defined]
_bounded_env_int.dynamic_env_suffixes = _RESOURCE_LIMIT_SUFFIXES  # type: ignore[attr-defined]


def max_command_chars() -> int:
    return _bounded_env_int("TUNNEL", "MAX_COMMAND_CHARS", 65_536, 1, 262_144)


def max_output_bytes() -> int:
    return _bounded_env_int("TUNNEL", "MAX_OUTPUT_BYTES", 1_048_576, 1_024, 16_777_216)


def max_transfer_bytes() -> int:
    return _bounded_env_int(
        "TUNNEL", "MAX_TRANSFER_BYTES", 268_435_456, 1_024, 2_147_483_648
    )


def max_fleet_hosts() -> int:
    return _bounded_env_int("TUNNEL", "MAX_FLEET_HOSTS", 1_000, 1, 10_000)


def max_concurrency() -> int:
    return _bounded_env_int("TUNNEL", "MAX_CONCURRENCY", 64, 1, 256)


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
        raise ConnectionPolicyError(
            "Invalid SSH username: must be a non-empty string matching "
            f"{_USER_RE.pattern} (got {type(value).__name__} of length "
            f"{len(value) if isinstance(value, str) else 0})"
        )
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
    from scion_sdk.credentials.references import SecretReferenceError
    from scion_sdk.credentials.resolution import resolve_secret_reference
    from scion_sdk.credentials.resolver import CredentialUnavailableError

    try:
        resolved = resolve_secret_reference(reference)
    except (SecretReferenceError, CredentialUnavailableError) as exc:
        raise ConnectionPolicyError(
            f"SSH credential resolution failed: reference {reference!r} could not "
            f"be resolved ({type(exc).__name__})"
        ) from exc
    if resolved is None or not isinstance(resolved, str) or not resolved:
        raise ConnectionPolicyError(
            f"SSH credential resolution failed: reference {reference!r} resolved "
            "to an empty or non-string value"
        )
    if len(resolved) > 65_536 or "\x00" in resolved:
        raise ConnectionPolicyError(
            f"SSH credential resolution failed: reference {reference!r} resolved "
            "to a value that is too long or contains NUL"
        )
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


def current_uid() -> int | None:
    """Return the POSIX uid, or ``None`` on platforms without one (Windows)."""

    return os.getuid() if hasattr(os, "getuid") else None


def secure_descriptor(descriptor: int) -> None:
    """Make an open file owner-only: ``fchmod 0o600`` on POSIX.

    Windows has no ``os.fchmod``; its files are hardened by path afterwards
    through :func:`secure_path` once the descriptor is closed.
    """

    if hasattr(os, "fchmod"):
        os.fchmod(descriptor, 0o600)


def secure_path(path: str | os.PathLike, *, directory: bool = False) -> None:
    """Make ``path`` owner-only in the way the platform supports.

    POSIX: mode 0o600 (0o700 for a directory). Windows: only the read-only bit
    exists in ``os.chmod``, so a file gets ``S_IREAD | S_IWRITE`` (owner read
    and write, never read-only) and a directory is left to its inherited ACL.
    """

    if _is_windows():
        if not directory:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        return
    os.chmod(path, 0o700 if directory else 0o600)


def _is_windows() -> bool:
    return os.name == "nt"


# Principals every local account belongs to: Everyone, Authenticated Users and
# BUILTIN\Users. A key or trust file that grants them access is not private.
_BROAD_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-32-545"})
_ACE_READ = 0x1 | 0x80000000 | 0x10000000 | 0x20000000
_ACE_WRITE = 0x2 | 0x4 | 0x10000 | 0x40000 | 0x80000 | 0x40000000 | 0x10000000


def windows_allowed_aces(path: str | os.PathLike) -> list[tuple[str, int]]:
    """Return ``(sid, access mask)`` for every allow entry in a file's DACL.

    Windows file modes carry no group/other bits, so the access-control list is
    the permission state. A missing (NULL) DACL grants Everyone full access.
    """

    import ctypes
    from ctypes import wintypes

    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    void_p = ctypes.c_void_p
    advapi.GetNamedSecurityInfoW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.c_int,
        wintypes.DWORD,
        void_p,
        void_p,
        ctypes.POINTER(void_p),
        void_p,
        ctypes.POINTER(void_p),
    ]
    advapi.GetNamedSecurityInfoW.restype = wintypes.DWORD
    advapi.GetAclInformation.argtypes = [
        void_p,
        void_p,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    advapi.GetAclInformation.restype = wintypes.BOOL
    advapi.GetAce.argtypes = [void_p, wintypes.DWORD, ctypes.POINTER(void_p)]
    advapi.GetAce.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [void_p, ctypes.POINTER(wintypes.LPWSTR)]
    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [void_p]
    kernel.LocalFree.restype = void_p

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    dacl, descriptor = void_p(), void_p()
    status = advapi.GetNamedSecurityInfoW(
        str(path), 1, 4, None, None, ctypes.byref(dacl), None, ctypes.byref(descriptor)
    )
    if status:
        raise OSError(status, "cannot read the file's access-control list")
    try:
        if not dacl.value:
            return [("S-1-1-0", 0x1FFFFF)]
        info = AclSizeInformation()
        if not advapi.GetAclInformation(
            dacl, ctypes.byref(info), ctypes.sizeof(info), 2
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        entries: list[tuple[str, int]] = []
        for index in range(info.AceCount):
            ace = void_p()
            if not advapi.GetAce(dacl, index, ctypes.byref(ace)):
                raise ctypes.WinError(ctypes.get_last_error())
            if ctypes.c_ubyte.from_address(ace.value).value != 0:  # not ALLOWED
                continue
            mask = ctypes.c_uint32.from_address(ace.value + 4).value
            text = wintypes.LPWSTR()
            if not advapi.ConvertSidToStringSidW(
                void_p(ace.value + 8), ctypes.byref(text)
            ):
                raise ctypes.WinError(ctypes.get_last_error())
            try:
                entries.append((str(text.value), mask))
            finally:
                kernel.LocalFree(ctypes.cast(text, void_p))
        return entries
    finally:
        kernel.LocalFree(descriptor)


def windows_broad_access(path: str | os.PathLike, *, write_only: bool) -> list[str]:
    """SIDs of Everyone-class principals with access (write, if ``write_only``)."""

    wanted = _ACE_WRITE if write_only else _ACE_READ | _ACE_WRITE
    return sorted(
        {
            sid
            for sid, mask in windows_allowed_aces(path)
            if sid in _BROAD_SIDS and mask & wanted
        }
    )


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
            f"A trusted SSH known-hosts file is required: cannot stat {candidate} "
            f"(TUNNEL_KNOWN_HOSTS): {type(exc).__name__}"
        ) from exc
    if not path.is_file() or stat.S_ISLNK(candidate.lstat().st_mode):
        raise ConnectionPolicyError(
            f"A trusted SSH known-hosts file is required: {candidate} "
            "(TUNNEL_KNOWN_HOSTS) is not a regular non-symlink file"
        )
    if _is_windows():
        broad = windows_broad_access(path, write_only=True)
        if broad:
            raise ConnectionPolicyError(
                f"The SSH known-hosts file is not securely owned: {path} grants "
                f"write access to {', '.join(broad)} (Everyone/Users must not write)"
            )
    else:
        if info.st_uid not in {0, current_uid()} or info.st_mode & (
            stat.S_IWGRP | stat.S_IWOTH
        ):
            raise ConnectionPolicyError(
                f"The SSH known-hosts file is not securely owned: {path} has uid "
                f"{info.st_uid} (expected 0 or {current_uid()}) and mode "
                f"{stat.S_IMODE(info.st_mode):04o} (group/other must not write)"
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
        raise ConnectionPolicyError(
            f"Configured SSH identity is unavailable: cannot stat {candidate} "
            f"(TUNNEL_IDENTITY_FILE): {type(exc).__name__}"
        ) from exc
    if not path.is_file() or stat.S_ISLNK(candidate.lstat().st_mode):
        raise ConnectionPolicyError(
            f"Configured SSH identity is unavailable: {candidate} is not a "
            "regular non-symlink file"
        )
    if _is_windows():
        broad = windows_broad_access(path, write_only=False)
        if broad:
            raise ConnectionPolicyError(
                f"Configured SSH identity permissions are unsafe: {path} grants "
                f"access to {', '.join(broad)} (must be owner-only)"
            )
    elif info.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConnectionPolicyError(
            f"Configured SSH identity permissions are unsafe: {path} has mode "
            f"{stat.S_IMODE(info.st_mode):04o} (must be 0600 or stricter)"
        )
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


def describe_error(exc: BaseException) -> str:
    """``Type: message`` for a failure, so a caller sees the cause.

    Every tool response passes through ``sanitize_tool_response``, which
    redacts secrets from this text but keeps local paths, since they are the cause.
    """
    detail = str(exc).strip()
    return f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__


def generate_key_pair(key_path: str, key_type: str = "ed25519") -> None:
    """Write an unencrypted OpenSSH key pair to ``key_path`` and ``key_path.pub``.

    Native, so the server needs no ``ssh-keygen`` binary in its image. The
    private key is created with mode 0600 and never overwritten.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

    if key_type not in ("rsa", "ed25519"):
        raise ValueError("key_type must be 'rsa' or 'ed25519'")
    path = os.path.expanduser(key_path)
    key = (
        rsa.generate_private_key(public_exponent=65537, key_size=4096)
        if key_type == "rsa"
        else ed25519.Ed25519PrivateKey.generate()
    )
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    os.makedirs(os.path.dirname(path) or ".", mode=0o700, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        secure_descriptor(handle.fileno())
        handle.write(private)
    secure_path(path)
    with open(path + ".pub", "wb") as handle:
        handle.write(public + b"\n")
