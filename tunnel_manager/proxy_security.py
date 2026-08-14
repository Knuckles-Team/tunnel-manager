"""No-shell proxy command validation shared by sync and async SSH clients."""

from __future__ import annotations

import os
import shlex
import shutil
from pathlib import Path

from agent_utilities.core.config import setting

_DEFAULT_EXECUTABLES = "ssh,nc,ncat,connect-proxy,corkscrew,tsh"
_MAX_COMMAND_LENGTH = 8_192
_MAX_ARGUMENTS = 64


class ProxyCommandError(ValueError):
    """Raised when inventory proxy configuration is not safe to execute."""


def _csv(name: str, default: str) -> tuple[str, ...]:
    return tuple(
        item.strip() for item in str(setting(name, default)).split(",") if item.strip()
    )


def _executable_name(value: str) -> str:
    name = Path(value).name.casefold()
    return name[:-4] if name.endswith(".exe") else name


def _reject_nested_execution(executable: str, arguments: list[str]) -> None:
    lowered = [argument.casefold() for argument in arguments]
    if executable == "ssh":
        forbidden = (
            "proxycommand",
            "localcommand",
            "permitlocalcommand",
            "knownhostscommand",
            "include=",
        )
        if any(any(token in argument for token in forbidden) for argument in lowered):
            raise ProxyCommandError("Nested SSH command execution is not permitted")
        if any(argument == "-f" or argument.startswith("-f") for argument in lowered):
            raise ProxyCommandError("Custom SSH config files are not permitted")
    if executable in {"nc", "ncat"}:
        forbidden_flags = {"-e", "--exec", "-c", "--sh-exec", "--lua-exec"}
        if any(argument in forbidden_flags for argument in lowered):
            raise ProxyCommandError(
                "Proxy executable process-launch flags are not permitted"
            )


def _trusted_directories() -> tuple[Path, ...]:
    configured = _csv("TUNNEL_PROXY_TRUSTED_DIRS", "")
    if configured:
        return tuple(Path(item).expanduser().resolve() for item in configured)
    if os.name == "nt":
        system_root = Path(setting("SYSTEMROOT", r"C:\Windows"))
        return (
            (system_root / "System32" / "OpenSSH").resolve(),
            (system_root / "System32").resolve(),
        )
    return tuple(
        Path(item)
        for item in ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin")
    )


def _contained_in(path: Path, roots: tuple[Path, ...]) -> bool:
    for root in roots:
        try:
            path.relative_to(root)
            return True
        except ValueError:
            continue
    return False


def proxy_command_argv(
    command: str,
    *,
    hostname: str,
    port: int,
    username: str = "",
) -> tuple[str, ...]:
    """Return a validated proxy argv, never a command-shell program string."""
    if (
        not isinstance(command, str)
        or not command.strip()
        or len(command) > _MAX_COMMAND_LENGTH
        or any(char in command for char in ("\x00", "\n", "\r"))
    ):
        raise ProxyCommandError("Invalid proxy command")
    try:
        parts = shlex.split(command, posix=os.name != "nt")
    except ValueError as exc:
        raise ProxyCommandError("Proxy command could not be parsed") from exc
    if not parts or len(parts) > _MAX_ARGUMENTS:
        raise ProxyCommandError("Proxy command argument limit exceeded")

    allowed = {
        _executable_name(name)
        for name in _csv("TUNNEL_PROXY_EXECUTABLES", _DEFAULT_EXECUTABLES)
    }
    executable_name = _executable_name(parts[0])
    if executable_name not in allowed:
        raise ProxyCommandError("Proxy executable is not allowlisted")
    _reject_nested_execution(executable_name, parts[1:])

    trusted_dirs = _trusted_directories()
    search_path = os.pathsep.join(str(path) for path in trusted_dirs)
    resolved_text = shutil.which(parts[0], path=search_path)
    if not resolved_text:
        raise ProxyCommandError(
            "Proxy executable is unavailable in trusted directories"
        )
    resolved = Path(resolved_text).resolve()
    # ``which`` already requires an executable regular file. The explicit root
    # check prevents a caller-supplied absolute path from bypassing our PATH.
    if not _contained_in(resolved, trusted_dirs):
        raise ProxyCommandError("Proxy executable is outside trusted directories")

    replacements = {
        "%h": hostname,
        "%p": str(port),
        "%r": username or "",
    }
    if any(
        not isinstance(value, str)
        or len(value) > 1_024
        or any(char in value for char in ("\x00", "\n", "\r"))
        for value in replacements.values()
    ):
        raise ProxyCommandError("Invalid SSH proxy placeholder value")
    expanded: list[str] = [str(resolved)]
    for argument in parts[1:]:
        for placeholder, value in replacements.items():
            argument = argument.replace(placeholder, value)
        if len(argument) > 4_096:
            raise ProxyCommandError("Proxy command argument is too long")
        expanded.append(argument)
    return tuple(expanded)


def proxy_command_string(argv: tuple[str, ...]) -> str:
    """Quote validated argv for Paramiko's shlex-based ProxyCommand adapter."""
    return shlex.join(argv)
