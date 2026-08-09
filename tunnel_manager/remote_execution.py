"""Entitlement-aware structured remote execution for repository workers.

CONCEPT:TM-OS.governance.entitlement-aware-remote-execution

This module is the small cross-package seam used by Repository Manager's future
remote workers.  Inventory aliases and structured argv are the only public
inputs.  ``HostConfig`` stays inside :class:`HostInventory` and the connection
is re-authorized immediately before dispatch, so a plan cannot retain stale
credentials or an entitlement that has since been revoked.

The wire-shaped models intentionally mirror Repository Manager's C-04
execution command/result contract without importing that package.  Tunnel
Manager owns SSH inventory, secret references, known-host policy, identity
files, proxy validation, and transport finalization; Repository Manager owns
job scheduling and durable WorkItems.
"""

from __future__ import annotations

import re
import shlex
import uuid
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from agent_utilities.core.config import setting
from agent_utilities.security.brain_context import ActorContext, use_actor
from agent_utilities.security.entitlements import identity_scoped_resources
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
    field_validator,
    model_validator,
)

from .connection_security import (
    ConnectionPolicyError,
    max_command_chars,
    max_output_bytes,
    max_transfer_bytes,
    validate_command,
    validate_identity_path,
    validate_secret_ref,
    validate_timeout,
    validated_known_hosts_path,
)
from .models import CommandResult, HostConfig
from .proxy_security import proxy_command_argv
from .tunnel_manager import HostManager, Tunnel, default_inventory_path

_ALIAS_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9])?\Z")
_ENV_REF_RE = re.compile(r"[A-Za-z][A-Za-z0-9_.:/-]*\Z")
_MAX_OUTPUT_TAIL_BYTES = 64 * 1024
_MAX_REMOTE_PATH_BYTES = 4_096
_SHELL_NAMES = frozenset({"ash", "bash", "csh", "dash", "fish", "ksh", "sh", "zsh"})


class ExecutionOutcome(StrEnum):
    """Wire values from Repository Manager C-04."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    REFUSED = "refused"


class FailureClass(StrEnum):
    """Stable C-10 failure categories emitted by the adapter."""

    INVALID_REQUEST = "invalid_request"
    UNAUTHORIZED_TARGET = "unauthorized_target"
    CONFLICT_BASE_MOVED = "conflict_base_moved"
    CAPACITY_DISK_DEFERRED = "capacity_disk_deferred"
    DEPENDENCY_BLOCKED = "dependency_blocked"
    CANCELLED_DEADLINE = "cancelled_deadline"
    WORKER_ENVIRONMENT_FAILURE = "worker_environment_failure"
    VALIDATION_CANDIDATE_FAILURE = "validation_candidate_failure"
    STALE_FENCE_DUPLICATE_EFFECT = "stale_fence_duplicate_effect"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    INTERNAL_ERROR = "internal_error"


class RemoteExecutionError(RuntimeError):
    """Base error with a stable, non-sensitive failure category."""

    failure_class = FailureClass.INTERNAL_ERROR


class RemoteRequestError(RemoteExecutionError, ValueError):
    """The structured command or target shape is invalid."""

    failure_class = FailureClass.INVALID_REQUEST


class RemoteTargetError(RemoteExecutionError, PermissionError):
    """The alias is unknown, revoked, or outside the actor's entitlement."""

    failure_class = FailureClass.UNAUTHORIZED_TARGET


class RemoteTransportError(RemoteExecutionError):
    """The trusted SSH environment or transport could not execute the request."""

    failure_class = FailureClass.WORKER_ENVIRONMENT_FAILURE


class AuthorizedTarget(BaseModel):
    """Opaque public view of an authorized inventory target.

    The alias is the only connection selector.  Hostname, username, identity,
    proxy, known-host, and secret fields are deliberately absent and are never
    serialized by this model.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    kind: str = "inventory_alias"
    alias: StrictStr
    capability_labels: tuple[StrictStr, ...] = ("ssh",)

    @field_validator("kind")
    @classmethod
    def validate_kind(_cls, value: str) -> str:
        if value != "inventory_alias":
            raise ValueError("remote targets must be inventory aliases")
        return value

    @field_validator("alias")
    @classmethod
    def validate_alias(_cls, value: str) -> str:
        if not _ALIAS_RE.fullmatch(value):
            raise ValueError("remote target requires a safe inventory alias")
        return value

    @field_validator("capability_labels", mode="before")
    @classmethod
    def normalize_labels(_cls, value: object) -> tuple[str, ...]:
        if isinstance(value, str) or value is None:
            raise ValueError("capability labels must be a sequence")
        labels = tuple(value)
        if any(not isinstance(item, str) or not item.strip() for item in labels):
            raise ValueError("capability labels must be non-empty strings")
        return tuple(sorted(set(labels)))


class RemoteCommandRequest(BaseModel):
    """C-04-compatible fixed-argv command request.

    ``environment_refs`` are opaque names, never environment values.  The SSH
    adapter currently refuses non-empty references because it has no approved
    remote environment resolver; RMDD-15 may add one behind the same field.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    argv: tuple[StrictStr, ...]
    workdir: StrictStr
    environment_refs: tuple[StrictStr, ...] = ()
    timeout_seconds: StrictInt = Field(default=3_600, ge=1, le=3_600)
    max_stdout_bytes: StrictInt = Field(
        default_factory=lambda: min(_MAX_OUTPUT_TAIL_BYTES, max_output_bytes()),
        ge=0,
        le=16_777_216,
    )
    max_stderr_bytes: StrictInt = Field(
        default_factory=lambda: min(_MAX_OUTPUT_TAIL_BYTES, max_output_bytes()),
        ge=0,
        le=16_777_216,
    )
    max_artifact_bytes: StrictInt = Field(
        default_factory=max_transfer_bytes,
        ge=0,
        le=2_147_483_648,
    )
    heartbeat_interval_seconds: StrictInt = Field(default=30, ge=1, le=3_600)
    cancellation_channel: StrictStr | None = None

    @field_validator("argv", mode="before")
    @classmethod
    def normalize_argv(_cls, value: object) -> tuple[str, ...]:
        if isinstance(value, (str, bytes, bytearray)) or value is None:
            raise ValueError("argv must be a non-empty sequence")
        try:
            values = tuple(value)
        except TypeError as exc:
            raise ValueError("argv must be a non-empty sequence") from exc
        if not values:
            raise ValueError("argv must not be empty")
        for item in values:
            if not isinstance(item, str) or not item:
                raise ValueError("argv entries must be non-empty strings")
            if any(ord(char) < 0x20 or ord(char) == 0x7F for char in item):
                raise ValueError("argv entries must not contain control characters")
        executable = Path(values[0]).name.casefold()
        if executable in _SHELL_NAMES and any(
            item in {"-c", "--command", "-command"} for item in values[1:]
        ):
            raise ValueError("raw shell command execution is not permitted")
        return values

    @field_validator("workdir")
    @classmethod
    def validate_workdir(_cls, value: str) -> str:
        if (
            not value
            or len(value.encode("utf-8")) > _MAX_REMOTE_PATH_BYTES
            or any(ord(char) < 0x20 or ord(char) == 0x7F for char in value)
            or not value.startswith("/")
            or any(part in {".", ".."} for part in Path(value).parts)
        ):
            raise ValueError("workdir must be a canonical absolute remote path")
        return value

    @field_validator("environment_refs", mode="before")
    @classmethod
    def normalize_environment_refs(_cls, value: object) -> tuple[str, ...]:
        if isinstance(value, str) or value is None:
            raise ValueError("environment_refs must be a sequence")
        values = tuple(value)
        if any(
            not isinstance(item, str) or not _ENV_REF_RE.fullmatch(item)
            for item in values
        ):
            raise ValueError(
                "environment_refs must contain approved reference names, not raw values"
            )
        return tuple(sorted(set(values)))

    @field_validator("cancellation_channel")
    @classmethod
    def validate_cancellation_channel(_cls, value: str | None) -> str | None:
        if value is not None and (not value or any(ord(char) < 0x20 for char in value)):
            raise ValueError("cancellation_channel must be an opaque identifier")
        return value

    @model_validator(mode="after")
    def validate_limits(self) -> RemoteCommandRequest:
        if self.max_stdout_bytes > max_output_bytes():
            raise ValueError("requested stdout limit exceeds tunnel policy")
        if self.max_stderr_bytes > max_output_bytes():
            raise ValueError("requested stderr limit exceeds tunnel policy")
        if self.max_artifact_bytes > max_transfer_bytes():
            raise ValueError("requested artifact limit exceeds tunnel policy")
        rendered = _render_command(self)
        if len(rendered) > max_command_chars():
            raise ValueError("rendered command exceeds tunnel policy")
        return self


class RemoteExecutionResult(BaseModel):
    """C-04-compatible bounded result with no private connection fields."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    contract_version: Literal["1"] = "1"
    command_id: StrictStr
    outcome: ExecutionOutcome
    exit_code: StrictInt | None = None
    signal: StrictInt | None = Field(default=None, ge=1)
    started_at: datetime
    finished_at: datetime
    duration_ms: StrictInt = Field(ge=0)
    worker_id: StrictStr
    fence: StrictStr
    stdout_tail: StrictStr = ""
    stderr_tail: StrictStr = ""
    log_refs: tuple[StrictStr, ...] = ()
    artifact_refs: tuple[StrictStr, ...] = ()
    failure_class: FailureClass | None = None
    cleanup_ok: StrictBool = True
    error_message: StrictStr | None = None

    @field_validator("started_at", "finished_at")
    @classmethod
    def require_timezone(_cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("execution timestamps must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("stdout_tail", "stderr_tail")
    @classmethod
    def bound_tails(_cls, value: str) -> str:
        if len(value.encode("utf-8")) > _MAX_OUTPUT_TAIL_BYTES:
            raise ValueError("execution output tails exceed the bounded limit")
        return value

    @model_validator(mode="after")
    def validate_result(self) -> RemoteExecutionResult:
        if self.finished_at < self.started_at:
            raise ValueError("execution finished_at cannot precede started_at")
        if self.exit_code is not None and self.signal is not None:
            raise ValueError("execution cannot report both exit code and signal")
        if self.outcome == ExecutionOutcome.SUCCEEDED:
            if self.exit_code != 0 or self.failure_class is not None:
                raise ValueError(
                    "successful execution requires exit_code=0 and no failure"
                )
        elif (
            self.outcome
            in {
                ExecutionOutcome.FAILED,
                ExecutionOutcome.CANCELLED,
                ExecutionOutcome.TIMED_OUT,
                ExecutionOutcome.REFUSED,
            }
            and self.failure_class is None
        ):
            raise ValueError("unsuccessful execution requires a failure class")
        return self


@runtime_checkable
class TunnelTransport(Protocol):
    """Minimal injectable transport used by the adapter and its fake tests."""

    def connect(self, timeout: int | None = None) -> None:
        """Open the already-validated SSH connection."""

    def run_command(self, command: str, timeout: int | None = None) -> CommandResult:
        """Run one fixed, internally rendered command."""

    def close(self) -> None:
        """Release the transport, including after a failed dispatch."""


def _render_command(request: RemoteCommandRequest) -> str:
    """Render structured inputs with fixed shell framing and strict quoting."""

    # ``cd`` and ``exec`` are controller-owned framing.  Every caller value is
    # one shlex-quoted argv element; metacharacters therefore remain data and
    # cannot add a second command or pipeline.
    rendered = (
        f"cd -- {shlex.quote(request.workdir)} && exec {shlex.join(request.argv)}"
    )
    return validate_command(rendered)


def render_remote_command(request: RemoteCommandRequest) -> str:
    """Return the deterministic command used by a transport fake or worker."""

    return _render_command(request)


def _new_id(prefix: str) -> str:
    return f"{prefix}:{uuid.uuid4()}"


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _bounded_text(
    value: object, limit: int, *, config: HostConfig | None = None
) -> str:
    """Redact connection material and return a UTF-8 bounded text tail."""

    text = str(value or "")
    if config is not None:
        replacements = [
            config.hostname,
            config.user,
            config.identity_file,
            config.key_path,
            config.known_hosts_file,
            config.proxy_command,
            config.password_ref,
        ]
        if config.password_ref:
            try:
                resolved_password = config.resolved_password()
            except Exception:  # noqa: BLE001 - never expose secret resolution details
                resolved_password = None
            if resolved_password:
                replacements.append(resolved_password)
        for sensitive in sorted(
            {item for item in replacements if item}, key=len, reverse=True
        ):
            text = text.replace(str(sensitive), "<redacted>")
    text = re.sub(r"(?:env|secret|sqlite|vault)://[^\s]+", "<redacted>", text)
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore")


class HostInventory:
    """Entitlement-aware alias resolver backed by the canonical HostManager."""

    def __init__(
        self,
        *,
        manager_factory: Callable[[], HostManager] | None = None,
    ) -> None:
        self._manager_factory = manager_factory or self._default_manager

    @staticmethod
    def _default_manager() -> HostManager:
        inventory = setting("TUNNEL_INVENTORY") or default_inventory_path()
        return HostManager(config_file=inventory)

    @staticmethod
    def _validate_alias(alias: str) -> str:
        if not isinstance(alias, str) or not _ALIAS_RE.fullmatch(alias):
            raise RemoteTargetError("remote target authorization failed")
        return alias

    def _resolve_config(self, alias: str, actor: ActorContext) -> HostConfig:
        """Reload, authorize, and return private config for one dispatch."""

        alias = self._validate_alias(alias)
        if actor is None:
            raise RemoteTargetError("remote target authorization failed")
        manager = self._manager_factory()
        try:
            entitled = identity_scoped_resources("ssh", [alias], actor=actor)
        except Exception as exc:  # noqa: BLE001 - fail closed without identity details
            raise RemoteTargetError("remote target authorization failed") from exc
        if alias not in entitled:
            raise RemoteTargetError("remote target authorization failed")
        try:
            # HostManager.get_host repeats the same entitlement check against
            # the ambient actor.  Binding the verified actor here prevents a
            # stale or different ambient context from authorizing dispatch.
            with use_actor(actor):
                config = manager.get_host(alias)
        except Exception as exc:  # noqa: BLE001 - do not leak inventory details
            raise RemoteTargetError("remote target authorization failed") from exc
        if config is None:
            raise RemoteTargetError("remote target authorization failed")
        try:
            return config if isinstance(config, HostConfig) else HostConfig(**config)
        except Exception as exc:  # noqa: BLE001 - malformed inventory is not public
            raise RemoteTransportError(
                "remote inventory configuration is invalid"
            ) from exc

    def resolve(self, alias: str, actor: ActorContext) -> AuthorizedTarget:
        """Resolve an alias to an opaque authorized target view.

        A fresh HostManager is loaded for every call.  The returned object has
        no credential or private connection material and is safe to persist in
        a Repository Manager plan.  Dispatch must call the private resolver
        again, so inventory edits and entitlement revocations take effect.
        """

        self._resolve_config(alias, actor)
        return AuthorizedTarget(alias=alias)


def _validate_host_config(config: HostConfig) -> None:
    """Apply all connection-boundary policy before a fake or real transport."""
    try:
        validate_secret_ref(config.password_ref)
        validated_known_hosts_path(
            config.known_hosts_file or setting("TUNNEL_KNOWN_HOSTS")
        )
        validate_identity_path(config.identity_file or config.key_path)
        certificate = config.extra_config.get(
            "certificate_file"
        ) or config.extra_config.get("certificatefile")
        validate_identity_path(certificate)
        if config.proxy_command:
            proxy_command_argv(
                config.proxy_command,
                hostname=config.hostname,
                port=config.port,
                username=config.user,
            )
    except ConnectionPolicyError:
        raise
    except Exception as exc:
        raise ConnectionPolicyError(
            "SSH policy rejected the inventory configuration"
        ) from exc


def _as_command_result(result: object) -> CommandResult:
    if isinstance(result, CommandResult):
        return result
    if isinstance(result, Mapping):
        return CommandResult.model_validate(result)
    success = bool(getattr(result, "success", False))
    return CommandResult(
        success=success,
        stdout=str(getattr(result, "stdout", "") or ""),
        stderr=str(getattr(result, "stderr", "") or ""),
        error_message=getattr(result, "error_message", None),
    )


class TunnelCommandExecutor:
    """Execute one structured command through an authorized inventory alias."""

    def __init__(
        self,
        inventory: HostInventory | None = None,
        *,
        transport_factory: Callable[[HostConfig], TunnelTransport] | None = None,
        worker_id: str = "tunnel-manager",
    ) -> None:
        if not worker_id or any(ord(char) < 0x20 for char in worker_id):
            raise ValueError("worker_id must be an opaque identifier")
        self.inventory = inventory or HostInventory()
        self._transport_factory = transport_factory or (
            lambda config: Tunnel(config=config)
        )
        self.worker_id = worker_id

    def execute(
        self,
        target: AuthorizedTarget | Mapping[str, Any],
        request: RemoteCommandRequest | Mapping[str, Any],
        actor: ActorContext,
    ) -> RemoteExecutionResult:
        """Reauthorize, validate, execute, and always close one remote command."""

        started = _utc_now()
        command_id = _new_id("rmcmd")
        fence = _new_id("fence")
        config: HostConfig | None = None
        transport: TunnelTransport | None = None
        result: RemoteExecutionResult | None = None
        cleanup_ok = True
        parsed_request: RemoteCommandRequest | None = None
        try:
            parsed_target = (
                target
                if isinstance(target, AuthorizedTarget)
                else AuthorizedTarget.model_validate(target)
            )
            parsed_request = (
                request
                if isinstance(request, RemoteCommandRequest)
                else RemoteCommandRequest.model_validate(request)
            )
            if parsed_request.environment_refs:
                raise RemoteRequestError(
                    "approved remote environment references are not configured"
                )
            # This is intentionally a fresh inventory load and entitlement
            # check, never a reuse of the plan-time target's HostConfig.
            config = self.inventory._resolve_config(parsed_target.alias, actor)
            _validate_host_config(config)
            timeout = validate_timeout(
                parsed_request.timeout_seconds, default=3_600, maximum=3_600
            )
            transport = self._transport_factory(config)
            # The concrete Tunnel already owns connection setup inside its
            # legacy run_command() method.  Calling connect() here would add a
            # second lifecycle call (and makes connection-counting fakes look
            # like duplicate dispatches).  Injectable worker transports retain
            # the explicit connect-before-run contract.
            if not isinstance(transport, Tunnel):
                transport.connect(timeout=timeout)
            rendered_command = _render_command(parsed_request)
            if isinstance(transport, Tunnel):
                raw_result = transport.run_command(
                    rendered_command,
                    timeout=timeout,
                    propagate_errors=True,
                )
            else:
                raw_result = transport.run_command(rendered_command, timeout=timeout)
            command_result = _as_command_result(raw_result)
            finished = _utc_now()
            if command_result.success:
                result = self._result(
                    command_id=command_id,
                    fence=fence,
                    started=started,
                    finished=finished,
                    outcome=ExecutionOutcome.SUCCEEDED,
                    exit_code=0,
                    stdout=command_result.stdout,
                    stderr=command_result.stderr,
                    request=parsed_request,
                    config=config,
                )
            else:
                failure = (
                    FailureClass.VALIDATION_CANDIDATE_FAILURE
                    if not command_result.error_message
                    else FailureClass.WORKER_ENVIRONMENT_FAILURE
                )
                result = self._result(
                    command_id=command_id,
                    fence=fence,
                    started=started,
                    finished=finished,
                    outcome=ExecutionOutcome.FAILED,
                    exit_code=1,
                    stdout=command_result.stdout,
                    stderr=command_result.stderr,
                    request=parsed_request,
                    config=config,
                    failure_class=failure,
                    error_message="remote command failed",
                )
        except RemoteTargetError as exc:
            result = self._failure_result(
                command_id,
                fence,
                started,
                ExecutionOutcome.REFUSED,
                exc.failure_class,
                "remote target authorization failed",
            )
        except ConnectionPolicyError:
            result = self._failure_result(
                command_id,
                fence,
                started,
                ExecutionOutcome.REFUSED,
                FailureClass.WORKER_ENVIRONMENT_FAILURE,
                "remote SSH policy refused the execution environment",
            )
        except (RemoteRequestError, ValidationError, ValueError) as exc:
            failure = (
                exc.failure_class
                if isinstance(exc, RemoteExecutionError)
                else FailureClass.INVALID_REQUEST
            )
            result = self._failure_result(
                command_id,
                fence,
                started,
                ExecutionOutcome.REFUSED,
                failure,
                "remote execution request was refused",
            )
        except TimeoutError:
            result = self._failure_result(
                command_id,
                fence,
                started,
                ExecutionOutcome.TIMED_OUT,
                FailureClass.CANCELLED_DEADLINE,
                "remote execution deadline exceeded",
            )
        except Exception:
            result = self._failure_result(
                command_id,
                fence,
                started,
                ExecutionOutcome.FAILED,
                FailureClass.WORKER_ENVIRONMENT_FAILURE,
                "remote transport failed",
            )
        finally:
            if transport is not None:
                try:
                    transport.close()
                except Exception:  # noqa: BLE001 - cleanup is reflected, not exposed
                    cleanup_ok = False

        if result is None:  # pragma: no cover - defensive invariant
            result = self._failure_result(
                command_id,
                fence,
                started,
                ExecutionOutcome.FAILED,
                FailureClass.INTERNAL_ERROR,
                "remote execution failed",
            )
        if not cleanup_ok:
            result = result.model_copy(
                update={
                    "outcome": ExecutionOutcome.FAILED,
                    "failure_class": FailureClass.WORKER_ENVIRONMENT_FAILURE,
                    "cleanup_ok": False,
                    "error_message": "remote transport cleanup failed",
                }
            )
        return result

    def _result(
        self,
        *,
        command_id: str,
        fence: str,
        started: datetime,
        finished: datetime,
        outcome: ExecutionOutcome,
        exit_code: int | None,
        stdout: object,
        stderr: object,
        request: RemoteCommandRequest,
        config: HostConfig | None,
        failure_class: FailureClass | None = None,
        error_message: str | None = None,
    ) -> RemoteExecutionResult:
        return RemoteExecutionResult(
            command_id=command_id,
            outcome=outcome,
            exit_code=exit_code,
            started_at=started,
            finished_at=finished,
            duration_ms=max(0, int((finished - started).total_seconds() * 1_000)),
            worker_id=self.worker_id,
            fence=fence,
            stdout_tail=_bounded_text(
                stdout,
                min(request.max_stdout_bytes, _MAX_OUTPUT_TAIL_BYTES),
                config=config,
            ),
            stderr_tail=_bounded_text(
                stderr,
                min(request.max_stderr_bytes, _MAX_OUTPUT_TAIL_BYTES),
                config=config,
            ),
            failure_class=failure_class,
            error_message=error_message,
        )

    def _failure_result(
        self,
        command_id: str,
        fence: str,
        started: datetime,
        outcome: ExecutionOutcome,
        failure_class: FailureClass,
        error_message: str,
    ) -> RemoteExecutionResult:
        finished = _utc_now()
        return RemoteExecutionResult(
            command_id=command_id,
            outcome=outcome,
            started_at=started,
            finished_at=finished,
            duration_ms=max(0, int((finished - started).total_seconds() * 1_000)),
            worker_id=self.worker_id,
            fence=fence,
            failure_class=failure_class,
            error_message=error_message,
        )


def create_tunnel_executor(
    inventory: HostInventory | None = None,
    *,
    transport_factory: Callable[[HostConfig], TunnelTransport] | None = None,
    worker_id: str = "tunnel-manager",
) -> TunnelCommandExecutor:
    """Build the stable executor seam for a Repository Manager worker."""

    return TunnelCommandExecutor(
        inventory,
        transport_factory=transport_factory,
        worker_id=worker_id,
    )


__all__ = [
    "AuthorizedTarget",
    "ExecutionOutcome",
    "FailureClass",
    "HostInventory",
    "RemoteCommandRequest",
    "RemoteExecutionError",
    "RemoteExecutionResult",
    "RemoteRequestError",
    "RemoteTargetError",
    "RemoteTransportError",
    "TunnelCommandExecutor",
    "TunnelTransport",
    "create_tunnel_executor",
    "render_remote_command",
]
