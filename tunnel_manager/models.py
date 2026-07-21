from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .connection_security import (
    validate_host,
    validate_port,
    validate_secret_ref,
    validate_username,
)


class HostConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    hostname: str
    user: str = Field(default="")
    port: int = 22
    identity_file: str | None = None
    password_ref: str | None = None
    proxy_command: str | None = None
    key_path: str | None = None
    known_hosts_file: str | None = None

    # Extra config mapped dynamically from arbitrary kwargs in YAML
    extra_config: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def reject_plaintext_credentials(cls, value: Any) -> Any:
        if isinstance(value, dict):
            if "allow_unknown_host_keys" in value:
                raise ValueError("unknown SSH host keys cannot be enabled")
            if any(key in value for key in ("password", "ansible_ssh_pass")):
                raise ValueError(
                    "plaintext SSH passwords are unsupported; configure password_ref"
                )
        return value

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value: str) -> str:
        return validate_host(value)

    @field_validator("user")
    @classmethod
    def validate_user(cls, value: str) -> str:
        return validate_username(value)

    @field_validator("port")
    @classmethod
    def validate_ssh_port(cls, value: int) -> int:
        return validate_port(value)

    @field_validator("password_ref")
    @classmethod
    def validate_password_reference(cls, value: str | None) -> str | None:
        return validate_secret_ref(value)

    def __init__(self, **data):
        super().__init__(**data)
        # Any keys not explicitly defined as fields go to extra_config
        extra_keys = set(data.keys()) - set(self.__class__.model_fields.keys())
        for key in extra_keys:
            self.extra_config[key] = data[key]

    def resolved_password(self) -> str | None:
        """Resolve a configured secret reference without persisting its value."""

        if not self.password_ref:
            return None
        from .connection_security import resolve_secret_ref

        return resolve_secret_ref(self.password_ref)


class InventoryGroup(BaseModel):
    hosts: dict[str, HostConfig] = Field(default_factory=dict)


class Inventory(BaseModel):
    groups: dict[str, InventoryGroup] = Field(default_factory=dict)


class CommandResult(BaseModel):
    success: bool
    stdout: str = ""
    stderr: str = ""
    error_message: str | None = None
    command: str | None = None

    def __iter__(self):
        yield self.stdout
        yield self.stderr


class ConnectionResult(BaseModel):
    success: bool
    message: str
    error_message: str | None = None


class FileTransferResult(BaseModel):
    success: bool
    local_path: str
    remote_path: str
    message: str
    error_message: str | None = None
