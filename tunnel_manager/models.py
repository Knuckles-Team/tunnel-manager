from pydantic import BaseModel, ConfigDict, Field


class HostConfig(BaseModel):
    model_config = ConfigDict(extra="allow")

    hostname: str
    user: str = Field(default="")
    port: int = 22
    identity_file: str | None = None
    password: str | None = None
    proxy_command: str | None = None
    key_path: str | None = None

    # Extra config mapped dynamically from arbitrary kwargs in YAML
    extra_config: dict[str, str] = Field(default_factory=dict)

    def __init__(self, **data):
        super().__init__(**data)
        # Any keys not explicitly defined as fields go to extra_config
        extra_keys = set(data.keys()) - set(self.__class__.model_fields.keys())
        for key in extra_keys:
            self.extra_config[key] = data[key]


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
