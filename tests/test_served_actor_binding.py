"""The served MCP stack binds one actor per request, by transport.

Each test builds the real tunnel-manager connector server and calls the generated
host tools through a real fastmcp client: in memory (the local transport, bound to
the SYSTEM actor) and over streamable HTTP served by uvicorn, with ``--auth-type none``
(the operator chose no auth: also the SYSTEM actor) or with a JWT (an authenticated
actor whose roles come from the token). A tokenless caller to a server with auth
configured is the ANONYMOUS actor and is refused with a named cause. Mirrors
scion-sdk ``tests/test_actor_binding_served.py``.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from mcp.shared.exceptions import MCPError
from scion_sdk.connector import build_server
from scion_sdk.identity import ANONYMOUS_ACTOR, ActorContext, ActorType, use_actor

from tunnel_manager.mcp_server import _tm_remote_run_command, host_manager
from tunnel_manager.remote_execution import HostInventory, RemoteTargetError

ALIASES = ("prod-a", "prod-b", "lab", "edge")
ISSUER = "https://idp.example.invalid/realms/demo"
AUDIENCE = "tunnel-manager-hosts"


@pytest.fixture(autouse=True)
def _inventory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        host_manager,
        "hosts",
        {a: {"hostname": f"{a}.example.com", "user": "ops"} for a in ALIASES},
    )


def _server(*argv: str) -> Any:
    _args, mcp = build_server("tunnel_manager", command_args=list(argv))
    return mcp


@contextmanager
def _serving(mcp: Any) -> Iterator[str]:
    ready = threading.Event()
    server = uvicorn.Server(
        uvicorn.Config(
            mcp.http_app(),
            host="127.0.0.1",
            port=0,
            log_level="error",
            lifespan="on",
            callback_notify=AsyncMock(side_effect=ready.set),
            timeout_notify=1,
        )
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        assert ready.wait(30) and server.started
        port = server.servers[0].sockets[0].getsockname()[1]
        yield f"http://127.0.0.1:{port}/mcp"
    finally:
        server.should_exit = True
        thread.join(10)


@pytest.mark.spec("CONN-TUNNEL-MANAGER-SDK-R005")
async def test_local_transport_lists_every_alias() -> None:
    async with Client(_server("--transport", "stdio")) as client:
        listed = await client.call_tool("tunnel_manager_list_hosts", {})
        assert set(listed.data) == set(ALIASES)
        host = await client.call_tool("tunnel_manager_get_host", {"alias": "lab"})
        assert host.data["hostname"] == "lab.example.com"


@pytest.mark.spec("CONN-TUNNEL-MANAGER-SDK-R005")
async def test_no_auth_http_lists_every_alias_and_runs_on_one() -> None:
    mcp = _server("--transport", "streamable-http", "--auth-type", "none")
    tunnel = MagicMock()
    tunnel.run_command.return_value = ("up 3 days", "")
    with (
        _serving(mcp) as endpoint,
        patch("tunnel_manager.mcp_server.Tunnel", return_value=tunnel),
    ):
        async with Client(endpoint) as client:
            listed = await client.call_tool("tunnel_manager_list_hosts", {})
            assert set(listed.data) == set(ALIASES)
            ran = await client.call_tool(
                "tm_remote_run_command", {"host": "lab", "cmd": "uptime"}
            )
    assert ran.structured_content["status_code"] == 200
    assert ran.structured_content["stdout"] == "up 3 days"


@pytest.mark.spec("CONN-TUNNEL-MANAGER-SDK-R005")
def test_an_anonymous_caller_is_refused_with_the_cause() -> None:
    with use_actor(ANONYMOUS_ACTOR):
        assert host_manager.list_hosts() == {}
        with pytest.raises(PermissionError, match="anonymous caller"):
            host_manager.get_host("lab")
    inventory = HostInventory(manager_factory=lambda: host_manager)
    with pytest.raises(RemoteTargetError, match="anonymous caller"):
        inventory.resolve("lab", ANONYMOUS_ACTOR)


@pytest.mark.spec("CONN-TUNNEL-MANAGER-SDK-R005")
async def test_an_unentitled_run_command_names_the_cause() -> None:
    operator = ActorContext(
        actor_id="operator-1",
        actor_type=ActorType.HUMAN,
        tenant_id="tenant-1",
        roles=("ssh:edge",),
        authenticated=True,
    )
    inventory = HostInventory(manager_factory=lambda: host_manager)
    with pytest.raises(RemoteTargetError, match="not entitled to ssh:lab"):
        inventory.resolve("lab", operator)
    names = "action host user password_ref password port id_file certificate proxy"
    names += (
        " cfg cmd lpath rpath key key_type new_key lcfg rcfg known_hosts timeout ctx"
    )
    arguments: dict[str, Any] = dict.fromkeys(names.split())
    arguments.update(action="run_command", host="lab", cmd="uptime")
    with use_actor(operator):
        ran = await _tm_remote_run_command(**arguments)
    assert ran["status_code"] == 403
    assert "not entitled to ssh:lab" in ran["message"]


@pytest.mark.spec("CONN-TUNNEL-MANAGER-SDK-R005")
async def test_authenticated_http_lists_the_entitled_aliases() -> None:
    keys = RSAKeyPair.generate()
    mcp = _server(
        "--transport",
        "streamable-http",
        "--auth-type",
        "jwt",
        "--token-issuer",
        ISSUER,
        "--token-audience",
        AUDIENCE,
        "--token-public-key",
        keys.public_key,
    )
    token = keys.create_token(
        subject="operator-1",
        issuer=ISSUER,
        audience=AUDIENCE,
        additional_claims={
            "tenant_id": "tenant-1",
            "realm_access": {"roles": ["ssh:prod-a"]},
            "resource_access": {"hosts": {"roles": ["ssh:edge"]}},
            "groups": ["/lab", "/prod-b-operators"],
        },
    )
    with _serving(mcp) as endpoint:
        async with Client(endpoint, auth=token) as client:
            listed = await client.call_tool("tunnel_manager_list_hosts", {})
            assert set(listed.data) == {"prod-a", "lab", "edge"}
            allowed = await client.call_tool(
                "tunnel_manager_get_host", {"alias": "edge"}
            )
            assert allowed.data["hostname"] == "edge.example.com"
            with pytest.raises(MCPError) as denied:
                await client.call_tool("tunnel_manager_get_host", {"alias": "prod-b"})
    assert denied.value.code == -32000
    assert "not entitled to ssh:prod-b" in denied.value.message
