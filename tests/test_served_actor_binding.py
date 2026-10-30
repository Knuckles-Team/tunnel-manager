"""The served MCP stack binds one actor per request, by transport.

Each test builds the real tunnel-manager connector server and calls the generated
host tools through a real fastmcp client: in memory (the local transport, bound to
the SYSTEM actor) and over streamable HTTP served by uvicorn, with no token (the
ANONYMOUS actor) or with a JWT (an authenticated actor whose roles come from the
token). Mirrors scion-sdk ``tests/test_actor_binding_served.py``.
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock

import pytest
import uvicorn
from fastmcp import Client
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from mcp.shared.exceptions import MCPError
from scion_sdk.connector import build_server
from scion_sdk.mcp import server as sdk_server
from scion_sdk.mcp.served_security import ServedSecurityOverride

from tunnel_manager.mcp_server import host_manager

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


def _server(*argv: str, anonymous: bool = False) -> Any:
    create = sdk_server.create_mcp_server
    if anonymous:
        create = functools.partial(
            create,
            served_security_override=ServedSecurityOverride(
                "test serves HTTP without auth"
            ),
        )
    original = sdk_server.create_mcp_server
    sdk_server.create_mcp_server = create
    try:
        _args, mcp = build_server("tunnel_manager", command_args=list(argv))
    finally:
        sdk_server.create_mcp_server = original
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
async def test_anonymous_http_lists_nothing_and_a_single_alias_is_refused() -> None:
    mcp = _server("--transport", "streamable-http", anonymous=True)
    with _serving(mcp) as endpoint:
        async with Client(endpoint) as client:
            listed = await client.call_tool("tunnel_manager_list_hosts", {})
            assert not listed.data
            with pytest.raises(MCPError) as denied:
                await client.call_tool("tunnel_manager_get_host", {"alias": "lab"})
    assert denied.value.code == -32000
    assert "not entitled" in denied.value.message
    assert "actor context is required" not in denied.value.message
    assert "Internal error" not in denied.value.message


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
    assert "not entitled" in denied.value.message
