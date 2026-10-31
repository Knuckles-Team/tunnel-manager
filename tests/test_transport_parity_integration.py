"""Every tool, three transports, one real SSH host (CONN-TUNNEL-MANAGER-SDK-R005).

An in-process asyncssh server (key auth, a real known_hosts entry, commands run
in a scratch remote home, SFTP with ``~`` mapped there) stands in for the managed host.
The inventory names it ``simhost`` and keeps its user, port, key and trust
store in GROUP vars only.

tunnel-manager's real MCP server is started as a subprocess three ways:

* stdio;
* streamable HTTP with an explicit ``--auth-type none`` on 0.0.0.0;
* streamable HTTP with JWT auth against a local JWKS endpoint, called with
  tokens shaped like the IdP issues for the arbora service principal (one
  with a tenant claim, one without), entitled by ``CONNECTOR_PRINCIPAL_GRANTS``.

A real fastmcp client calls every tool on each. The per-tool outcomes must be
identical across all of them. Refusals (unknown alias, missing token, missing
entitlement) must name their cause the same way.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import asyncssh
import httpx
import pytest
import yaml
from fastmcp import Client
from fastmcp.client.transports import StdioTransport, StreamableHttpTransport
from fastmcp.server.auth.providers.jwt import RSAKeyPair

ISSUER = "https://idp.example.invalid/realms/homelab"
AUDIENCE = "agent-services"
ALIAS = "simhost"
SPEC = "CONN-TUNNEL-MANAGER-SDK-R005"
CALL_TIMEOUT = 90
# The server limits each non-local actor to 10 requests/s (burst 20). A sweep of
# ~45 fast calls would exceed that and be refused, so calls start at least this
# far apart: half the sustained limit, whatever the machine's speed.
MIN_CALL_SPACING = 0.2
_last_call = [0.0]


async def _pace() -> None:
    wait = _last_call[0] + MIN_CALL_SPACING - time.monotonic()
    if wait > 0:
        await asyncio.sleep(wait)
    _last_call[0] = time.monotonic()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# --------------------------------------------------------------------- SSH host
class _SSHHost:
    """asyncssh server on its own loop and thread."""

    def __init__(self, root: Path) -> None:
        self.remote_home = root / "remote-home"
        self.remote_home.mkdir()
        (self.remote_home / ".ssh").mkdir(mode=0o700)
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.client_key = asyncssh.generate_private_key("ssh-ed25519")
        self.port = 0
        self._loop = asyncio.new_event_loop()
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    async def _process(self, process: asyncssh.SSHServerProcess) -> None:
        # The simulated host is POSIX: run its commands with a real sh (Git's on
        # Windows), not cmd.exe, and keep the variables Windows needs to spawn it.
        sh = shutil.which("sh")
        assert sh, "the simulated POSIX host needs an sh executable"
        env = {
            "HOME": self.remote_home.as_posix(),
            "PATH": os.pathsep.join([str(Path(sh).parent), os.environ.get("PATH", "")]),
            "LANG": "C",
        }
        for name in ("SYSTEMROOT", "TEMP", "TMP"):
            if name in os.environ:
                env[name] = os.environ[name]
        proc = await asyncio.create_subprocess_exec(
            sh,
            "-c",
            process.command or "true",
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.remote_home,
            env=env,
        )
        try:
            out, err = await asyncio.wait_for(proc.communicate(), 60)
        except TimeoutError:
            proc.kill()
            out, err = b"", b"timeout"
        process.stdout.write(out.decode(errors="replace"))
        process.stderr.write(err.decode(errors="replace"))
        process.exit(proc.returncode or 0)

    def _run(self) -> None:
        asyncio.set_event_loop(self._loop)
        authorized = asyncssh.import_authorized_keys(
            self.client_key.export_public_key().decode()
        )
        home = self.remote_home.as_posix()

        class _HomeSFTP(asyncssh.SFTPServer):
            """Real paths; ``~`` and relative paths land in the remote home."""

            def map_path(self, path: bytes) -> bytes:
                text = path.decode()
                if text.startswith("~"):
                    text = home + text[1:]
                elif not (text.startswith("/") or Path(text).is_absolute()):
                    text = f"{home}/{text}"
                return text.encode()

        async def start() -> None:
            server = await asyncssh.listen(
                "127.0.0.1",
                0,
                server_host_keys=[self.host_key],
                authorized_client_keys=authorized,
                process_factory=self._process,
                sftp_factory=_HomeSFTP,
                allow_scp=False,
            )
            self.port = server.sockets[0].getsockname()[1]
            self._ready.set()

        self._loop.run_until_complete(start())
        self._loop.run_forever()

    def start(self) -> None:
        self._thread.start()
        assert self._ready.wait(30)

    def stop(self) -> None:
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(10)


# ------------------------------------------------------------------------- JWKS
def _jwks(keys: RSAKeyPair) -> dict[str, Any]:
    from cryptography.hazmat.primitives import serialization

    public = serialization.load_pem_public_key(keys.public_key.encode())
    numbers = public.public_numbers()  # type: ignore[union-attr]

    def b64(value: int) -> str:
        raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return {
        "keys": [
            {
                "kty": "RSA",
                "kid": "test-key",
                "use": "sig",
                "alg": "RS256",
                "n": b64(numbers.n),
                "e": b64(numbers.e),
            }
        ]
    }


def _serve_jwks(document: dict[str, Any]) -> tuple[HTTPServer, str]:
    body = json.dumps(document).encode()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - http.server API
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/jwks"


# -------------------------------------------------------------------- the world
class _World:
    """One SSH host, one JWKS, and a fresh client home per server."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.ssh = _SSHHost(root)
        self.ssh.start()
        self.keys = RSAKeyPair.generate()
        self.jwks_server, self.jwks_uri = _serve_jwks(_jwks(self.keys))

    def client_home(self, name: str) -> dict[str, str]:
        home = self.root / name / "home"
        ssh_dir = home / ".ssh"
        ssh_dir.mkdir(parents=True, mode=0o700)
        key = ssh_dir / "id_ed25519"
        key.write_bytes(self.ssh.client_key.export_private_key())
        key.chmod(0o600)
        (ssh_dir / "id_ed25519.pub").write_bytes(
            self.ssh.client_key.export_public_key()
        )
        known = ssh_dir / "known_hosts"
        host_pub = self.ssh.host_key.export_public_key().decode().strip()
        known.write_text(f"[127.0.0.1]:{self.ssh.port} {host_pub}\n")
        known.chmod(0o600)
        (ssh_dir / "config").write_text("# empty\n")
        config = self.root / name / "config"
        inventory = config / "agent-connectors" / "inventory.yml"
        inventory.parent.mkdir(parents=True)
        inventory.write_text(
            yaml.safe_dump(
                {
                    "all": {
                        "children": {
                            "sim": {
                                "vars": {
                                    "ansible_user": "operator",
                                    "ansible_port": self.ssh.port,
                                    "ansible_ssh_private_key_file": str(key),
                                    "ansible_ssh_known_hosts_file": str(known),
                                },
                                "hosts": {ALIAS: {"ansible_host": "127.0.0.1"}},
                            }
                        }
                    }
                }
            )
        )
        local = self.root / name / "local.txt"
        local.write_text("hello from the client\n")
        lcfg = self.root / name / "ssh_config_to_copy"
        lcfg.write_text("Host *\n  ServerAliveInterval 30\n")
        return {
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "INVENTORY": str(inventory),
            "LOCAL_FILE": str(local),
            "LCFG": str(lcfg),
            "WORK": str(self.root / name),
            "KEY": str(key),
        }

    def token(self, *, principal: str = "arbora", tenant: bool = True) -> str:
        claims: dict[str, Any] = {
            "azp": principal,
            "client_id": principal,
            "preferred_username": f"service-account-{principal}",
            "typ": "Bearer",
            "scope": "openid profile email",
            "realm_access": {"roles": ["offline_access", "uma_authorization"]},
        }
        if tenant:
            claims["tenant_id"] = "homelab"
        return self.keys.create_token(
            subject=f"{principal}-service-account-id",
            issuer=ISSUER,
            audience=AUDIENCE,
            additional_claims=claims,
            kid="test-key",
        )


@pytest.fixture(scope="module")
def world(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_World]:
    built = _World(tmp_path_factory.mktemp("parity"))
    yield built
    built.jwks_server.shutdown()
    built.ssh.stop()


def _server_env(paths: dict[str, str]) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("TUNNEL_", "AUTH_", "FASTMCP_", "CONNECTOR_", "MCP_"))
    }
    env.update(
        HOME=paths["HOME"],
        XDG_CONFIG_HOME=paths["XDG_CONFIG_HOME"],
        TUNNEL_KG_INGEST="false",
        MCP_FLEET_REGISTRATION="false",
        CONNECTOR_PRINCIPAL_GRANTS="arbora=ssh:*",
        PYTHONUNBUFFERED="1",
    )
    return env


def _executable() -> str:
    found = Path(sys.executable).parent / "tunnel-manager-mcp"
    return str(found) if found.exists() else shutil.which("tunnel-manager-mcp") or ""


class _HttpServer:
    def __init__(self, argv: list[str], env: dict[str, str], port: int) -> None:
        self.url = f"http://127.0.0.1:{port}/mcp"
        # The server logs every request to stderr. An undrained PIPE fills (a few
        # KB on Windows) and blocks the server mid-request, so the client times
        # out. A file never blocks and keeps the log to show on failure.
        self.log_path = Path(env["HOME"]).parent / f"server-{port}.log"
        self.log = self.log_path.open("w+", encoding="utf-8", errors="replace")
        self.proc = subprocess.Popen(
            [_executable(), *argv, "--port", str(port)],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=self.log,
            text=True,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise AssertionError(f"server exited: {self._read_log()}")
            try:
                httpx.get(f"http://127.0.0.1:{port}/health", timeout=1)
                return
            except httpx.HTTPError:
                time.sleep(0.2)
        raise AssertionError("server did not start")

    def _read_log(self) -> str:
        self.log.flush()
        return self.log_path.read_text(encoding="utf-8", errors="replace")

    def stop(self) -> str:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.log.close()
        err = self._read_log()
        # pytest shows captured output for a failing test: the server's cause.
        print(f"--- server stderr ({self.log_path.name}) ---\n{err[-6000:]}")
        return err


# ------------------------------------------------------------------ the sweep
def _arguments(paths: dict[str, str]) -> dict[str, dict[str, Any]]:
    """Arguments per tool. Destructive inventory tools come last."""
    work = Path(paths["WORK"]).as_posix()
    remote = {"host": ALIAS, "timeout": 30}
    inventory = {"inventory": paths["INVENTORY"], "group": "sim", "timeout": 30}
    system = {"remote_host": ALIAS}
    files = {"remote_host": ALIAS}
    return {
        "tunnel_manager_list_hosts": {},
        "tunnel_manager_get_host": {"alias": ALIAS},
        "tunnel_manager_load_inventory": {},
        "tm_inventory_run_command": {**inventory, "host": ALIAS, "cmd": "echo ok"},
        "tm_remote_run_command": {**remote, "cmd": "echo ok"},
        "tm_remote_send_file": {
            **remote,
            "lpath": paths["LOCAL_FILE"],
            "rpath": f"{work}/uploaded.txt",
        },
        "tm_remote_receive_file": {
            **remote,
            "rpath": f"{work}/uploaded.txt",
            "lpath": f"{work}/received.txt",
        },
        "tm_remote_check_ssh": dict(remote),
        "tm_remote_test_key_auth": {**remote, "key": paths["KEY"]},
        "tm_remote_setup_passwordless": dict(remote),
        "tm_remote_copy_ssh_config": {
            **remote,
            "lcfg": paths["LCFG"],
            "rcfg": "copied_config",
        },
        "tm_inventory_send_file": {
            **inventory,
            "lpath": paths["LOCAL_FILE"],
            "rpath": f"{work}/inv_uploaded.txt",
        },
        "tm_inventory_receive_file": {
            **inventory,
            "rpath": f"{work}/inv_uploaded.txt",
            "lpath_prefix": f"{work}/inv_recv_",
        },
        "tm_inventory_copy_ssh_config": {
            **inventory,
            "cfg": paths["LCFG"],
            "rmt_cfg": "inv_copied_config",
        },
        "tm_operation_start": {"operation_type": "run_command", "total_steps": 2},
        "tm_operation_get_progress": {},
        "tm_operation_cancel": {},
        "tm_operation_get_metrics": {},
        "tm_operation_list_sessions": {},
        "tm_system_get_info": dict(system),
        "tm_system_discover_services": dict(system),
        "tm_system_analyze_logs": {
            **system,
            "log_paths": ["/etc/hostname"],
            "patterns": ["a"],
        },
        "tm_system_network_topology": dict(system),
        "tm_file_recursive_ops": {
            **files,
            "operation": "list",
            "source": str(Path(paths["HOME"]).parent),
        },
        "tm_file_content_search": {
            **files,
            "search_paths": [work],
            "pattern": "hello",
        },
        "tm_file_watch": {**files, "watch_paths": [work], "duration": 1},
        "tm_file_diff_compare": {
            "file_path": paths["LOCAL_FILE"],
            "host1": ALIAS,
            "host2": ALIAS,
        },
        "tm_file_backup": {
            **files,
            "backup_paths": [paths["LOCAL_FILE"]],
            "backup_dest": f"{work}/backup",
        },
        "tm_security_security_audit": dict(system),
        "tm_security_compliance_check": dict(system),
        "tm_security_vulnerability_scan": dict(system),
        "tm_security_access_control_audit": dict(system),
        "tunnel_ingest_hosts": {},
        "tm_remote_rotate_key": {**remote, "new_key": f"{work}/rotated_key"},
        "tm_inventory_rotate_key": {**inventory, "key_pfx": f"{work}/inv_rotated_"},
        "tm_inventory_configure_key_auth": {
            **inventory,
            "key": f"{work}/shared_key",
        },
        "tm_inventory_mesh_bootstrap": {
            **inventory,
            "key": f"{work}/mesh_key",
        },
        "tm_remote_remove_host_key": {**remote, "confirm": True},
        "tunnel_manager_save_inventory": {},
        "tunnel_manager_add_host": {
            "alias": "added",
            "hostname": "127.0.0.1",
            "user": "operator",
        },
        "tunnel_manager_remove_host": {"alias": "added"},
    }


def _outcome(result: Any) -> str:
    """A transport-independent summary of one tool result."""
    if isinstance(result, Exception):
        return f"error: {str(result)[:120]}"
    data = result.structured_content
    if not isinstance(data, dict):
        text = " ".join(getattr(part, "text", "") for part in result.content)
        return f"{'error' if result.is_error else 'ok'}: {text[:80]}"
    if "status_code" in data:
        if data["status_code"] == 200:
            return "200"
        errors = data.get("errors") or [data.get("stderr", "")]
        return f"{data['status_code']} {data.get('message', '')}: {errors[0]}"[:200]
    if "status" in data:
        return f"{data['status']}"
    return "ok"


async def _sweep(client: Client[Any], paths: dict[str, str]) -> dict[str, str]:
    listed = {tool.name for tool in await client.list_tools()}
    arguments = _arguments(paths)
    assert listed == set(arguments), listed ^ set(arguments)
    outcomes: dict[str, str] = {}
    for name, args in arguments.items():
        await _pace()
        try:
            result = await asyncio.wait_for(
                client.call_tool(name, args, raise_on_error=False), CALL_TIMEOUT
            )
        except Exception as exc:  # noqa: BLE001 - recorded, then compared
            result = exc
        outcomes[name] = _outcome(result)
        if name in _EXPECT_STDOUT:
            data = result.structured_content
            outcomes[f"{name}:stdout"] = _EXPECT_STDOUT[name](data)
    return outcomes


def _remote_stdout(data: dict[str, Any]) -> str:
    return str(data.get("stdout", "")).strip()


def _inventory_stdout(data: dict[str, Any]) -> str:
    rows = data["details"]["host_results"]
    return ";".join(str(row.get("stdout", "")).strip() for row in rows)


def _host_list(data: dict[str, Any]) -> str:
    hosts = data.get("result", data)
    return ",".join(sorted(hosts)) + f"|port={hosts[ALIAS]['port']}"


_EXPECT_STDOUT = {
    "tm_remote_run_command": _remote_stdout,
    "tm_inventory_run_command": _inventory_stdout,
    "tunnel_manager_list_hosts": _host_list,
}


async def _refusals(client: Client[Any]) -> dict[str, str]:
    unknown_remote = await client.call_tool(
        "tm_remote_run_command", {"host": "nosuch", "cmd": "echo ok"}
    )
    unknown_inventory = await client.call_tool(
        "tm_inventory_run_command", {"host": "nosuch", "cmd": "echo ok"}
    )
    return {
        "remote": unknown_remote.structured_content["message"],
        "inventory": unknown_inventory.structured_content["message"],
        "codes": f"{unknown_remote.structured_content['status_code']},"
        f"{unknown_inventory.structured_content['status_code']}",
    }


_RESULTS: dict[str, dict[str, str]] = {}


def _record(config: str, outcomes: dict[str, str]) -> None:
    _RESULTS[config] = outcomes
    table = (
        Path(os.environ.get("TM_PARITY_TABLE", ""))
        if os.environ.get("TM_PARITY_TABLE")
        else None
    )
    if table is not None:
        table.write_text(json.dumps(_RESULTS, indent=1, sort_keys=True))


def _assert_core_success(outcomes: dict[str, str]) -> None:
    assert outcomes["tm_inventory_run_command"] == "200"
    assert outcomes["tm_inventory_run_command:stdout"] == "ok"
    assert outcomes["tm_remote_run_command"] == "200"
    assert outcomes["tm_remote_run_command:stdout"] == "ok"
    assert outcomes["tunnel_manager_list_hosts"] == "ok"
    assert outcomes["tunnel_manager_list_hosts:stdout"].startswith(f"{ALIAS}|port=")
    assert outcomes["tunnel_manager_list_hosts:stdout"] != f"{ALIAS}|port=22"


_UNKNOWN = {
    "remote": "Unknown host alias: nosuch",
    "inventory": "Unknown host alias: nosuch",
    "codes": "400,400",
}


# ---------------------------------------------------------------------- tests
@pytest.mark.spec(SPEC)
@pytest.mark.timeout(900)
async def test_stdio_serves_every_tool(world: _World) -> None:
    paths = world.client_home("stdio")
    transport = StdioTransport(
        command=_executable(),
        args=["--transport", "stdio"],
        env=_server_env(paths),
    )
    async with Client(transport, timeout=CALL_TIMEOUT) as client:
        outcomes = await _sweep(client, paths)
        assert await _refusals(client) == _UNKNOWN
    _record("stdio", outcomes)
    _assert_core_success(outcomes)


@pytest.mark.spec(SPEC)
@pytest.mark.timeout(900)
async def test_http_without_auth_serves_every_tool_identically(world: _World) -> None:
    paths = world.client_home("http-none")
    port = _free_port()
    server = _HttpServer(
        [
            "--transport",
            "streamable-http",
            "--auth-type",
            "none",
            "--host",
            "0.0.0.0",
            "--allowed-hosts",
            f"127.0.0.1:{port},localhost:{port}",
        ],
        _server_env(paths),
        port,
    )
    try:
        transport = StreamableHttpTransport(server.url)
        async with Client(transport, timeout=CALL_TIMEOUT) as client:
            outcomes = await _sweep(client, paths)
            assert await _refusals(client) == _UNKNOWN
    finally:
        stderr = server.stop()
    assert "auth type none" in stderr
    _record("http-none", outcomes)
    _assert_core_success(outcomes)
    if "stdio" in _RESULTS:
        assert outcomes == _RESULTS["stdio"]


def _jwt_argv(world: _World, port: int) -> list[str]:
    return [
        "--transport",
        "streamable-http",
        "--auth-type",
        "jwt",
        "--host",
        "127.0.0.1",
        "--token-issuer",
        ISSUER,
        "--token-audience",
        AUDIENCE,
        "--token-jwks-uri",
        world.jwks_uri,
        "--allowed-hosts",
        f"127.0.0.1:{port},localhost:{port}",
    ]


@pytest.mark.spec(SPEC)
@pytest.mark.timeout(900)
async def test_http_with_jwt_serves_every_tool_identically(world: _World) -> None:
    paths = world.client_home("http-jwt")
    port = _free_port()
    server = _HttpServer(_jwt_argv(world, port), _server_env(paths), port)
    try:
        transport = StreamableHttpTransport(server.url, auth=world.token())
        async with Client(transport, timeout=CALL_TIMEOUT) as client:
            outcomes = await _sweep(client, paths)
            assert await _refusals(client) == _UNKNOWN
    finally:
        server.stop()
    _record("http-jwt", outcomes)
    _assert_core_success(outcomes)
    for other in ("stdio", "http-none"):
        if other in _RESULTS:
            assert outcomes == _RESULTS[other], other


@pytest.mark.spec(SPEC)
@pytest.mark.timeout(300)
async def test_jwt_refusals_name_their_cause(world: _World) -> None:
    paths = world.client_home("http-jwt-refusals")
    port = _free_port()
    server = _HttpServer(_jwt_argv(world, port), _server_env(paths), port)
    try:
        # No token: refused at HTTP before any tool runs.
        response = httpx.post(
            server.url,
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            headers={"Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401

        # A tenantless service-principal token resolves to its issuer's tenant.
        tenantless = StreamableHttpTransport(server.url, auth=world.token(tenant=False))
        async with Client(tenantless, timeout=CALL_TIMEOUT) as client:
            ran = await client.call_tool(
                "tm_remote_run_command", {"host": ALIAS, "cmd": "echo ok"}
            )
            assert ran.structured_content["stdout"].strip() == "ok"

        # A valid token whose principal holds no grant is refused, by name.
        other = StreamableHttpTransport(
            server.url, auth=world.token(principal="unentitled")
        )
        async with Client(other, timeout=CALL_TIMEOUT) as client:
            listed = await client.call_tool("tunnel_manager_list_hosts", {})
            assert listed.structured_content in ({}, {"result": {}})
            remote = await client.call_tool(
                "tm_remote_run_command", {"host": ALIAS, "cmd": "echo ok"}
            )
            inventory = await client.call_tool(
                "tm_inventory_run_command", {"host": ALIAS, "cmd": "echo ok"}
            )
    finally:
        server.stop()
    refusal = f"Refused: not entitled to ssh:{ALIAS}"
    assert remote.structured_content["status_code"] == 403
    assert remote.structured_content["message"] == refusal
    assert inventory.structured_content["status_code"] == 403
    assert inventory.structured_content["message"] == refusal
