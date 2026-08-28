"""Characterization tests for `register_inventory_tools.tm_inventory`
(CXA-FL-TUNNELMANAGER-01, CCN 117 in tunnel_manager/mcp_server.py).

Before this file, only the `run_command` action branch had any coverage
(tests/test_mcp_server.py). These tests pin the happy-path (and, where a bug
was found, the AS-IS buggy) behaviour of the other six actions —
configure_key_auth, mesh_bootstrap, copy_ssh_config, rotate_key, send_file,
receive_file — plus the trailing "unknown action" branch, so the dispatcher
can be decomposed without changing behaviour.
"""

import inspect
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import pytest


def _capture_tm_inventory():
    """Register the tool against a fake FastMCP and return the raw async fn."""
    from tunnel_manager.mcp_server import register_inventory_tools

    mcp = MagicMock()
    captured = {}

    def decorator(fn):
        captured["fn"] = fn
        return fn

    mcp.tool.return_value = decorator
    register_inventory_tools(mcp)
    assert "fn" in captured
    return captured["fn"]


DEFAULT_KWARGS = dict(
    inventory="/fake/inventory.yaml",
    group="all",
    host="",
    preview=False,
    parallel=False,
    max_threads=6,
    cmd="",
    key="",
    key_type="ed25519",
    key_pfx="",
    cfg="",
    rmt_cfg="",
    lpath="",
    rpath="",
    lpath_prefix="",
    timeout=60,
    ctx=None,
)


def _call(fn, **overrides):
    kwargs = dict(DEFAULT_KWARGS)
    kwargs.update(overrides)
    return fn(**kwargs)


MOCK_HOSTS = [
    {
        "hostname": "192.0.2.17",
        "username": "testuser",
        "key_path": "/fake/key",
        "port": 22,
        "password_ref": None,
        "known_hosts_file": None,
    }
]


class TestConfigureKeyAuth:
    @pytest.mark.asyncio
    async def test_happy_path_existing_key(self, tmp_path):
        fn = _capture_tm_inventory()
        key = tmp_path / "id_ed25519"
        key.write_text("fake-private-key")
        pub = tmp_path / "id_ed25519.pub"
        pub.write_text("ssh-ed25519 " + "A" * 68)

        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.test_key_auth.return_value = (True, "")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="configure_key_auth", key=str(key), key_type="ed25519"
            )

        assert result["status_code"] == 200
        assert result["details"]["host_results"][0]["status"] == "success"
        # Not asserting the exact hostname string: sanitize_for_persistence's
        # NER pass non-deterministically (context-dependent) also tags a bare
        # dotted-quad as [REDACTED_LOCATION] in this action's message shape.
        assert len(result["details"]["host_results"]) == 1
        # sanitize_for_persistence redacts local absolute paths.
        assert result["files_copied"] == ["[REDACTED_POSIX_LOCAL_PATH]"]

    @pytest.mark.asyncio
    async def test_invalid_key_type_rejected(self):
        fn = _capture_tm_inventory()
        result = await _call(
            fn, action="configure_key_auth", key="/fake/key", key_type="dsa"
        )
        assert result["status_code"] == 400
        assert "key_type" in result["errors"][0]


class TestMeshBootstrap:
    @pytest.mark.asyncio
    async def test_happy_path(self):
        fn = _capture_tm_inventory()
        with patch(
            "tunnel_manager.mcp_server.Tunnel.setup_full_mesh_ssh",
            return_value={
                "status": "success",
                "host_results": [{"hostname": "h1", "status": "success"}],
                "errors": [],
            },
        ) as mock_mesh:
            result = await _call(fn, action="mesh_bootstrap", key="/fake/key")

        mock_mesh.assert_called_once()
        assert result["status_code"] == 200
        assert result["message"] == "Full-mesh SSH bootstrap completed successfully"

    @pytest.mark.asyncio
    async def test_invalid_key_type_rejected(self):
        fn = _capture_tm_inventory()
        result = await _call(fn, action="mesh_bootstrap", key_type="dsa")
        assert result["status_code"] == 400


class TestCopySshConfig:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path):
        fn = _capture_tm_inventory()
        cfg = tmp_path / "config"
        cfg.write_text("Host *\n")

        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(fn, action="copy_ssh_config", cfg=str(cfg))

        assert result["status_code"] == 200
        assert result["files_copied"] == ["[REDACTED_POSIX_LOCAL_PATH]"]
        assert result["details"]["host_results"][0]["status"] == "success"

    @pytest.mark.asyncio
    async def test_missing_cfg_file_rejected(self, tmp_path):
        fn = _capture_tm_inventory()
        missing = str(tmp_path / "nope")
        result = await _call(fn, action="copy_ssh_config", cfg=missing)
        assert result["status_code"] == 400
        assert "No cfg file" in result["message"]


class TestRotateKey:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path):
        fn = _capture_tm_inventory()
        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn,
                action="rotate_key",
                key_pfx=str(tmp_path / "id_"),
                key_type="ed25519",
            )

        assert result["status_code"] == 200
        assert result["details"]["host_results"][0]["status"] == "success"
        assert result["files_copied"] == ["[REDACTED_POSIX_LOCAL_PATH]"]
        # The new key path is `key_pfx + hostname`, expanded.
        mock_tunnel.rotate_ssh_key.assert_called_once_with(
            str(tmp_path / "id_192.0.2.17"), key_type="ed25519"
        )

    @pytest.mark.asyncio
    async def test_invalid_key_type_rejected(self):
        fn = _capture_tm_inventory()
        result = await _call(fn, action="rotate_key", key_type="dsa")
        assert result["status_code"] == 400


class TestSendFile:
    @pytest.mark.asyncio
    async def test_happy_path_pins_results_seed_bug(self, tmp_path):
        """CXA-FL-TUNNELMANAGER-01 BUG: `results` is seeded with `[_lpath]`
        instead of `files` (mcp_server.py:2053), so `host_results[0]` is the
        local path STRING, not a per-host dict, and `files_copied` stays
        empty. This test pins that AS-IS behaviour (do not fix here)."""
        fn = _capture_tm_inventory()
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")

        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="send_file", lpath=str(local), rpath="/remote/payload.bin"
            )

        assert result["status_code"] == 200
        host_results = result["details"]["host_results"]
        # BUG, pinned as-is: index 0 is the seeded local-path string (redacted
        # by sanitize_for_persistence), not a per-host result dict; the real
        # per-host dict is pushed to index 1.
        assert host_results[0] == "[REDACTED_POSIX_LOCAL_PATH]"
        assert len(host_results) == 2
        assert host_results[1]["status"] == "success"
        # BUG, pinned as-is: files_copied is empty; `files` is never
        # appended to inside this action (only `locations` is).
        assert result["files_copied"] == []

    @pytest.mark.asyncio
    async def test_missing_lpath_rpath_rejected(self):
        fn = _capture_tm_inventory()
        result = await _call(fn, action="send_file", lpath="", rpath="")
        assert result["status_code"] == 400
        assert "Need lpath, rpath" in result["message"]


class TestReceiveFile:
    @pytest.mark.asyncio
    async def test_happy_path(self, tmp_path):
        fn = _capture_tm_inventory()
        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn,
                action="receive_file",
                rpath="/remote/payload.bin",
                lpath_prefix=str(tmp_path / "downloads"),
            )

        assert result["status_code"] == 200
        assert result["details"]["host_results"][0]["status"] == "success"
        assert result["files_copied"] == ["/remote/payload.bin"]

    @pytest.mark.asyncio
    async def test_missing_rpath_rejected(self, tmp_path):
        fn = _capture_tm_inventory()
        result = await _call(
            fn, action="receive_file", rpath="", lpath_prefix=str(tmp_path)
        )
        assert result["status_code"] == 400
        assert "Need rpath, lpath_prefix" in result["message"]


class TestBulkHostFailureFailClosed:
    """BUG-CX-034: a bulk ``tm_inventory`` action folded EVERY per-host
    failure -- an authorization denial (``PermissionError``) exactly like a
    transient network fault -- into the same generic ``status_code: 500``
    with only the exception's TYPE NAME recorded, discarding the message
    that says what was actually denied. And a worker that let an exception
    escape instead of catching it (the ``_fan_out_parallel`` safety net) lost
    the offending host's identity entirely, reporting ``hostname: "unknown"``.
    These tests pin the FIXED, fail-closed behaviour: a denial is
    distinguishable (403) from an internal fault (500), the specific message
    survives, and a parallel-mode escape keeps its host."""

    @pytest.mark.asyncio
    async def test_permission_denied_host_is_403_not_generic_500(self, tmp_path):
        """A per-host ``PermissionError`` (e.g. the local upload source
        isn't readable -- ``tunnel_manager.py``'s
        ``_validate_local_upload_source``) must surface as 403, not the same
        500 a plain connection failure would produce, and the specific
        message must survive -- not just ``"PermissionError"``."""
        fn = _capture_tm_inventory()
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")

        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.send_file.side_effect = PermissionError(
                "Configured local file is not readable"
            )
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="send_file", lpath=str(local), rpath="/remote/payload.bin"
            )

        assert result["status_code"] == 403
        assert result["status_code"] != 500
        joined_errors = " ".join(result["errors"])
        assert "Configured local file is not readable" in joined_errors
        assert "PermissionError" in joined_errors

    @pytest.mark.asyncio
    async def test_internal_fault_host_still_500(self, tmp_path):
        """A control: a non-authorization per-host failure keeps its 500 --
        the fix must not turn EVERY failure into a 403."""
        fn = _capture_tm_inventory()
        local = tmp_path / "payload.bin"
        local.write_bytes(b"hello")

        with (
            patch(
                "tunnel_manager.mcp_server.load_inventory",
                return_value=(MOCK_HOSTS, {}),
            ),
            patch("tunnel_manager.mcp_server.Tunnel") as mock_tunnel_cls,
        ):
            mock_tunnel = MagicMock()
            mock_tunnel.send_file.side_effect = ConnectionError("Connection refused")
            mock_tunnel_cls.return_value = mock_tunnel

            result = await _call(
                fn, action="send_file", lpath=str(local), rpath="/remote/payload.bin"
            )

        assert result["status_code"] == 500
        assert "Connection refused" in " ".join(result["errors"])

    @pytest.mark.asyncio
    async def test_parallel_worker_escape_preserves_host_and_message(self):
        """``_fan_out_parallel``'s safety net for a worker that let an
        exception escape (rather than being caught into its own per-host
        dict) must keep the offending host's identity and the real message,
        not collapse to ``hostname: "unknown"`` + a bare exception class
        name."""
        from tunnel_manager.mcp_server import _fan_out_parallel, _HostResults

        hosts = [
            {"hostname": "good-host"},
            {"hostname": "bad-host"},
        ]

        async def worker(h: dict) -> dict:
            if h["hostname"] == "bad-host":
                raise PermissionError("not entitled to ssh host 'bad-host'")
            return {"hostname": h["hostname"], "status": "success", "errors": []}

        results = _HostResults()
        await _fan_out_parallel(hosts, worker, None, 2, results)

        assert results.status_code == 403
        by_host = {r["hostname"]: r for r in results.results}
        assert "bad-host" in by_host, (
            f"offending host lost, only have: {list(by_host)}"
        )
        assert "not entitled to ssh host 'bad-host'" in " ".join(
            by_host["bad-host"]["errors"]
        )


class TestUnknownAction:
    @pytest.mark.asyncio
    async def test_unresolvable_action_raises_before_dispatch(self):
        """CXA-FL-TUNNELMANAGER-01 FINDING: `resolve_action` runs before the
        dispatch chain and RAISES ValueError for any action string outside
        the 7-item whitelist (it never returns a plain string that could fall
        through to the dispatcher's own `else`), so the tm_inventory
        dispatcher's trailing `else: return ResponseBuilder.build(400,
        "Unknown action...")` branch is unreachable given current wiring."""
        fn = _capture_tm_inventory()
        with pytest.raises(ValueError, match="Unknown action"):
            await _call(fn, action="not_a_real_action")
