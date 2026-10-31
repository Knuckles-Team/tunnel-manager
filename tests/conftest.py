"""Shared test fixtures for Tunnel Manager."""

import pytest


@pytest.fixture
def mock_env(monkeypatch):
    """Set standard test environment variables."""
    monkeypatch.setenv("TUNNEL_URL", "https://test.example.com")
    monkeypatch.setenv("TUNNEL_TOKEN", "test-token-12345")
    monkeypatch.setenv("TUNNEL_SSL_VERIFY", "False")


@pytest.fixture(autouse=True)
def _bound_system_actor():
    """Bind an authenticated, tenant-bound admin actor (the SDK fails closed without one)."""
    from scion_sdk.identity import ActorContext, ActorType, use_actor

    actor = ActorContext(
        actor_id="system:test",
        actor_type=ActorType.SYSTEM,
        tenant_id="tenant:test",
        roles=("admin",),
        authenticated=True,
    )
    with use_actor(actor):
        yield actor


@pytest.fixture
def grant_broad_access():
    """Make a file readable (and optionally writable) by group/other or Everyone."""
    import os
    import subprocess

    def grant(path, write=False):
        if os.name == "nt":
            right = "(R,W)" if write else "(R)"
            subprocess.run(
                ["icacls", str(path), "/grant", f"*S-1-1-0:{right}"],
                check=True,
                capture_output=True,
            )
        else:
            os.chmod(path, 0o622 if write else 0o644)

    return grant
