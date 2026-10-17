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
    from agent_connector_sdk.identity import ActorContext, ActorType, use_actor

    actor = ActorContext(
        actor_id="system:test",
        actor_type=ActorType.SYSTEM,
        tenant_id="tenant:test",
        roles=("admin",),
        authenticated=True,
    )
    with use_actor(actor):
        yield actor
