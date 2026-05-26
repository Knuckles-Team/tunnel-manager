"""Shared test fixtures for Tunnel Manager."""

import pytest


@pytest.fixture
def mock_env(monkeypatch):
    """Set standard test environment variables."""
    monkeypatch.setenv("TUNNEL_URL", "https://test.example.com")
    monkeypatch.setenv("TUNNEL_TOKEN", "test-token-12345")
    monkeypatch.setenv("TUNNEL_SSL_VERIFY", "False")
