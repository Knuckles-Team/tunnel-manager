"""CONN-TUNNEL-MANAGER-INVENTORY-R004: a failed inventory write leaves no trace."""

from __future__ import annotations

import pytest

from tunnel_manager.tunnel_manager import HostManager


def test_failed_add_host_does_not_leave_a_ghost(tmp_path, monkeypatch):
    manager = HostManager(config_file=str(tmp_path / "inventory.yml"))
    manager.hosts = {"keep": {"hostname": "192.0.2.1", "user": "u"}}

    def refuse(*_a, **_k):
        raise RuntimeError("inventory is read-only")

    monkeypatch.setattr(manager, "save_inventory", refuse)

    with pytest.raises(RuntimeError):
        manager.add_host(alias="ghost", hostname="192.0.2.9", user="nobody")
    assert "ghost" not in manager.hosts

    with pytest.raises(RuntimeError):
        manager.remove_host("keep")
    assert "keep" in manager.hosts
