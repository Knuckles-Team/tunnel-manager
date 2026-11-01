"""CONN-TUNNEL-MANAGER-INVENTORY-R001: one canonical inventory path, no fallback."""

from __future__ import annotations

import os

import pytest

from tunnel_manager.tunnel_manager import HostManager, default_inventory_path


@pytest.mark.spec("CONN-TUNNEL-MANAGER-INVENTORY-R001")
def test_single_canonical_inventory_path(tmp_path, monkeypatch):
    """Only the scion-sdk path is read; legacy directories and .yaml are ignored."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    canonical = tmp_path / "scion-sdk" / "inventory.yml"

    # No file present: the canonical path is still the answer.
    assert default_inventory_path() == str(canonical)

    # Legacy locations never win.
    legacy_dir = tmp_path / "agent-connectors"
    legacy_dir.mkdir()
    (legacy_dir / "inventory.yml").write_text("all: {}\n")
    (legacy_dir / "inventory.yaml").write_text("all: {}\n")
    (tmp_path / "scion-sdk").mkdir()
    (tmp_path / "scion-sdk" / "inventory.yaml").write_text("all: {}\n")
    assert default_inventory_path() == str(canonical)

    # With the canonical file present, every reader resolves the same file.
    canonical.write_text("all: {}\n")
    assert default_inventory_path() == str(canonical)
    assert HostManager().config_file == str(canonical)
    assert os.path.basename(os.path.dirname(default_inventory_path())) == "scion-sdk"
