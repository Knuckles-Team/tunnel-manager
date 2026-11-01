"""Tests for the `inventory` CLI actions."""

import os

import yaml

from tunnel_manager.tunnel_manager import (
    _inventory_doctor,
    _inventory_init,
)


def _config_dir(tmp_path, monkeypatch):
    """Point XDG_CONFIG_HOME at a temp dir and return the scion-sdk dir."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config_dir = tmp_path / "scion-sdk"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


class TestInventoryInit:
    def test_init_writes_parseable_template(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = str(config_dir / "inventory.yml")
        assert _inventory_init(dest, force=False) == 0
        assert os.path.exists(dest)
        with open(dest) as f:
            parsed = yaml.safe_load(f)
        assert "all" in parsed

    def test_init_refuses_to_clobber_without_force(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        dest.write_text("all: {hosts: {keep: {ansible_host: 1.1.1.1}}}\n")
        assert _inventory_init(str(dest), force=False) == 1
        assert "keep" in dest.read_text()

    def test_init_force_overwrites(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        dest.write_text("stale\n")
        assert _inventory_init(str(dest), force=True) == 0
        assert "all:" in dest.read_text()


class TestInventoryDoctor:
    def test_doctor_missing_file_is_error(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        assert _inventory_doctor(str(config_dir / "inventory.yml")) == 1

    def test_doctor_valid_inventory_ok(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        dest.write_text(
            yaml.dump(
                {
                    "all": {
                        "vars": {"ansible_user": "operator"},
                        "hosts": {"edge-node": {"ansible_host": "192.0.2.13"}},
                    }
                }
            )
        )
        assert _inventory_doctor(str(dest)) == 0

    def test_doctor_flags_missing_required_field(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        # Host with no user anywhere -> missing 'user'.
        dest.write_text(
            yaml.dump({"all": {"hosts": {"edge-node": {"ansible_host": "192.0.2.13"}}}})
        )
        assert _inventory_doctor(str(dest)) == 1

    def test_doctor_invalid_yaml_is_error(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        dest.write_text("all: [unclosed\n")
        assert _inventory_doctor(str(dest)) == 1
