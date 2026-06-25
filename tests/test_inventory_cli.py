"""Tests for the inventory path resolver and the `inventory` CLI actions."""

import os

import yaml

from tunnel_manager.tunnel_manager import (
    _inventory_doctor,
    _inventory_init,
    default_inventory_path,
)


def _config_dir(tmp_path, monkeypatch):
    """Point XDG_CONFIG_HOME at a temp dir and return the agent-utilities dir."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    config_dir = tmp_path / "agent-utilities"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


class TestDefaultInventoryPath:
    def test_prefers_yml_when_present(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        (config_dir / "inventory.yml").write_text("all: {}\n")
        (config_dir / "inventory.yaml").write_text("all: {}\n")
        assert default_inventory_path() == str(config_dir / "inventory.yml")

    def test_falls_back_to_yaml_legacy(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        (config_dir / "inventory.yaml").write_text("all: {}\n")
        assert default_inventory_path() == str(config_dir / "inventory.yaml")

    def test_defaults_to_yml_when_neither_exists(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        assert default_inventory_path() == str(config_dir / "inventory.yml")


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
        assert _inventory_doctor(str(config_dir / "inventory.yml"), fix=False) == 1

    def test_doctor_valid_inventory_ok(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        dest.write_text(
            yaml.dump(
                {
                    "all": {
                        "vars": {"ansible_user": "genius"},
                        "hosts": {"r820": {"ansible_host": "10.0.0.13"}},
                    }
                }
            )
        )
        assert _inventory_doctor(str(dest), fix=False) == 0

    def test_doctor_flags_missing_required_field(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        # Host with no user anywhere -> missing 'user'.
        dest.write_text(
            yaml.dump({"all": {"hosts": {"r820": {"ansible_host": "10.0.0.13"}}}})
        )
        assert _inventory_doctor(str(dest), fix=False) == 1

    def test_doctor_invalid_yaml_is_error(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        dest = config_dir / "inventory.yml"
        dest.write_text("all: [unclosed\n")
        assert _inventory_doctor(str(dest), fix=False) == 1

    def test_doctor_fix_migrates_legacy_yaml(self, tmp_path, monkeypatch):
        config_dir = _config_dir(tmp_path, monkeypatch)
        legacy = config_dir / "inventory.yaml"
        legacy.write_text(
            yaml.dump(
                {
                    "all": {
                        "vars": {"ansible_user": "genius"},
                        "hosts": {"r820": {"ansible_host": "10.0.0.13"}},
                    }
                }
            )
        )
        # Pass the legacy path; --fix should migrate it to .yml and validate that.
        rc = _inventory_doctor(str(legacy), fix=True)
        assert rc == 0
        assert (config_dir / "inventory.yml").exists()
        assert not legacy.exists()
