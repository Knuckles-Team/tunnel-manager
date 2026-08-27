"""Characterization tests for `tunnel_manager.mcp_server.load_inventory`.

CXA-FL-TUNNELMANAGER-01: pins current behaviour of `load_inventory` (CCN 86)
before decomposition. `load_inventory` had zero direct tests before this file
(existing tests only mock it out, or exercise the unrelated
`HostManager.load_inventory` method).
"""

import logging

import pytest
import yaml

from tunnel_manager.mcp_server import load_inventory


@pytest.fixture
def logger():
    return logging.getLogger("test-load-inventory")


def _write_inventory(tmp_path, data):
    path = tmp_path / "inventory.yaml"
    path.write_text(yaml.safe_dump(data))
    return str(path)


class TestAnsibleStyle:
    def test_group_all_direct_hosts(self, tmp_path, logger):
        inv = {
            "all": {
                "hosts": {
                    "web1": {"ansible_host": "10.0.0.1", "ansible_user": "deploy"},
                }
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert error == {}
        assert hosts == [
            {
                "hostname": "10.0.0.1",
                "username": "deploy",
                "password_ref": None,
                "known_hosts_file": None,
                "key_path": None,
                "port": 22,
            }
        ]

    def test_group_all_includes_children(self, tmp_path, logger):
        inv = {
            "all": {
                "hosts": {"web1": {"ansible_host": "10.0.0.1", "ansible_user": "a"}},
                "children": {
                    "db": {
                        "hosts": {"db1": {"ansible_host": "10.0.0.2"}},
                        "vars": {"ansible_user": "dbadmin"},
                    }
                },
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert error == {}
        hostnames = {h["hostname"]: h["username"] for h in hosts}
        assert hostnames == {"10.0.0.1": "a", "10.0.0.2": "dbadmin"}

    def test_specific_group_in_children(self, tmp_path, logger):
        inv = {
            "all": {
                "hosts": {"web1": {"ansible_host": "10.0.0.1", "ansible_user": "a"}},
                "children": {
                    "db": {
                        "hosts": {"db1": {"ansible_host": "10.0.0.2"}},
                        "vars": {"ansible_user": "dbadmin"},
                    }
                },
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "db", logger)
        assert error == {}
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "10.0.0.2"
        assert hosts[0]["username"] == "dbadmin"

    def test_group_not_in_children_falls_back_to_legacy_toplevel(
        self, tmp_path, logger
    ):
        inv = {
            "all": {"hosts": {"web1": {"ansible_host": "10.0.0.1"}}},
            "extra": {"hosts": {"x1": {"ansible_host": "10.0.0.9", "user": "u1"}}},
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "extra", logger)
        assert error == {}
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "10.0.0.9"
        assert hosts[0]["username"] == "u1"

    def test_invalid_group_returns_400(self, tmp_path, logger):
        inv = {"all": {"hosts": {"web1": {"ansible_host": "10.0.0.1"}}}}
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "nonexistent", logger)
        assert hosts == []
        assert error["status_code"] == 400
        assert error["message"] == "Configured inventory group is invalid"

    def test_host_without_username_is_skipped(self, tmp_path, logger):
        inv = {
            "all": {
                "hosts": {
                    "no_user": {"ansible_host": "10.0.0.5"},
                    "has_user": {"ansible_host": "10.0.0.6", "ansible_user": "u"},
                }
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert error == {}
        assert [h["hostname"] for h in hosts] == ["10.0.0.6"]

    def test_password_ref_resolved_from_ansible_ssh_pass_ref(self, tmp_path, logger):
        inv = {
            "all": {
                "hosts": {
                    "web1": {
                        "ansible_host": "10.0.0.1",
                        "ansible_user": "a",
                        "ansible_ssh_pass_ref": "vault://secret/web1#password",
                    }
                }
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert error == {}
        assert hosts[0]["password_ref"] == "vault://secret/web1#password"

    def test_plaintext_password_raises_value_error_bubbles_to_500(
        self, tmp_path, logger
    ):
        inv = {
            "all": {
                "hosts": {
                    "web1": {
                        "ansible_host": "10.0.0.1",
                        "ansible_user": "a",
                        "ansible_ssh_pass": "plaintext-secret",
                    }
                }
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert hosts == []
        assert error["status_code"] == 500
        assert error["message"] == "Load inv fail"


class TestLegacyStyle:
    def test_group_all_flat(self, tmp_path, logger):
        inv = {
            "web1": {"hostname": "10.0.0.1", "user": "deploy"},
            "web2": {"hostname": "10.0.0.2", "username": "deploy2"},
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert error == {}
        hostnames = {h["hostname"]: h["username"] for h in hosts}
        assert hostnames == {"10.0.0.1": "deploy", "10.0.0.2": "deploy2"}

    def test_specific_group_toplevel_hosts(self, tmp_path, logger):
        inv = {
            "mygroup": {
                "hosts": {
                    "h1": {"ansible_host": "10.0.0.3", "user": "legacyuser"},
                }
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "mygroup", logger)
        assert error == {}
        assert len(hosts) == 1
        assert hosts[0]["hostname"] == "10.0.0.3"
        assert hosts[0]["username"] == "legacyuser"

    def test_invalid_group_returns_400(self, tmp_path, logger):
        inv = {"web1": {"hostname": "10.0.0.1", "user": "deploy"}}
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "nosuchgroup", logger)
        assert hosts == []
        assert error["status_code"] == 400
        assert error["message"] == "Configured inventory group is invalid"


class TestLimitsAndErrors:
    def test_no_hosts_in_group_returns_400(self, tmp_path, logger):
        inv = {"all": {"hosts": {}}}
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert hosts == []
        assert error["status_code"] == 400
        assert error["message"] == "No hosts in configured inventory group"

    def test_exceeds_max_fleet_hosts_returns_400(
        self, tmp_path, logger, monkeypatch
    ):
        monkeypatch.setenv("TUNNEL_MAX_FLEET_HOSTS", "2")
        inv = {
            "all": {
                "hosts": {
                    f"h{i}": {"ansible_host": f"10.0.0.{i}", "ansible_user": "u"}
                    for i in range(5)
                }
            }
        }
        path = _write_inventory(tmp_path, inv)
        hosts, error = load_inventory(path, "all", logger)
        assert hosts == []
        assert error["status_code"] == 400
        assert error["message"] == "Configured inventory exceeds the fleet limit"

    def test_missing_file_returns_500(self, tmp_path, logger):
        missing = str(tmp_path / "does-not-exist.yaml")
        hosts, error = load_inventory(missing, "all", logger)
        assert hosts == []
        assert error["status_code"] == 500
        assert error["message"] == "Load inv fail"

    def test_invalid_yaml_returns_500(self, tmp_path, logger):
        path = tmp_path / "bad.yaml"
        path.write_text("not: valid: yaml: [unclosed")
        hosts, error = load_inventory(str(path), "all", logger)
        assert hosts == []
        assert error["status_code"] == 500
        assert error["message"] == "Load inv fail"
