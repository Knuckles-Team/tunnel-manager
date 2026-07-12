"""Identity-scoped host auto-load (CONCEPT:AU-OS.identity.identity-scoped-resource-autoload).

The caller's entitled SSH host aliases auto-load; a non-entitled named host is
denied. Tests the resolution/enforcement logic with the entitlement source
mocked (the resolver itself is tested in agent-utilities).
"""

import pytest

from tunnel_manager.tunnel_manager import HostManager


def _hm(entitled, hosts):
    hm = object.__new__(HostManager)  # bypass __init__ (no inventory file I/O)
    hm.hosts = hosts
    hm._entitled = lambda namespace, names: [n for n in names if n in entitled]
    return hm


def _hosts(*aliases):
    return {a: {"hostname": f"{a}.example.com", "user": "ops"} for a in aliases}


def test_list_hosts_filters_to_entitled():
    hm = _hm({"prod"}, _hosts("prod", "dev"))
    assert set(hm.list_hosts().keys()) == {"prod"}


def test_list_hosts_returns_all_when_fully_entitled():
    hm = _hm({"prod", "dev"}, _hosts("prod", "dev"))
    assert set(hm.list_hosts().keys()) == {"prod", "dev"}


def test_list_hosts_empty_when_nothing_entitled():
    hm = _hm(set(), _hosts("prod", "dev"))
    assert hm.list_hosts() == {}


def test_get_host_entitled_alias_allowed():
    hm = _hm({"prod", "dev"}, _hosts("prod", "dev"))
    host = hm.get_host("dev")
    assert host is not None
    assert host.hostname == "dev.example.com"


def test_get_host_non_entitled_alias_denied():
    hm = _hm({"prod"}, _hosts("prod", "dev"))
    with pytest.raises(PermissionError):
        hm.get_host("dev")


def test_get_host_unknown_alias_returns_none():
    hm = _hm({"prod"}, _hosts("prod"))
    assert hm.get_host("ghost") is None
