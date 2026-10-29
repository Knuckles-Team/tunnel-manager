"""Identity-scoped host lookup: an unknown alias is not an error.

Listing and entitlement denial are proven through the served stack in
``test_served_actor_binding.py``.
"""

from tunnel_manager.tunnel_manager import HostManager


def _hm(entitled, hosts):
    hm = object.__new__(HostManager)  # bypass __init__ (no inventory file I/O)
    hm.hosts = hosts
    hm._entitled = lambda namespace, names: [n for n in names if n in entitled]
    return hm


def _hosts(*aliases):
    return {a: {"hostname": f"{a}.example.com", "user": "ops"} for a in aliases}


def test_get_host_unknown_alias_returns_none():
    hm = _hm({"prod"}, _hosts("prod"))
    assert hm.get_host("ghost") is None
