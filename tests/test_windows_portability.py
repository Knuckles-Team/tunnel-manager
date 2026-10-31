"""Windows portability: no POSIX-only API is required to run."""

import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

from tunnel_manager import connection_security as cs
from tunnel_manager.tunnel_manager import _atomic_private_yaml


@pytest.fixture
def windows(monkeypatch):
    """Make the process look like Windows: no fchmod, no getuid, os.name nt."""
    chmods = []
    monkeypatch.delattr(os, "fchmod", raising=False)
    monkeypatch.delattr(os, "getuid", raising=False)
    monkeypatch.setattr(os, "chmod", lambda p, m: chmods.append((str(p), m)))
    monkeypatch.setattr(os, "name", "nt")
    return chmods


def test_secure_descriptor_is_noop_without_fchmod(windows):
    cs.secure_descriptor(-1)  # would raise OSError/AttributeError if it called fchmod


def test_secure_path_uses_read_write_bits_on_windows(windows):
    cs.secure_path("key")
    cs.secure_path("dir", directory=True)
    assert windows == [("key", stat.S_IREAD | stat.S_IWRITE)]


def test_current_uid_is_none_without_getuid(windows):
    assert cs.current_uid() is None


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX mode check")
def test_posix_modes_unchanged(tmp_path):
    f = tmp_path / "k"
    f.write_text("x")
    cs.secure_path(f)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    cs.secure_path(tmp_path, directory=True)
    assert stat.S_IMODE(tmp_path.stat().st_mode) == 0o700


def test_inventory_write_without_fchmod(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "fchmod", raising=False)
    target = tmp_path / "new" / "inventory.yml"
    _atomic_private_yaml(str(target), {"all": {"hosts": {}}})
    assert yaml.safe_load(target.read_text()) == {"all": {"hosts": {}}}


def test_generate_key_pair_without_fchmod(tmp_path, monkeypatch):
    monkeypatch.delattr(os, "fchmod", raising=False)
    key = tmp_path / "id_test"
    cs.generate_key_pair(str(key), "ed25519")
    assert key.exists() and Path(str(key) + ".pub").exists()
    if os.name != "nt":
        assert stat.S_IMODE(key.stat().st_mode) == 0o600


def test_no_hardcoded_ssh_keygen_or_unguarded_posix_calls():
    root = Path(cs.__file__).parent
    for path in root.rglob("*.py"):
        text = path.read_text()
        assert "/usr/bin/ssh-keygen" not in text, path
        for line in text.splitlines():
            if "os.fchmod(" in line:
                assert 'hasattr(os, "fchmod")' in text, path
            assert "os.getuid()" not in line or "hasattr(os" in line, path


def _as_windows(monkeypatch, aces):
    monkeypatch.setattr(cs, "_is_windows", lambda: True)
    monkeypatch.setattr(cs, "windows_allowed_aces", lambda _path: aces)


def test_windows_identity_with_everyone_access_is_unsafe(tmp_path, monkeypatch):
    key = tmp_path / "id"
    key.write_text("x")
    _as_windows(monkeypatch, [("S-1-5-21-1-2-3-1001", 0x1F01FF), ("S-1-1-0", 0x1)])
    with pytest.raises(cs.ConnectionPolicyError, match="permissions are unsafe"):
        cs.validate_identity_path(str(key))


def test_windows_owner_only_identity_is_accepted(tmp_path, monkeypatch):
    key = tmp_path / "id"
    key.write_text("x")
    _as_windows(
        monkeypatch, [("S-1-5-21-1-2-3-1001", 0x1F01FF), ("S-1-5-18", 0x1F01FF)]
    )
    assert cs.validate_identity_path(str(key)) == str(key.resolve())


def test_windows_known_hosts_readable_by_users_but_not_writable(tmp_path, monkeypatch):
    hosts = tmp_path / "known_hosts"
    hosts.write_text("h ssh-ed25519 AAAA\n")
    _as_windows(monkeypatch, [("S-1-5-32-545", 0x1200A9)])
    assert cs.validated_known_hosts_path(str(hosts)) == str(hosts.resolve())
    _as_windows(monkeypatch, [("S-1-5-32-545", 0x2)])
    with pytest.raises(cs.ConnectionPolicyError, match="securely owned"):
        cs.validated_known_hosts_path(str(hosts))


def test_proxy_trusted_dirs_match_case_insensitively():
    import ntpath

    from tunnel_manager import proxy_security as ps

    root = Path("/usr/bin")
    assert ps._contained_in(Path("/usr/bin/tsh"), (root,))
    assert not ps._contained_in(Path("/usr/binx/tsh"), (root,))
    assert ntpath.normcase(r"C:\WINDOWS\System32") == ntpath.normcase(
        r"c:\windows\system32"
    )
