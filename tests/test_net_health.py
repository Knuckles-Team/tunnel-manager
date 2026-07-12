"""Tests for the network-layer health producer (``tunnel_manager.net_health``) —
Phase C of the unified infra-intelligence plan
(``reports/unified-infra-intelligence-plan.md``).

Mirrors ``fan_manager/tests/test_kg_control.py`` and
``systems_manager/tests/test_os_health.py``'s shape: pure probing via injected
seams (fake ping runner + fake SSH tunnel factory — no real pings or SSH
connections in tests), the distill-not-per-sample buffer, an end-to-end
derivation pass against a fake KG, and the guarded-import no-op path.
"""

from __future__ import annotations

import tunnel_manager.net_health as nh


class _FakeRunner:
    def __init__(self, which: dict | None = None, outputs: dict | None = None) -> None:
        self._which = which or {}
        self._outputs = outputs or {}

    def which(self, name: str) -> str | None:
        return self._which.get(name)

    def run(self, argv: list[str], *, check: bool = True) -> str:
        return self._outputs.get(argv[-1], self._outputs.get(argv[0], ""))


class _FakeHostConfig:
    def __init__(self, hostname: str) -> None:
        self.hostname = hostname


class _FakeSshClient:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeTunnel:
    """Fake ``Tunnel`` — records whether ``connect()`` was called, never touches
    a real socket."""

    instances: list[_FakeTunnel] = []

    def __init__(self, host_config, *, fail: bool = False) -> None:
        self.host_config = host_config
        self.fail = fail
        self.ssh_client = _FakeSshClient()
        _FakeTunnel.instances.append(self)

    def connect(self, timeout=None):
        if self.fail:
            raise ConnectionError("simulated unreachable host")


def _tunnel_factory(*, fail_hosts: set[str] | None = None):
    fail_hosts = fail_hosts or set()

    def factory(host_config):
        return _FakeTunnel(host_config, fail=host_config.hostname in fail_hosts)

    return factory


PING_OK = (
    "PING h1 (10.0.0.1) 56(84) bytes of data.\n"
    "64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.5 ms\n"
    "\n"
    "--- h1 ping statistics ---\n"
    "4 packets transmitted, 4 received, 0% packet loss, time 3054ms\n"
    "rtt min/avg/max/mdev = 0.400/0.523/0.700/0.050 ms\n"
)

PING_ALL_LOST = (
    "PING h2 (10.0.0.2) 56(84) bytes of data.\n"
    "\n"
    "--- h2 ping statistics ---\n"
    "4 packets transmitted, 0 received, 100% packet loss, time 3054ms\n"
)


# --- collect_network_signals -------------------------------------------------- #
def test_collect_network_signals_reads_injected_seam():
    hosts = {"h1": _FakeHostConfig("h1")}
    runner = _FakeRunner(which={"ping": "/usr/bin/ping"}, outputs={"h1": PING_OK})
    signals = nh.collect_network_signals(
        hosts, runner=runner, tunnel_factory=_tunnel_factory()
    )
    assert signals["h1"]["rtt_ms"] == 0.523
    assert signals["h1"]["packet_loss_pct"] == 0.0
    assert signals["h1"]["reachable"] == 1.0
    assert signals["h1"]["ssh_connect_ms"] >= 0.0


def test_collect_network_signals_all_packets_lost_marks_unreachable():
    hosts = {"h2": _FakeHostConfig("h2")}
    runner = _FakeRunner(which={"ping": "/usr/bin/ping"}, outputs={"h2": PING_ALL_LOST})
    signals = nh.collect_network_signals(
        hosts, runner=runner, tunnel_factory=_tunnel_factory(fail_hosts={"h2"})
    )
    assert signals["h2"]["packet_loss_pct"] == 100.0
    assert "rtt_ms" not in signals["h2"]  # no rtt line when every packet is lost
    assert signals["h2"]["reachable"] == 0.0
    assert "ssh_connect_ms" not in signals["h2"]


def test_collect_network_signals_no_ping_binary_falls_back_to_ssh():
    # ping unavailable on PATH -> reachable/latency come from the SSH probe alone.
    hosts = {"h1": _FakeHostConfig("h1")}
    runner = _FakeRunner()  # which() returns None for everything
    signals = nh.collect_network_signals(
        hosts, runner=runner, tunnel_factory=_tunnel_factory()
    )
    assert "rtt_ms" not in signals["h1"]
    assert "packet_loss_pct" not in signals["h1"]
    assert signals["h1"]["reachable"] == 1.0
    assert "ssh_connect_ms" in signals["h1"]


def test_collect_network_signals_never_raises_on_total_failure():
    hosts = {"h3": _FakeHostConfig("h3")}
    runner = _FakeRunner()
    signals = nh.collect_network_signals(
        hosts, runner=runner, tunnel_factory=_tunnel_factory(fail_hosts={"h3"})
    )
    assert signals["h3"] == {"reachable": 0.0}


# --- distill-to-trend buffer: one trend per window, never per sample --------- #
class _FakeBuffer:
    instances = 0

    def __init__(self, **_kwargs) -> None:
        _FakeBuffer.instances += 1
        self.calls = 0

    def add(self, value, **_kwargs):
        self.calls += 1
        if self.calls < 3:
            return None
        return {
            "min": value,
            "max": value,
            "avg": value,
            "avg_control": None,
            "samples": self.calls,
            "window_s": 3600,
        }


def test_sample_and_ingest_distills_not_per_sample(monkeypatch):
    nh._BUFFERS.clear()
    _FakeBuffer.instances = 0
    monkeypatch.setattr(nh, "_HAS_SHARED_HEALTH", True)
    monkeypatch.setattr(nh, "HealthTrendBuffer", _FakeBuffer, raising=False)
    monkeypatch.setattr(
        nh, "collect_network_signals", lambda *a, **kw: {"h1": {"rtt_ms": 0.5}}
    )
    ingested: list[dict] = []
    monkeypatch.setattr(
        nh,
        "ingest_health_trend",
        lambda **kw: ingested.append(kw) or {"nodes": 1, "edges": 1},
        raising=False,
    )

    for _ in range(3):
        result = nh.sample_and_ingest()

    # only the 3rd pass crossed the buffer's window -> exactly one :HealthTrend write
    assert len(ingested) == 1
    assert ingested[0]["signal"] == "rtt_ms"
    assert ingested[0]["entity_id"] == "tunnel:host:h1"
    assert ingested[0]["layer"] == "network"
    assert ingested[0]["entity_type"] == "Host"
    # the buffer is created ONCE per (host, signal) and reused across passes
    assert _FakeBuffer.instances == 1
    assert result["ingested"] is True
    assert result["flushed"][0]["signal"] == "rtt_ms"


def test_sample_and_ingest_disabled_by_env(monkeypatch):
    monkeypatch.setenv("TUNNEL_MANAGER_HEALTH_INGEST", "false")
    monkeypatch.setattr(nh, "_HAS_SHARED_HEALTH", True)
    monkeypatch.setattr(
        nh, "collect_network_signals", lambda *a, **kw: {"h1": {"rtt_ms": 0.5}}
    )
    called = []
    monkeypatch.setattr(
        nh, "ingest_health_trend", lambda **kw: called.append(kw), raising=False
    )
    result = nh.sample_and_ingest()
    assert result["ingested"] is False
    assert result["signals"] == {"h1": {"rtt_ms": 0.5}}
    assert called == []


# --- guarded-import no-op path (shared kernels absent) ----------------------- #
def test_module_imports_cleanly_regardless_of_shared_health():
    # The guarded import must never raise, whether or not the shared kernels are
    # installed; _HAS_SHARED_HEALTH just reports which path is active.
    assert isinstance(nh._HAS_SHARED_HEALTH, bool)


def test_sample_and_ingest_noop_when_shared_health_absent(monkeypatch):
    monkeypatch.setattr(nh, "_HAS_SHARED_HEALTH", False)
    monkeypatch.setattr(
        nh, "collect_network_signals", lambda *a, **kw: {"h1": {"rtt_ms": 0.5}}
    )
    result = nh.sample_and_ingest()
    assert result["ingested"] is False
    assert result["signals"] == {"h1": {"rtt_ms": 0.5}}
    assert result["reason"] == "shared health kernels unavailable"


def test_run_net_derivation_noop_when_shared_health_absent(monkeypatch):
    monkeypatch.setattr(nh, "_HAS_SHARED_HEALTH", False)
    assert nh.run_net_derivation(["h1"]) == {"hosts": 0, "results": {}}


# --- run_net_derivation: end-to-end against a fake KG ------------------------- #
def test_run_net_derivation_end_to_end(monkeypatch):
    monkeypatch.setattr(nh, "_HAS_SHARED_HEALTH", True)

    h1_rtt_trends = [{"avg": v} for v in (10, 20, 30, 40, 50, 60)]

    def fake_read_health_trends(entity_id, signal, *, days=14):
        host = entity_id.rsplit(":", 1)[-1]
        if host == "h1" and signal == "rtt_ms":
            return h1_rtt_trends
        return []

    def fake_compute_baseline(trends, *, value_key, min_windows=6, **_kwargs):
        if len(trends) < min_windows:
            return None
        return {
            "p50": 30.0,
            "p95": 45.0,
            "min_env": 10.0,
            "max_env": 60.0,
            "avg_control": None,
            "inertia": None,
            "windows": len(trends),
        }

    def fake_detect_anomaly(recent, baseline, *, value_key, **_kw):
        if not baseline or not recent:
            return None
        observed = recent[-1][value_key]
        if observed > baseline["p95"]:
            return {
                "kind": "above-baseline",
                "zscore": 9.9,
                "observed": observed,
                "expected": baseline["p50"],
            }
        return None

    correlate_calls = []

    def fake_correlate(anomalies, total, **_kwargs):
        correlate_calls.append((dict(anomalies), total))
        return anomalies

    baselines_written: list[tuple] = []
    anomalies_written: list[tuple] = []
    notified: list[str] = []

    monkeypatch.setattr(
        nh, "read_health_trends", fake_read_health_trends, raising=False
    )
    monkeypatch.setattr(nh, "compute_baseline", fake_compute_baseline, raising=False)
    monkeypatch.setattr(nh, "detect_anomaly", fake_detect_anomaly, raising=False)
    monkeypatch.setattr(nh, "correlate", fake_correlate, raising=False)
    monkeypatch.setattr(
        nh,
        "ingest_health_baseline",
        lambda eid, sig, b, **kw: baselines_written.append((eid, sig, b)),
        raising=False,
    )
    monkeypatch.setattr(
        nh,
        "ingest_health_anomaly",
        lambda eid, sig, a, **kw: anomalies_written.append((eid, sig, a)),
        raising=False,
    )
    monkeypatch.setattr(nh, "_notify", lambda msg: notified.append(msg))

    out = nh.run_net_derivation(["h1", "empty"], days=14)

    assert out["hosts"] == 2
    h1_rtt = out["results"]["h1"]["rtt_ms"]
    assert h1_rtt["trends"] == 6
    assert h1_rtt["baseline"]["p95"] == 45.0
    assert h1_rtt["anomaly"]["kind"] == "above-baseline"

    empty_rtt = out["results"]["empty"]["rtt_ms"]
    assert empty_rtt["trends"] == 0
    assert empty_rtt["baseline"] is None
    assert empty_rtt["anomaly"] is None

    # baseline/anomaly writes only happen where there was real history
    assert ("tunnel:host:h1", "rtt_ms", h1_rtt["baseline"]) in baselines_written
    assert not any(eid == "tunnel:host:empty" for eid, _, _ in baselines_written)
    assert ("tunnel:host:h1", "rtt_ms", h1_rtt["anomaly"]) in anomalies_written

    # correlate ran once per signal (report-only — never touched a host/tunnel)
    assert len(correlate_calls) == len(nh.NET_SIGNALS)
    assert any(msg for msg in notified if "h1" in msg and "rtt_ms" in msg)
