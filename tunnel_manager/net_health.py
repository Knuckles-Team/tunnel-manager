"""Network-layer health producer — Phase C of the unified infra-intelligence plan
(``reports/unified-infra-intelligence-plan.md``). Probes the shared fleet inventory
for reachability/latency/loss/SSH-connect-time, distills them to lightweight
per-window trends, learns per-host baselines, and flags anomalies — the
network-layer twin of ``fan_manager.kg_control`` (hardware/thermal) and
``systems_manager.os_health`` (OS) generalized via the shared fleet primitive.

CONCEPT:TM-NET.observability.net-health-producer. This module is a thin
**producer**: it emits named numeric signals into the shared kernels
(:mod:`agent_utilities.observability.health` / ``health_ingest``) and gets
trend/baseline/anomaly for free — no bespoke statistics live here. Probing reuses
tunnel-manager's own host inventory (``tunnel_manager.tunnel_manager.HostManager``)
and connection logic (``tunnel_manager.tunnel_manager.Tunnel``) rather than
reinventing either, and a ``CommandRunner`` seam mirroring
``systems_manager.os_health.CommandRunner`` for the one shell-out (``ping``) so
both are injectable/testable.

**Central, not per-node.** Unlike the OS/hardware producers (one instance per
host), network probing is inherently centralized — a single pod probes
reachability/latency to every fleet host over the LAN, the way tunnel-manager
itself already operates.

**Guarded import:** tunnel-manager installs ``agent-utilities`` from PyPI, which
may predate the shared ``agent_utilities.observability.health*`` modules (another
session publishes them separately). Every entry point below degrades to a clean
no-op when the shared kernels are absent — this package never crashes for it,
mirroring ``fan_manager.kg_control``'s / ``systems_manager.os_health``'s
``_HAS_SHARED_HEALTH`` guard exactly.

**Report-only by design.** This producer only observes and writes typed KG nodes;
it never mutates a host or a tunnel — see the plan's
"report-only → approved → closed-loop" staging.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from agent_utilities.core.config import setting

logger = logging.getLogger("tunnel_manager.net_health")

try:
    from agent_utilities.observability.health import (
        HealthTrendBuffer,
        compute_baseline,
        correlate,
        detect_anomaly,
    )
    from agent_utilities.observability.health_ingest import (
        ingest_health_anomaly,
        ingest_health_baseline,
        ingest_health_trend,
        read_health_trends,
    )

    _HAS_SHARED_HEALTH = True
except Exception as _e:  # noqa: BLE001 — older/absent agent-utilities: no-op producer
    logger.debug(
        "shared health kernels unavailable, net-health producer degrades to no-op: %s",
        _e,
    )
    _HAS_SHARED_HEALTH = False

# The named network signals this producer samples (CONCEPT:TM-NET.observability.net-health-producer).
NET_SIGNALS: tuple[str, ...] = (
    "reachable",
    "rtt_ms",
    "packet_loss_pct",
    "ssh_connect_ms",
)

# Ping-burst tuning (fixed argv — no user input reaches the command line).
_PING_COUNT = 4
_PING_TIMEOUT_S = 2
_SSH_CONNECT_TIMEOUT_S = 5

_PING_LOSS_RE = re.compile(r"(\d+(?:\.\d+)?)%\s+packet\s+loss")
_PING_RTT_RE = re.compile(r"=\s*[\d.]+/([\d.]+)/")


# --------------------------------------------------------------------------- #
# command-runner seam (mirrors systems_manager.os_health.CommandRunner)        #
# --------------------------------------------------------------------------- #
@runtime_checkable
class CommandRunner(Protocol):
    """Seam for resolving and executing the local ``ping`` binary.

    Injecting this runner lets callers and tests substitute the shell-out without
    globally monkeypatching :mod:`subprocess`, matching the DI seam
    ``systems_manager.os_health.CommandRunner``/``fan_manager.fan_manager.CommandRunner``
    use for their shell-outs.
    """

    def which(self, name: str) -> str | None:
        """Resolve an executable on ``PATH`` (``None`` if absent)."""
        ...

    def run(self, argv: list[str], *, check: bool = True) -> str:
        """Run a fixed argv with ``shell=False`` and return captured stdout."""
        ...


class SubprocessCommandRunner:
    """Default :class:`CommandRunner` backed by ``shutil.which``/``subprocess.run``."""

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(self, argv: list[str], *, check: bool = True) -> str:
        # Fixed argv, shell=False: no user input reaches the command line.
        completed = subprocess.run(  # nosec B603 - fixed argv, no shell, no user input
            argv,
            capture_output=True,
            text=True,
            check=check,
        )
        return completed.stdout


_DEFAULT_RUNNER: CommandRunner = SubprocessCommandRunner()


# --------------------------------------------------------------------------- #
# inventory — reuse tunnel-manager's own HostManager, do not reinvent it       #
# --------------------------------------------------------------------------- #
def _hosts_from_env() -> list[str]:
    raw = str(setting("TUNNEL_MANAGER_HOSTS", "")).strip()
    return [h.strip() for h in raw.split(",") if h.strip()]


def _resolve_hosts() -> dict[str, Any]:
    """The probe target set: tunnel-manager's own inventory (``HostManager``),
    optionally narrowed by ``TUNNEL_MANAGER_HOSTS`` (comma-separated aliases).

    Enumerates via ``list_hosts()`` (identity-entitlement-scoped — a caller only
    ever probes hosts it may reach) but resolves each target via ``get_host()``
    to get the real, unredacted ``HostConfig`` (``list_hosts()`` strips
    ``password``/``password_ref`` for display; a real SSH connect needs them).
    """
    from tunnel_manager.tunnel_manager import HostManager

    try:
        manager = HostManager()
        aliases = list(manager.list_hosts().keys())
    except Exception as e:  # noqa: BLE001 — no/unreadable inventory -> nothing to probe
        logger.debug("net-health: inventory unavailable: %s", e)
        return {}
    wanted = _hosts_from_env()
    if wanted:
        aliases = [alias for alias in aliases if alias in wanted]
    resolved: dict[str, Any] = {}
    for alias in aliases:
        try:
            config = manager.get_host(alias)
        except Exception as e:  # noqa: BLE001 — e.g. entitlement denial -> skip, not fatal
            logger.debug("net-health: host %s unavailable: %s", alias, e)
            continue
        if config is not None:
            resolved[alias] = config
    return resolved


def _target_hostname(alias: str, host_config: Any) -> str:
    return getattr(host_config, "hostname", None) or alias


# --------------------------------------------------------------------------- #
# probing — one short ping burst + one real SSH connect, both best-effort      #
# --------------------------------------------------------------------------- #
def _ping(target: str, runner: CommandRunner) -> tuple[float | None, float | None]:
    """Short ping burst against ``target`` -> ``(avg_rtt_ms, packet_loss_pct)``.

    Either element is ``None`` when ``ping`` is unavailable or its output can't be
    parsed (e.g. 100% loss omits the rtt line) — sampling is always best-effort.
    """
    if runner.which("ping") is None:
        return None, None
    try:
        out = runner.run(
            ["ping", "-c", str(_PING_COUNT), "-W", str(_PING_TIMEOUT_S), target],
            check=False,
        )
    except Exception as e:  # noqa: BLE001 — sampling is best-effort
        logger.debug("ping unavailable for %s: %s", target, e)
        return None, None
    loss_match = _PING_LOSS_RE.search(out)
    rtt_match = _PING_RTT_RE.search(out)
    loss_pct = float(loss_match.group(1)) if loss_match else None
    rtt_ms = float(rtt_match.group(1)) if rtt_match else None
    return rtt_ms, loss_pct


def _default_tunnel_factory(host_config: Any) -> Any:
    from tunnel_manager.tunnel_manager import Tunnel

    return Tunnel(config=host_config, connect_timeout=_SSH_CONNECT_TIMEOUT_S)


def _ssh_connect_ms(
    host_config: Any, tunnel_factory: Callable[[Any], Any]
) -> float | None:
    """Wall-clock time (ms) to establish a real SSH connection via tunnel-manager's
    own :class:`~tunnel_manager.tunnel_manager.Tunnel` — reuses its connection
    logic (auth, proxy-command, retries) rather than reimplementing SSH handshake
    timing. ``None`` on any connection failure (host unreachable, auth failure)."""
    try:
        tunnel = tunnel_factory(host_config)
    except Exception as e:  # noqa: BLE001 — sampling is best-effort
        logger.debug("ssh_connect_ms: tunnel construction failed: %s", e)
        return None
    start = time.perf_counter()
    try:
        tunnel.connect()
    except (
        Exception
    ) as e:  # noqa: BLE001 — unreachable/auth failure is a data point, not a crash
        logger.debug("ssh_connect_ms unavailable: %s", e)
        return None
    finally:
        client = getattr(tunnel, "ssh_client", None)
        if client is not None:
            try:
                client.close()
            except Exception:  # noqa: BLE001 — nosec B110 — best-effort cleanup
                pass  # nosec B110 - close() failure is inconsequential here
    return round((time.perf_counter() - start) * 1000.0, 3)


def collect_network_signals(
    hosts: dict[str, Any] | None = None,
    *,
    runner: CommandRunner | None = None,
    tunnel_factory: Callable[[Any], Any] | None = None,
) -> dict[str, dict[str, float]]:
    """Probe each fleet host's current network health (CONCEPT:TM-NET.observability.net-health-producer).

    ``hosts``: ``{alias: HostConfig}`` (default: tunnel-manager's own inventory via
    :func:`_resolve_hosts`, i.e. ``HostManager().list_hosts()`` narrowed by
    ``TUNNEL_MANAGER_HOSTS``). Returns ``{alias: {signal: value}}``. Each signal is
    skipped (not raised) when it can't be read, so a partial environment still
    yields a partial reading rather than an empty one. Signals: ``rtt_ms`` /
    ``packet_loss_pct`` (short ping burst), ``ssh_connect_ms`` (real SSH connect
    via tunnel-manager's own :class:`Tunnel`), ``reachable`` (1/0, derived from
    whichever probe answered).
    """
    hosts = hosts if hosts is not None else _resolve_hosts()
    runner = runner or _DEFAULT_RUNNER
    tunnel_factory = tunnel_factory or _default_tunnel_factory

    results: dict[str, dict[str, float]] = {}
    for alias, host_config in hosts.items():
        signals: dict[str, float] = {}
        target = _target_hostname(alias, host_config)

        rtt_ms, loss_pct = _ping(target, runner)
        reachable: float | None = None
        if loss_pct is not None:
            reachable = 1.0 if loss_pct < 100.0 else 0.0
        if rtt_ms is not None:
            signals["rtt_ms"] = rtt_ms
        if loss_pct is not None:
            signals["packet_loss_pct"] = loss_pct

        ssh_ms = _ssh_connect_ms(host_config, tunnel_factory)
        if ssh_ms is not None:
            signals["ssh_connect_ms"] = ssh_ms
            if reachable is None:
                reachable = 1.0
        elif reachable is None:
            reachable = 0.0

        if reachable is not None:
            signals["reachable"] = reachable
        results[alias] = signals
    return results


# --------------------------------------------------------------------------- #
# distill-to-trend — one HealthTrendBuffer per (host, signal); bounded writes  #
# --------------------------------------------------------------------------- #
_BUFFERS: dict[tuple[str, str], Any] = {}


def _buffer_for(host: str, signal: str) -> Any | None:
    """Return the ``(host, signal)``'s rolling :class:`HealthTrendBuffer`, or
    ``None`` when the shared kernel is unavailable."""
    if not _HAS_SHARED_HEALTH:
        return None
    key = (host, signal)
    buf = _BUFFERS.get(key)
    if buf is None:
        window_s = int(setting("TUNNEL_MANAGER_HEALTH_AGGREGATE_S", 3600))
        buf = HealthTrendBuffer(window_s=window_s)
        _BUFFERS[key] = buf
    return buf


def _health_ingest_enabled() -> bool:
    return str(setting("TUNNEL_MANAGER_HEALTH_INGEST", "true")).strip().lower() not in {
        "0",
        "false",
        "no",
    }


def sample_and_ingest(
    hosts: dict[str, Any] | None = None,
    *,
    runner: CommandRunner | None = None,
    tunnel_factory: Callable[[Any], Any] | None = None,
) -> dict[str, Any]:
    """One collection pass: probe every host → feed the per-(host,signal) trend
    buffers → ingest any flushed trends (CONCEPT:TM-NET.observability.net-health-producer).

    Idempotent and best-effort: a disabled toggle
    (``TUNNEL_MANAGER_HEALTH_INGEST=false``) or an absent shared-health kernel
    both degrade to collecting signals without writing to the KG — never raises.
    Bounded by design: a ``:HealthTrend`` node is written only when a buffer's
    aggregate window elapses, never per sample.
    """
    collected = collect_network_signals(
        hosts, runner=runner, tunnel_factory=tunnel_factory
    )
    if not _health_ingest_enabled():
        return {
            "hosts": list(collected),
            "signals": collected,
            "ingested": False,
            "flushed": [],
        }
    if not _HAS_SHARED_HEALTH:
        return {
            "hosts": list(collected),
            "signals": collected,
            "ingested": False,
            "flushed": [],
            "reason": "shared health kernels unavailable",
        }

    flushed: list[dict[str, Any]] = []
    for host, signals in collected.items():
        entity_id = f"tunnel:host:{host}"
        for signal, value in signals.items():
            buf = _buffer_for(host, signal)
            if buf is None:
                continue
            trend = buf.add(value)
            if trend is None:
                continue
            result = ingest_health_trend(
                entity_id=entity_id,
                entity_type="Host",
                layer="network",
                signal=signal,
                trend=trend,
                host=host,
            )
            flushed.append(
                {
                    "host": host,
                    "signal": signal,
                    "trend": trend,
                    "ingested": bool(result),
                }
            )
            logger.info(
                "net-health trend[%s]: %s avg=%s min=%s max=%s over %d samples",
                host,
                signal,
                trend.get("avg"),
                trend.get("min"),
                trend.get("max"),
                trend.get("samples") or 0,
            )
    return {
        "hosts": list(collected),
        "signals": collected,
        "ingested": True,
        "flushed": flushed,
    }


# --------------------------------------------------------------------------- #
# orchestration — one report-only derivation pass over the fleet               #
# --------------------------------------------------------------------------- #
def _derivation_hosts() -> list[str]:
    wanted = _hosts_from_env()
    if wanted:
        return wanted
    return list(_resolve_hosts())


def _notify(message: str) -> None:
    """Best-effort push to the intelligent alert router
    (``TUNNEL_MANAGER_HEALTH_NOTIFY_URL``), mirroring
    ``fan_manager.kg_control._notify``/``systems_manager.os_health._notify``."""
    import urllib.request

    url = setting("TUNNEL_MANAGER_HEALTH_NOTIFY_URL")
    logger.info(message)
    if not url:
        return
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(
                {"source": "tunnel-manager-health", "message": message}
            ).encode(),
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(
            req, timeout=5
        )  # noqa: S310  # nosec B310 — operator-configured URL
    except Exception as e:  # noqa: BLE001 — notification is best-effort
        logger.debug("notify skipped: %s", e)


def run_net_derivation(
    hosts: list[str] | None = None, *, days: int = 14
) -> dict[str, Any]:
    """One learn→flag pass over ``hosts`` (default: ``TUNNEL_MANAGER_HOSTS`` or the
    full inventory).

    For each host×signal: reads recent ``:HealthTrend`` history, learns a
    ``:HealthBaseline``, and checks the recent tail for a ``:HealthAnomaly`` off
    that baseline. Anomalies simultaneous across a majority of hosts for the same
    signal are collapsed into one ``systemic`` cause — e.g. every host's rtt/loss
    spiking together points at a shared switch/uplink fault, not N independent
    host problems. **Report-only** — no remediation, no tunnel/host mutation;
    only writes typed KG nodes and a best-effort notification. All KG I/O is
    best-effort: with no reachable engine every host degrades to "no data". With
    no shared health kernel this is a clean no-op.
    """
    if not _HAS_SHARED_HEALTH:
        logger.info("net-health derivation skipped: shared health kernels unavailable")
        return {"hosts": 0, "results": {}}

    hosts = hosts or _derivation_hosts()
    results: dict[str, dict[str, Any]] = {host: {} for host in hosts}
    anomalies_by_signal: dict[str, dict[str, dict[str, Any] | None]] = {
        signal: {} for signal in NET_SIGNALS
    }

    for host in hosts:
        entity_id = f"tunnel:host:{host}"
        for signal in NET_SIGNALS:
            trends = read_health_trends(entity_id, signal, days=days) or []
            baseline = compute_baseline(trends, value_key="avg", peak_key="max")
            anomaly = detect_anomaly(trends[-3:], baseline, value_key="avg")
            anomalies_by_signal[signal][host] = anomaly
            results[host][signal] = {
                "trends": len(trends),
                "baseline": baseline,
                "anomaly": anomaly,
            }

    for _signal, anomalies in anomalies_by_signal.items():
        correlate(
            anomalies, len(hosts), kind="above-baseline", systemic_kind="systemic"
        )

    for host in hosts:
        entity_id = f"tunnel:host:{host}"
        seen_signals = 0
        for signal in NET_SIGNALS:
            data = results[host][signal]
            baseline = data["baseline"]
            if baseline:
                ingest_health_baseline(entity_id, signal, baseline, entity_type="Host")
            anomaly = anomalies_by_signal[signal][host]
            data["anomaly"] = anomaly
            if data["trends"]:
                seen_signals += 1
            if anomaly:
                ingest_health_anomaly(entity_id, signal, anomaly, entity_type="Host")
                _notify(
                    f"[tunnel-manager-health] {host}: {signal} {anomaly['kind']} — "
                    f"observed={anomaly['observed']} expected={anomaly['expected']} "
                    f"(z={anomaly['zscore']})"
                )
        anomaly_count = sum(1 for s in NET_SIGNALS if anomalies_by_signal[s][host])
        logger.info(
            "%s: %d/%d signals with history, %d anomal%s",
            host,
            seen_signals,
            len(NET_SIGNALS),
            anomaly_count,
            "y" if anomaly_count == 1 else "ies",
        )

    return {"hosts": len(hosts), "results": results}


# --------------------------------------------------------------------------- #
# CLI entry points                                                              #
# --------------------------------------------------------------------------- #
def main_sample() -> None:
    """CLI (``tunnel-manager-health``): one probe+ingest pass; prints a JSON summary."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    summary = sample_and_ingest()
    print(json.dumps(summary, default=str, indent=2))


def main_derive() -> None:
    """CLI (``tunnel-manager-health-derive``): one derivation pass; prints a JSON summary."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    p = argparse.ArgumentParser(
        description="tunnel-manager net-health derivation pass."
    )
    p.add_argument(
        "--days", type=int, default=14, help="trend lookback window (default 14)"
    )
    p.add_argument(
        "--hosts",
        default="",
        help="comma-separated hosts (default $TUNNEL_MANAGER_HOSTS)",
    )
    args = p.parse_args()
    hosts = [h.strip() for h in args.hosts.split(",") if h.strip()] or None
    summary = run_net_derivation(hosts, days=args.days)
    print(json.dumps(summary, default=str, indent=2))


def main() -> None:
    """CLI: ``python -m tunnel_manager.net_health {sample|derive} [options]``
    (mirrors ``systems_manager.os_health.main``/``fan_manager.kg_control.main``);
    defaults to ``sample``."""
    import argparse

    p = argparse.ArgumentParser(description="tunnel-manager network-health producer.")
    sub = p.add_subparsers(dest="command")
    sub.add_parser("sample", help="one probe+ingest pass (default)")
    derive_p = sub.add_parser(
        "derive", help="learn baselines + flag anomalies (report-only)"
    )
    derive_p.add_argument("--days", type=int, default=14)
    derive_p.add_argument(
        "--hosts",
        default="",
        help="comma-separated hosts (default $TUNNEL_MANAGER_HOSTS)",
    )
    args = p.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    if args.command == "derive":
        hosts = [h.strip() for h in args.hosts.split(",") if h.strip()] or None
        summary = run_net_derivation(hosts, days=args.days)
    else:
        summary = sample_and_ingest()
    print(json.dumps(summary, default=str, indent=2))


if __name__ == "__main__":
    main()
