"""Metadata-only configuration and security diagnostics for Tunnel Manager."""

from __future__ import annotations

import json

from agent_utilities.core.config import setting

from .connection_security import ConnectionPolicyError, security_posture


def diagnose() -> dict[str, object]:
    """Return bounded facts without exposing hosts, paths, or secret references."""

    try:
        checks = security_posture()
    except ConnectionPolicyError:
        return {
            "status": "failed",
            "checks": {"resource_limits_valid": False},
        }
    checks.update(
        {
            "inventory_configured": bool(setting("TUNNEL_INVENTORY")),
            "remote_target_configured": bool(
                setting("TUNNEL_REMOTE_HOST") and setting("TUNNEL_USERNAME")
            ),
            "identity_configured": bool(setting("TUNNEL_IDENTITY_FILE")),
            "proxy_configured": bool(setting("TUNNEL_PROXY_COMMAND")),
            "kg_ingest_enabled": bool(setting("TUNNEL_KG_INGEST", True)),
            "health_ingest_enabled": bool(
                setting("TUNNEL_MANAGER_HEALTH_INGEST", True)
            ),
            "health_filter_configured": bool(setting("TUNNEL_MANAGER_HOSTS")),
            "health_notification_configured": bool(
                setting("TUNNEL_MANAGER_HEALTH_NOTIFY_URL")
            ),
        }
    )
    ready = bool(
        checks["known_hosts_ready"]
        and checks["plaintext_password_env_absent"]
        and checks["local_forward_loopback_only"]
    )
    return {"status": "ready" if ready else "action_required", "checks": checks}


def main() -> None:
    """Print the privacy-safe doctor result and return a useful process status."""

    result = diagnose()
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(0 if result["status"] == "ready" else 1)


if __name__ == "__main__":
    main()
