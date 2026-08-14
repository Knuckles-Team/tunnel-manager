"""Native epistemic-graph ingestion for governed SSH inventory metadata.

All writes use the required ``agent_utilities.knowledge_graph.memory.native_ingest``
primitive. Nodes use canonical ``node_type`` and edges use canonical ``relationship``;
nodes and edges commit in one native transaction. Missing engine dependencies, rejected
records, conflicts, and transaction failures propagate as ``NativeIngestError``.
"""

from __future__ import annotations

import logging
from typing import Any

from agent_utilities.knowledge_graph.memory.native_ingest import (
    ingest_documents as _native_ingest_documents,
)
from agent_utilities.knowledge_graph.memory.native_ingest import (
    ingest_entities as _native_ingest_entities,
)

logger = logging.getLogger("tunnel_manager.kg")

_SOURCE = "tunnel-manager"
_DOMAIN = "tunnel"


def ingest_entities(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
    *,
    source: str = _SOURCE,
    domain: str = _DOMAIN,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int]:
    """Write canonical typed nodes and relationships in one native transaction."""
    return _native_ingest_entities(
        entities,
        relationships,
        source=source,
        domain=domain,
        client=client,
        graph=graph,
    )


def ingest_documents(
    documents: list[dict[str, Any]],
    *,
    source: str = _SOURCE,
    domain: str = _DOMAIN,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int]:
    """Write text records as canonical Document nodes."""
    return _native_ingest_documents(
        documents, source=source, domain=domain, client=client, graph=graph
    )


def _host_to_dict(host: Any) -> dict[str, Any]:
    """Normalize a HostConfig / mapping into a plain dict of host fields."""
    if hasattr(host, "model_dump"):
        try:
            return host.model_dump(exclude_unset=False)
        except Exception as exc:  # noqa: BLE001
            logger.debug(
                "Host normalization recovery: error_type=%s", type(exc).__name__
            )
    if isinstance(host, dict):
        return dict(host)
    return {}


def ingest_hosts(
    hosts: dict[str, Any],
    *,
    group: str | None = None,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int]:
    """Map a HostManager inventory (``{alias: HostConfig|dict}``) → ``:Host`` nodes.

    Emits a ``:Host`` per alias (with hostname/user/port/identity/proxy fields), an
    optional ``:HostGroup`` (``:inGroup`` link), an ``:SshKey`` per distinct identity
    file (``:usesKey`` link), and a ``:proxiesThrough`` self-link stub is skipped
    (jump-host aliases are not resolvable from a proxy_command string). Returns the
    ``{"nodes":n, "edges":m}`` count or ``None``.
    """
    entities: list[dict[str, Any]] = []
    relationships: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    group_id = f"tunnel:group:{group}" if group else None
    if group_id:
        entities.append({"id": group_id, "node_type": "HostGroup", "name": group})

    for alias, raw in (hosts or {}).items():
        if not alias:
            continue
        h = _host_to_dict(raw)
        host_id = f"tunnel:host:{alias}"
        identity = h.get("identity_file") or h.get("key_path")
        entities.append(
            {
                "id": host_id,
                "node_type": "Host",
                "name": alias,
                "hostname": h.get("hostname"),
                "sshUser": h.get("user") or None,
                "sshPort": h.get("port"),
                "identityFile": identity,
                "proxyCommand": h.get("proxy_command"),
                "externalToolId": alias,
            }
        )
        if group_id:
            relationships.append(
                {"source": host_id, "target": group_id, "relationship": "inGroup"}
            )
        if identity:
            key_id = f"tunnel:sshkey:{identity}"
            if key_id not in seen_keys:
                seen_keys.add(key_id)
                entities.append(
                    {
                        "id": key_id,
                        "node_type": "SshKey",
                        "name": identity,
                        "path": identity,
                    }
                )
            relationships.append(
                {"source": host_id, "target": key_id, "relationship": "usesKey"}
            )

    return ingest_entities(entities, relationships, client=client, graph=graph)
