"""Native epistemic-graph ingestion for governed SSH inventory metadata.

All writes go through the ``agent_connector_sdk.ingest`` knowledge-ingest facade
(the generated EG client). Nodes use canonical ``node_type`` and edges use
canonical ``relationship``; nodes and edges commit in one submission. Missing
engine dependencies, rejected records, and conflicts propagate as ``IngestError``.
"""

from __future__ import annotations

import logging
from typing import Any

from agent_connector_sdk.ingest import (
    ChangeSet,
    Document,
    Entity,
    IngestBinding,
    IngestError,
    KnowledgeIngest,
    Relationship,
    current_ingest,
)

logger = logging.getLogger("tunnel_manager.kg")

_SOURCE = "tunnel-manager"
_DOMAIN = "tunnel"
_BINDING = IngestBinding(connector="tunnel-manager", stream=_DOMAIN)


def _to_entity(record: dict[str, Any]) -> Entity:
    return Entity(
        id=record.get("id"),
        node_type=record.get("node_type"),
        properties={
            k: v for k, v in record.items() if k not in ("id", "node_type")
        },
    )


def _to_relationship(record: dict[str, Any]) -> Relationship:
    props = {
        k: v
        for k, v in record.items()
        if k not in ("source", "target", "relationship")
    }
    return Relationship(
        source=record["source"],
        target=record["target"],
        relationship=record["relationship"],
        properties=props or None,
    )


def _to_document(record: dict[str, Any]) -> Document:
    return Document(
        id=record.get("id"),
        text=record.get("text", ""),
        title=record.get("title"),
        properties={
            k: v for k, v in record.items() if k not in ("id", "text", "title")
        },
    )


async def ingest_entities(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
    *,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int]:
    """Write canonical typed nodes and relationships in one submission."""
    if not entities:
        raise IngestError("ingest_entities needs at least one entity")
    change_set = ChangeSet(
        entities=tuple(_to_entity(e) for e in entities),
        relationships=tuple(_to_relationship(r) for r in relationships or ()),
    )
    service = ingest or current_ingest()
    receipt = await service.submit(_BINDING, change_set)
    return {"nodes": receipt.affected_count, "edges": receipt.relationship_count}


async def ingest_documents(
    documents: list[dict[str, Any]],
    *,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int]:
    """Write text records as canonical Document nodes."""
    if not documents:
        raise IngestError("ingest_documents needs at least one document")
    change_set = ChangeSet(documents=tuple(_to_document(d) for d in documents))
    service = ingest or current_ingest()
    receipt = await service.submit(_BINDING, change_set)
    return {"nodes": receipt.affected_count, "edges": receipt.relationship_count}


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


async def ingest_hosts(
    hosts: dict[str, Any],
    *,
    group: str | None = None,
    ingest: KnowledgeIngest | None = None,
) -> dict[str, int] | None:
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

    if not entities:
        return None
    return await ingest_entities(entities, relationships, ingest=ingest)
