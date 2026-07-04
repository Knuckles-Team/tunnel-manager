"""Native epistemic-graph ingestion for tunnel-manager records (typed graph nodes).

CONCEPT:AU-KG.ingest.enterprise-source-extractor. The connector natively pushes its
SSH host inventory into the ONE epistemic-graph knowledge graph as **typed OWL nodes**
(`:Host`, `:HostGroup`, `:SshKey`) plus their links (`:inGroup`, `:usesKey`,
`:proxiesThrough`), matching the classes federated by ``tunnel_manager.ontology``.

Everything is best-effort and dependency-/engine-guarded: with no agent-utilities KG
stack or no reachable engine, every entry point **no-ops** (returns ``None``), so the
connector keeps working with zero KG infrastructure. Writes ride the lightweight engine
client (``GraphComputeEngine()._client`` + ``txn``) — the same fast client the blob
``MediaStore`` uses, NOT the heavy in-process ingestion engine. This module is a thin
mapper: it delegates the txn write path to the shared primitive
``agent_utilities.knowledge_graph.memory.native_ingest`` when present, and falls back to
a self-contained txn otherwise (the primitive is not yet in the installed
agent_utilities). Node ids follow ``tunnel:<class>:<externalId>``.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("tunnel_manager.kg")

_SOURCE = "tunnel-manager"
_DOMAIN = "tunnel"
_DEFAULT_GRAPH = "__commons__"


def _client() -> tuple[Any | None, str]:
    """Return ``(engine_client, graph_name)`` or ``(None, "")`` when unavailable."""
    try:
        from agent_utilities.knowledge_graph.core.graph_compute import (
            GraphComputeEngine,
        )
    except Exception as e:  # noqa: BLE001 — KG stack absent
        logger.debug("KG ingest unavailable (import): %s", e)
        return None, ""
    try:
        engine = GraphComputeEngine()
        client = getattr(engine, "_client", None)
        if client is None:
            return None, ""
        return client, (getattr(engine, "graph_name", None) or _DEFAULT_GRAPH)
    except Exception as e:  # noqa: BLE001 — engine unreachable
        logger.debug("KG ingest: engine unreachable: %s", e)
        return None, ""


def _fallback_write_nodes(
    client: Any,
    graph: str,
    nodes: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None,
) -> dict[str, int] | None:
    """Self-contained txn write (used when the shared primitive is absent)."""
    nodes = [n for n in nodes if n.get("id")]
    if not nodes:
        return None
    try:
        txn = client.txn.begin(graph=graph)
        for node in nodes:
            props = {k: v for k, v in node.items() if k != "id" and v is not None}
            props.setdefault("source", _SOURCE)
            props.setdefault("domain", _DOMAIN)
            client.txn.add_node(txn, node["id"], props)
        committed = client.txn.commit(txn)
    except Exception as e:  # noqa: BLE001 — engine/txn failure is non-fatal
        logger.warning("KG ingest: txn failed: %s", e)
        return None
    if not committed:
        logger.warning("KG ingest: txn not committed (conflict)")
        return None

    edges = 0
    for rel in relationships or []:
        try:
            client.edges.add(
                rel["source"], rel["target"], {"type": rel.get("type", "RELATED")}
            )
            edges += 1
        except Exception as e:  # noqa: BLE001 — pure edge link, best-effort
            logger.debug("KG ingest: edge skipped: %s", e)

    logger.info("KG ingest: wrote %d nodes, %d edges", len(nodes), edges)
    return {"nodes": len(nodes), "edges": edges}


def ingest_entities(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
    *,
    source: str = _SOURCE,
    domain: str = _DOMAIN,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int] | None:
    """Write typed OWL nodes (+ edges) into epistemic-graph.

    ``entities``: ``[{"id":..., "type":<owl:Class>, ...props}]``.
    ``relationships``: ``[{"source":id, "target":id, "type":<link>}]``.
    Returns ``{"nodes":n, "edges":m}`` or ``None`` (no engine / failure; never raises).
    Delegates to the shared ``native_ingest`` primitive when available; otherwise uses
    a self-contained txn fallback. ``client``/``graph`` may be injected (tests).
    """
    entities = [e for e in (entities or []) if e.get("id")]
    if not entities:
        return None
    # Prefer the shared primitive (single implementation of the txn write path).
    if client is None:
        try:
            from agent_utilities.knowledge_graph.memory.native_ingest import (
                ingest_entities as _shared,
            )

            return _shared(
                entities,
                relationships,
                source=source,
                domain=domain,
                graph=graph,
            )
        except Exception as e:  # noqa: BLE001 — primitive absent; use fallback
            logger.debug("KG ingest: shared primitive unavailable: %s", e)
        client, graph = _client()
    if client is None:
        return None
    return _fallback_write_nodes(
        client, graph or _DEFAULT_GRAPH, entities, relationships
    )


def ingest_documents(
    documents: list[dict[str, Any]],
    *,
    source: str = _SOURCE,
    domain: str = _DOMAIN,
    client: Any | None = None,
    graph: str | None = None,
) -> dict[str, int] | None:
    """Write text records as ``:Document`` nodes (semantic-search fodder).

    Each doc: ``{"id":..., "text":..., "title"?:..., "source_uri"?:..., ...props}``.
    Delegates to the shared primitive when available; otherwise a thin fallback that
    tags the nodes as ``:Document`` and writes them via the self-contained txn.
    """
    documents = [d for d in (documents or []) if d.get("id")]
    if not documents:
        return None
    if client is None:
        try:
            from agent_utilities.knowledge_graph.memory.native_ingest import (
                ingest_documents as _shared,
            )

            return _shared(documents, source=source, domain=domain, graph=graph)
        except Exception as e:  # noqa: BLE001 — primitive absent; use fallback
            logger.debug("KG ingest: shared primitive unavailable: %s", e)
        client, graph = _client()
    if client is None:
        return None
    nodes: list[dict[str, Any]] = []
    for doc in documents:
        text = doc.get("text") or doc.get("content")
        if not text:
            continue
        node = {k: v for k, v in doc.items() if k != "content" and v is not None}
        node["type"] = "Document"
        node["text"] = text
        nodes.append(node)
    return _fallback_write_nodes(client, graph or _DEFAULT_GRAPH, nodes, None)


def _host_to_dict(host: Any) -> dict[str, Any]:
    """Normalize a HostConfig / mapping into a plain dict of host fields."""
    if hasattr(host, "model_dump"):
        try:
            return host.model_dump(exclude_unset=False)
        except Exception:  # noqa: BLE001
            pass
    if isinstance(host, dict):
        return dict(host)
    return {}


def ingest_hosts(
    hosts: dict[str, Any],
    *,
    group: str | None = None,
    client: Any | None = None,
    graph: str | None = None,
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
        entities.append({"id": group_id, "type": "HostGroup", "name": group})

    for alias, raw in (hosts or {}).items():
        if not alias:
            continue
        h = _host_to_dict(raw)
        host_id = f"tunnel:host:{alias}"
        identity = h.get("identity_file") or h.get("key_path")
        entities.append(
            {
                "id": host_id,
                "type": "Host",
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
                {"source": host_id, "target": group_id, "type": "inGroup"}
            )
        if identity:
            key_id = f"tunnel:sshkey:{identity}"
            if key_id not in seen_keys:
                seen_keys.add(key_id)
                entities.append(
                    {"id": key_id, "type": "SshKey", "name": identity, "path": identity}
                )
            relationships.append(
                {"source": host_id, "target": key_id, "type": "usesKey"}
            )

    return ingest_entities(entities, relationships, client=client, graph=graph)
