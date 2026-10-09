"""Native epistemic-graph typed-node ingestion — Wire-First coverage.

Exercises the real ``ingest_entities`` / ``ingest_documents`` / ``ingest_hosts`` seam
with a fake transport one level below ``agent_connector_sdk.ingest.KnowledgeIngest``
(no engine required), so the SDK's own request-building/validation/privacy-guard
contract runs unfaked, asserting the HostManager inventory →
:Host/:HostGroup/:SshKey mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from agent_connector_sdk.ingest import IngestError, KnowledgeIngest

from tunnel_manager.kg_ingest import (
    ingest_documents,
    ingest_entities,
    ingest_hosts,
)
from tunnel_manager.models import HostConfig


class _FakeTransport:
    def __init__(self) -> None:
        self.requests: list[Any] = []

    async def source_status(self, connector: str, stream: str):
        return SimpleNamespace(accepted_checkpoint=None)

    async def submit(self, request):
        self.requests.append(request)
        return SimpleNamespace(
            affected_count=len(request.records),
            relationship_count=len(request.relationships),
        )

    async def store_blob(self, data: bytes) -> str:
        raise AssertionError("this connector's node/edge ingestion carries no media")


@pytest.fixture
def ingest():
    transport = _FakeTransport()
    return KnowledgeIngest(transport, loop=None), transport


def _by_id(request):
    return {record.record_id: record for record in request.records}


async def test_ingest_entities_writes_nodes_and_edges(ingest):
    service, transport = ingest
    res = await ingest_entities(
        [
            {"id": "a", "node_type": "Host", "name": "box"},
            {"id": "g", "node_type": "HostGroup"},
        ],
        [{"source": "a", "target": "g", "relationship": "inGroup"}],
        ingest=service,
    )
    assert res == {"nodes": 2, "edges": 1}
    request = transport.requests[0]
    assert set(_by_id(request)) == {"a", "g"}
    assert len(request.relationships) == 1


async def test_ingest_hosts_maps_host_group_and_key(ingest):
    service, transport = ingest
    res = await ingest_hosts(
        {
            "app-node": {
                "hostname": "192.0.2.14",
                "user": "operator",
                "port": 22,
                "identity_file": "~/.ssh/id_shared",
            }
        },
        group="example-fleet",
        ingest=service,
    )
    # 3 nodes: group + host + key; 2 edges: inGroup + usesKey
    assert res == {"nodes": 3, "edges": 2}
    request = transport.requests[0]
    by_id = _by_id(request)
    host = by_id["tunnel:host:app-node"]
    assert host.mapping_reference.endswith("/Host")
    # the SDK's PersistencePrivacyGuard redacts IP-shaped values.
    assert host.payload["hostname"] == "[REDACTED_LOCATION]"
    assert host.payload["sshUser"] == "operator"
    assert host.payload["sshPort"] == 22
    assert host.payload["identityFile"] == "~/.ssh/id_shared"
    assert host.payload["externalToolId"] == "app-node"
    assert by_id["tunnel:group:example-fleet"].mapping_reference.endswith("/HostGroup")
    assert by_id["tunnel:sshkey:~/.ssh/id_shared"].mapping_reference.endswith("/SshKey")
    edge_types = {
        (rel.source.record_id, rel.target.record_id, rel.relation_reference.rsplit("/relations/", 1)[-1])
        for rel in request.relationships
    }
    assert ("tunnel:host:app-node", "tunnel:group:example-fleet", "inGroup") in edge_types
    assert ("tunnel:host:app-node", "tunnel:sshkey:~/.ssh/id_shared", "usesKey") in edge_types


async def test_ingest_hosts_dedups_shared_key(ingest):
    service, transport = ingest
    res = await ingest_hosts(
        {
            "a": {"hostname": "h1", "user": "u", "identity_file": "/k"},
            "b": {"hostname": "h2", "user": "u", "identity_file": "/k"},
        },
        group="g",
        ingest=service,
    )
    # group + 2 hosts + 1 shared key = 4 nodes; 2 inGroup + 2 usesKey = 4 edges
    assert res == {"nodes": 4, "edges": 4}
    assert "tunnel:sshkey:/k" in _by_id(transport.requests[0])


async def test_ingest_hosts_accepts_host_config_model_dump(ingest):
    service, transport = ingest
    res = await ingest_hosts(
        {"x": HostConfig(hostname="h", user="u", port=2222)}, ingest=service
    )
    assert res == {"nodes": 1, "edges": 0}
    assert _by_id(transport.requests[0])["tunnel:host:x"].payload["sshPort"] == 2222


async def test_ingest_hosts_empty_is_a_noop(ingest):
    service, _ = ingest
    assert await ingest_hosts({}, ingest=service) is None


async def test_ingest_documents_tags_document_type(ingest):
    service, transport = ingest
    res = await ingest_documents(
        [{"id": "d1", "text": "audit report", "title": "CIS scan"}],
        ingest=service,
    )
    assert res == {"nodes": 1, "edges": 0}
    record = _by_id(transport.requests[0])["d1"]
    assert record.mapping_reference.endswith("/Document")
    assert record.payload["text"] == "audit report"


async def test_retired_structural_alias_is_rejected(ingest):
    service, _ = ingest
    with pytest.raises(IngestError, match="node_type"):
        await ingest_entities([{"id": "a", "type": "Host"}], ingest=service)


async def test_empty_native_ingest_is_rejected(ingest):
    service, _ = ingest
    with pytest.raises(IngestError, match="at least one entity"):
        await ingest_entities([], ingest=service)
