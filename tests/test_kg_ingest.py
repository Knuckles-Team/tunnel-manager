"""Native epistemic-graph typed-node ingestion — Wire-First coverage.

Exercises the real ``ingest_entities`` / ``ingest_documents`` / ``ingest_hosts`` seam
with a fake engine client (no engine required), asserting the txn add_node/commit +
edge calls and the HostManager inventory → :Host/:HostGroup/:SshKey mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

from typing import Any

import msgpack
import pytest
from agent_utilities.knowledge_graph.memory.native_ingest import NativeIngestError
from agent_utilities.security.brain_context import ActorContext, use_actor
from agent_utilities.models.company_brain import ActorType
from agent_utilities.knowledge_graph.core.session import GraphSession, use_session

from tunnel_manager.kg_ingest import (
    ingest_documents,
    ingest_entities,
    ingest_hosts,
)


@pytest.fixture(autouse=True)
def _governed_session():
    actor = ActorContext(
        actor_id="subject:opaque:synthetic",
        actor_type=ActorType.AUTOMATED_SERVICE,
        roles=(),
        tenant_id="tenant:opaque:synthetic",
        authenticated=True,
    )
    session = GraphSession(
        actor=actor,
        tenant=actor.tenant_id,
        scopes=frozenset({"kg:write"}),
        graph="graph:opaque:synthetic",
        policy_version="policy:opaque:synthetic",
        audience="epistemic-graph",
    )
    with use_actor(actor), use_session(session):
        yield


class _FakeNodes:
    def __init__(self) -> None:
        self.values: dict[str, dict[str, Any]] = {}

    def properties(self, node_id: str) -> dict[str, Any] | None:
        return self.values.get(node_id)

    def list(self) -> list[tuple[str, dict[str, Any]]]:
        return list(self.values.items())


class _FakeChanges:
    def __init__(self, nodes: _FakeNodes) -> None:
        self.nodes = nodes
        self.edges: list[tuple[str, str, dict[str, Any]]] = []
        self.applied: list[dict[str, Any]] = []
        self.records: dict[str, dict[str, Any]] = {}
        self.versions: dict[str, dict[str, Any]] = {}

    def get(self, envelope_id: str) -> dict[str, Any] | None:
        return self.records.get(envelope_id)

    def content_version(self, object_id: str) -> dict[str, Any] | None:
        return self.versions.get(object_id)

    def cursor(self, _source: str, _partition: str = "") -> None:
        return None

    def apply(self, envelope: dict[str, Any]) -> dict[str, Any]:
        self.applied.append(envelope)
        mutation = envelope["mutation"]
        for operation in mutation["operations"]:
            method = operation["method"]
            params = method["params"]
            properties = msgpack.unpackb(params["properties_msgpack"], raw=False)
            if method["method"] == "AddNode":
                self.nodes.values[params["node_id"]] = properties
            elif method["method"] == "AddEdge":
                self.edges.append(
                    (params["source_id"], params["target_id"], properties)
                )
        version = envelope["content_version"]
        self.versions[version["object_id"]] = version
        self.records[envelope["envelope_id"]] = envelope
        return {
            "batch_id": mutation["batch_id"],
            "replayed": False,
            "projection_pending": False,
        }


class _FakeRdf:
    def validate_shacl(self, _shapes: str, _data_graph: str) -> dict[str, Any]:
        return {"conforms": True, "results": []}


class _FakeClient:
    def __init__(self) -> None:
        self.nodes = _FakeNodes()
        self.changes = _FakeChanges(self.nodes)
        self.rdf = _FakeRdf()

    @staticmethod
    def supports(operation: str) -> bool:
        return operation == "ApplyChangeEnvelope"


def test_ingest_entities_writes_nodes_and_edges():
    c = _FakeClient()
    res = ingest_entities(
        [
            {"id": "a", "node_type": "Host", "name": "box"},
            {"id": "g", "node_type": "HostGroup"},
        ],
        [{"source": "a", "target": "g", "relationship": "inGroup"}],
        client=c,
    )
    assert res == {"nodes": 2, "edges": 1}
    assert len(c.changes.applied) == 1
    assert set(c.nodes.values) == {"a", "g"}
    # provenance is stamped
    assert c.nodes.values["a"]["source"] == "tunnel-manager"
    assert c.nodes.values["a"]["domain"] == "tunnel"
    assert c.changes.edges == [("a", "g", {"relationship": "inGroup"})]


def test_ingest_hosts_maps_host_group_and_key():
    c = _FakeClient()
    res = ingest_hosts(
        {
            "app-node": {
                "hostname": "192.0.2.14",
                "user": "operator",
                "port": 22,
                "identity_file": "~/.ssh/id_shared",
            }
        },
        group="example-fleet",
        client=c,
    )
    # 3 nodes: group + host + key; 2 edges: inGroup + usesKey
    assert res == {"nodes": 3, "edges": 2}
    host = c.nodes.values["tunnel:host:app-node"]
    assert host["node_type"] == "Host"
    # native_ingest's governed PII scrubber redacts IP-shaped values.
    assert host["hostname"] == "[REDACTED_LOCATION]"
    assert host["sshUser"] == "operator"
    assert host["sshPort"] == 22
    assert host["identityFile"] == "~/.ssh/id_shared"
    assert host["externalToolId"] == "app-node"
    assert c.nodes.values["tunnel:group:example-fleet"]["node_type"] == "HostGroup"
    assert c.nodes.values["tunnel:sshkey:~/.ssh/id_shared"]["node_type"] == "SshKey"
    assert (
        "tunnel:host:app-node",
        "tunnel:group:example-fleet",
        {"relationship": "inGroup"},
    ) in (c.changes.edges)
    assert (
        "tunnel:host:app-node",
        "tunnel:sshkey:~/.ssh/id_shared",
        {"relationship": "usesKey"},
    ) in c.changes.edges


def test_ingest_hosts_dedups_shared_key():
    c = _FakeClient()
    res = ingest_hosts(
        {
            "a": {"hostname": "h1", "user": "u", "identity_file": "/k"},
            "b": {"hostname": "h2", "user": "u", "identity_file": "/k"},
        },
        group="g",
        client=c,
    )
    # group + 2 hosts + 1 shared key = 4 nodes; 2 inGroup + 2 usesKey = 4 edges
    assert res == {"nodes": 4, "edges": 4}
    assert "tunnel:sshkey:/k" in c.nodes.values


def test_ingest_hosts_accepts_model_dump_objects():
    class _HC:
        def model_dump(self, exclude_unset=False):
            return {"hostname": "h", "user": "u", "port": 2222}

    c = _FakeClient()
    res = ingest_hosts({"x": _HC()}, client=c)
    assert res == {"nodes": 1, "edges": 0}
    assert c.nodes.values["tunnel:host:x"]["sshPort"] == 2222


def test_ingest_documents_tags_document_type():
    c = _FakeClient()
    res = ingest_documents(
        [{"id": "d1", "text": "audit report", "title": "CIS scan"}],
        client=c,
    )
    assert res == {"nodes": 1, "edges": 0}
    assert c.nodes.values["d1"]["node_type"] == "Document"
    assert c.nodes.values["d1"]["text"] == "audit report"


def test_retired_structural_alias_is_rejected():
    with pytest.raises(NativeIngestError, match="canonical node_type"):
        ingest_entities([{"id": "a", "type": "Host"}], client=_FakeClient())


def test_empty_native_ingest_is_rejected():
    with pytest.raises(NativeIngestError, match="at least one entity"):
        ingest_entities([], client=_FakeClient())
