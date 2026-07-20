"""Native epistemic-graph typed-node ingestion — Wire-First coverage.

Exercises the real ``ingest_entities`` / ``ingest_documents`` / ``ingest_hosts`` seam
with a fake engine client (no engine required), asserting the txn add_node/commit +
edge calls and the HostManager inventory → :Host/:HostGroup/:SshKey mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

import pytest
from agent_utilities.knowledge_graph.memory.native_ingest import NativeIngestError

from tunnel_manager.kg_ingest import (
    ingest_documents,
    ingest_entities,
    ingest_hosts,
)


class _FakeTxn:
    def __init__(self):
        self.nodes = {}
        self.edges = []
        self.committed = False
        self.graph = None

    def begin(self, graph=None):
        self.graph = graph
        return "txn-1"

    def add_node(self, txn, node_id, props):
        self.nodes[node_id] = props

    def add_edge(self, txn, source, target, props):
        self.edges.append((source, target, props))

    def commit(self, txn):
        self.committed = True
        return True


class _FakeClient:
    def __init__(self):
        self.txn = _FakeTxn()


def test_ingest_entities_writes_nodes_and_edges():
    c = _FakeClient()
    res = ingest_entities(
        [
            {"id": "a", "node_type": "Host", "name": "box"},
            {"id": "g", "node_type": "HostGroup"},
        ],
        [{"source": "a", "target": "g", "relationship": "inGroup"}],
        client=c,
        graph="__commons__",
    )
    assert res == {"nodes": 2, "edges": 1}
    assert c.txn.committed is True
    assert set(c.txn.nodes) == {"a", "g"}
    # provenance is stamped
    assert c.txn.nodes["a"]["source"] == "tunnel-manager"
    assert c.txn.nodes["a"]["domain"] == "tunnel"
    assert c.txn.edges == [("a", "g", {"relationship": "inGroup"})]


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
        graph="__commons__",
    )
    # 3 nodes: group + host + key; 2 edges: inGroup + usesKey
    assert res == {"nodes": 3, "edges": 2}
    host = c.txn.nodes["tunnel:host:app-node"]
    assert host["node_type"] == "Host"
    assert host["hostname"] == "192.0.2.14"
    assert host["sshUser"] == "operator"
    assert host["sshPort"] == 22
    assert host["identityFile"] == "~/.ssh/id_shared"
    assert host["externalToolId"] == "app-node"
    assert c.txn.nodes["tunnel:group:example-fleet"]["node_type"] == "HostGroup"
    assert c.txn.nodes["tunnel:sshkey:~/.ssh/id_shared"]["node_type"] == "SshKey"
    assert (
        "tunnel:host:app-node",
        "tunnel:group:example-fleet",
        {"relationship": "inGroup"},
    ) in (
        c.txn.edges
    )
    assert (
        "tunnel:host:app-node",
        "tunnel:sshkey:~/.ssh/id_shared",
        {"relationship": "usesKey"},
    ) in c.txn.edges


def test_ingest_hosts_dedups_shared_key():
    c = _FakeClient()
    res = ingest_hosts(
        {
            "a": {"hostname": "h1", "user": "u", "identity_file": "/k"},
            "b": {"hostname": "h2", "user": "u", "identity_file": "/k"},
        },
        group="g",
        client=c,
        graph="__commons__",
    )
    # group + 2 hosts + 1 shared key = 4 nodes; 2 inGroup + 2 usesKey = 4 edges
    assert res == {"nodes": 4, "edges": 4}
    assert "tunnel:sshkey:/k" in c.txn.nodes


def test_ingest_hosts_accepts_model_dump_objects():
    class _HC:
        def model_dump(self, exclude_unset=False):
            return {"hostname": "h", "user": "u", "port": 2222}

    c = _FakeClient()
    res = ingest_hosts({"x": _HC()}, client=c, graph="__commons__")
    assert res == {"nodes": 1, "edges": 0}
    assert c.txn.nodes["tunnel:host:x"]["sshPort"] == 2222


def test_ingest_documents_tags_document_type():
    c = _FakeClient()
    res = ingest_documents(
        [{"id": "d1", "text": "audit report", "title": "CIS scan"}],
        client=c,
        graph="__commons__",
    )
    assert res == {"nodes": 1, "edges": 0}
    assert c.txn.nodes["d1"]["node_type"] == "Document"
    assert c.txn.nodes["d1"]["text"] == "audit report"


def test_retired_structural_alias_is_rejected():
    with pytest.raises(NativeIngestError, match="canonical node_type"):
        ingest_entities([{"id": "a", "type": "Host"}], client=_FakeClient())


def test_empty_native_ingest_is_rejected():
    with pytest.raises(NativeIngestError, match="at least one entity"):
        ingest_entities([], client=_FakeClient())
