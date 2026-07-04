"""Native epistemic-graph typed-node ingestion — Wire-First coverage.

Exercises the real ``ingest_entities`` / ``ingest_documents`` / ``ingest_hosts`` seam
with a fake engine client (no engine required), asserting the txn add_node/commit +
edge calls and the HostManager inventory → :Host/:HostGroup/:SshKey mapping.
CONCEPT:AU-KG.ingest.enterprise-source-extractor.
"""

from __future__ import annotations

from tunnel_manager.kg_ingest import (
    ingest_documents,
    ingest_entities,
    ingest_hosts,
)


class _FakeTxn:
    def __init__(self):
        self.nodes = {}
        self.committed = False
        self.graph = None

    def begin(self, graph=None):
        self.graph = graph
        return "txn-1"

    def add_node(self, txn, node_id, props):
        self.nodes[node_id] = props

    def commit(self, txn):
        self.committed = True
        return True


class _FakeEdges:
    def __init__(self):
        self.edges = []

    def add(self, src, dst, props):
        self.edges.append((src, dst, props))


class _FakeClient:
    def __init__(self):
        self.txn = _FakeTxn()
        self.edges = _FakeEdges()


def test_ingest_entities_writes_nodes_and_edges():
    c = _FakeClient()
    res = ingest_entities(
        [
            {"id": "a", "type": "Host", "name": "box"},
            {"id": "g", "type": "HostGroup"},
        ],
        [{"source": "a", "target": "g", "type": "inGroup"}],
        client=c,
        graph="__commons__",
    )
    assert res == {"nodes": 2, "edges": 1}
    assert c.txn.committed is True
    assert set(c.txn.nodes) == {"a", "g"}
    # provenance is stamped
    assert c.txn.nodes["a"]["source"] == "tunnel-manager"
    assert c.txn.nodes["a"]["domain"] == "tunnel"
    assert c.edges.edges == [("a", "g", {"type": "inGroup"})]


def test_ingest_hosts_maps_host_group_and_key():
    c = _FakeClient()
    res = ingest_hosts(
        {
            "rw710": {
                "hostname": "10.0.0.14",
                "user": "genius",
                "port": 22,
                "identity_file": "~/.ssh/id_shared",
            }
        },
        group="homelab",
        client=c,
        graph="__commons__",
    )
    # 3 nodes: group + host + key; 2 edges: inGroup + usesKey
    assert res == {"nodes": 3, "edges": 2}
    host = c.txn.nodes["tunnel:host:rw710"]
    assert host["type"] == "Host"
    assert host["hostname"] == "10.0.0.14"
    assert host["sshUser"] == "genius"
    assert host["sshPort"] == 22
    assert host["identityFile"] == "~/.ssh/id_shared"
    assert host["externalToolId"] == "rw710"
    assert c.txn.nodes["tunnel:group:homelab"]["type"] == "HostGroup"
    assert c.txn.nodes["tunnel:sshkey:~/.ssh/id_shared"]["type"] == "SshKey"
    assert ("tunnel:host:rw710", "tunnel:group:homelab", {"type": "inGroup"}) in (
        c.edges.edges
    )
    assert (
        "tunnel:host:rw710",
        "tunnel:sshkey:~/.ssh/id_shared",
        {"type": "usesKey"},
    ) in c.edges.edges


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
    assert c.txn.nodes["d1"]["type"] == "Document"
    assert c.txn.nodes["d1"]["text"] == "audit report"


def test_ingest_noops_without_engine():
    # No injected client + no reachable engine -> clean no-op.
    assert ingest_entities([{"id": "a", "type": "Host"}]) is None


def test_ingest_empty_is_noop():
    assert ingest_entities([], client=_FakeClient()) is None
    assert ingest_hosts({}, client=_FakeClient()) is None
    assert ingest_documents([], client=_FakeClient()) is None
