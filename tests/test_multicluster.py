"""멀티 클러스터 비교 도구 검증 — 두 k8s 상태를 나란히 읽는다."""

from __future__ import annotations

from src.tools.multicluster import COMPARE_RESOURCES, make_multicluster_tools


class FakeClient:
    def __init__(self, name):
        self.name = name

    def list_namespaces(self):
        return [{"name": f"ns-{self.name}"}]

    def list_deployments(self, ns):
        return [{"name": "bronze-ingestor", "replicas": 1, "ctx": self.name, "ns": ns}]

    def list_nodes(self):
        return [{"name": f"node-{self.name}"}]


def _tools(n=2):
    clients = {f"ctx-{i}": FakeClient(str(i)) for i in range(n)}
    return {t.name: t for t in make_multicluster_tools(clients)}, clients


def test_disabled_below_two_clusters():
    assert make_multicluster_tools({}) == []
    assert make_multicluster_tools({"only": FakeClient("x")}) == []


def test_three_tools_registered():
    tools, _ = _tools()
    assert set(tools) == {"k8s_list_contexts", "k8s_compare", "k8s_read_at"}


def test_compare_returns_side_by_side():
    tools, _ = _tools()
    r = tools["k8s_compare"].invoke({"resource": "deployments", "namespace": "nexus-lake"})
    assert set(r["by_context"]) == {"ctx-0", "ctx-1"}
    assert r["by_context"]["ctx-0"]["count"] == 1
    assert r["by_context"]["ctx-1"]["items"][0]["ctx"] == "1"


def test_compare_namespace_scoped_requires_namespace():
    tools, _ = _tools()
    r = tools["k8s_compare"].invoke({"resource": "pods"})  # namespace 누락
    assert "error" in r and "namespace" in r["error"]
    # 클러스터 스코프는 namespace 불필요
    r2 = tools["k8s_compare"].invoke({"resource": "namespaces"})
    assert set(r2["by_context"]) == {"ctx-0", "ctx-1"}


def test_read_at_targets_single_context():
    tools, _ = _tools()
    r = tools["k8s_read_at"].invoke({"context": "ctx-1", "resource": "nodes"})
    assert r["context"] == "ctx-1" and r["items"][0]["name"] == "node-1"
    bad = tools["k8s_read_at"].invoke({"context": "nope", "resource": "nodes"})
    assert "error" in bad


def test_invalid_resource_rejected_by_validator():
    tools, _ = _tools()
    r = tools["k8s_compare"].invoke({"resource": "secrets!!"})
    assert "거부됨" in str(r)  # verb_validator resource enum 검증


def test_read_only_verb_registered():
    from src.tools import verb_validator as vv
    _tools()  # 등록 트리거
    for name in ("k8s_list_contexts", "k8s_compare", "k8s_read_at"):
        spec = vv.registered_tools().get(name)
        assert spec is not None and spec.verb == "list"  # read-only


def test_resource_catalog_covers_core_kinds():
    for kind in ("pods", "deployments", "services", "nodes", "namespaces", "events", "pvcs"):
        assert kind in COMPARE_RESOURCES
