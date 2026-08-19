"""신규 k8s 분석·감사 도구 검증 — 등록·verb·인자 게이트·뷰 헬퍼(무클러스터).

실 클러스터 없이도 검증 가능한 것: 도구가 read-only verb(list/get)로 등록되는지,
대표 인자가 executor 게이트를 통과하는지, RBAC/NetworkPolicy 뷰 헬퍼가 값 유출 없이
요약만 뽑는지.
"""

from __future__ import annotations

from src.tools import verb_validator as vv
from src.tools.k8s_read import (
    _netpol_rules,
    _rbac_rule_summary,
    make_tools,
)


class WideStub:
    """모든 read 메서드를 빈 리스트/딕트로 응답하는 스텁."""

    def __getattr__(self, name):
        return lambda *a, **k: [] if name.startswith("list_") else {}


_NEW_TOOLS = {
    "k8s_list_endpoints": "list",
    "k8s_list_replicasets": "list",
    "k8s_list_hpas": "list",
    "k8s_list_pdbs": "list",
    "k8s_list_networkpolicies": "list",
    "k8s_list_serviceaccounts": "list",
    "k8s_list_role_bindings": "list",
    "k8s_list_cluster_role_bindings": "list",
    "k8s_get_role": "get",
    "k8s_list_pvs": "list",
    "k8s_list_resourcequotas": "list",
}


def test_new_tools_registered_readonly():
    make_tools(WideStub())
    for name, verb in _NEW_TOOLS.items():
        spec = vv.registered_tools().get(name)
        assert spec is not None, f"{name} 미등록"
        assert spec.verb == verb
        assert spec.verb in ("list", "get")  # mutating 아님


def test_cluster_role_bindings_bool_arg_validates():
    make_tools(WideStub())
    # include_system 이 _BOOL_ARGS 에 등록돼 fail-closed 거부되지 않아야 한다
    assert vv.validate_tool_call("k8s_list_cluster_role_bindings", {"include_system": False}).allowed
    assert vv.validate_tool_call("k8s_list_cluster_role_bindings", {"include_system": True}).allowed
    # 불리언 아닌 값은 거부
    assert not vv.validate_tool_call(
        "k8s_list_cluster_role_bindings", {"include_system": "yes"}).allowed


def test_get_role_name_namespace_validates():
    make_tools(WideStub())
    assert vv.validate_tool_call("k8s_get_role", {"name": "admin", "namespace": ""}).allowed
    assert vv.validate_tool_call("k8s_get_role", {"name": "edit", "namespace": "kube-system"}).allowed
    # 셸 메타문자 이름 거부
    assert not vv.validate_tool_call("k8s_get_role", {"name": "a;b"}).allowed


def test_tools_invoke_via_stub_return_empty():
    tools = {t.name: t for t in make_tools(WideStub())}
    r = tools["k8s_list_endpoints"].invoke({"namespace": "default"})
    assert r == [] or isinstance(r, list)
    r2 = tools["k8s_list_cluster_role_bindings"].invoke({"include_system": False})
    assert isinstance(r2, list)


def test_rbac_rule_summary_is_summary_only():
    class _Rule:
        def __init__(self):
            self.verbs = ["get", "list", "escalate"]
            self.resources = ["secrets"]
            self.api_groups = [""]
            self.resource_names = []

    out = _rbac_rule_summary([_Rule()])
    assert out[0]["verbs"] == ["get", "list", "escalate"]  # 위험 verb 는 '내용'으로만 보고
    assert out[0]["resources"] == ["secrets"]


def test_netpol_rules_caps_and_summarizes():
    class _Sel:
        match_labels = {"app": "b"}

    class _Peer:
        pod_selector = _Sel()
        namespace_selector = None
        ip_block = None

    class _Port:
        port = 8080
        protocol = "TCP"

    # NetworkPolicy 규칙의 피어 필드명은 'from'(예약어)이라 setattr 로 붙인다.
    rule = type("Rule", (), {})()
    setattr(rule, "from", [_Peer()])
    rule.ports = [_Port()]
    out = _netpol_rules([rule], "from")
    assert out[0]["peers"][0]["pod_selector"] == {"app": "b"}
    assert out[0]["peer_count"] == 1
    assert out[0]["ports"][0] == {"port": "8080", "protocol": "TCP"}
