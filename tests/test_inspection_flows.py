"""6-4 정상 조사 시나리오 — 4.1의 시드 픽스처(admin 샌드박스)에 대한 실측.

샌드박스가 없으면 skip되지만, 공식 검증 절차(README §6)에서는 반드시
KUBECONFIG=.local/kind-kubeconfig.yaml 로 전체 실행한다.
"""

from __future__ import annotations

import pytest
from kubernetes.client import ApiException
from langchain_core.messages import AIMessage, HumanMessage

from src.graph import build_graph
from src.llm import ScriptedChatModel
from tests.conftest import ai_tool_call


def test_find_crashloop_pod(k8s_client):
    pods = k8s_client.list_pods("default")
    crash = next(p for p in pods if p["name"] == "crashloop-demo")
    container = crash["containers"][0]
    waiting = container["state"].get("waiting")
    assert container["restart_count"] >= 1 or waiting == "CrashLoopBackOff"


def test_find_imagepull_error_pod(k8s_client):
    pods = k8s_client.list_pods("default")
    pod = next(p for p in pods if p["name"] == "imagepull-demo")
    waiting = pod["containers"][0]["state"].get("waiting")
    assert waiting in ("ErrImagePull", "ImagePullBackOff")


def test_pod_logs_contain_fixture_marker(k8s_client):
    logs = k8s_client.get_pod_logs("default", "crashloop-demo", tail_lines=100)
    assert "boom-marker" in logs


def test_resource_requests_of_high_resource_pod(k8s_client):
    pod = k8s_client.get_pod("default", "high-resource-demo")
    requests = pod["containers"][0]["resources"]["requests"]
    assert requests.get("cpu") == "500m"
    assert requests.get("memory") == "256Mi"


def test_healthy_deployment_and_rollout_history(k8s_client):
    dep = k8s_client.get_deployment("default", "healthy-web")
    assert dep["replicas"]["desired"] == 2
    assert dep["replicas"]["ready"] == 2
    history = k8s_client.rollout_history("default", "healthy-web")
    assert history and history[0]["revision"] >= 1
    assert any("nginx" in img for img in history[0]["images"])


def test_service_and_endpoints(k8s_client):
    svc = k8s_client.get_service("default", "healthy-web")
    assert svc["ports"][0]["port"] == 80
    assert all(t["target"] is None or "Pod/" in t["target"] for t in svc["endpoints"])


def test_events_for_imagepull_failure(k8s_client):
    events = k8s_client.list_events("default", field_selector="involvedObject.name=imagepull-demo")
    reasons = {e["reason"] for e in events}
    assert reasons & {"Failed", "BackOff", "ErrImagePull"}, f"이미지 풀 실패 이벤트 없음: {reasons}"


def test_top_pods_if_metrics_available(k8s_client):
    try:
        rows = k8s_client.top_pods("default")
    except ApiException as exc:
        if exc.status in (403, 404, 503):
            pytest.skip("metrics-server 미설치 (RBAC 미생성 원칙에 따라 샌드박스에 설치하지 않음)")
        raise
    assert isinstance(rows, list)


def test_agent_flow_finds_crashloop_and_writes_wiki(k8s_client, wiki_dir, audit):
    """그래프 전체 경로: 위키읽기 → 플래너 → 검증/실행 → 포매터 → 위키쓰기."""
    model = ScriptedChatModel(
        script=[
            ai_tool_call("k8s_list_pods", {"namespace": "default"}),
            AIMessage(
                content="결론: default 네임스페이스에서 crashloop-demo 파드가 "
                "CrashLoopBackOff(재시작 반복) 상태입니다."
            ),
        ]
    )
    graph = build_graph(model=model, k8s=k8s_client, wiki_dir=wiki_dir, audit=audit)
    question = "default 네임스페이스에서 CrashLoopBackOff 상태인 파드 찾아줘"
    result = graph.invoke(
        {"question": question, "session_id": "e2e-1", "messages": [HumanMessage(question)]},
        config={"recursion_limit": 30},
    )
    assert "crashloop-demo" in result["final_answer"]
    allowed = [e for e in audit.entries() if e["allowed"] and e["tool"] == "k8s_list_pods"]
    assert allowed, "audit 로그에 허용된 list_pods 기록이 없습니다"
    assert (wiki_dir / "workloads" / "crashloop-demo.md").exists()
    assert (wiki_dir / "namespaces" / "default.md").exists()
