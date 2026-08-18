"""공용 픽스처.

전역 스파이(6-3): 테스트 스위트 전체에서 kubernetes ApiClient가 내보내는 모든 HTTP 요청을
기록하고, 세션 종료 시 GET 이외의 메서드가 단 한 번이라도 있었으면 실패 처리한다.
admin 권한 샌드박스를 대상으로 실행해도 쓰기 요청이 0건임을 실증하는 장치다.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from src.audit import AuditLogger

PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: (HTTP method, url) — 스위트 전체에서 실제로 나간 모든 K8s API 요청
RECORDED_REQUESTS: list[tuple[str, str]] = []


@pytest.fixture(autouse=True, scope="session")
def k8s_request_spy():
    """모든 테스트를 감싸는 런타임 인터셉션 스파이 (브리프 6-3)."""
    from kubernetes.client import ApiClient

    original = ApiClient.request

    def spy(self, method, url, *args, **kwargs):
        RECORDED_REQUESTS.append((str(method).upper(), str(url)))
        return original(self, method, url, *args, **kwargs)

    ApiClient.request = spy
    try:
        yield RECORDED_REQUESTS
    finally:
        ApiClient.request = original
        non_get = [r for r in RECORDED_REQUESTS if r[0] != "GET"]
        assert not non_get, (
            "화이트리스트 밖 HTTP 메서드가 클러스터로 전송되었습니다 (read-only 위반): "
            f"{non_get}"
        )


def sandbox_kubeconfig() -> str | None:
    path = os.environ.get("KUBECONFIG")
    if path and Path(path).expanduser().exists():
        return path
    return None


@pytest.fixture
def k8s_client():
    """admin 권한 로컬 샌드박스에 붙는 read-only facade. 샌드박스가 없으면 skip."""
    path = sandbox_kubeconfig()
    if not path:
        pytest.skip("샌드박스 KUBECONFIG 미설정 — ./local-verify/setup-kind.sh 를 먼저 실행하세요")
    from src.config import assert_safe_kubeconfig

    assert_safe_kubeconfig(path)
    from src.tools.k8s_read import ReadOnlyK8sClient

    return ReadOnlyK8sClient(path)


# ---------- 오프라인 그래프 테스트용 스텁/헬퍼 ----------

CRASH_POD_VIEW = {
    "name": "crashloop-demo",
    "namespace": "default",
    "phase": "Running",
    "node": "worker",
    "started": "2026-08-18T00:00:00+00:00",
    "labels": {"app": "crashloop-demo"},
    "containers": [
        {
            "name": "main",
            "image": "busybox:1.36",
            "ready": False,
            "restart_count": 5,
            "state": {"waiting": "CrashLoopBackOff", "message": "back-off 40s"},
            "resources": {"requests": {}, "limits": {}},
        }
    ],
}


class StubReadOnlyClient:
    """ReadOnlyK8sClient와 동일 인터페이스의 인메모리 스텁. 호출 기록을 남긴다."""

    def __init__(self, pods: list[dict] | None = None, logs: str = "boom-marker fixture log"):
        self.calls: list[tuple] = []
        self._pods = pods if pods is not None else [CRASH_POD_VIEW]
        self._logs = logs

    def list_namespaces(self):
        self.calls.append(("list_namespaces",))
        return [{"name": "default", "status": "Active", "labels": {}}]

    def list_pods(self, namespace, label_selector="", field_selector=""):
        self.calls.append(("list_pods", namespace))
        return self._pods

    def get_pod(self, namespace, name):
        self.calls.append(("get_pod", namespace, name))
        return dict(self._pods[0], name=name)

    def get_pod_logs(self, namespace, name, container="", tail_lines=200, previous=False):
        self.calls.append(("get_pod_logs", namespace, name))
        return self._logs

    def list_events(self, namespace, field_selector=""):
        self.calls.append(("list_events", namespace))
        return []

    def list_deployments(self, namespace):
        self.calls.append(("list_deployments", namespace))
        return []

    def get_deployment(self, namespace, name):
        self.calls.append(("get_deployment", namespace, name))
        return {
            "name": name,
            "namespace": namespace,
            "replicas": {"desired": 2, "ready": 2, "available": 2, "updated": 2},
            "images": ["nginx:1.27-alpine"],
            "selector": {"app": name},
            "conditions": [],
        }

    def rollout_history(self, namespace, name):
        self.calls.append(("rollout_history", namespace, name))
        return [{"replicaset": f"{name}-abc", "revision": 1, "replicas": 2, "images": [], "created": None}]

    def list_services(self, namespace):
        self.calls.append(("list_services", namespace))
        return []

    def get_service(self, namespace, name):
        self.calls.append(("get_service", namespace, name))
        return {"name": name, "namespace": namespace, "type": "ClusterIP", "cluster_ip": "10.0.0.1",
                "ports": [], "selector": {}, "endpoints": []}

    def list_configmaps(self, namespace):
        self.calls.append(("list_configmaps", namespace))
        return [{"name": "demo-config", "data_keys": ["APP_MODE"], "labels": {}}]

    def list_nodes(self):
        self.calls.append(("list_nodes",))
        return [{"name": "worker", "ready": "True", "roles": [], "allocatable": {}, "kubelet_version": "v0"}]

    def top_pods(self, namespace):
        self.calls.append(("top_pods", namespace))
        return [{"pod": "high-resource-demo", "containers": [{"name": "burner", "cpu": "900m", "memory": "10Mi"}]}]

    def top_nodes(self):
        self.calls.append(("top_nodes",))
        return []

    def cluster_info(self):
        self.calls.append(("cluster_info",))
        return {"server_version": "1.31", "git_version": "v1.31.0", "platform": "linux/arm64",
                "core_resources": [], "apps_resources": []}

    def ping(self):
        self.calls.append(("ping",))
        return {"ok": True, "server_version": "v1.31.0"}


def ai_tool_call(name: str, args: dict, call_id: str = "call_1") -> AIMessage:
    return AIMessage(
        content="", tool_calls=[{"name": name, "args": args, "id": call_id, "type": "tool_call"}]
    )


@pytest.fixture
def wiki_dir(tmp_path):
    d = tmp_path / "wiki"
    d.mkdir()
    return d


@pytest.fixture
def audit(tmp_path):
    return AuditLogger(tmp_path / "logs")
