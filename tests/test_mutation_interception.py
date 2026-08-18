"""6-3 런타임 인터셉션 검증.

- 전송 가드(GuardedApiClient)가 GET 이외 메서드·금지 경로를 네트워크 IO 이전에 차단하는지
- admin 권한 샌드박스를 대상으로 실제 조회를 수행해도 나가는 요청이 전부 GET인지
  (전역 스파이는 conftest.k8s_request_spy — 스위트 종료 시에도 최종 검증된다)
"""

from __future__ import annotations

import pytest

from src.tools.guarded_client import GuardedApiClient, ReadOnlyViolation, check_request_allowed

BASE = "https://127.0.0.1:6443"


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
def test_transport_guard_blocks_non_get(method):
    client = GuardedApiClient()
    with pytest.raises(ReadOnlyViolation):
        client.request(method, f"{BASE}/api/v1/namespaces/default/pods")


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/namespaces/default/pods/x/exec",
        "/api/v1/namespaces/default/pods/x/attach",
        "/api/v1/namespaces/default/pods/x/portforward",
        "/api/v1/namespaces/default/services/x/proxy",
        "/api/v1/namespaces/default/secrets",
        "/api/v1/namespaces/default/secrets/db-password",
        "/api/v1/namespaces/default/pods/x/eviction",
    ],
)
def test_transport_guard_blocks_forbidden_paths_even_on_get(path):
    with pytest.raises(ReadOnlyViolation):
        check_request_allowed("GET", f"{BASE}{path}")


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/namespaces/default/pods",
        "/api/v1/namespaces/default/pods/crashloop-demo/log?tailLines=200",
        "/apis/apps/v1/namespaces/default/deployments",
        "/apis/metrics.k8s.io/v1beta1/namespaces/default/pods",
        "/version",
    ],
)
def test_transport_guard_allows_read_paths(path):
    check_request_allowed("GET", f"{BASE}{path}")  # 예외가 없어야 한다


def test_admin_sandbox_receives_only_get(k8s_client, k8s_request_spy):
    """admin kubeconfig로 실제 조회를 돌려도 나간 요청은 전부 GET이어야 한다."""
    before = len(k8s_request_spy)
    k8s_client.ping()
    k8s_client.list_namespaces()
    k8s_client.list_pods("default")
    k8s_client.list_deployments("default")
    k8s_client.cluster_info()
    sent = k8s_request_spy[before:]
    assert sent, "요청이 기록되지 않았습니다 (스파이 미동작)"
    non_get = [r for r in sent if r[0] != "GET"]
    assert not non_get, f"GET 이외 요청 발견: {non_get}"
