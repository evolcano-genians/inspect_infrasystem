"""오픈소스 인벤토리 도구 검증 — 이미지→프로젝트 식별, 집계, executor 게이트."""

from __future__ import annotations

from src.tools.oss_catalog import identify_oss, is_internal


def test_identify_known_oss():
    assert identify_oss("traefik:v3.6.23")["project"] == "Traefik"
    assert identify_oss("trinodb/trino:480")["project"] == "Trino"
    assert identify_oss("quay.io/prometheus/prometheus:v2.48.0")["project"] == "Prometheus"
    assert identify_oss("apache/kafka:4.1.2")["category"] == "messaging"
    assert identify_oss("crowdsecurity/crowdsec:v1.6.6")["category"] == "security"
    # 버전(태그) 추출
    assert identify_oss("grafana/grafana:10.2.2")["version"] == "10.2.2"
    # 다이제스트는 무시
    assert identify_oss("traefik:v3.6@sha256:abc")["version"] == "v3.6"


def test_internal_apps_flagged():
    assert is_internal("docker.io/genians/genian-nexus-shell:latest")
    r = identify_oss("docker.io/genians/genian-keycloak-dev:x")
    # 회사 자체 keycloak 빌드는 카탈로그의 keycloak 보다 internal 판정이 우선? — 카탈로그 우선.
    # keycloak 패턴이 먼저 잡히므로 third_party True (업스트림 Keycloak 기반)
    assert r["project"] == "Keycloak"
    # 순수 회사 앱은 internal
    r2 = identify_oss("docker.io/genians/genian-nexus-shell-bff:latest")
    assert r2["third_party"] is False and r2["category"] == "genians-app"


def test_unknown_third_party_guessed():
    r = identify_oss("somevendor/cool-thing:1.0")
    assert r["third_party"] is True and r["project"] == "cool-thing"
    assert r["category"] == "기타(추정)"


class FakeK8s:
    def list_namespaces(self):
        return [{"name": "infra"}, {"name": "app"}]

    def list_deployments(self, ns):
        if ns == "infra":
            return [{"name": "traefik", "images": ["traefik:v3.6.23"]},
                    {"name": "grafana", "images": ["grafana/grafana:10.2.2"]}]
        return [{"name": "shell", "images": ["docker.io/genians/genian-nexus-shell:latest"]}]

    def list_statefulsets(self, ns):
        return [{"name": "kafka", "images": ["apache/kafka:4.1.2"]}] if ns == "infra" else []

    def list_daemonsets(self, ns):
        return [{"name": "calico", "images": ["docker.io/calico/node:v3.28.1"]}] if ns == "infra" else []


def test_oss_inventory_aggregates_and_excludes_internal():
    from src.tools.k8s_read import make_tools

    tools = {t.name: t for t in make_tools(FakeK8s())}
    assert "k8s_oss_inventory" in tools
    # 직접 클라이언트 메서드 호출 (도구 래퍼 없이 로직 검증)
    from src.tools.k8s_read import ReadOnlyK8sClient
    # ReadOnlyK8sClient.oss_inventory 는 인스턴스 메서드 — FakeK8s 에 바인딩해 호출
    result = ReadOnlyK8sClient.oss_inventory(FakeK8s())
    projs = {p["project"] for p in result["projects"]}
    assert {"Traefik", "Grafana", "Apache Kafka", "Calico (CNI)"} <= projs
    assert result["oss_count"] >= 4
    # 회사앱은 기본 제외되고 카운트만
    assert "genian-nexus-shell" not in projs
    assert result["internal_app_images"] == 1
    assert result["by_category"].get("ingress/proxy") == 1


def test_oss_inventory_include_internal():
    from src.tools.k8s_read import ReadOnlyK8sClient
    result = ReadOnlyK8sClient.oss_inventory(FakeK8s(), include_internal=True)
    projs = {p["project"] for p in result["projects"]}
    assert "genian-nexus-shell" in projs


def test_oss_tool_passes_executor_gate():
    """k8s_oss_inventory 가 verb_validator(executor 게이트)를 통과하는지."""
    from src.tools import verb_validator
    from src.tools.k8s_read import make_tools
    make_tools(FakeK8s())  # 등록 트리거
    v = verb_validator.validate_tool_call("k8s_oss_inventory",
                                          {"namespace": "infra", "include_internal": False})
    assert v.allowed, v.reason
