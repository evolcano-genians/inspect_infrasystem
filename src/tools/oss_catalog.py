"""오픈소스 식별 카탈로그 — 컨테이너 이미지 → 오픈소스 프로젝트·범주.

클러스터에 배포된 이미지 저장소(repo) 문자열을 보고 어떤 오픈소스인지, 어느 범주인지,
회사 자체 앱(third-party 아님)인지 판별한다. 순수 함수라 네트워크·클러스터 접근이 없다.
매핑은 실제 dev 클러스터 관찰(69개 이미지)에 기반하며, 미지의 이미지는 휴리스틱으로 추정한다.
"""

from __future__ import annotations

# (이미지 repo에 포함되는 부분문자열) -> (프로젝트명, 범주)
# 더 구체적인 패턴이 먼저 오도록 정렬(길이 우선 매칭).
_CATALOG: tuple[tuple[str, str, str], ...] = (
    # ingress / proxy / gateway
    ("traefik", "Traefik", "ingress/proxy"),
    ("ingress-nginx", "ingress-nginx", "ingress/proxy"),
    ("oauth2-proxy", "oauth2-proxy", "auth/proxy"),
    ("kube-rbac-proxy", "kube-rbac-proxy", "auth/proxy"),
    # auth / identity
    ("keycloak", "Keycloak", "auth/identity"),
    # policy
    ("openpolicyagent/opa", "Open Policy Agent (OPA)", "policy"),
    ("permitio/opal-server", "OPAL Server", "policy"),
    ("permitio/opal-client", "OPAL Client", "policy"),
    # messaging / streaming
    ("apache/kafka", "Apache Kafka", "messaging"),
    ("kestra", "Kestra", "orchestration"),
    # data lakehouse
    ("trino", "Trino", "data/lakehouse"),
    ("apache/hive", "Apache Hive Metastore", "data/lakehouse"),
    ("apache/spark", "Apache Spark", "data/lakehouse"),
    ("jena-fuseki", "Apache Jena Fuseki", "data/graph"),
    ("minio", "MinIO", "storage/object"),
    # databases
    ("postgres", "PostgreSQL", "database"),
    ("percona", "Percona XtraDB (MySQL)", "database"),
    ("mysql", "MySQL", "database"),
    ("adminer", "Adminer", "database/tool"),
    # observability
    ("prometheus-operator/prometheus-operator", "Prometheus Operator", "observability"),
    ("prometheus-config-reloader", "Prometheus Config Reloader", "observability"),
    ("prometheus-adapter", "Prometheus Adapter", "observability"),
    ("prometheus/alertmanager", "Alertmanager", "observability"),
    ("prometheus/blackbox-exporter", "Blackbox Exporter", "observability"),
    ("prometheus/node-exporter", "Node Exporter", "observability"),
    ("prometheus/prometheus", "Prometheus", "observability"),
    ("kube-state-metrics", "kube-state-metrics", "observability"),
    ("metrics-server", "metrics-server", "observability"),
    ("grafana/loki", "Grafana Loki", "observability/logs"),
    ("grafana/grafana", "Grafana", "observability"),
    ("fluent/fluent-bit", "Fluent Bit", "observability/logs"),
    ("fluentd", "Fluentd", "observability/logs"),
    ("configmap-reload", "configmap-reload", "observability"),
    ("botkube", "Botkube", "observability/alerting"),
    # security
    ("crowdsec", "CrowdSec", "security"),
    # networking (CNI) / dns
    ("calico/node", "Calico (CNI)", "networking/cni"),
    ("calico/kube-controllers", "Calico kube-controllers", "networking/cni"),
    ("coredns", "CoreDNS", "networking/dns"),
    # storage / CSI
    ("aws-ebs-csi-driver", "AWS EBS CSI Driver", "storage/csi"),
    ("efs-provisioner", "EFS Provisioner", "storage/csi"),
    ("azuredisk", "Azure Disk CSI", "storage/csi"),
    ("azurefile", "Azure File CSI", "storage/csi"),
    ("hostpath-provisioner", "Hostpath Provisioner", "storage/csi"),
    ("csi-attacher", "CSI Attacher", "storage/csi"),
    ("csi-provisioner", "CSI Provisioner", "storage/csi"),
    ("csi-resizer", "CSI Resizer", "storage/csi"),
    ("csi-snapshotter", "CSI Snapshotter", "storage/csi"),
    ("csi-node-driver-registrar", "CSI Node Driver Registrar", "storage/csi"),
    ("livenessprobe", "CSI livenessprobe", "storage/csi"),
    # generic web
    ("nginx", "nginx", "web"),
    ("httpd", "Apache HTTP Server", "web"),
    ("custom-error-pages", "custom-error-pages", "web"),
)

# 회사 자체 이미지(오픈소스 아님)로 보는 저장소 접두/부분
_INTERNAL_MARKERS = ("genians/genian", "genians/nexus", "genians/gsp",
                     "nexus-lake", "security-view", "soyejin02", "tenant-monitor")


def _repo_and_tag(image: str) -> tuple[str, str]:
    """이미지에서 (repo, tag) 를 뽑는다. 다이제스트(@sha256)는 무시."""
    base = (image or "").split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        tag = last.rsplit(":", 1)[1]
        repo = base.rsplit(":", 1)[0]
    else:
        tag = ""
        repo = base
    return repo, tag


def is_internal(image: str) -> bool:
    low = (image or "").lower()
    return any(m in low for m in _INTERNAL_MARKERS)


def identify_oss(image: str) -> dict:
    """이미지 → {project, category, version, third_party, repo}.

    카탈로그에 없으면 휴리스틱: 회사 이미지가 아니면 repo의 마지막 조각을 프로젝트명으로 추정.
    """
    repo, tag = _repo_and_tag(image)
    low = repo.lower()
    for needle, project, category in _CATALOG:
        if needle in low:
            return {"project": project, "category": category, "version": tag,
                    "third_party": True, "repo": repo}
    if is_internal(image):
        return {"project": repo.rsplit("/", 1)[-1], "category": "genians-app",
                "version": tag, "third_party": False, "repo": repo}
    # 미지의 서드파티 — repo 마지막 조각으로 추정
    guess = repo.rsplit("/", 1)[-1]
    return {"project": guess, "category": "기타(추정)", "version": tag,
            "third_party": True, "repo": repo}
