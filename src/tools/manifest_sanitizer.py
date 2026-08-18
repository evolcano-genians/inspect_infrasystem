"""실 클러스터 매니페스트 → kind 샌드박스용 정제(sanitize).

helm get manifest 로 얻은 배포 YAML을 로컬 kind에서 구동 가능하게 변환한다:
- 클라우드 전용 요소 제거: AWS 어노테이션, nodeSelector/tolerations/affinity,
  LoadBalancer→ClusterIP, storageClassName→기본 SC(standard)
- RBAC(Role/RoleBinding/ClusterRole/ClusterRoleBinding)은 기본 제외 (ServiceAccount는 유지 —
  파드가 참조하므로 앱 구동에 필요), 샌드박스에 없는 CRD 기반 리소스 제외
- imagePullSecrets 제거 (이미지는 kind load로 사전 적재)
- Secret 스텁: 실 클러스터의 Secret을 **읽지 않고**, 매니페스트에 나타난 참조
  (secretKeyRef/volume items 의 key 이름)만으로 더미 Secret 을 합성한다

모든 판단은 결정론적이며 제외/변경 내역은 report 로 반환된다.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import yaml

_RBAC_KINDS = {"Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"}
_WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"}
#: kind 기본 제공 API 로 항상 적용 가능한 kind (CRD 판정에 사용)
_CORE_KINDS = {
    "Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet", "Pod",
    "Service", "ConfigMap", "Secret", "ServiceAccount", "PersistentVolumeClaim",
    "Ingress", "NetworkPolicy", "HorizontalPodAutoscaler", "PodDisruptionBudget",
    "Namespace", "LimitRange", "ResourceQuota", "Endpoints",
}
_AWS_ANNOTATION_MARKERS = ("amazonaws.com", "service.beta.kubernetes.io/aws")


@dataclass
class SanitizeReport:
    kept: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    secret_stubs: dict[str, list[str]] = field(default_factory=dict)  # name -> keys


def _pod_spec_of(doc: dict) -> dict | None:
    kind = doc.get("kind")
    if kind == "Pod":
        return doc.get("spec") or {}
    if kind in ("CronJob",):
        return (((doc.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}) \
            .get("template", {}).get("spec")
    if kind in _WORKLOAD_KINDS:
        return ((doc.get("spec") or {}).get("template") or {}).get("spec")
    return None


def _strip_aws_annotations(meta: dict, report: SanitizeReport, where: str) -> None:
    annotations = meta.get("annotations") or {}
    removed = [k for k in annotations if any(m in k for m in _AWS_ANNOTATION_MARKERS)]
    for key in removed:
        annotations.pop(key, None)
        report.changes.append(f"{where}: AWS 어노테이션 제거 ({key})")
    if annotations == {}:
        meta.pop("annotations", None)


def _collect_secret_refs(pod_spec: dict, report: SanitizeReport) -> None:
    """파드 스펙의 Secret 참조에서 (이름, 키)를 수집한다 — 실 Secret은 읽지 않는다."""
    for container in (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or []):
        for env in container.get("env") or []:
            ref = ((env.get("valueFrom") or {}).get("secretKeyRef")) or {}
            if ref.get("name"):
                report.secret_stubs.setdefault(ref["name"], [])
                if ref.get("key") and ref["key"] not in report.secret_stubs[ref["name"]]:
                    report.secret_stubs[ref["name"]].append(ref["key"])
        for env_from in container.get("envFrom") or []:
            ref = (env_from.get("secretRef")) or {}
            if ref.get("name"):
                report.secret_stubs.setdefault(ref["name"], [])
                report.warnings.append(
                    f"envFrom secretRef '{ref['name']}': 키 목록을 매니페스트에서 알 수 없어 "
                    "placeholder 키만 생성됨 — 앱이 특정 키를 요구하면 수동 보완 필요"
                )
    for volume in pod_spec.get("volumes") or []:
        sec = volume.get("secret") or {}
        if sec.get("secretName"):
            keys = report.secret_stubs.setdefault(sec["secretName"], [])
            for item in sec.get("items") or []:
                if item.get("key") and item["key"] not in keys:
                    keys.append(item["key"])


def _sanitize_pod_spec(pod_spec: dict, report: SanitizeReport, where: str) -> None:
    for field_name in ("nodeSelector", "tolerations", "affinity", "topologySpreadConstraints"):
        if pod_spec.pop(field_name, None) is not None:
            report.changes.append(f"{where}: {field_name} 제거")
    if pod_spec.pop("imagePullSecrets", None) is not None:
        report.changes.append(f"{where}: imagePullSecrets 제거 (이미지는 kind load 로 적재)")
    for container in (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or []):
        if container.get("image"):
            if container["image"] not in report.images:
                report.images.append(container["image"])
    _collect_secret_refs(pod_spec, report)


def sanitize_manifests(
    yaml_text: str,
    *,
    available_kinds: set[str] | None = None,
    scale_to_one: bool = True,
    include_rbac: bool = False,
) -> tuple[str, SanitizeReport]:
    """매니페스트 전체를 정제한다. 반환: (정제된 YAML, 리포트). O(문서 수 × 크기)."""
    report = SanitizeReport()
    kept_docs: list[dict] = []

    for doc in yaml.safe_load_all(yaml_text):
        if not isinstance(doc, dict) or not doc.get("kind"):
            continue
        kind = str(doc["kind"])
        name = str((doc.get("metadata") or {}).get("name", "?"))
        ident = f"{kind}/{name}"

        if kind in _RBAC_KINDS and not include_rbac:
            report.dropped.append(f"{ident} (RBAC — 기본 제외, include_rbac 로 포함 가능)")
            continue
        if kind == "Secret":
            report.dropped.append(f"{ident} (Secret 은 복제하지 않음 — 참조 기반 스텁으로 대체)")
            continue
        if kind not in _CORE_KINDS and kind not in _RBAC_KINDS:
            if available_kinds is None or kind not in available_kinds:
                report.dropped.append(f"{ident} (CRD 기반 — 샌드박스에 미지원)")
                continue

        meta = doc.setdefault("metadata", {})
        _strip_aws_annotations(meta, report, ident)

        if kind == "Service":
            spec = doc.get("spec") or {}
            if spec.get("type") == "LoadBalancer":
                spec["type"] = "ClusterIP"
                report.changes.append(f"{ident}: LoadBalancer → ClusterIP")
            spec.pop("loadBalancerSourceRanges", None)
            for port in spec.get("ports") or []:
                port.pop("nodePort", None)

        if kind == "PersistentVolumeClaim":
            spec = doc.get("spec") or {}
            if spec.get("storageClassName") not in (None, "standard"):
                report.changes.append(
                    f"{ident}: storageClassName {spec.get('storageClassName')} → standard"
                )
                spec["storageClassName"] = "standard"

        if kind == "StatefulSet":
            for vct in ((doc.get("spec") or {}).get("volumeClaimTemplates")) or []:
                vspec = vct.get("spec") or {}
                if vspec.get("storageClassName") not in (None, "standard"):
                    report.changes.append(f"{ident}: volumeClaimTemplate SC → standard")
                    vspec["storageClassName"] = "standard"

        pod_spec = _pod_spec_of(doc)
        if pod_spec:
            _sanitize_pod_spec(pod_spec, report, ident)
            if scale_to_one and kind in ("Deployment", "StatefulSet", "ReplicaSet"):
                spec = doc.get("spec") or {}
                if (spec.get("replicas") or 1) > 1:
                    report.changes.append(f"{ident}: replicas {spec['replicas']} → 1")
                    spec["replicas"] = 1

        report.kept.append(ident)
        kept_docs.append(doc)

    sanitized = "\n---\n".join(
        yaml.safe_dump(d, allow_unicode=True, sort_keys=False, default_flow_style=False)
        for d in kept_docs
    )
    return sanitized, report


def build_secret_stubs(secret_stubs: dict[str, list[str]], namespace: str) -> str:
    """참조 기반 더미 Secret YAML 을 합성한다 (실 Secret 미접근 — 값은 전부 'dummy')."""
    docs = []
    for name, keys in sorted(secret_stubs.items()):
        string_data = {key: "dummy" for key in (keys or ["placeholder"])}
        docs.append(
            {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {
                    "name": name,
                    "namespace": namespace,
                    "labels": {"inspect-k8s/stub": "true"},
                },
                "type": "Opaque",
                "stringData": string_data,
            }
        )
    return "\n---\n".join(
        yaml.safe_dump(d, allow_unicode=True, sort_keys=False) for d in docs
    )
