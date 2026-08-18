"""매니페스트 정제 + 샌드박스 쓰기 계층 검증.

- manifest_sanitizer: 클라우드 요소 제거·정제·Secret 스텁 합성 (결정론적)
- SandboxCluster: 루프백 강제 — 실 클러스터로는 객체 생성 자체가 불가능
- CloneService: helm 읽기 부속명령만 허용, prod 원본 거부, 파이프라인 오케스트레이션
"""

from __future__ import annotations

import textwrap

import pytest
import yaml

from src.tools.manifest_sanitizer import build_secret_stubs, sanitize_manifests
from src.tools.sandbox_ops import CloneService, SandboxCluster, SandboxSafetyError

REAL_MANIFEST = textwrap.dedent(
    """\
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: web
      annotations:
        service.beta.kubernetes.io/aws-load-balancer-type: nlb
    spec:
      replicas: 3
      template:
        spec:
          nodeSelector: {role-tenant: "true"}
          tolerations: [{key: dedicated, operator: Exists}]
          imagePullSecrets: [{name: regcred}]
          containers:
            - name: app
              image: genians/app:1.0
              env:
                - name: DB_PASS
                  valueFrom: {secretKeyRef: {name: db-secret, key: password}}
              volumeMounts: [{name: certs, mountPath: /certs}]
          volumes:
            - name: certs
              secret: {secretName: tls-secret, items: [{key: tls.crt, path: tls.crt}]}
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: web
    spec:
      type: LoadBalancer
      ports: [{port: 80, targetPort: 8080, nodePort: 31000}]
    ---
    apiVersion: v1
    kind: PersistentVolumeClaim
    metadata:
      name: data
    spec:
      storageClassName: shared
      resources: {requests: {storage: 8Gi}}
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: web-role
    rules: []
    ---
    apiVersion: v1
    kind: Secret
    metadata:
      name: db-secret
    data: {password: c2VjcmV0}
    ---
    apiVersion: traefik.io/v1alpha1
    kind: IngressRoute
    metadata:
      name: web-route
    spec: {routes: []}
    """
)


def _by_kind(yaml_text):
    return {d["kind"] for d in yaml.safe_load_all(yaml_text) if isinstance(d, dict) and d.get("kind")}


def test_sanitize_drops_cloud_and_cluster_specifics():
    out, report = sanitize_manifests(REAL_MANIFEST)  # available_kinds=None → CRD 제외
    kinds = _by_kind(out)
    assert kinds == {"Deployment", "Service", "PersistentVolumeClaim"}
    # RBAC/Secret/CRD 제외
    joined = " ".join(report.dropped)
    assert "Role/web-role" in joined and "Secret/db-secret" in joined and "IngressRoute" in joined


def test_sanitize_transforms():
    out, report = sanitize_manifests(REAL_MANIFEST)
    docs = {d["kind"]: d for d in yaml.safe_load_all(out) if isinstance(d, dict)}
    # LoadBalancer→ClusterIP, nodePort 제거
    assert docs["Service"]["spec"]["type"] == "ClusterIP"
    assert "nodePort" not in docs["Service"]["spec"]["ports"][0]
    # storageClass→standard
    assert docs["PersistentVolumeClaim"]["spec"]["storageClassName"] == "standard"
    # replicas→1, nodeSelector/tolerations/imagePullSecrets/AWS 어노테이션 제거
    dep = docs["Deployment"]
    assert dep["spec"]["replicas"] == 1
    pod = dep["spec"]["template"]["spec"]
    assert "nodeSelector" not in pod and "tolerations" not in pod and "imagePullSecrets" not in pod
    assert "annotations" not in dep["metadata"]
    # 이미지 수집
    assert "genians/app:1.0" in report.images


def test_sanitize_collects_secret_refs_without_reading_secrets():
    _, report = sanitize_manifests(REAL_MANIFEST)
    assert set(report.secret_stubs) == {"db-secret", "tls-secret"}
    assert "password" in report.secret_stubs["db-secret"]
    assert "tls.crt" in report.secret_stubs["tls-secret"]


def test_build_secret_stubs_are_dummy():
    stubs = build_secret_stubs({"db-secret": ["password"], "empty": []}, "demo")
    docs = {d["metadata"]["name"]: d for d in yaml.safe_load_all(stubs)}
    assert docs["db-secret"]["stringData"] == {"password": "dummy"}
    assert docs["db-secret"]["metadata"]["namespace"] == "demo"
    assert docs["empty"]["stringData"] == {"placeholder": "dummy"}  # 키 없으면 placeholder


def test_available_kinds_keeps_crd():
    out, report = sanitize_manifests(REAL_MANIFEST, available_kinds={"IngressRoute"})
    assert "IngressRoute" in _by_kind(out)


# ---------- 루프백 강제 ----------

def _write_kubeconfig(path, server, context):
    path.write_text(yaml.safe_dump({
        "apiVersion": "v1", "kind": "Config",
        "clusters": [{"name": "c", "cluster": {"server": server}}],
        "contexts": [{"name": context, "context": {"cluster": "c", "user": "u"}}],
        "users": [{"name": "u", "user": {}}],
        "current-context": context,
    }), encoding="utf-8")
    return str(path)


def test_sandbox_refuses_non_loopback(tmp_path):
    real = _write_kubeconfig(tmp_path / "real.yaml", "https://10.0.0.5:6443", "aws-seoul-clouddev")
    with pytest.raises(SandboxSafetyError, match="루프백"):
        SandboxCluster(real)


def test_sandbox_refuses_non_kind_context(tmp_path):
    cfg = _write_kubeconfig(tmp_path / "k.yaml", "https://127.0.0.1:60000", "docker-desktop")
    with pytest.raises(SandboxSafetyError, match="kind 컨텍스트"):
        SandboxCluster(cfg)


def test_sandbox_accepts_loopback_kind(tmp_path):
    cfg = _write_kubeconfig(tmp_path / "k.yaml", "https://127.0.0.1:60000", "kind-demo")
    sb = SandboxCluster(cfg)
    assert sb.cluster_name == "demo"


# ---------- CloneService (mocked runner) ----------

class FakeProc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_clone_service_refuses_prod_origin(tmp_path):
    sb_cfg = _write_kubeconfig(tmp_path / "k.yaml", "https://127.0.0.1:60000", "kind-demo")
    sb = SandboxCluster(sb_cfg)
    real = _write_kubeconfig(tmp_path / "real.yaml", "https://10.0.0.5:6443", "aws-cloudprod")
    with pytest.raises(SandboxSafetyError, match="prod"):
        CloneService(real, "aws-cloudprod", sb)


def test_clone_service_rejects_helm_write_subcommands(tmp_path):
    sb_cfg = _write_kubeconfig(tmp_path / "k.yaml", "https://127.0.0.1:60000", "kind-demo")
    real = _write_kubeconfig(tmp_path / "real.yaml", "https://10.0.0.5:6443", "aws-seoul-clouddev")
    svc = CloneService(real, "aws-seoul-clouddev", SandboxCluster(sb_cfg))
    for bad in ("install", "upgrade", "uninstall", "delete", "rollback"):
        with pytest.raises(SandboxSafetyError):
            svc._helm_read(bad, "x")


def test_clone_release_pipeline_uses_only_reads_on_real(tmp_path):
    """clone_release: 실 클러스터엔 helm get(read)만, 쓰기는 kubectl(샌드박스)만."""
    sb_cfg = _write_kubeconfig(tmp_path / "k.yaml", "https://127.0.0.1:60000", "kind-demo")
    real = _write_kubeconfig(tmp_path / "real.yaml", "https://10.0.0.5:6443", "aws-seoul-clouddev")
    calls = []

    def fake_runner(args, **kwargs):
        calls.append(args)
        if args[0] == "helm":
            return FakeProc(0, REAL_MANIFEST)
        if args[0] == "kubectl" and "api-resources" in args:
            return FakeProc(0, "deployments\nservices\nconfigmaps")
        if args[0] == "kubectl" and "get" in args and "pods" in args:
            return FakeProc(0, '{"items":[]}')
        return FakeProc(0, "applied")

    sb = SandboxCluster(sb_cfg, runner=fake_runner)
    svc = CloneService(real, "aws-seoul-clouddev", sb, runner=fake_runner)
    report = svc.clone_release("web", "nexus-shell", target_namespace="clone-web")

    # 실 클러스터(helm)로 나간 건 전부 read 부속명령
    helm_calls = [c for c in calls if c[0] == "helm"]
    assert helm_calls and all(c[1] in ("get", "list", "status", "history") for c in helm_calls)
    # 쓰기(apply)는 kubectl(샌드박스 kubeconfig)로만
    apply_calls = [c for c in calls if c[0] == "kubectl" and "apply" in c]
    assert apply_calls and all(sb_cfg in c for c in apply_calls)
    # 결과: 정제 반영, Secret 스텁 합성
    assert "Service/web" in report.kept
    assert set(report.secret_stubs) == {"db-secret", "tls-secret"}
    assert report.target_namespace == "clone-web"
