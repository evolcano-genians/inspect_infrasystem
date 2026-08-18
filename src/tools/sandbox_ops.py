"""샌드박스 전용 운영 도구 — 에이전트의 '로컬 실험실' (2계층 도구 모델의 쓰기 계층).

원칙 (사용자 확정): 실 클러스터(aws/azure dev)는 read-only, **로컬 kind 복제본에서는
자유롭게 테스트**할 수 있다. 이 모듈이 그 쓰기 계층이며, 구조적 안전장치로 격리된다:

1. **루프백 강제**: SandboxCluster 는 kubeconfig 의 서버가 127.0.0.1/localhost 이고
   컨텍스트가 kind-* 일 때만 생성된다 — 실 클러스터를 가리키는 설정으로는 객체 생성
   자체가 불가능하다. 모든 쓰기는 이 객체를 통해서만 나간다.
2. **실 클러스터 접근은 조회 argv 고정**: helm get manifest 등 미리 정해진 읽기
   부속명령만, 셸 없이 인자 배열로 실행한다 (쓰기 부속명령은 거부).
3. **Secret 무접근**: 실 클러스터의 Secret 은 읽지 않는다. 매니페스트에 드러난 참조만으로
   더미 스텁을 합성한다 (manifest_sanitizer.build_secret_stubs).
4. 기존 read-only 4중 방어선(k8s_read)은 이 모듈과 무관하게 그대로 유지된다.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .manifest_sanitizer import build_secret_stubs, sanitize_manifests

_DNS_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
_KIND_RE = re.compile(r"^[A-Za-z]{1,63}$")
_LOOPBACK_RE = re.compile(r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$")
#: 실 클러스터에 허용하는 helm 읽기 부속명령 (쓰기 install/upgrade/uninstall 등은 거부)
_HELM_READ_SUBCOMMANDS = {"get", "list", "status", "history"}
#: 샌드박스에서 제거 가능한 kind (클러스터 인프라 보호)
_SANDBOX_REMOVE_KINDS = {
    "deployment", "statefulset", "daemonset", "pod", "service", "configmap",
    "secret", "job", "cronjob", "namespace", "persistentvolumeclaim", "ingress",
}
_CMD_TIMEOUT = 180


class SandboxSafetyError(RuntimeError):
    """샌드박스 격리 위반 시도가 감지되었다."""


def _run(args: list[str], *, input_text: str | None = None, timeout: int = _CMD_TIMEOUT,
         runner=subprocess.run) -> tuple[int, str]:
    proc = runner(
        args, input=input_text, capture_output=True, text=True, timeout=timeout, shell=False
    )
    output = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
    return proc.returncode, output.strip()


class SandboxCluster:
    """루프백 kind 클러스터만 다루는 쓰기 가능 핸들."""

    def __init__(self, kubeconfig_path: str | Path, *, runner=subprocess.run):
        self._runner = runner
        path = Path(kubeconfig_path).expanduser()
        if not path.is_file():
            raise SandboxSafetyError(f"샌드박스 kubeconfig 없음: {path} — setup-kind.sh 를 먼저 실행")
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        clusters = data.get("clusters") or []
        servers = [str((c.get("cluster") or {}).get("server", "")) for c in clusters]
        if not servers or not all(_LOOPBACK_RE.match(s) for s in servers):
            raise SandboxSafetyError(
                f"샌드박스 kubeconfig 의 서버가 루프백이 아닙니다: {servers} — "
                "실 클러스터로의 쓰기는 구조적으로 차단됩니다."
            )
        contexts = [str(c.get("name", "")) for c in data.get("contexts") or []]
        if not contexts or not all(name.startswith("kind-") for name in contexts):
            raise SandboxSafetyError(f"kind 컨텍스트가 아닙니다: {contexts}")
        self.kubeconfig = str(path)
        self.cluster_name = contexts[0].removeprefix("kind-")

    # ---- kubectl (쓰기 포함 — 루프백 클러스터 한정) ----

    def _kubectl(self, *args: str, input_text: str | None = None) -> tuple[int, str]:
        return _run(
            ["kubectl", "--kubeconfig", self.kubeconfig, *args],
            input_text=input_text, runner=self._runner,
        )

    def ensure_namespace(self, namespace: str) -> None:
        if not _DNS_RE.match(namespace):
            raise SandboxSafetyError(f"잘못된 네임스페이스: {namespace}")
        manifest = yaml.safe_dump(
            {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": namespace}}
        )
        self._kubectl("apply", "-f", "-", input_text=manifest)

    def apply_yaml(self, yaml_text: str, namespace: str) -> tuple[int, str]:
        if not _DNS_RE.match(namespace):
            raise SandboxSafetyError(f"잘못된 네임스페이스: {namespace}")
        if not (yaml_text or "").strip():
            return 0, "(적용할 리소스 없음)"
        return self._kubectl("apply", "-n", namespace, "-f", "-", input_text=yaml_text)

    def remove_resource(self, kind: str, name: str, namespace: str) -> tuple[int, str]:
        if kind.lower() not in _SANDBOX_REMOVE_KINDS:
            raise SandboxSafetyError(f"샌드박스에서도 제거가 허용되지 않는 kind: {kind}")
        if not (_KIND_RE.match(kind) and _DNS_RE.match(name) and _DNS_RE.match(namespace)):
            raise SandboxSafetyError("kind/name/namespace 형식 오류")
        return self._kubectl("delete", kind.lower(), name, "-n", namespace,
                             "--ignore-not-found", "--wait=false")

    def pods_status(self, namespace: str) -> list[dict]:
        code, out = self._kubectl("get", "pods", "-n", namespace, "-o", "json")
        if code != 0:
            return [{"error": out[:400]}]
        pods = []
        for item in (json.loads(out or "{}").get("items") or []):
            statuses = item.get("status", {}).get("containerStatuses") or []
            waiting = [
                (s.get("state", {}).get("waiting") or {}).get("reason")
                for s in statuses if (s.get("state", {}).get("waiting") or {}).get("reason")
            ]
            pods.append({
                "name": item["metadata"]["name"],
                "phase": item.get("status", {}).get("phase"),
                "ready": sum(1 for s in statuses if s.get("ready")),
                "containers": len(statuses),
                "restarts": sum(s.get("restartCount", 0) for s in statuses),
                "waiting": waiting,
            })
        return pods

    def available_kinds(self) -> set[str]:
        code, out = self._kubectl("api-resources", "-o", "name")
        if code != 0:
            return set()
        kinds = set()
        for line in out.splitlines():
            base = line.split(".", 1)[0].strip()
            if base:
                kinds.add(base.rstrip("s").capitalize())  # 근사 — 정확 판정은 apply 가 최종
        return kinds

    def load_image(self, image: str) -> tuple[bool, str]:
        if shutil.which("kind") is None:
            return False, "kind CLI 없음"
        code, out = _run(["docker", "pull", image], timeout=600, runner=self._runner)
        if code != 0:
            return False, f"docker pull 실패: {out[-300:]}"
        code, out = _run(
            ["kind", "load", "docker-image", image, "--name", self.cluster_name],
            timeout=600, runner=self._runner,
        )
        return (code == 0), out[-300:]


@dataclass
class CloneReport:
    release: str
    namespace: str
    target_namespace: str = ""
    kept: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    changes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    images: list[str] = field(default_factory=list)
    images_loaded: list[str] = field(default_factory=list)
    images_failed: list[str] = field(default_factory=list)
    secret_stubs: list[str] = field(default_factory=list)
    apply_output: str = ""
    pods: list[dict] = field(default_factory=list)

    def summary(self) -> str:
        return (
            f"[{self.namespace}/{self.release} → {self.target_namespace}] "
            f"적용 {len(self.kept)} · 제외 {len(self.dropped)} · 변경 {len(self.changes)} · "
            f"스텁 Secret {len(self.secret_stubs)} · 이미지 적재 {len(self.images_loaded)}/"
            f"{len(self.images_loaded) + len(self.images_failed)}"
        )


class CloneService:
    """실 클러스터(read-only 조회) → 정제 → 샌드박스 배포 파이프라인.

    실 클러스터에는 helm 읽기 부속명령만 나가고(쓰기 부속명령 거부), 쓰기는 전부
    SandboxCluster(루프백 강제)를 통해서만 발생한다.
    """

    def __init__(
        self,
        real_kubeconfig: str,
        real_context: str,
        sandbox: SandboxCluster,
        *,
        runner=subprocess.run,
    ):
        real_path = Path(real_kubeconfig).expanduser()
        if not real_path.is_file():
            raise SandboxSafetyError(f"실 kubeconfig 없음: {real_path}")
        if not real_context or not _DNS_RE.match(real_context):
            raise SandboxSafetyError(f"실 컨텍스트 이름 형식 오류: {real_context!r}")
        if "prod" in real_context.lower():
            raise SandboxSafetyError(f"prod 컨텍스트는 복제 원본으로 쓸 수 없습니다: {real_context}")
        self._real_kubeconfig = str(real_path)
        self._real_context = real_context
        self.sandbox = sandbox
        self._runner = runner

    def _helm_read(self, *args: str) -> tuple[int, str]:
        if not args or args[0] not in _HELM_READ_SUBCOMMANDS:
            raise SandboxSafetyError(
                f"helm 쓰기/미허용 부속명령 거부: {args[:1]} (허용: {sorted(_HELM_READ_SUBCOMMANDS)})"
            )
        return _run(
            ["helm", *args, "--kubeconfig", self._real_kubeconfig,
             "--kube-context", self._real_context],
            runner=self._runner,
        )

    def list_releases(self, namespace: str | None = None) -> list[dict]:
        args = ["list", "-o", "json"]
        args += (["-n", namespace] if namespace else ["-A"])
        code, out = self._helm_read(*args)
        if code != 0:
            raise SandboxSafetyError(f"helm list 실패: {out[-300:]}")
        return json.loads(out or "[]")

    def fetch_manifest(self, release: str, namespace: str) -> str:
        if not (_DNS_RE.match(release) and _DNS_RE.match(namespace)):
            raise SandboxSafetyError(f"release/namespace 형식 오류: {release}/{namespace}")
        code, out = self._helm_read("get", "manifest", release, "-n", namespace)
        if code != 0:
            raise SandboxSafetyError(f"helm get manifest 실패: {out[-300:]}")
        return out

    def plan_release(self, release: str, namespace: str, *, scale_to_one: bool = True):
        """적용 없이 정제 계획만 산출한다 (실 클러스터 read + 로컬 정제, 쓰기 없음)."""
        manifest = self.fetch_manifest(release, namespace)
        return sanitize_manifests(manifest, available_kinds=None, scale_to_one=scale_to_one)

    def clone_release(
        self,
        release: str,
        namespace: str,
        *,
        target_namespace: str | None = None,
        load_images: bool = False,
        scale_to_one: bool = True,
    ) -> CloneReport:
        target_ns = target_namespace or namespace
        report = CloneReport(release=release, namespace=namespace, target_namespace=target_ns)

        manifest = self.fetch_manifest(release, namespace)
        available = self.sandbox.available_kinds()
        sanitized, sreport = sanitize_manifests(
            manifest, available_kinds=available or None, scale_to_one=scale_to_one
        )
        report.kept = sreport.kept
        report.dropped = sreport.dropped
        report.changes = sreport.changes
        report.warnings = sreport.warnings
        report.images = sreport.images

        self.sandbox.ensure_namespace(target_ns)

        if sreport.secret_stubs:
            stubs = build_secret_stubs(sreport.secret_stubs, target_ns)
            self.sandbox.apply_yaml(stubs, target_ns)
            report.secret_stubs = sorted(sreport.secret_stubs)

        if load_images:
            for image in sreport.images:
                ok, _msg = self.sandbox.load_image(image)
                (report.images_loaded if ok else report.images_failed).append(image)

        code, out = self.sandbox.apply_yaml(sanitized, target_ns)
        report.apply_output = out[-2000:]
        report.pods = self.sandbox.pods_status(target_ns)
        return report
