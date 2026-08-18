"""샌드박스 격리 bash 실행기 — 보안 테스트/pentest 도구의 실행 기반.

OpenHands의 컨테이너 격리 패턴을 따르되, 이 프로젝트의 2계층 원칙을 구조적으로 강제한다:
**실 클러스터·클라우드 자격증명에는 절대 도달할 수 없고, 로컬 샌드박스에서만 실행된다.**

구조적 안전장치 (설정 오류로도 실 인프라를 건드릴 수 없게):
1. **자격증명 무마운트**: 호스트 경로 볼륨 마운트를 전면 금지한다. ~/.kube, ~/.aws, ~/.ssh,
   ~/.docker 등이 컨테이너에 들어갈 경로가 존재하지 않는다. 작업공간은 tmpfs 뿐이다.
2. **네트워크 격리**: 컨테이너 네트워크는 화이트리스트(none | kind | 전용 샌드박스 네트워크)만
   허용한다. host 네트워크·기본 bridge(인터넷 경유)는 거부된다. 기본값은 kind
   (샌드박스에 복제한 앱만 도달 가능, 실 클라우드는 불가).
3. **최소 권한**: non-root, cap_drop=ALL, no-new-privileges, read-only rootfs,
   mem/pids/cpu 제한, 일회용 컨테이너(--rm).
4. **자격증명 env 차단**: KUBECONFIG/AWS_*/AZURE_* 등은 컨테이너 env로 전달하지 않는다.

이 실행기는 opt-in(SANDBOX_BASH_ENABLED=1)이며, 기존 read-only 4중 방어선과 독립적이다.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass

#: 허용 네트워크 — host/기본 bridge(인터넷 경유)는 배제. kind = 샌드박스 앱 도달용.
ALLOWED_NETWORKS: frozenset[str] = frozenset({"none", "kind"})
#: 컨테이너 env로 절대 전달하지 않는 자격증명성 키 접두사
_CREDENTIAL_ENV_PREFIXES = ("KUBECONFIG", "AWS_", "AZURE_", "GOOGLE_", "GCP_", "DOCKER_",
                            "SSH_", "GIT_", "OPENAI_", "ANTHROPIC_", "KUBE_")
_DEFAULT_IMAGE = "alpine:latest"
_MAX_OUTPUT = 40_000


class SandboxExecError(RuntimeError):
    pass


@dataclass(frozen=True)
class BashResult:
    exit_code: int
    output: str
    truncated: bool
    timed_out: bool


def _assert_safe_config(network: str, volumes: dict | None, environment: dict | None) -> None:
    """실 인프라 접근 가능성을 구조적으로 차단하는 사전 검증."""
    if network not in ALLOWED_NETWORKS:
        raise SandboxExecError(
            f"네트워크 '{network}' 는 허용되지 않습니다 (허용: {sorted(ALLOWED_NETWORKS)}). "
            "host/bridge 네트워크는 실 인프라 도달 가능성 때문에 금지됩니다."
        )
    if volumes:
        raise SandboxExecError(
            "호스트 볼륨 마운트는 금지됩니다 — 자격증명(~/.kube 등)이 컨테이너에 들어갈 수 "
            "없어야 합니다. 작업공간은 tmpfs 만 사용하세요."
        )
    for key in (environment or {}):
        if any(key.upper().startswith(p) for p in _CREDENTIAL_ENV_PREFIXES):
            raise SandboxExecError(f"자격증명성 환경변수 '{key}' 는 샌드박스에 전달할 수 없습니다.")


class BashSandbox:
    """일회용 Docker 컨테이너에서 bash 명령을 실행하는 격리 실행기."""

    def __init__(
        self,
        *,
        image: str = _DEFAULT_IMAGE,
        network: str = "kind",
        mem_limit: str = "1g",
        pids_limit: int = 512,
        cpu_quota: int = 100_000,  # 1 CPU
        workdir: str = "/work",
        docker_client=None,
    ):
        _assert_safe_config(network, None, None)
        self.image = image
        self.network = network
        self.mem_limit = mem_limit
        self.pids_limit = pids_limit
        self.cpu_quota = cpu_quota
        self.workdir = workdir
        if docker_client is None:
            import docker

            docker_client = docker.from_env()
        self._docker = docker_client

    def run(self, command: str, *, timeout: int = 120, environment: dict | None = None) -> BashResult:
        """명령을 일회용 컨테이너에서 실행한다. 셸 파이프라인 허용(컨테이너 안에 격리됨)."""
        _assert_safe_config(self.network, None, environment)
        if not command or not command.strip():
            raise SandboxExecError("빈 명령")
        timeout = max(1, min(int(timeout), 1800))
        # timeout 은 컨테이너 안에서 강제 (busybox/coreutils timeout)
        wrapped = f"timeout {timeout} sh -c {shlex.quote(command)}"
        try:
            container = self._docker.containers.run(
                self.image,
                command=["sh", "-c", wrapped],
                detach=True,
                network_mode=self.network,
                mem_limit=self.mem_limit,
                pids_limit=self.pids_limit,
                cpu_quota=self.cpu_quota,
                nano_cpus=None,
                user="1000:1000",
                working_dir=self.workdir,
                read_only=True,
                tmpfs={self.workdir: "rw,size=512m,uid=1000,gid=1000", "/tmp": "rw,size=128m"},
                cap_drop=["ALL"],
                security_opt=["no-new-privileges"],
                environment=environment or {},
                labels={"inspect-k8s/sandbox-bash": "true"},
                auto_remove=False,
            )
        except SandboxExecError:
            raise
        except Exception as exc:  # docker 오류
            raise SandboxExecError(f"컨테이너 실행 실패: {type(exc).__name__}: {exc}") from exc

        try:
            result = container.wait(timeout=timeout + 30)
            exit_code = int(result.get("StatusCode", -1))
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
        finally:
            try:
                container.remove(force=True)
            except Exception:
                pass

        timed_out = exit_code == 124  # timeout(1)의 종료코드
        truncated = len(logs) > _MAX_OUTPUT
        return BashResult(
            exit_code=exit_code,
            output=logs[:_MAX_OUTPUT],
            truncated=truncated,
            timed_out=timed_out,
        )
