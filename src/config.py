"""환경 설정 로딩과 fail-fast 인증 안전장치.

2계층 접근 모델:
- **실 클러스터(aws/azure dev 등)**: read-only 조사만. 4중 방어선(read facade·verb 검증·
  GET-only 전송 가드·스파이)이 admin 자격증명이어도 GET만 나가도록 구조적으로 보장한다 —
  이것이 브리프의 핵심 전제("마스터 크리덴셜을 그대로 써도 안전")다.
- **로컬 kind 샌드박스(복제본)**: 실증·테스트·버그 수정을 위한 쓰기 자유 공간
  (이 저장소의 read-only 에이전트가 아니라 별도 복제/테스트 도구가 담당).

안전장치:
- 실 kubeconfig(~/.kube/config) 사용은 명시적 opt-in(AGENT_ALLOW_REAL_CLUSTER=1)과
  컨텍스트 지정(KUBE_CONTEXT)을 함께 요구한다 — 실수로 실 클러스터를 건드리지 않게.
- 컨텍스트 이름에 prod/production이 포함되면 어떤 모드에서도 즉시 종료(fail-fast, 브리프 4.4).
- KUBECONFIG는 환경변수로만 주입한다. 코드·로그 어디에도 경로를 하드코딩하지 않는다.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from dotenv import load_dotenv

FORBIDDEN_CONTEXT_MARKERS: tuple[str, ...] = ("prod", "production")

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class UnsafeKubeconfigError(RuntimeError):
    """위험한 kubeconfig/컨텍스트 조합이 감지되었다."""


#: Codex 추론 단계 허용값. "minimal"/"none"(fast 모드)과 "xhigh"(ultra)는 정책상 배제한다 —
#: fast는 조사 품질이, ultra는 지연·토큰 비용이 문제라 양극단을 모두 금지한다.
ALLOWED_REASONING_EFFORTS: tuple[str, ...] = ("low", "medium", "high")
FORBIDDEN_REASONING_EFFORTS: tuple[str, ...] = ("minimal", "none", "xhigh", "ultra")


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    kubeconfig: str | None
    model_provider: str
    codex_model: str
    codex_reasoning_effort: str
    wiki_dir: Path
    logs_dir: Path
    checkpoint_db: Path
    agents_dir: Path
    kube_context: str = ""
    allow_real_cluster: bool = False
    source_ssh_host: str = ""  # user@host — 소스 read-only 조회용 (SOURCE_SSH_HOST)
    sandbox_bash_enabled: bool = False  # 샌드박스 격리 bash (SANDBOX_BASH_ENABLED)
    strix_enabled: bool = False  # strix pentest (STRIX_ENABLED)
    #: strix 대상 허용목록 치환 (STRIX_ALLOWED_TARGETS, 콤마 구분 CIDR/호스트/`*.도메인`).
    #: 미설정 시 기본값(루프백·로컬 kind 172.18/16·`*.vmlab.test`·전용 작업 디렉터리)만 허용.
    strix_allowed_targets: str = ""
    trino_endpoint: str = ""  # nexus-lake Trino read-only SQL (TRINO_ENDPOINT)
    trino_user: str = "inspect-k8s"
    trino_token: str = ""
    trino_catalog: str = ""
    trino_schema: str = ""
    shell_envs: dict = field(default_factory=dict)  # nexus-shell HTTP 조사 환경 (SHELL_*)
    curator_enabled: bool = False  # 위키 큐레이터 주기 실행 (CURATOR_ENABLED)
    curator_interval_s: int = 6 * 3600  # 큐레이션 사이클 간격(초, CURATOR_INTERVAL_S)


def load_settings(root: Path | None = None) -> Settings:
    root = root or PROJECT_ROOT
    load_dotenv(root / ".env", override=False)
    return Settings(
        kubeconfig=os.environ.get("KUBECONFIG"),
        model_provider=os.environ.get("MODEL_PROVIDER", "codex-oauth"),
        codex_model=os.environ.get("CODEX_MODEL", "gpt-5.6-sol"),
        codex_reasoning_effort=os.environ.get("CODEX_REASONING_EFFORT", "medium"),
        wiki_dir=root / "wiki",
        logs_dir=root / "logs",
        checkpoint_db=root / ".checkpoints" / "graph.sqlite",
        agents_dir=root / ".agents",
        kube_context=os.environ.get("KUBE_CONTEXT", ""),
        allow_real_cluster=_truthy(os.environ.get("AGENT_ALLOW_REAL_CLUSTER")),
        source_ssh_host=os.environ.get("SOURCE_SSH_HOST", ""),
        sandbox_bash_enabled=_truthy(os.environ.get("SANDBOX_BASH_ENABLED")),
        strix_enabled=_truthy(os.environ.get("STRIX_ENABLED")),
        strix_allowed_targets=os.environ.get("STRIX_ALLOWED_TARGETS", ""),
        trino_endpoint=os.environ.get("TRINO_ENDPOINT", ""),
        trino_user=os.environ.get("TRINO_USER", "inspect-k8s"),
        trino_token=os.environ.get("TRINO_TOKEN", ""),
        trino_catalog=os.environ.get("TRINO_CATALOG", ""),
        trino_schema=os.environ.get("TRINO_SCHEMA", ""),
        shell_envs=_load_shell_envs(),
        curator_enabled=_truthy(os.environ.get("CURATOR_ENABLED")),
        curator_interval_s=int(os.environ.get("CURATOR_INTERVAL_S", str(6 * 3600))),
    )


def _load_shell_envs() -> dict:
    from .tools.shell_http import load_shell_envs

    return load_shell_envs(dict(os.environ))


def resolve_contexts(kubeconfig: str) -> tuple[list[str], str]:
    """kubeconfig의 (컨텍스트 이름 목록, current-context)를 반환한다. 값·시크릿은 읽지 않는다."""
    data = yaml.safe_load(Path(kubeconfig).expanduser().read_text(encoding="utf-8")) or {}
    names = [c.get("name", "") for c in data.get("contexts", []) if isinstance(c, dict)]
    return names, str(data.get("current-context", ""))


def is_real_kubeconfig(kubeconfig: str, *, home: Path | None = None) -> bool:
    """이 kubeconfig가 사용자의 실제 기본 kubeconfig(~/.kube/config)인지 판별한다."""
    home_dir = (home or Path.home()).expanduser().resolve()
    master = home_dir / ".kube" / "config"
    try:
        return master.exists() and Path(kubeconfig).expanduser().resolve() == master.resolve()
    except OSError:
        return False


def _has_prod_marker(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in FORBIDDEN_CONTEXT_MARKERS)


def assert_safe_kubeconfig(
    kubeconfig: str | None,
    *,
    context: str | None = None,
    allow_real: bool = False,
    home: Path | None = None,
) -> None:
    """kubeconfig/컨텍스트 조합이 read-only 조사에 안전한지 검증한다. 위반 시 UnsafeKubeconfigError.

    - KUBECONFIG 미설정/파일 없음 → 거부
    - 실 kubeconfig(~/.kube/config): allow_real=True + 명시적 context 필요 (실수 방지)
    - 선택된 컨텍스트(또는 샌드박스의 모든 컨텍스트)에 prod/production 마커 → 거부
    - 샌드박스 kubeconfig: 기존과 동일 (prod 마커 없는 격리 파일)
    """
    if not kubeconfig:
        raise UnsafeKubeconfigError(
            "KUBECONFIG 환경변수가 설정되지 않았습니다. "
            "샌드박스(.local/kind-kubeconfig.yaml) 또는 실 kubeconfig 경로를 명시하세요."
        )

    path = Path(kubeconfig).expanduser()
    if not path.is_file():
        raise UnsafeKubeconfigError(f"KUBECONFIG 파일이 존재하지 않습니다: {path}")

    names, current = resolve_contexts(kubeconfig)
    effective = (context or current or "").strip()

    if is_real_kubeconfig(kubeconfig, home=home):
        if not allow_real:
            raise UnsafeKubeconfigError(
                "실 kubeconfig(~/.kube/config)로 실행하려면 명시적 opt-in이 필요합니다. "
                "read-only 조사임을 확인했다면 AGENT_ALLOW_REAL_CLUSTER=1 과 "
                "KUBE_CONTEXT=<컨텍스트> 를 함께 설정하세요. "
                "(에이전트는 4중 방어선으로 GET만 발생하지만, 실 클러스터 접속은 의도적 선택이어야 합니다.)"
            )
        if context and context not in names:
            raise UnsafeKubeconfigError(
                f"컨텍스트 '{context}' 가 kubeconfig에 없습니다 (사용 가능: {names})."
            )
        if _has_prod_marker(effective):
            raise UnsafeKubeconfigError(
                f"선택한 컨텍스트 '{effective}' 에 prod 마커가 있어 거부합니다 (fail-fast). "
                "실 프로덕션 클러스터는 이 에이전트로도 조회하지 않습니다."
            )
        return

    # 샌드박스 kubeconfig: 격리된 파일이어야 하며 prod 컨텍스트가 섞여 있으면 안 된다.
    for name in [*names, current]:
        if _has_prod_marker(name):
            raise UnsafeKubeconfigError(
                f"컨텍스트 이름 '{name}' 에 금지 마커({FORBIDDEN_CONTEXT_MARKERS})가 "
                "포함되어 있어 즉시 종료합니다 (fail-fast)."
            )
