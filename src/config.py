"""환경 설정 로딩과 fail-fast 인증 안전장치.

- KUBECONFIG는 환경변수로만 주입한다. 코드·로그 어디에도 경로를 하드코딩하지 않는다.
- 사용자의 실제 마스터 kubeconfig(~/.kube/config)는 어떤 실행 경로에서도 사용이 거부된다.
  (이 파일에서 해당 경로를 참조하는 유일한 이유는 "사용을 금지"하기 위해서다.)
- 컨텍스트 이름에 prod/production이 포함되면 즉시 종료한다 (브리프 4.4).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import yaml
from dotenv import load_dotenv

FORBIDDEN_CONTEXT_MARKERS: tuple[str, ...] = ("prod", "production")

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class UnsafeKubeconfigError(RuntimeError):
    """마스터 kubeconfig 사용 또는 위험 컨텍스트가 감지되었다."""


#: Codex 추론 단계 허용값. "minimal"/"none"(fast 모드)과 "xhigh"(ultra)는 정책상 배제한다 —
#: fast는 조사 품질이, ultra는 지연·토큰 비용이 문제라 양극단을 모두 금지한다.
ALLOWED_REASONING_EFFORTS: tuple[str, ...] = ("low", "medium", "high")
FORBIDDEN_REASONING_EFFORTS: tuple[str, ...] = ("minimal", "none", "xhigh", "ultra")


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
    )


def assert_safe_kubeconfig(kubeconfig: str | None, *, home: Path | None = None) -> None:
    """kubeconfig가 로컬 샌드박스용임을 검증한다. 위반 시 UnsafeKubeconfigError.

    검사 항목:
    1. KUBECONFIG 미설정 → 거부 (기본 경로 fallback으로 마스터를 집어들 위험 차단)
    2. 경로가 사용자의 실제 마스터 kubeconfig와 동일 → 거부
    3. 컨텍스트 이름(전체 + current-context)에 prod/production 포함 → 거부
    """
    if not kubeconfig:
        raise UnsafeKubeconfigError(
            "KUBECONFIG 환경변수가 설정되지 않았습니다. "
            "로컬 샌드박스 kubeconfig(.local/kind-kubeconfig.yaml 등)를 명시하세요."
        )

    path = Path(kubeconfig).expanduser().resolve()
    if not path.is_file():
        raise UnsafeKubeconfigError(f"KUBECONFIG 파일이 존재하지 않습니다: {path}")

    home_dir = (home or Path.home()).expanduser().resolve()
    master = home_dir / ".kube" / "config"
    if master.exists() and path == master.resolve():
        raise UnsafeKubeconfigError(
            "실제 마스터 kubeconfig(~/.kube/config)는 이 에이전트에서 사용할 수 없습니다. "
            "local-verify/setup-kind.sh 로 생성한 샌드박스 kubeconfig를 사용하세요."
        )

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    context_names = [c.get("name", "") for c in data.get("contexts", []) if isinstance(c, dict)]
    context_names.append(str(data.get("current-context", "")))
    for name in context_names:
        lowered = name.lower()
        if any(marker in lowered for marker in FORBIDDEN_CONTEXT_MARKERS):
            raise UnsafeKubeconfigError(
                f"컨텍스트 이름 '{name}' 에 금지 마커({FORBIDDEN_CONTEXT_MARKERS})가 "
                "포함되어 있어 즉시 종료합니다 (fail-fast)."
            )
