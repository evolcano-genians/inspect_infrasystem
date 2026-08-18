"""6-2 구조적 배제 검증 + 수용 기준 grep류 자동화.

src/ 전체를 AST로 정적 분석해 mutating 심볼이 참조되지 않음을 증명한다.
(문자열 상수는 허용 — verb_validator의 금지 목록 등은 실행 코드가 아니다.)
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import yaml

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC = PROJECT_ROOT / "src"

FORBIDDEN_PREFIXES = ("create_", "delete_", "patch_", "replace_", "connect_")

#: K8s가 아닌 로컬 저장소 API에 한해 문서화된 예외.
#: - delete_thread: LangGraph SqliteSaver의 로컬 체크포인트(대화 이력) 삭제 —
#:   클러스터로 나가는 호출이 아니다. 단, K8s 레이어(src/tools/)에서는 예외 없이 금지된다.
ALLOWED_LOCAL_SYMBOLS = frozenset({"delete_thread"})


def _iter_src_files():
    return sorted(SRC.rglob("*.py"))


def _identifiers(tree: ast.AST):
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            yield node.attr
        elif isinstance(node, ast.Name):
            yield node.id
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node.name


def test_no_mutating_symbols_anywhere_in_src():
    violations = []
    for path in _iter_src_files():
        in_k8s_layer = "tools" in path.relative_to(SRC).parts
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for ident in _identifiers(tree):
            if not any(ident.startswith(p) for p in FORBIDDEN_PREFIXES):
                continue
            if ident in ALLOWED_LOCAL_SYMBOLS and not in_k8s_layer:
                continue  # 로컬 저장소 API (위 문서화된 예외)
            violations.append(f"{path.relative_to(PROJECT_ROOT)}: {ident}")
    assert not violations, f"mutating 심볼이 참조되었습니다: {violations}"


def test_no_secret_reader_bound_in_k8s_read():
    """Secret을 읽는 메서드가 facade에 바인딩되어 있지 않아야 한다 (브리프 2.5)."""
    tree = ast.parse((SRC / "tools" / "k8s_read.py").read_text(encoding="utf-8"))
    secretish = [i for i in _identifiers(tree) if "secret" in i.lower()]
    assert not secretish, f"Secret 관련 심볼 발견: {secretish}"


def test_fixtures_contain_no_rbac_or_secrets():
    """local-verify 매니페스트에 RBAC·ServiceAccount·Secret 리소스가 없어야 한다."""
    forbidden_kinds = {
        "Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount", "Secret",
    }
    for path in sorted((PROJECT_ROOT / "local-verify").rglob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict):
                assert doc.get("kind") not in forbidden_kinds, (
                    f"{path.name} 에 금지 리소스 kind={doc.get('kind')} 가 있습니다"
                )


def test_no_rbac_creation_commands_in_repo():
    """`kubectl (create|apply) ... (role|serviceaccount|token)` 류 명령이 없어야 한다."""
    pattern = re.compile(
        r"(kubectl|kctl)\s+(-\S+\s+)*(create|apply)\b.*\b(role|rolebinding|clusterrole|serviceaccount|token)\b",
        re.IGNORECASE,
    )
    targets = list(SRC.rglob("*.py")) + list((PROJECT_ROOT / "local-verify").glob("*.sh"))
    hits = [
        f"{p.name}: {line.strip()}"
        for p in targets
        for line in p.read_text(encoding="utf-8").splitlines()
        if pattern.search(line)
    ]
    assert not hits, f"RBAC/SA/토큰 생성 명령 발견: {hits}"


def test_no_openai_api_key_anywhere():
    """OPENAI_API_KEY 하드코딩·요구가 없어야 한다 (Codex OAuth만 사용)."""
    targets = list(SRC.rglob("*.py")) + [PROJECT_ROOT / ".env.example", PROJECT_ROOT / "pyproject.toml"]
    hits = [str(p) for p in targets if "OPENAI_API_KEY" in p.read_text(encoding="utf-8")]
    assert not hits, f"OPENAI_API_KEY 참조 발견: {hits}"


def test_master_kubeconfig_only_referenced_by_readonly_or_loopback_paths():
    """~/.kube/config 참조는 2계층 모델상 정당한 파일에서만 허용된다.

    - config.py: 실 kubeconfig 판별·가드 (read-only 조사 opt-in)
    - guard-check.sh: 샌드박스 격리 검증
    - clone_cli.py: 실 클러스터 read(helm get) + 루프백 kind에만 write (SandboxCluster 강제)
    이 외의 파일이 마스터 kubeconfig를 참조하면 예기치 않은 접근이므로 실패한다.
    """
    allowed = {
        SRC / "config.py",
        SRC / "clone_cli.py",
        PROJECT_ROOT / "local-verify" / "guard-check.sh",
    }
    targets = list(SRC.rglob("*.py")) + list((PROJECT_ROOT / "local-verify").glob("*.sh"))
    hits = [
        str(p)
        for p in targets
        if p not in allowed and ".kube/config" in p.read_text(encoding="utf-8")
    ]
    assert not hits, f"마스터 kubeconfig 경로 참조 발견: {hits}"


def test_real_cluster_write_is_structurally_impossible():
    """실 클러스터 쓰기 차단: 쓰기 계층(sandbox_ops)은 루프백 kubeconfig에서만 동작하고,
    helm 쓰기 부속명령(install/upgrade/uninstall)은 허용 집합에 없다."""
    from src.tools import sandbox_ops

    assert sandbox_ops._LOOPBACK_RE.match("https://127.0.0.1:60000")
    assert not sandbox_ops._LOOPBACK_RE.match("https://10.0.0.5:6443")
    assert sandbox_ops._HELM_READ_SUBCOMMANDS <= {"get", "list", "status", "history"}
    for write_sub in ("install", "upgrade", "uninstall", "rollback", "delete"):
        assert write_sub not in sandbox_ops._HELM_READ_SUBCOMMANDS


def test_forbidden_verbs_never_registrable():
    """금지 verb는 도구 등록 단계에서부터 거부된다."""
    import pytest

    from src.tools import verb_validator

    for verb in ("create", "delete", "patch", "replace", "exec", "scale", "apply"):
        with pytest.raises(ValueError):
            verb_validator.register_tool(f"evil_{verb}_tool", verb, "pods")
