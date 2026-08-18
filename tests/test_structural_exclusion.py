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
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for ident in _identifiers(tree):
            if any(ident.startswith(p) for p in FORBIDDEN_PREFIXES):
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


def test_no_master_kubeconfig_usage():
    """~/.kube/config 참조는 '사용 금지 검증' 목적의 두 파일에서만 허용된다."""
    allowed = {SRC / "config.py", PROJECT_ROOT / "local-verify" / "guard-check.sh"}
    targets = list(SRC.rglob("*.py")) + list((PROJECT_ROOT / "local-verify").glob("*.sh"))
    hits = [
        str(p)
        for p in targets
        if p not in allowed and ".kube/config" in p.read_text(encoding="utf-8")
    ]
    assert not hits, f"마스터 kubeconfig 경로 참조 발견: {hits}"


def test_forbidden_verbs_never_registrable():
    """금지 verb는 도구 등록 단계에서부터 거부된다."""
    import pytest

    from src.tools import verb_validator

    for verb in ("create", "delete", "patch", "replace", "exec", "scale", "apply"):
        with pytest.raises(ValueError):
            verb_validator.register_tool(f"evil_{verb}_tool", verb, "pods")
