"""결정론적 verb 검증 미들웨어 — 방어선 2.

도구 실행 직전에 (도구 이름 → verb) 매핑을 화이트리스트와 대조하고 인자 형식을 검사한다.
이 검증은 LLM의 판단이 아니라 순수 결정론적 코드다. 화이트리스트 밖이면 subprocess/API
호출로 절대 넘어가지 않는다.

방어선 1(구조적 배제)이 뚫릴 수 없는 구조이지만, 이중 확인 차원에서 유지한다 (브리프 2.1-2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

#: 허용 verb (브리프 2.2). 이 집합에 없는 verb는 전부 거부된다.
ALLOWED_VERBS: frozenset[str] = frozenset(
    {
        "get",
        "list",
        "watch",
        "describe",
        "logs",
        "top",
        "explain",
        "api-resources",
        "version",
        "cluster-info",
        "ping",
        "source-read",  # SSH 개발 서버 소스 read-only 조회 (source_reader)
        "sandbox-exec",  # 샌드박스 격리 컨테이너 실행 (bash/pentest — 실 인프라 도달 불가)
        "sql-read",  # Trino read-only SQL 조회 (trino_reader — SELECT/SHOW/DESCRIBE만)
        "http-read",  # nexus-shell 로그인 후 read-only HTTP 조회 (shell_http)
        "jira-read",  # Jira 이슈/댓글 read-only 조회 (jira_reader — GET만)
    }
)

#: 명시적 금지 verb — ALLOWED_VERBS에 없으므로 어차피 거부되지만,
#: 거부 사유 메시지를 명확히 하기 위한 목록 (문자열 상수일 뿐, 실행 코드가 아니다).
FORBIDDEN_VERBS: frozenset[str] = frozenset(
    {
        "create", "apply", "delete", "patch", "edit", "replace", "scale",
        "rollout", "cordon", "drain", "uncordon", "exec", "cp", "port-forward",
        "label", "annotate", "install", "upgrade", "uninstall", "set",
    }
)

# RFC 1123 서브도메인 이름 (namespace / 리소스 이름 / 컨테이너 이름)
_DNS_NAME_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,251}[a-z0-9])?$")
# label/field selector에 허용하는 안전 문자 집합 (셸 메타문자·개행 등 배제 — 공백은 스페이스만)
_SELECTOR_RE = re.compile(r"^[A-Za-z0-9_.,=!/\- ()]*$")
# CRD 좌표: group(traefik.io), version(v1alpha1), plural(ingressroutes)
_CRD_TOKEN_RE = re.compile(r"^[a-z0-9]([-a-z0-9.]{0,63}[a-z0-9])?$")

#: 인자 이름 → 검증 방식. 여기 없는 인자는 전부 거부된다 (fail-closed).
_NAME_ARGS = frozenset({"namespace", "name", "container"})
_CRD_ARGS = frozenset({"group", "version", "plural"})
_SELECTOR_ARGS = frozenset({"label_selector", "field_selector"})
_INT_ARGS: dict[str, tuple[int, int]] = {
    "tail_lines": (1, 5000),
    "since_seconds": (0, 7 * 24 * 3600),  # 로그 시간 창: 최대 7일 (0 = 미지정)
    "start": (1, 10_000_000),   # 소스 파일 읽기 시작 줄
    "lines": (1, 2000),         # 소스 파일 읽을 줄 수
    "max_results": (1, 500),    # 소스 검색 결과 상한
    "limit": (1, 100),          # git log 개수
    "max_rows": (1, 100_000),   # trino 조회 행 상한
    "timeout": (1, 1800),       # sandbox_bash 실행 타임아웃(초)
}
_BOOL_ARGS = frozenset({"previous", "include_system", "include_internal"})
# 소스 조회(source_reader) 전용 인자 — SourceHost 내부에서 재검증·shlex 인용된다.
_SOURCE_PATH_ARGS = frozenset({"path"})
_SOURCE_FREE_ARGS = frozenset({"pattern", "glob", "filename"})
_SOURCE_PATH_RE = re.compile(r"^[A-Za-z0-9._/\-~]{1,300}$")
_SOURCE_FREE_RE = re.compile(r"^[^\n'\"`\\]{0,300}$")

# ── 확장 도구(trino/shell_http/sandbox) 인자 ──────────────────────────────
# 원칙: 여기서는 구조적 검증(타입·길이·형식)만 한다. 실제 심층 방어선은 각 도구 내부:
#   trino  → assert_readonly_sql (SELECT/SHOW/DESCRIBE만), _ident (식별자 인젝션 차단)
#   sandbox→ BashSandbox Docker 격리 + _is_sandbox_target (루프백/사설/.test만)
#   shell  → Keycloak 로그인 후 GET-only + 호스트 화이트리스트
# 따라서 fail-closed 대상에서 빼되, 셸/제어문자·과길이만 결정론적으로 배제한다.
_TRINO_IDENT_ARGS = frozenset({"catalog", "schema", "table", "column"})
_TRINO_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")  # trino_reader._IDENT_RE 와 동일
_ENVNAME_ARGS = frozenset({"env"})              # shell_http 환경 키 (SHELL_<NAME>_*)
_ENVNAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_TARGET_ARGS = frozenset({"target"})            # strix 대상 — _is_sandbox_target 이 실검증
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:/\-~]{1,300}$")
_ENUM_ARGS: dict[str, frozenset[str]] = {
    "mode": frozenset({"", "quick", "standard", "deep"}),
    # web_test: HTTP 메서드 — 대소문자 허용을 열어두고 정규화는 도구가 수행(GET/HEAD 로 강제).
    "method": frozenset({"", "GET", "HEAD", "get", "head"}),
}
# ── 웹 테스팅 도구(web_test) 인자 ──────────────────────────────────────────
# url 은 여기서 형식(http/https·셸/따옴표/공백 메타문자 배제·길이상한)만 본다.
# 실 SSRF 인가는 도구 내부 게이트(_authorize_web_target)가 수행한다(strix/jira 와 동형).
_URL_ARGS = frozenset({"url"})
_URL_RE = re.compile(r"^https?://[A-Za-z0-9._~:/?#\[\]@!$&()*+,;=%\-]{3,2000}$", re.I)
# 멀티 클러스터 비교(multicluster) 인자 — 실검증은 도구 내부(컨텍스트 dict·resource enum)
_CONTEXT_ARGS = frozenset({"context"})          # 비교 대상 컨텍스트명 (kube context)
_CONTEXT_RE = re.compile(r"^[A-Za-z0-9_.@:/\-]{1,253}$")
_RESOURCE_ARGS = frozenset({"resource"})        # 비교 리소스 종류 (list_* 매핑 키)
_RESOURCE_RE = re.compile(r"^[a-z]{1,32}$")
# 자유 텍스트 인자 → 길이 상한만. 실검증은 도구 내부(SQL 파서·샌드박스 격리)가 수행.
_FREETEXT_ARGS: dict[str, int] = {"sql": 20_000, "command": 10_000, "instruction": 2_000,
                                  "jql": 2_000}
# Jira 이슈 키(또는 browse URL) — jira_reader 내부에서 키를 재추출·검증한다.
_JIRA_KEY_ARGS = frozenset({"key"})
_JIRA_KEY_RE = re.compile(r"^[A-Za-z0-9:/._\-]{1,200}$")  # 키 또는 https://.../browse/KEY


@dataclass(frozen=True)
class ToolSpec:
    """등록된 read-only 도구의 명세."""

    name: str
    verb: str
    resource: str


@dataclass(frozen=True)
class ValidationResult:
    allowed: bool
    reason: str
    spec: ToolSpec | None = None


# 도구 레지스트리: k8s_read.make_tools()가 도구를 만들면서 등록한다.
# 여기 등록되지 않은 도구 이름은 무조건 거부된다.
_REGISTRY: dict[str, ToolSpec] = {}


def register_tool(name: str, verb: str, resource: str) -> ToolSpec:
    """read-only 도구를 레지스트리에 등록한다. 금지 verb는 등록 자체가 불가능하다."""
    if verb not in ALLOWED_VERBS:
        raise ValueError(
            f"도구 '{name}' 등록 거부: verb '{verb}' 는 허용 목록에 없습니다. "
            f"허용: {sorted(ALLOWED_VERBS)}"
        )
    spec = ToolSpec(name=name, verb=verb, resource=resource)
    _REGISTRY[name] = spec
    return spec


def registered_tools() -> dict[str, ToolSpec]:
    return dict(_REGISTRY)


def _validate_arg(key: str, value: object) -> str | None:
    """인자 하나를 검증한다. 문제 있으면 사유 문자열, 없으면 None."""
    if key in _NAME_ARGS:
        if value in ("", None):
            return None  # 선택적 이름 인자 (예: container="")
        if not isinstance(value, str) or not _DNS_NAME_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 K8s 이름(RFC1123)이 아닙니다"
        return None
    if key in _CRD_ARGS:
        if not isinstance(value, str) or not _CRD_TOKEN_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 CRD 좌표(group/version/plural)가 아닙니다"
        return None
    if key in _SOURCE_PATH_ARGS:
        if not isinstance(value, str) or ".." in value or not _SOURCE_PATH_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 소스 경로가 아닙니다(.. 금지)"
        return None
    if key in _SOURCE_FREE_ARGS:
        if value in ("", None):
            return None
        if not isinstance(value, str) or not _SOURCE_FREE_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 에 허용되지 않는 문자가 있습니다(셸 메타문자 금지)"
        return None
    if key in _SELECTOR_ARGS:
        if value in ("", None):
            return None
        if not isinstance(value, str) or not _SELECTOR_RE.match(value) or len(value) > 512:
            return f"인자 '{key}' 값 {value!r} 에 허용되지 않는 문자가 있습니다"
        return None
    if key in _INT_ARGS:
        low, high = _INT_ARGS[key]
        if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
            return f"인자 '{key}' 값 {value!r} 은 {low}..{high} 범위의 정수여야 합니다"
        return None
    if key in _BOOL_ARGS:
        if not isinstance(value, bool):
            return f"인자 '{key}' 값 {value!r} 은 불리언이어야 합니다"
        return None
    if key in _TRINO_IDENT_ARGS:
        if not isinstance(value, str) or not _TRINO_IDENT_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 Trino 식별자가 아닙니다"
        return None
    if key in _ENVNAME_ARGS:
        if not isinstance(value, str) or not _ENVNAME_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 환경 키가 아닙니다"
        return None
    if key in _TARGET_ARGS:
        if not isinstance(value, str) or not _TARGET_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 대상(host/URL)이 아닙니다"
        return None
    if key in _ENUM_ARGS:
        if value not in _ENUM_ARGS[key]:
            return f"인자 '{key}' 값 {value!r} 은 {sorted(_ENUM_ARGS[key])} 중 하나여야 합니다"
        return None
    if key in _CONTEXT_ARGS:
        if not isinstance(value, str) or not _CONTEXT_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 컨텍스트명이 아닙니다"
        return None
    if key in _RESOURCE_ARGS:
        if not isinstance(value, str) or not _RESOURCE_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 리소스 종류가 아닙니다"
        return None
    if key in _FREETEXT_ARGS:
        cap = _FREETEXT_ARGS[key]
        if value in ("", None):
            return None  # instruction 등 선택적 자유 텍스트
        if not isinstance(value, str) or len(value) > cap:
            return f"인자 '{key}' 는 {cap}자 이하의 문자열이어야 합니다"
        return None
    if key in _JIRA_KEY_ARGS:
        if not isinstance(value, str) or not _JIRA_KEY_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 Jira 이슈 키/URL 이 아닙니다"
        return None
    if key in _URL_ARGS:
        if not isinstance(value, str) or not _URL_RE.match(value):
            return f"인자 '{key}' 값 {value!r} 이 유효한 http/https URL 이 아닙니다"
        return None
    return f"알 수 없는 인자 '{key}' (fail-closed 거부)"


def validate_tool_call(tool_name: str, args: dict | None) -> ValidationResult:
    """도구 호출 1건을 결정론적으로 검증한다.

    시간 복잡도 O(인자 수 × 인자 길이). LLM·네트워크·subprocess 미개입.
    """
    spec = _REGISTRY.get(tool_name)
    if spec is None:
        lowered = tool_name.lower()
        hit = next((v for v in sorted(FORBIDDEN_VERBS) if v.replace("-", "_") in lowered or v in lowered), None)
        if hit:
            return ValidationResult(
                False,
                f"도구 '{tool_name}' 거부: 금지 verb '{hit}' 계열 도구는 존재하지 않으며 노출되지 않습니다",
            )
        return ValidationResult(False, f"도구 '{tool_name}' 거부: 등록되지 않은 도구입니다")

    if spec.verb not in ALLOWED_VERBS:  # register_tool이 이미 막지만 이중 확인
        return ValidationResult(False, f"도구 '{tool_name}' 거부: verb '{spec.verb}' 미허용", spec)

    if "secret" in spec.resource.lower():
        return ValidationResult(False, f"도구 '{tool_name}' 거부: Secret 리소스는 범위 밖입니다", spec)

    for key, value in (args or {}).items():
        problem = _validate_arg(key, value)
        if problem:
            return ValidationResult(False, f"도구 '{tool_name}' 거부: {problem}", spec)

    return ValidationResult(True, "ok", spec)
