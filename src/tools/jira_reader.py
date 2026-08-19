"""Jira read-only 조회 도구 — 코드 리뷰 시 이슈(CL-1415 등) 내용을 참고한다.

설계 (기존 read-only 통합 4종과 동일 원칙):
1. **구조적 read-only**: JiraClient 는 GET 조회 메서드(get_issue/get_comments/search)만 노출한다.
   POST/PUT/DELETE 를 보내는 범용 request() 가 존재하지 않는다 — 이슈 생성·수정·전이·댓글
   작성은 도구 자체가 없다. (k8s 파사드가 list_/get_ 만 바인딩하는 것과 같은 구조.)
2. **자격증명 격리**: base_url·토큰은 .env(JIRA_*)로만 주입하고, repr·로그·오류에서 마스킹한다.
   토큰 하드코딩·URL 노출 없음. JIRA_BASE_URL 미설정이면 도구가 아예 조립되지 않는다(opt-in).
3. **호스트 잠금**: 설정된 Jira 호스트로만 요청하고, 타 호스트로의 리다이렉트는 따르지 않는다.
4. **레다크션**: 이슈 설명·댓글에 섞인 시크릿은 출력 전에 redact_text 로 제거한다.
5. **인증 방식**: Jira Server/DC 는 PAT(Bearer), Cloud/basic 은 user+token. JIRA_USER 유무로 자동 선택.

리뷰 흐름과의 연계: CL-1678 처럼 SVN helm 변경 리뷰 이슈는 **댓글에 바뀐 리비전(r####)**이
적혀 있다. get_issue 는 댓글을 함께 가져오고 본문에서 리비전/CL 참조를 추출해, 리뷰어가
src_repo_log/src_read_file 로 실제 SVN 변경을 대조하도록 돕는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ISSUE_KEY_RE = re.compile(r"\b([A-Z][A-Z0-9]+-\d+)\b")
_BROWSE_RE = re.compile(r"/browse/([A-Z][A-Z0-9]+-\d+)")
# 댓글·본문에서 SVN 리비전을 뽑는다 (리뷰 대상 변경 추적용).
# 실제 커밋 알림 댓글은 Fisheye 링크 형식이다: `*Revision:* [7797|https://fisheye…/?cs=7797]`
# → 키워드와 숫자 사이의 `:`/`*`/`[`/공백을 폭넓게 허용해야 잡힌다. `r7797` 형태도 함께 지원.
_REVISION_RE = re.compile(
    r"\br(\d{2,7})\b"                                        # r7797
    r"|\b(?:revision|리비전|rev)\b[\s:#*\[\]]*(\d{2,7})\b"    # *Revision:* [7797|…]
    r"|[?&]cs=(\d{2,7})\b",                                  # fisheye …/?cs=7797
    re.IGNORECASE,
)
# 커밋 알림 댓글의 Diffstat 블록 — 실제 변경된 파일 경로가 여기 있다(리뷰 범위의 핵심).
_DIFFSTAT_RE = re.compile(r"\{noformat\}(.*?)(?:\{noformat\}|$)", re.DOTALL)
_PATH_LINE_RE = re.compile(r"^\s*([A-Za-z0-9._/\-]+/[A-Za-z0-9._/\-]+)\s*\|")
_MAX_OUTPUT = 24_000
_TIMEOUT = 20


class JiraError(RuntimeError):
    pass


@dataclass
class JiraConfig:
    base_url: str
    token: str = ""
    user: str = ""             # 있으면 basic auth, 없으면 Bearer(PAT)
    cookie: str = ""           # SSO 전용 인스턴스용 세션 쿠키 폴백(브라우저에서 복사)
    verify_tls: bool = True
    field_names: dict = field(default_factory=dict)

    def auth_kind(self) -> str:
        if self.cookie:
            return "cookie"
        if self.user:
            return "basic"
        if self.token:
            return "bearer"
        return "none"

    def __repr__(self) -> str:  # 자격증명 유출 방지
        return f"JiraConfig(base_url={self.base_url!r}, auth={self.auth_kind()})"


def extract_issue_key(url_or_key: str) -> str:
    """browse URL 또는 원시 키에서 이슈 키(CL-1415)를 추출·검증한다."""
    s = (url_or_key or "").strip()
    m = _BROWSE_RE.search(s)
    if m:
        return m.group(1)
    m = _ISSUE_KEY_RE.fullmatch(s) or _ISSUE_KEY_RE.search(s)
    if m:
        return m.group(1)
    raise JiraError(f"이슈 키를 찾을 수 없습니다: {url_or_key!r} (예: CL-1415 또는 .../browse/CL-1415)")


def find_revisions(text: str) -> list[str]:
    """텍스트에서 SVN 리비전(r####)·리비전 번호를 중복 없이 뽑는다."""
    out: list[str] = []
    for m in _REVISION_RE.finditer(text or ""):
        rev = m.group(1) or m.group(2) or m.group(3)
        if rev and f"r{rev}" not in out:
            out.append(f"r{rev}")
    return out


def find_changed_paths(text: str, limit: int = 40) -> list[str]:
    """커밋 알림 댓글의 Diffstat 블록에서 변경된 파일 경로를 뽑는다.

    Fisheye 알림 댓글은 `{noformat}경로 | 변경량{noformat}` 형태로 변경 파일을 나열한다.
    이 목록이 곧 **리뷰해야 할 범위**라, 리뷰어가 src_read_file 로 바로 열어볼 수 있게 한다.
    """
    paths: list[str] = []
    for block in _DIFFSTAT_RE.findall(text or ""):
        for line in block.splitlines():
            m = _PATH_LINE_RE.match(line)
            if m:
                p = m.group(1)
                if p not in paths:
                    paths.append(p)
                    if len(paths) >= limit:
                        return paths
    return paths


def _adf_or_text(value) -> str:
    """설명 필드가 문자열(Server/DC 위키마크업) 또는 ADF(dict, Cloud)일 수 있다 — 텍스트만 뽑는다."""
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    # ADF: {content:[{content:[{type:text,text:...}]}]}
    parts: list[str] = []

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "text" and isinstance(node.get("text"), str):
                parts.append(node["text"])
            for v in node.get("content", []) or []:
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(value)
    return "\n".join(parts)


class JiraClient:
    """설정된 Jira 인스턴스에 read-only(GET) 조회만 수행하는 핸들."""

    def __init__(self, config: JiraConfig, *, client=None):
        from urllib.parse import urlparse

        if not config.base_url:
            raise JiraError("JIRA_BASE_URL 이 설정되지 않았습니다")
        self.config = config
        self._base = config.base_url.rstrip("/")
        self._host = urlparse(self._base).hostname
        self._client = client  # 테스트 주입용

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.config.cookie:  # SSO 세션 쿠키 폴백 (PAT 미지원 인스턴스)
            h["Cookie"] = self.config.cookie
        elif self.config.user:  # basic
            import base64
            raw = f"{self.config.user}:{self.config.token}".encode()
            h["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        elif self.config.token:  # PAT bearer (권장)
            h["Authorization"] = "Bearer " + self.config.token
        return h

    def _auth_hint(self, status: int) -> str:
        """401/403 에 대해 '무엇을 고쳐야 하는지'까지 알려준다.

        가장 흔한 실수: Atlassian **Cloud** API 토큰(`ATATT...`)을 Bearer 로 보내는 것.
        Cloud 는 반드시 `이메일 + API 토큰` basic 인증을 요구한다(PAT Bearer 는 Server/DC 전용).
        """
        kind = self.config.auth_kind()
        cloud_token = self.config.token.startswith("ATATT")
        if kind == "none":
            return f"인증 정보 없음({status}) — JIRA_TOKEN 을 설정하세요"
        if cloud_token and kind == "bearer":
            return (
                f"인증 실패({status}) — 토큰이 Atlassian **Cloud** API 토큰(ATATT…)인데 "
                "Bearer 로 전송되었습니다. Cloud 는 '이메일 + API 토큰' basic 인증만 받습니다. "
                "설정에서 **User** 칸에 Atlassian 계정 이메일을 입력하세요 "
                "(Bearer PAT 는 Jira Server/DC 전용)."
            )
        if kind == "basic":
            return (f"인증 실패({status}) — 이메일(JIRA_USER)과 API 토큰 조합을 확인하세요. "
                    "Cloud 토큰은 https://id.atlassian.com/manage-profile/security/api-tokens 에서 발급합니다.")
        if kind == "cookie":
            return f"인증 실패({status}) — 세션 쿠키가 만료되었을 수 있습니다. 브라우저에서 다시 복사하세요."
        return (f"인증 실패({status}) — 토큰/권한을 확인하세요. Server/DC 는 PAT(Bearer), "
                "Cloud 는 이메일+API토큰(basic) 입니다.")

    def _get(self, path: str, params: dict | None = None) -> dict:
        """GET 만 수행한다. 호스트 잠금 + 리다이렉트 미추종(호스트 이탈 방지)."""
        from urllib.parse import urlparse

        url = f"{self._base}{path}"
        client = self._client
        owns = False
        if client is None:
            import httpx
            client = httpx.Client(timeout=_TIMEOUT, verify=self.config.verify_tls,
                                  follow_redirects=False)
            owns = True
        try:
            resp = client.get(url, params=params or {}, headers=self._headers())
            # 리다이렉트가 오면 타 호스트 유출 위험 — 따라가지 않고 거부
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if loc and urlparse(loc).hostname not in (None, self._host):
                    raise JiraError(f"타 호스트로의 리다이렉트를 거부했습니다: {urlparse(loc).hostname}")
                raise JiraError(f"예상치 못한 리다이렉트(status={resp.status_code})")
            if resp.status_code in (401, 403):
                raise JiraError(self._auth_hint(resp.status_code))
            if resp.status_code == 404:
                raise JiraError("이슈/리소스를 찾을 수 없습니다(404)")
            if resp.status_code >= 400:
                raise JiraError(f"Jira 오류 status={resp.status_code}")
            return resp.json()
        finally:
            if owns:
                client.close()

    def get_issue(self, key: str) -> dict:
        fields = ("summary,description,issuetype,status,priority,assignee,reporter,"
                  "labels,components,fixVersions,created,updated,issuelinks,subtasks")
        data = self._get(f"/rest/api/2/issue/{key}", {"fields": fields})
        f = data.get("fields", {}) or {}

        def name_of(v):
            return (v or {}).get("name") or (v or {}).get("displayName") or ""

        return {
            "key": data.get("key", key),
            "summary": f.get("summary", ""),
            "type": name_of(f.get("issuetype")),
            "status": name_of(f.get("status")),
            "priority": name_of(f.get("priority")),
            "assignee": name_of(f.get("assignee")),
            "reporter": name_of(f.get("reporter")),
            "labels": f.get("labels", []) or [],
            "components": [name_of(c) for c in (f.get("components") or [])],
            "fix_versions": [name_of(v) for v in (f.get("fixVersions") or [])],
            "created": f.get("created", ""),
            "updated": f.get("updated", ""),
            "description": _adf_or_text(f.get("description")),
            "links": [
                (name_of(l.get("type")) + ": " +
                 (l.get("outwardIssue") or l.get("inwardIssue") or {}).get("key", ""))
                for l in (f.get("issuelinks") or [])
            ],
            "subtasks": [s.get("key", "") for s in (f.get("subtasks") or [])],
        }

    def get_comments(self, key: str, max_comments: int = 30) -> list[dict]:
        data = self._get(f"/rest/api/2/issue/{key}/comment", {"maxResults": max_comments})
        out = []
        for c in (data.get("comments") or [])[:max_comments]:
            out.append({
                "author": (c.get("author") or {}).get("displayName", ""),
                "created": c.get("created", ""),
                "body": _adf_or_text(c.get("body")),
            })
        return out

    def search(self, jql: str, max_results: int = 20) -> list[dict]:
        data = self._get("/rest/api/2/search",
                         {"jql": jql, "maxResults": max(1, min(int(max_results), 50)),
                          "fields": "summary,status,issuetype,assignee,updated"})
        out = []
        for it in (data.get("issues") or []):
            f = it.get("fields", {}) or {}
            out.append({
                "key": it.get("key", ""),
                "summary": f.get("summary", ""),
                "status": ((f.get("status") or {}).get("name") or ""),
                "type": ((f.get("issuetype") or {}).get("name") or ""),
                "updated": f.get("updated", ""),
            })
        return out


def load_jira_config(env: dict) -> JiraConfig | None:
    """환경변수에서 Jira 설정을 만든다. JIRA_BASE_URL 없으면 None(도구 비활성)."""
    base = (env.get("JIRA_BASE_URL") or "").strip()
    if not base:
        return None
    return JiraConfig(
        base_url=base,
        token=(env.get("JIRA_TOKEN") or "").strip(),
        user=(env.get("JIRA_USER") or "").strip(),
        cookie=(env.get("JIRA_COOKIE") or "").strip(),
        verify_tls=str(env.get("JIRA_VERIFY_TLS", "1")).strip().lower() not in ("0", "false", "no"),
    )


def make_jira_tools(config: JiraConfig, audit=None, redactor=None) -> list:
    """Jira read-only 조회 도구를 만든다 (verb 는 전부 jira-read)."""
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    client = JiraClient(config)
    _redact = redactor or (lambda s: s)

    def _guarded(tool_name: str, fn):
        verb_validator.register_tool(tool_name, "jira-read", "jira")

        def wrapper(**kwargs):
            verdict = verb_validator.validate_tool_call(tool_name, kwargs)
            if not verdict.allowed:
                if audit:
                    audit.record(tool=tool_name, verb="jira-read", resource="jira",
                                 allowed=False, reason=verdict.reason)
                return f"[거부됨 · read-only 정책] {verdict.reason}"
            started = time.perf_counter()
            try:
                result = fn(**kwargs)
            except JiraError as exc:
                if audit:
                    audit.record(tool=tool_name, verb="jira-read", resource="jira",
                                 allowed=False, reason=str(exc))
                return f"[Jira 조회 실패] {exc}"
            except Exception as exc:
                return f"[Jira 조회 오류] {type(exc).__name__}: {exc}"
            if audit:
                audit.record(tool=tool_name, verb="jira-read", resource="jira", allowed=True,
                             duration_ms=(time.perf_counter() - started) * 1000,
                             result_chars=len(str(result)))
            return result

        return wrapper

    def get_issue(key: str) -> str:
        k = extract_issue_key(key)
        issue = client.get_issue(k)
        comments = client.get_comments(k)
        # 본문+댓글에서 리뷰 대상 SVN 리비전을 추출해 리뷰어가 바로 대조하게 한다
        blob = issue["description"] + "\n" + "\n".join(c["body"] for c in comments)
        revisions = find_revisions(blob)
        changed = find_changed_paths(blob)

        lines = [
            f"# {issue['key']}: {issue['summary']}",
            f"유형={issue['type']} · 상태={issue['status']} · 우선순위={issue['priority']}",
            f"담당={issue['assignee']} · 보고={issue['reporter']} · 갱신={issue['updated']}",
        ]
        if issue["components"]:
            lines.append("컴포넌트: " + ", ".join(issue["components"]))
        if issue["fix_versions"]:
            lines.append("fixVersion: " + ", ".join(issue["fix_versions"]))
        if issue["labels"]:
            lines.append("라벨: " + ", ".join(issue["labels"]))
        if issue["links"]:
            lines.append("링크: " + " / ".join(l for l in issue["links"] if l.strip(": ")))
        if issue["subtasks"]:
            lines.append("하위: " + ", ".join(issue["subtasks"]))
        if revisions:
            lines.append("★ 변경 리비전(댓글의 커밋 알림): " + ", ".join(revisions)
                         + "  → src_repo_log 로 SVN 변경 이력을 대조하라")
        if changed:
            lines.append("★ 변경 파일 " + str(len(changed)) + "개 (리뷰 범위 — src_read_file 로 열어보라):")
            for p in changed[:25]:
                lines.append("   - " + p)
            if len(changed) > 25:
                lines.append(f"   … 외 {len(changed) - 25}개")
        lines.append("\n## 설명\n" + (issue["description"] or "(없음)"))
        if comments:
            lines.append("\n## 댓글 (" + str(len(comments)) + "개)")
            for c in comments:
                lines.append(f"- [{c['author']} · {c['created'][:10]}] {c['body']}")
        text = "\n".join(lines)[:_MAX_OUTPUT]
        return _redact(text)

    def search(jql: str, max_results: int = 20) -> str:
        rows = client.search(jql, max_results)
        if not rows:
            return "(검색 결과 없음)"
        out = ["| 키 | 상태 | 유형 | 요약 |", "|---|---|---|---|"]
        for r in rows:
            out.append(f"| {r['key']} | {r['status']} | {r['type']} | {r['summary'][:80]} |")
        return _redact("\n".join(out))

    specs = [
        ("jira_get_issue",
         "Jira 이슈를 조회한다 (키 또는 https://.../browse/CL-1415 URL). 요약·상태·설명·댓글을 "
         "가져오고, 본문·댓글에서 SVN 리비전(r####)을 추출해 리뷰 대상 변경을 짚어준다. "
         "코드 리뷰 전 이슈의 요구사항·수용 기준·변경 리비전을 파악하는 데 쓴다.",
         lambda key: get_issue(key)),
        ("jira_search",
         "JQL 로 이슈를 검색한다 (읽기 전용, 예: 'project=CL AND status=Open ORDER BY updated DESC'). "
         "관련 티켓·이력을 찾을 때 사용. max_results 로 개수 제한(최대 50).",
         lambda jql, max_results=20: search(jql, max_results)),
    ]

    tools = []
    for name, description, fn in specs:
        tools.append(StructuredTool.from_function(
            func=_make_typed(fn, _guarded(name, fn)), name=name, description=description,
        ))
    return tools


def _make_typed(original, guarded):
    """StructuredTool 스키마 추론을 위해 원본 람다 시그니처를 래퍼에 입힌다."""
    import inspect

    sig = inspect.signature(original)

    def typed(**kwargs):
        return guarded(**kwargs)

    typed.__signature__ = sig  # type: ignore[attr-defined]
    typed.__annotations__ = {
        name: (int if isinstance(p.default, int) and not isinstance(p.default, bool) else str)
        for name, p in sig.parameters.items()
    }
    return typed
