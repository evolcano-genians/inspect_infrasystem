"""FishEye/Crucible read-only 조회 도구 — 코드 리뷰(CRU) 내용을 참고한다.

리뷰 루프의 마지막 조각: Jira 이슈(CL-####)가 "무엇을 왜" 바꿨는지 알려주고, 이 모듈의
Crucible 리뷰(RGA-####)가 "실제로 어떤 파일·리비전이 리뷰되었고 리뷰어가 무엇을 지적했는지"를
알려준다. 두 정보를 합치면 src_* 로 SVN 소스를 열어 대조하고, 격리 환경에서 실증할 수 있다.

설계 (jira_reader 와 동일 원칙):
1. **구조적 read-only**: GET 조회 메서드만 노출한다. 리뷰 생성·코멘트 작성·상태 전이를 보내는
   범용 request() 가 존재하지 않는다.
2. **자격증명 격리**: base_url·계정은 .env(FISHEYE_*)로만 주입하고 repr·오류에서 마스킹한다.
   FISHEYE_BASE_URL 미설정이면 도구가 조립되지 않는다(opt-in).
3. **호스트 잠금**: 설정된 호스트로만 요청하고 타 호스트 리다이렉트는 거부한다.
4. **레다크션**: 리뷰 본문·코멘트의 시크릿은 출력 전에 redact_text 로 제거한다.
5. **인증**: FishEye/Crucible 서버는 HTTP Basic(계정+비밀번호 또는 앱 비밀번호)을 받는다.
   (Atlassian Cloud 의 API 토큰과는 별개 시스템이다 — 같은 토큰이 통하지 않는다.)

verb 는 기존 ``http-read`` 를 재사용하고 인자는 ``key`` 하나만 쓴다 — 새 verb·인자를
추가하지 않으므로 검증층(verb_validator)을 건드리지 않는다.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# 리뷰 키: RGA-2362 / CR-123 등 (프로젝트 접두 + 번호)
_REVIEW_KEY_RE = re.compile(r"\b([A-Z][A-Z0-9]*-\d+)\b")
_CRU_URL_RE = re.compile(r"/cru/([A-Z][A-Z0-9]*-\d+)")
_MAX_OUTPUT = 24_000
_TIMEOUT = 20


class FisheyeError(RuntimeError):
    pass


@dataclass
class FisheyeConfig:
    base_url: str
    user: str = ""
    password: str = ""
    verify_tls: bool = True

    def auth_kind(self) -> str:
        return "basic" if (self.user and self.password) else "none"

    def __repr__(self) -> str:  # 자격증명 유출 방지
        return f"FisheyeConfig(base_url={self.base_url!r}, user={self.user!r}, auth={self.auth_kind()})"


def extract_review_key(url_or_key: str) -> str:
    """Crucible URL 또는 원시 키에서 리뷰 키(RGA-2362)를 추출·검증한다."""
    s = (url_or_key or "").strip()
    m = _CRU_URL_RE.search(s)
    if m:
        return m.group(1)
    m = _REVIEW_KEY_RE.fullmatch(s) or _REVIEW_KEY_RE.search(s)
    if m:
        return m.group(1)
    raise FisheyeError(
        f"리뷰 키를 찾을 수 없습니다: {url_or_key!r} (예: RGA-2362 또는 .../cru/RGA-2362)"
    )


class FisheyeClient:
    """FishEye/Crucible 에 read-only(GET) 조회만 수행하는 핸들."""

    def __init__(self, config: FisheyeConfig, *, client=None):
        from urllib.parse import urlparse

        if not config.base_url:
            raise FisheyeError("FISHEYE_BASE_URL 이 설정되지 않았습니다")
        self.config = config
        self._base = config.base_url.rstrip("/")
        self._host = urlparse(self._base).hostname
        self._client = client  # 테스트 주입용

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.config.user and self.config.password:
            import base64

            raw = f"{self.config.user}:{self.config.password}".encode()
            h["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        return h

    def _get(self, path: str, params: dict | None = None) -> dict:
        """GET 만 수행한다. 호스트 잠금 + 리다이렉트 미추종."""
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
            if resp.status_code in (301, 302, 303, 307, 308):
                loc = resp.headers.get("location", "")
                if loc and urlparse(loc).hostname not in (None, self._host):
                    raise FisheyeError(f"타 호스트로의 리다이렉트를 거부했습니다: {urlparse(loc).hostname}")
                raise FisheyeError(f"예상치 못한 리다이렉트(status={resp.status_code})")
            if resp.status_code in (401, 403):
                kind = self.config.auth_kind()
                if kind == "none":
                    raise FisheyeError(
                        f"인증 정보 없음({resp.status_code}) — FISHEYE_USER/FISHEYE_PASSWORD 를 "
                        "설정하세요. FishEye/Crucible 은 온프레미스 서버라 Atlassian Cloud 의 "
                        "API 토큰과 별개 계정입니다."
                    )
                raise FisheyeError(
                    f"인증 실패({resp.status_code}) — 계정/비밀번호 또는 이 리뷰에 대한 열람 권한을 "
                    "확인하세요."
                )
            if resp.status_code == 404:
                raise FisheyeError("리뷰/리소스를 찾을 수 없습니다(404)")
            if resp.status_code >= 400:
                raise FisheyeError(f"FishEye 오류 status={resp.status_code}")
            return resp.json()
        finally:
            if owns:
                client.close()

    def get_review(self, key: str) -> dict:
        """리뷰 메타(제목·상태·작성자·리뷰어·연결 이슈)를 조회한다."""
        data = self._get(f"/rest-service/reviews-v1/{key}")

        def user_of(v):
            if isinstance(v, dict):
                return v.get("displayName") or v.get("userName") or ""
            return str(v or "")

        reviewers = []
        rs = (data.get("reviewers") or {}).get("reviewer") or []
        if isinstance(rs, dict):
            rs = [rs]
        for r in rs:
            name = user_of(r)
            completed = r.get("completed") if isinstance(r, dict) else None
            reviewers.append(f"{name}{'(완료)' if completed else ''}")

        return {
            "key": (data.get("permaId") or {}).get("id") or key,
            "name": data.get("name", ""),
            "state": data.get("state", ""),
            "author": user_of(data.get("author")),
            "creator": user_of(data.get("creator")),
            "moderator": user_of(data.get("moderator")),
            "reviewers": reviewers,
            "description": data.get("description", "") or "",
            "jira_issue": data.get("jiraIssueKey", "") or "",
            "created": data.get("createDate", ""),
            "due": data.get("dueDate", ""),
        }

    def get_review_items(self, key: str) -> list[dict]:
        """리뷰에 포함된 파일·리비전 목록(=리뷰 범위)을 조회한다."""
        data = self._get(f"/rest-service/reviews-v1/{key}/reviewitems")
        items = data.get("reviewItem") or []
        if isinstance(items, dict):
            items = [items]
        out = []
        for it in items:
            revs = (it.get("expandedRevisions") or it.get("revisions") or {})
            rev_list = revs.get("revisionData") if isinstance(revs, dict) else None
            rev_nums: list[str] = []
            for rd in (rev_list or []):
                r = rd.get("revision") if isinstance(rd, dict) else None
                if r:
                    rev_nums.append(str(r))
            out.append({
                "path": it.get("toPath") or it.get("fromPath") or "",
                "repository": it.get("repositoryName", ""),
                "revisions": rev_nums,
                "type": it.get("commitType", "") or it.get("fileType", ""),
            })
        return out

    def get_comments(self, key: str, max_comments: int = 40) -> list[dict]:
        """리뷰의 일반 코멘트를 조회한다 (리뷰어 지적사항)."""
        data = self._get(f"/rest-service/reviews-v1/{key}/comments")
        raw = data.get("comments") or data.get("generalCommentData") or []
        if isinstance(raw, dict):
            raw = [raw]
        out = []
        for c in raw[:max_comments]:
            if not isinstance(c, dict):
                continue
            user = c.get("user")
            author = (user.get("displayName") or user.get("userName")) if isinstance(user, dict) else str(user or "")
            out.append({
                "author": author,
                "created": c.get("createDate", ""),
                "defect": bool(c.get("defectRaised")),
                "body": c.get("message", "") or "",
            })
        return out


def load_fisheye_config(env: dict) -> FisheyeConfig | None:
    """환경변수에서 FishEye 설정을 만든다. FISHEYE_BASE_URL 없으면 None(도구 비활성)."""
    base = (env.get("FISHEYE_BASE_URL") or "").strip()
    if not base:
        return None
    return FisheyeConfig(
        base_url=base,
        user=(env.get("FISHEYE_USER") or "").strip(),
        password=(env.get("FISHEYE_PASSWORD") or "").strip(),
        verify_tls=str(env.get("FISHEYE_VERIFY_TLS", "1")).strip().lower() not in ("0", "false", "no"),
    )


def make_fisheye_tools(config: FisheyeConfig, audit=None, redactor=None) -> list:
    """Crucible 리뷰 read-only 조회 도구를 만든다 (verb 는 http-read 재사용)."""
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    client = FisheyeClient(config)
    _redact = redactor or (lambda s: s)

    def _guarded(tool_name: str, fn):
        verb_validator.register_tool(tool_name, "http-read", "fisheye")

        def wrapper(**kwargs):
            verdict = verb_validator.validate_tool_call(tool_name, kwargs)
            if not verdict.allowed:
                if audit:
                    audit.record(tool=tool_name, verb="http-read", resource="fisheye",
                                 allowed=False, reason=verdict.reason)
                return f"[거부됨 · read-only 정책] {verdict.reason}"
            started = time.perf_counter()
            try:
                result = fn(**kwargs)
            except FisheyeError as exc:
                if audit:
                    audit.record(tool=tool_name, verb="http-read", resource="fisheye",
                                 allowed=False, reason=str(exc))
                return f"[FishEye 조회 실패] {exc}"
            except Exception as exc:
                return f"[FishEye 조회 오류] {type(exc).__name__}: {exc}"
            if audit:
                audit.record(tool=tool_name, verb="http-read", resource="fisheye", allowed=True,
                             duration_ms=(time.perf_counter() - started) * 1000,
                             result_chars=len(str(result)))
            return result

        return wrapper

    def get_review(key: str) -> str:
        k = extract_review_key(key)
        rv = client.get_review(k)
        items = client.get_review_items(k)
        comments = client.get_comments(k)

        lines = [
            f"# 코드 리뷰 {rv['key']}: {rv['name']}",
            f"상태={rv['state']} · 작성={rv['author'] or rv['creator']} · 중재={rv['moderator']}",
        ]
        if rv["reviewers"]:
            lines.append("리뷰어: " + ", ".join(rv["reviewers"]))
        if rv["jira_issue"]:
            lines.append(f"연결 이슈: {rv['jira_issue']}  → jira_get_issue 로 요구사항을 확인하라")
        if rv["description"]:
            lines.append("\n## 설명\n" + rv["description"])
        if items:
            lines.append(f"\n## 리뷰 대상 파일 {len(items)}개 (리뷰 범위 — src_read_file 로 열어보라)")
            for it in items[:30]:
                revs = ("@" + ",".join("r" + r for r in it["revisions"])) if it["revisions"] else ""
                lines.append(f"- {it['path']}{revs}  [{it['repository']}]")
            if len(items) > 30:
                lines.append(f"… 외 {len(items) - 30}개")
        if comments:
            defects = sum(1 for c in comments if c["defect"])
            lines.append(f"\n## 리뷰 코멘트 {len(comments)}개 (결함 지적 {defects}건)")
            for c in comments:
                mark = "🐞" if c["defect"] else "💬"
                lines.append(f"- {mark} [{c['author']} · {str(c['created'])[:10]}] {c['body']}")
        return _redact("\n".join(lines)[:_MAX_OUTPUT])

    specs = [
        ("fisheye_get_review",
         "Crucible 코드 리뷰를 조회한다 (키 또는 https://fisheye.../cru/RGA-2362 URL). "
         "리뷰 상태·리뷰어·연결 Jira 이슈·리뷰 대상 파일과 리비전·리뷰어 코멘트(결함 지적 포함)를 "
         "가져온다. 코드 리뷰 시 '무엇이 이미 지적되었는지' 파악해 중복을 피하고 남은 문제에 집중하라.",
         lambda key: get_review(key)),
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
    typed.__annotations__ = {name: str for name in sig.parameters}
    return typed
