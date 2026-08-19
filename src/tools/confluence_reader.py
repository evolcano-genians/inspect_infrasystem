"""Confluence read-only 조회 도구 — 설계 문서·런북을 리뷰·디버깅 근거로 참고한다.

Confluence 는 Jira 와 **같은 Atlassian Cloud 인스턴스**(geni-works.atlassian.net)에 있으므로
**Jira 와 동일한 이메일 + API 토큰**으로 인증된다 — 별도 자격증명이 필요 없다(실측 확인).
따라서 JIRA_USER/JIRA_TOKEN 이 설정돼 있으면 CONFLUENCE_BASE_URL 없이도 자동으로 동작한다.

설계 (jira_reader 와 동일 원칙):
1. **구조적 read-only**: GET 조회 메서드만 노출한다. 페이지 생성·수정·삭제를 보내는 범용
   request() 가 존재하지 않는다.
2. **자격증명 격리**: .env 로만 주입, repr·오류에서 마스킹.
3. **호스트 잠금**: 설정된 호스트로만 요청, 타 호스트 리다이렉트 거부.
4. **레다크션**: 페이지 본문의 시크릿은 출력 전에 redact_text 로 제거한다.

verb 는 기존 ``jira-read`` 를 재사용한다(같은 Atlassian read 계열).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass

_PAGE_ID_RE = re.compile(r"\b(\d{4,20})\b")
# Confluence URL 형태: /wiki/spaces/KEY/pages/123456789/Title  또는 /wiki/pages/viewpage.action?pageId=123
_URL_PAGE_ID_RE = re.compile(r"/pages/(\d+)|[?&]pageId=(\d+)")
_TAG_RE = re.compile(r"<[^>]+>")
_MAX_OUTPUT = 24_000
_TIMEOUT = 20


class ConfluenceError(RuntimeError):
    pass


@dataclass
class ConfluenceConfig:
    base_url: str          # 예: https://geni-works.atlassian.net (뒤에 /wiki 는 붙이지 않는다)
    user: str = ""
    token: str = ""
    verify_tls: bool = True

    def auth_kind(self) -> str:
        return "basic" if (self.user and self.token) else ("bearer" if self.token else "none")

    def __repr__(self) -> str:  # 자격증명 유출 방지
        return f"ConfluenceConfig(base_url={self.base_url!r}, user={self.user!r}, auth={self.auth_kind()})"


def extract_page_id(url_or_id: str) -> str:
    """Confluence URL 또는 원시 페이지 ID를 추출한다."""
    s = (url_or_id or "").strip()
    m = _URL_PAGE_ID_RE.search(s)
    if m:
        return m.group(1) or m.group(2)
    if s.isdigit():
        return s
    raise ConfluenceError(
        f"페이지 ID를 찾을 수 없습니다: {url_or_id!r} "
        "(예: 123456789 또는 https://.../wiki/spaces/KEY/pages/123456789/Title). "
        "제목으로 찾으려면 confluence_search 를 쓰세요."
    )


def storage_to_text(storage_html: str) -> str:
    """Confluence storage(XHTML) 본문에서 읽을 수 있는 텍스트를 뽑는다."""
    if not storage_html:
        return ""
    s = storage_html
    # 블록 경계를 줄바꿈으로 (문단·리스트·표·제목)
    s = re.sub(r"</(p|li|tr|h[1-6]|div|td|th)>", "\n", s, flags=re.I)
    s = re.sub(r"<br\s*/?>", "\n", s, flags=re.I)
    s = _TAG_RE.sub("", s)                      # 남은 태그 제거
    s = html.unescape(s)
    s = re.sub(r"\n{3,}", "\n\n", s)            # 과도한 빈 줄 정리
    return s.strip()


class ConfluenceClient:
    """Confluence 에 read-only(GET) 조회만 수행하는 핸들."""

    def __init__(self, config: ConfluenceConfig, *, client=None):
        from urllib.parse import urlparse

        if not config.base_url:
            raise ConfluenceError("CONFLUENCE_BASE_URL(또는 JIRA_BASE_URL)이 설정되지 않았습니다")
        self.config = config
        self._base = config.base_url.rstrip("/")
        self._host = urlparse(self._base).hostname
        self._client = client

    def _headers(self) -> dict:
        h = {"Accept": "application/json"}
        if self.config.user and self.config.token:
            import base64

            raw = f"{self.config.user}:{self.config.token}".encode()
            h["Authorization"] = "Basic " + base64.b64encode(raw).decode()
        elif self.config.token:
            h["Authorization"] = "Bearer " + self.config.token
        return h

    def _get(self, path: str, params: dict | None = None) -> dict:
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
                    raise ConfluenceError(f"타 호스트로의 리다이렉트를 거부했습니다: {urlparse(loc).hostname}")
                raise ConfluenceError(f"예상치 못한 리다이렉트(status={resp.status_code})")
            if resp.status_code in (401, 403):
                raise ConfluenceError(
                    f"인증/권한 실패({resp.status_code}) — Confluence 는 Jira 와 같은 Atlassian "
                    "Cloud 계정을 씁니다. 이메일(JIRA_USER)+API 토큰(JIRA_TOKEN) 조합과 "
                    "해당 스페이스 열람 권한을 확인하세요."
                )
            if resp.status_code == 404:
                raise ConfluenceError("페이지/리소스를 찾을 수 없습니다(404)")
            if resp.status_code >= 400:
                raise ConfluenceError(f"Confluence 오류 status={resp.status_code}")
            return resp.json()
        finally:
            if owns:
                client.close()

    def get_page(self, page_id: str) -> dict:
        data = self._get(f"/wiki/rest/api/content/{page_id}",
                         {"expand": "body.storage,version,space,ancestors"})
        body = ((data.get("body") or {}).get("storage") or {}).get("value", "")
        return {
            "id": data.get("id", page_id),
            "title": data.get("title", ""),
            "space": ((data.get("space") or {}).get("name") or ""),
            "space_key": ((data.get("space") or {}).get("key") or ""),
            "version": ((data.get("version") or {}).get("number") or ""),
            "updated": ((data.get("version") or {}).get("when") or ""),
            "updated_by": (((data.get("version") or {}).get("by") or {}).get("displayName") or ""),
            "text": storage_to_text(body),
            "url": f"{self._base}/wiki{(data.get('_links') or {}).get('webui', '')}",
        }

    def search(self, query: str, limit: int = 15) -> list[dict]:
        """텍스트 또는 CQL 로 검색한다. CQL 문법이 아니면 전문 검색으로 감싼다."""
        q = (query or "").strip()
        looks_cql = any(op in q.lower() for op in ("=", "~", " and ", " or ", "type:", "space="))
        cql = q if looks_cql else f'text ~ "{q}"'
        data = self._get("/wiki/rest/api/content/search",
                         {"cql": cql, "limit": max(1, min(int(limit), 50)),
                          "expand": "space,version"})
        out = []
        for r in (data.get("results") or []):
            out.append({
                "id": r.get("id", ""),
                "title": r.get("title", ""),
                "type": r.get("type", ""),
                "space": ((r.get("space") or {}).get("key") or ""),
                "updated": ((r.get("version") or {}).get("when") or "")[:10],
            })
        return out


def load_confluence_config(env: dict) -> ConfluenceConfig | None:
    """환경변수에서 Confluence 설정을 만든다.

    CONFLUENCE_BASE_URL 이 없으면 **JIRA_BASE_URL 을 그대로 재사용**한다 — 같은 Atlassian
    Cloud 인스턴스이므로 별도 설정 없이 동작한다. 자격증명도 Jira 것을 공유한다.
    """
    base = (env.get("CONFLUENCE_BASE_URL") or env.get("JIRA_BASE_URL") or "").strip()
    if not base:
        return None
    # Cloud 커스텀 도메인은 API basic 인증을 거부하는 경우가 있어 /wiki 접미는 제거해 둔다.
    base = base.rstrip("/")
    if base.endswith("/wiki"):
        base = base[: -len("/wiki")]
    user = (env.get("CONFLUENCE_USER") or env.get("JIRA_USER") or "").strip()
    token = (env.get("CONFLUENCE_TOKEN") or env.get("JIRA_TOKEN") or "").strip()
    if not token:
        return None
    return ConfluenceConfig(
        base_url=base, user=user, token=token,
        verify_tls=str(env.get("JIRA_VERIFY_TLS", "1")).strip().lower() not in ("0", "false", "no"),
    )


def make_confluence_tools(config: ConfluenceConfig, audit=None, redactor=None) -> list:
    """Confluence read-only 조회 도구를 만든다 (verb 는 jira-read 재사용)."""
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    client = ConfluenceClient(config)
    _redact = redactor or (lambda s: s)

    def _guarded(tool_name: str, fn):
        verb_validator.register_tool(tool_name, "jira-read", "confluence")

        def wrapper(**kwargs):
            verdict = verb_validator.validate_tool_call(tool_name, kwargs)
            if not verdict.allowed:
                if audit:
                    audit.record(tool=tool_name, verb="jira-read", resource="confluence",
                                 allowed=False, reason=verdict.reason)
                return f"[거부됨 · read-only 정책] {verdict.reason}"
            started = time.perf_counter()
            try:
                result = fn(**kwargs)
            except ConfluenceError as exc:
                if audit:
                    audit.record(tool=tool_name, verb="jira-read", resource="confluence",
                                 allowed=False, reason=str(exc))
                return f"[Confluence 조회 실패] {exc}"
            except Exception as exc:
                return f"[Confluence 조회 오류] {type(exc).__name__}: {exc}"
            if audit:
                audit.record(tool=tool_name, verb="jira-read", resource="confluence", allowed=True,
                             duration_ms=(time.perf_counter() - started) * 1000,
                             result_chars=len(str(result)))
            return result

        return wrapper

    def get_page(key: str) -> str:
        pid = extract_page_id(key)
        p = client.get_page(pid)
        lines = [
            f"# {p['title']}",
            f"스페이스={p['space']}({p['space_key']}) · v{p['version']} · "
            f"갱신={str(p['updated'])[:10]} by {p['updated_by']}",
            f"URL: {p['url']}",
            "",
            p["text"] or "(본문 없음)",
        ]
        return _redact("\n".join(lines)[:_MAX_OUTPUT])

    def search(jql: str, max_results: int = 15) -> str:
        rows = client.search(jql, max_results)
        if not rows:
            return "(검색 결과 없음)"
        out = ["| ID | 스페이스 | 유형 | 갱신 | 제목 |", "|---|---|---|---|---|"]
        for r in rows:
            out.append(f"| {r['id']} | {r['space']} | {r['type']} | {r['updated']} | {r['title'][:70]} |")
        out.append("\n→ confluence_get_page 로 ID를 열어 본문을 읽어라")
        return _redact("\n".join(out))

    specs = [
        ("confluence_get_page",
         "Confluence 페이지를 조회한다 (페이지 ID 또는 https://.../wiki/spaces/KEY/pages/123/Title URL). "
         "설계 문서·런북·아키텍처 문서를 리뷰·디버깅 근거로 읽을 때 사용.",
         lambda key: get_page(key)),
        ("confluence_search",
         "Confluence 를 검색한다. 일반 문장을 넣으면 전문 검색, CQL 문법(예: "
         "'space=CLOUD and title ~ \"helm\"')을 넣으면 그대로 사용한다. 결과의 ID를 "
         "confluence_get_page 에 넣어 본문을 읽어라.",
         lambda jql, max_results=15: search(jql, max_results)),
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
