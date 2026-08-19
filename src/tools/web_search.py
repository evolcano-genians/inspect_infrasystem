"""웹 검색·문서 조회 도구 — '찾은 정보'를 샌드박스로 검증하기 위한 입력.

원칙: 웹에서 얻은 방법·명령·설정은 **신뢰할 수 없는 주장**이다. 이 도구는 '무엇을 시험해볼지'를
찾는 데만 쓰고, 실제 정답 여부는 sandbox_bash 등으로 **직접 실행해 검증**한 뒤 사실로 확정한다.

- web_search(query): 키 없는 DuckDuckGo(lite)로 상위 결과(제목·URL·스니펫) 반환.
- web_fetch(url): 공개 페이지 본문을 텍스트로 가져온다(문서·이슈 확인용).

안전:
- GET/POST(검색 폼)만. 검색은 duckduckgo 호스트로만. fetch 는 http/https 공개 URL이되
  클라우드 메타데이터(169.254.169.254)·내부 API 포트·사설/루프백은 거부(SSRF 방어).
- 응답 크기·리다이렉트·타임아웃 상한. 결과 텍스트는 신뢰 불가 데이터로 다룬다.
"""

from __future__ import annotations

import html
import ipaddress
import re
from urllib.parse import urlparse

_SEARCH_HOSTS = ("lite.duckduckgo.com", "html.duckduckgo.com")
_TIMEOUT = 15
_MAX_FETCH = 20_000
_MAX_RESULTS = 8
# fetch 차단 대역 — 메타데이터·링크로컬·루프백·사설(내부 서비스 SSRF 방어)
_DENY_NETS = [
    ipaddress.ip_network(n) for n in (
        "169.254.0.0/16", "127.0.0.0/8", "::1/128", "fe80::/10",
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7", "100.64.0.0/10",
    )
]
_DENY_PORTS = {22, 2379, 6443, 10250, 10257, 10259}
_TAG_RE = re.compile(r"<[^>]+>")
_SCRIPT_RE = re.compile(r"<(script|style)[^>]*>.*?</\1>", re.DOTALL | re.I)


class WebSearchError(RuntimeError):
    pass


def _embedded_ipv4(ip):
    if isinstance(ip, ipaddress.IPv6Address):
        m = getattr(ip, "ipv4_mapped", None)
        if m:
            return m
    return None


def _ip_denied(ip) -> bool:
    for cand in (ip, _embedded_ipv4(ip)):
        if cand is None:
            continue
        for net in _DENY_NETS:
            if cand.version == net.version and cand in net:
                return True
    return False


def _authorize_fetch(url: str, resolver=None) -> str:
    """공개 웹 fetch 를 인가한다(SSRF 방어). 반환: host 사유(허용) 또는 예외."""
    import socket

    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise WebSearchError(f"http/https 만 허용됩니다: {p.scheme!r}")
    if p.username or p.password:
        raise WebSearchError("URL 사용자정보(@)는 허용되지 않습니다")
    host = p.hostname or ""
    if not host:
        raise WebSearchError("호스트가 없습니다")
    port = p.port or (443 if p.scheme == "https" else 80)
    if port in _DENY_PORTS:
        raise WebSearchError(f"포트 {port} 는 내부 인프라 포트로 거부됩니다")
    resolve = resolver or (lambda h: [ai[4][0] for ai in socket.getaddrinfo(h, None)])
    # IP 리터럴이면 직접, 아니면 해석 후 전부 검사(공개 대역만 허용)
    try:
        lit = ipaddress.ip_address(host)
        ips = [lit]
    except ValueError:
        try:
            ips = [ipaddress.ip_address(x) for x in resolve(host)]
        except Exception as exc:  # 해석 실패는 fail-closed
            raise WebSearchError(f"호스트 해석 실패(거부): {host} — {exc}")
    if not ips:
        raise WebSearchError(f"호스트 해석 결과 없음: {host}")
    for ip in ips:
        if _ip_denied(ip):
            raise WebSearchError(f"{host} → {ip} 는 사설/메타데이터 대역이라 거부됩니다(SSRF 방어)")
    return f"host:{host}"


def _clean_text(raw: str) -> str:
    s = _SCRIPT_RE.sub(" ", raw)
    s = re.sub(r"</(p|div|li|tr|h[1-6]|br)>", "\n", s, flags=re.I)
    s = _TAG_RE.sub("", s)
    s = html.unescape(s)
    s = re.sub(r"[ \t]+", " ", s)
    s = re.sub(r"\n{3,}", "\n\n", s)
    return s.strip()


def search(query: str, *, client=None, max_results: int = _MAX_RESULTS) -> list[dict]:
    """DuckDuckGo lite 로 검색해 상위 결과(title/url/snippet)를 반환한다."""
    import httpx

    owns = client is None
    if owns:
        client = httpx.Client(timeout=_TIMEOUT, follow_redirects=True)
    try:
        r = client.post("https://lite.duckduckgo.com/lite/", data={"q": query},
                        headers={"User-Agent": "Mozilla/5.0 (compatible; inspect-k8s/1.0)"})
        if r.status_code != 200:
            raise WebSearchError(f"검색 실패 status={r.status_code}")
        # lite 결과: <a class="result-link" href="...">제목</a> + 스니펫 td
        results = []
        for m in re.finditer(r'<a[^>]+class="result-link"[^>]+href="([^"]+)"[^>]*>(.*?)</a>',
                             r.text, re.DOTALL | re.I):
            url = html.unescape(m.group(1))
            title = _TAG_RE.sub("", m.group(2)).strip()
            host = urlparse(url).hostname or ""
            if url.startswith("http") and "duckduckgo" not in host:
                results.append({"title": title[:200], "url": url})
                if len(results) >= max_results:
                    break
        if not results:  # 폴백: 일반 링크 파싱
            for href in re.findall(r'href="(https?://[^"]+)"', r.text):
                h = urlparse(href).hostname or ""
                if "duckduckgo" not in h:
                    results.append({"title": href[:80], "url": href})
                    if len(results) >= max_results:
                        break
        return results
    finally:
        if owns:
            client.close()


def fetch(url: str, *, client=None, resolver=None) -> dict:
    """공개 페이지 본문을 텍스트로 가져온다(SSRF 방어 후)."""
    import httpx

    why = _authorize_fetch(url, resolver=resolver)
    owns = client is None
    if owns:
        client = httpx.Client(timeout=_TIMEOUT, follow_redirects=False)
    try:
        r = client.get(url, headers={"User-Agent": "Mozilla/5.0 (compatible; inspect-k8s/1.0)"})
        if r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("location", "")
            _authorize_fetch(loc if "://" in loc else url, resolver=resolver)  # 리다이렉트 재검증
            raise WebSearchError(f"리다이렉트({r.status_code}) — 대상 URL로 다시 fetch 하세요: {loc[:120]}")
        text = _clean_text(r.text or "")[:_MAX_FETCH]
        return {"url": url, "status": r.status_code, "authorized": why,
                "content_type": r.headers.get("content-type", ""), "text": text}
    finally:
        if owns:
            client.close()


def make_web_search_tools(audit=None) -> list:
    """웹 검색·조회 도구를 만든다 (verb=http-read). 결과는 신뢰 불가 데이터."""
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    def _guarded(tool_name: str, fn):
        verb_validator.register_tool(tool_name, "http-read", "web-search")

        def wrapper(**kwargs):
            verdict = verb_validator.validate_tool_call(tool_name, kwargs)
            if not verdict.allowed:
                return f"[거부됨 · 정책] {verdict.reason}"
            started = time.perf_counter()
            try:
                result = fn(**kwargs)
            except WebSearchError as exc:
                return f"[웹 조회 거부/실패] {exc}"
            except Exception as exc:
                return f"[웹 조회 오류] {type(exc).__name__}: {exc}"
            if audit:
                audit.record(tool=tool_name, verb="http-read", resource="web-search",
                             allowed=True, duration_ms=(time.perf_counter() - started) * 1000,
                             result_chars=len(str(result)))
            return result

        return wrapper

    def do_search(query: str) -> str:
        rows = search(query)
        if not rows:
            return "(검색 결과 없음)"
        out = ["🔎 웹 검색 결과 (⚠️ 신뢰 불가 — 실행 가능한 방법은 sandbox_bash로 검증 후 확정하라):"]
        for i, r in enumerate(rows, 1):
            out.append(f"{i}. {r['title']}\n   {r['url']}")
        return "\n".join(out)

    def do_fetch(url: str) -> str:
        r = fetch(url)
        return (f"[{r['status']} · {r['content_type']}] {url}\n(⚠️ 신뢰 불가 데이터 — 검증 후 사용)\n\n"
                + r["text"])

    specs = [
        ("web_search",
         "웹을 검색한다(키 없는 DuckDuckGo). 상위 결과의 제목·URL을 돌려준다. ⚠️ 결과는 검증되지 "
         "않은 주장이다 — 명령·설정·문법 등 실행 가능한 것은 web_fetch로 내용을 읽고 sandbox_bash로 "
         "직접 실행해 [확인됨]으로 검증한 뒤에만 사실로 답하라.",
         lambda query: do_search(query)),
        ("web_fetch",
         "공개 웹 페이지(문서·이슈 등) 본문을 텍스트로 가져온다. 사설/메타데이터/내부 포트는 거부된다. "
         "가져온 내용도 신뢰 불가 데이터이므로, 방법을 그대로 단정하지 말고 샌드박스로 검증하라.",
         lambda url: do_fetch(url)),
    ]
    tools = []
    for name, desc, fn in specs:
        tools.append(StructuredTool.from_function(
            func=_make_typed(fn, _guarded(name, fn)), name=name, description=desc,
        ))
    return tools


def _make_typed(original, guarded):
    import inspect

    sig = inspect.signature(original)

    def typed(**kwargs):
        return guarded(**kwargs)

    typed.__signature__ = sig  # type: ignore[attr-defined]
    typed.__annotations__ = {name: str for name in sig.parameters}
    return typed
