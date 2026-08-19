"""웹 검색·조회 도구 검증 — 결과 파싱·SSRF 방어·verb 등록 (fake httpx)."""

from __future__ import annotations

import pytest

from src.tools.web_search import (
    WebSearchError,
    _authorize_fetch,
    fetch,
    make_web_search_tools,
    search,
)


class FakeResp:
    def __init__(self, text, status=200, headers=None):
        self.text = text
        self.status_code = status
        self.headers = headers or {"content-type": "text/html"}


class FakeHttp:
    def __init__(self, text="", status=200, headers=None):
        self.text, self.status, self.headers_ = text, status, headers
        self.calls = []

    def post(self, url, data=None, headers=None):
        self.calls.append(("POST", url, data))
        return FakeResp(self.text, self.status, self.headers_)

    def get(self, url, headers=None):
        self.calls.append(("GET", url, None))
        return FakeResp(self.text, self.status, self.headers_)

    def close(self):
        pass


_DDG_HTML = '''
<a class="result-link" href="https://trino.io/docs/current/sql/show-catalogs.html">SHOW CATALOGS</a>
<a class="result-link" href="https://kubernetes.io/docs/x">K8s docs</a>
<a href="https://duckduckgo.com/y">ad</a>
'''


def test_search_parses_results_and_skips_ddg():
    rows = search("trino show catalogs", client=FakeHttp(_DDG_HTML))
    urls = [r["url"] for r in rows]
    assert "https://trino.io/docs/current/sql/show-catalogs.html" in urls
    assert all("duckduckgo" not in u for u in urls)   # 광고/자체 링크 제외
    assert rows[0]["title"] == "SHOW CATALOGS"


def test_fetch_blocks_metadata_and_private(monkeypatch):
    # 메타데이터 IP
    with pytest.raises(WebSearchError, match="SSRF|메타데이터|사설"):
        _authorize_fetch("http://169.254.169.254/latest/meta-data/")
    # 사설(내부 서비스)로 해석되는 도메인
    with pytest.raises(WebSearchError):
        _authorize_fetch("http://internal.test/", resolver=lambda h: ["10.152.130.71"])
    # 내부 API 포트
    with pytest.raises(WebSearchError, match="포트"):
        _authorize_fetch("https://example.com:6443/")
    # 비 http 스킴·userinfo
    with pytest.raises(WebSearchError):
        _authorize_fetch("file:///etc/passwd")
    with pytest.raises(WebSearchError):
        _authorize_fetch("http://user@evil/")


def test_fetch_allows_public_and_returns_text():
    fake = FakeHttp("<html><body><p>Hello <b>Trino</b></p><script>x()</script></body></html>")
    r = fetch("https://trino.io/docs/current/", client=fake,
              resolver=lambda h: ["93.184.216.34"])   # 공개 IP
    assert r["status"] == 200
    assert "Hello Trino" in r["text"] and "x()" not in r["text"]  # 스크립트 제거


def test_fetch_dns_failure_is_fail_closed():
    def boom(h):
        raise OSError("nxdomain")
    with pytest.raises(WebSearchError, match="해석 실패"):
        _authorize_fetch("https://nope.invalid/", resolver=boom)


def test_tools_registered_and_gated():
    from src.tools import verb_validator
    tools = {t.name: t for t in make_web_search_tools()}
    assert set(tools) == {"web_search", "web_fetch"}
    for n in tools:
        assert verb_validator.registered_tools()[n].verb == "http-read"
    # query 인자가 executor 게이트를 통과
    assert verb_validator.validate_tool_call("web_search", {"query": "kubectl logs"}).allowed
    assert verb_validator.validate_tool_call("web_fetch", {"url": "https://trino.io/"}).allowed
