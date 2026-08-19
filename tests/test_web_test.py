"""웹 테스팅 도구 검증 — SSRF 게이트·GET-only·보안 헤더 평가 (fake httpx로 무네트워크)."""

from __future__ import annotations

import pytest

from src.tools.web_test import (
    WebTestPolicy,
    _authorize_web_target,
    make_web_test_tools,
)


# ---------- fake httpx ----------

class FakeResponse:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text


class FakeClient:
    """url → FakeResponse 매핑. request 호출(method,url)을 기록한다."""

    def __init__(self, routes: dict):
        self.routes = routes
        self.calls: list[tuple[str, str]] = []

    def request(self, method, url):
        self.calls.append((method, url))
        if url in self.routes:
            return self.routes[url]
        return FakeResponse(404, {}, "not found")

    def close(self):
        pass


def _resolver(mapping: dict):
    """호스트명 → IP 문자열 목록. 미등록 호스트는 예외(해석 실패 → fail-closed)."""
    def resolve(host, port):
        if host not in mapping:
            raise OSError(f"no such host: {host}")
        return list(mapping[host])
    return resolve


# ---------- SSRF 게이트 ----------

def test_rejects_non_http_scheme():
    ok, why, _ = _authorize_web_target("file:///etc/passwd")
    assert not ok and "스킴" in why


def test_rejects_userinfo():
    ok, why, _ = _authorize_web_target("http://user:pw@example.test/")
    assert not ok and "userinfo" in why


def test_rejects_metadata_ip_literal():
    ok, why, _ = _authorize_web_target("http://169.254.169.254/latest/meta-data/")
    assert not ok and "denylist" in why


def test_rejects_internal_api_port():
    ok, why, _ = _authorize_web_target(
        "https://cluster.test:6443/", resolver=_resolver({"cluster.test": ["10.0.0.5"]})
    )
    assert not ok and "포트" in why


def test_rejects_dns_rebinding_to_metadata():
    # 이름은 평범하지만 169.254.169.254 로 해석되면 거부(split-horizon/rebinding 방어)
    ok, why, _ = _authorize_web_target(
        "http://sneaky.test/", resolver=_resolver({"sneaky.test": ["169.254.169.254"]})
    )
    assert not ok and "denylist" in why


def test_rejects_unresolvable_host_fail_closed():
    ok, why, _ = _authorize_web_target("http://nope.test/", resolver=_resolver({}))
    assert not ok and ("해석" in why)


def test_allows_public_host():
    ok, label, pins = _authorize_web_target(
        "https://example.test/", resolver=_resolver({"example.test": ["93.184.216.34"]})
    )
    assert ok and pins == ("93.184.216.34",)


def test_allows_loopback_for_kind():
    ok, label, pins = _authorize_web_target("http://127.0.0.1:8080/")
    assert ok and "8080" in label


def test_whitelist_mode_rejects_outside():
    policy = WebTestPolicy(allow_host_suffixes=("vmlab.test",))
    ok, why, _ = _authorize_web_target(
        "https://example.test/", policy, resolver=_resolver({"example.test": ["93.184.216.34"]})
    )
    assert not ok and "화이트리스트" in why
    ok2, _, _ = _authorize_web_target(
        "https://nexus.vmlab.test/", policy,
        resolver=_resolver({"nexus.vmlab.test": ["10.1.2.3"]})
    )
    assert ok2


# ---------- 도구 동작 (GET-only, 보안 평가) ----------

def _tools(routes, mapping):
    client = FakeClient(routes)
    tools = make_web_test_tools(resolver=_resolver(mapping), http_client=client)
    return {t.name: t for t in tools}, client


def test_probe_is_get_only_and_reports_headers():
    resp = FakeResponse(200, {"content-type": "text/html",
                              "strict-transport-security": "max-age=31536000"},
                        "<html>ok</html>")
    routes = {"https://app.test/": resp}
    tools, client = _tools(routes, {"app.test": ["93.184.216.34"]})
    # method=POST 를 넘겨도 내부에서 GET 으로 강제 정규화된다
    out = tools["web_probe"].invoke({"url": "https://app.test/", "method": "POST"})
    assert "HTTP 200" in out
    assert all(m in ("GET", "HEAD") for m, _ in client.calls)
    assert client.calls[0][0] == "GET"
    assert "strict-transport-security" in out


def test_probe_blocks_metadata():
    tools, _ = _tools({}, {})
    out = tools["web_probe"].invoke({"url": "http://169.254.169.254/"})
    assert "거부됨" in out


def test_redirect_to_metadata_is_reblocked():
    # 공개 URL 이 메타데이터로 리다이렉트 → 홉마다 재검증되어 거부
    resp = FakeResponse(302, {"location": "http://169.254.169.254/latest/"}, "")
    routes = {"https://app.test/": resp}
    tools, _ = _tools(routes, {"app.test": ["93.184.216.34"]})
    out = tools["web_probe"].invoke({"url": "https://app.test/"})
    assert "거부됨" in out


def test_security_scan_flags_missing_headers_and_cors():
    resp = FakeResponse(200, {"content-type": "text/html",
                              "access-control-allow-origin": "*",
                              "server": "nginx/1.25.0",
                              "set-cookie": "sid=secretvalue; Path=/"},
                        "<html></html>")
    routes = {"https://app.test/": resp}
    tools, _ = _tools(routes, {"app.test": ["93.184.216.34"]})
    out = tools["web_security_scan"].invoke({"url": "https://app.test/"})
    assert "nosniff 누락" in out
    assert "와일드카드" in out
    # 쿠키 값은 노출하지 않고 플래그만
    assert "secretvalue" not in out
    assert "!Secure" in out and "!HttpOnly" in out


def test_links_classifies_internal_external():
    body = ('<a href="/internal/page">x</a>'
            '<a href="https://external.test/y">y</a>'
            '<script src="https://app.test/app.js"></script>')
    resp = FakeResponse(200, {"content-type": "text/html"}, body)
    routes = {"https://app.test/": resp}
    tools, _ = _tools(routes, {"app.test": ["93.184.216.34"]})
    out = tools["web_links"].invoke({"url": "https://app.test/"})
    assert "https://app.test/internal/page" in out
    assert "https://external.test/y" in out


def test_tools_registered_http_read():
    from src.tools import verb_validator as vv

    make_web_test_tools()
    for name in ("web_probe", "web_security_scan", "web_links"):
        spec = vv.registered_tools().get(name)
        assert spec is not None and spec.verb == "http-read"


@pytest.mark.parametrize("url", [
    "http://[::ffff:169.254.169.254]/latest/meta-data/",   # IPv4-매핑 IPv6
    "http://[::ffff:a9fe:a9fe]/",                          # 16진 표기 IPv4-매핑
    "http://[64:ff9b::169.254.169.254]/",                  # NAT64 well-known prefix
])
def test_rejects_ipv6_wrapped_metadata(url):
    """IPv6 로 감싼 IPv4 메타데이터 주소도 거부해야 한다.

    적대검증에서 확인된 실제 우회: IPv4 대역(169.254.0.0/16)과 IPv6Address 를 직접
    대조하면 항상 False 라 IMDS 가 그대로 도달했다. 정규화 후 대조로 차단한다.
    """
    ok, why, _ = _authorize_web_target(url)
    assert not ok and "denylist" in why


def test_normal_targets_still_allowed_after_ipv6_normalization():
    """정규화 도입이 정상 대상을 막지 않는지(회귀 방지)."""
    for url in ("https://nexus.vmlab.test/", "http://127.0.0.1:8080/"):
        ok, _why, _ = _authorize_web_target(url)
        assert ok, url
