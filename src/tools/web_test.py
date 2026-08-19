"""웹 보안 테스팅 도구 — SSRF 안전 read-only HTTP 프로브.

권한 맥락: 사용자는 자사 dev/실증 인프라에 대한 인가된 보안 테스터다. 이 모듈은 웹 자산의
**동적 read-only 점검**(상태코드·응답시간·보안 헤더·쿠키 플래그·정보노출·링크맵)을 제공한다.
쓰기 메서드(POST/PUT/DELETE 등)는 구조적으로 존재하지 않는다 — 도구가 노출하는 전송은
``client.request('GET'|'HEAD', ...)`` 둘뿐이고 method 인자는 도구 내부에서 강제 정규화된다.

[4중 방어선 대응]
- 방어선1(구조적): 변경 메서드 코드 경로가 아예 없다. method 는 upper() 후 'HEAD' 가
  아니면 'GET' 으로 강제된다(k8s 의 create_/delete_ 미바인딩과 동형).
- 방어선2(verb_validator): url/method 인자를 등록해 executor 게이트를 통과시킨다. url 은
  형식(http/https·메타문자 배제)만, method 는 enum(GET/HEAD)으로 중앙 검증된다.
- 방어선3(SSRF 게이트 `_authorize_web_target`): 스킴·userinfo·포트·하드 denylist(메타데이터·
  링크로컬)·DNS 해석 핀을 매 요청·매 리다이렉트 홉마다 재실행한다. 공개·사설 웹 GET 은
  허용하되 클라우드 메타데이터(169.254.169.254)·내부 API 포트(6443/etcd/kubelet 등)만 차단.
- 방어선4(감사): 모든 호출에 audit.record(verb='http-read', resource='web').

[상한·유출 방지]
- 타임아웃 하드 상한, 본문 저장 상한(_MAX_BODY), 리다이렉트 상한(_MAX_REDIRECTS).
- 응답 헤더/본문은 shell_http._mask 로 토큰/쿠키/JWT 를 마스킹한다. 보안 스캔은 쿠키 값
  대신 이름+플래그만 노출한다.
- TLS 는 self-signed 실증 랩 도달을 위해 verify=False(shell_http 선례)로 두되, 검증 통과
  여부는 '보고'만 한다(값 노출 아님).
"""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from .shell_http import _mask

_MAX_BODY = 64_000            # 본문 저장 상한(무제한 다운로드 금지)
_MAX_REDIRECTS = 5            # 리다이렉트 추종 상한
_TIMEOUT = 15.0              # connect+read 총 하드 상한(초)
_SNIPPET_CHARS = 800          # 본문 스니펫 상한

#: 항상 거부하는 하드 denylist 대역 — 클라우드 메타데이터·링크로컬. 정책으로 못 푼다.
_DENY_CIDRS: tuple = (
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 링크로컬 + 클라우드 메타데이터 169.254.169.254
    ipaddress.ip_network("fe80::/10"),        # IPv6 링크로컬
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IPv6 IMDS
)
#: 구조적으로 차단하는 내부 인프라 포트(SSH·etcd·kube-apiserver·kubelet·controller/scheduler).
_DENY_PORTS: frozenset[int] = frozenset({22, 2379, 6443, 10250, 10257, 10259})

# 평가할 보안 헤더 (존재/값). 값은 그대로가 아니라 존재·요약만 보고.
_SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)
# 본문 정보노출 마커(가벼운 스캔) — 값은 마스킹된 뒤라 위치 신호로만 쓴다.
_INFO_MARKERS = (
    re.compile(r'<meta[^>]+http-equiv=["\']?refresh', re.I),
    re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\."),  # JWT 형태
)


class WebTestError(RuntimeError):
    """웹 테스트 요청이 정책·전송 단계에서 거부/실패했다."""


@dataclass(frozen=True)
class WebTestPolicy:
    """웹 GET 프로브 정책. deny 는 항상 우선하며 allowed_targets 로 대상을 더 좁힐 수 있다."""

    deny_cidrs: tuple = _DENY_CIDRS
    deny_ports: frozenset[int] = _DENY_PORTS
    allow_schemes: tuple[str, ...] = ("http", "https")
    max_redirects: int = _MAX_REDIRECTS
    timeout: float = _TIMEOUT
    max_body: int = _MAX_BODY
    # 비면 공개·사설 웹 GET 허용(메타데이터·내부 API만 차단). 지정하면 화이트리스트 모드.
    allow_cidrs: tuple = ()
    allow_hosts: tuple[str, ...] = ()
    allow_host_suffixes: tuple[str, ...] = ()

    @property
    def has_whitelist(self) -> bool:
        return bool(self.allow_cidrs or self.allow_hosts or self.allow_host_suffixes)


def _default_port(scheme: str) -> int:
    return 443 if scheme == "https" else 80


def _resolve_ips(host: str, resolver) -> list:
    """호스트명을 IP 목록으로 해석한다. resolver 는 getaddrinfo 형태 또는 문자열 목록 반환."""
    ips = []
    for info in resolver(host, None) or []:
        raw = info
        if not isinstance(info, str):
            sockaddr = info[4]
            raw = sockaddr[0] if isinstance(sockaddr, (tuple, list)) else str(sockaddr)
        raw = str(raw).split("%", 1)[0]  # IPv6 zone id 제거
        try:
            ips.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    return ips


def _host_matches_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    h = (host or "").lower().rstrip(".")
    for suffix in suffixes:
        s = (suffix or "").lower().strip(".")
        if s and (h == s or h.endswith("." + s)):
            return True
    return False


#: NAT64 well-known prefix — 64:ff9b::/96 은 하위 32비트에 IPv4 를 그대로 담는다.
_NAT64_PREFIX = ipaddress.ip_network("64:ff9b::/96")


def _embedded_ipv4(ip):
    """IPv6 표기 안에 감춰진 IPv4 주소를 꺼낸다. 없으면 None.

    `::ffff:169.254.169.254`(IPv4-매핑)·`64:ff9b::169.254.169.254`(NAT64)처럼 IPv4 를
    IPv6 로 감싸면, IPv4 대역(169.254.0.0/16 등)과 직접 대조했을 때 항상 False 가 되어
    denylist 를 통째로 우회한다(적대검증에서 확인된 실제 우회). 대조 전에 반드시 벗겨낸다.
    """
    if not isinstance(ip, ipaddress.IPv6Address):
        return None
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        return mapped
    for attr in ("sixtofour", "teredo"):  # 6to4/Teredo 도 IPv4 를 품는다
        v = getattr(ip, attr, None)
        if v is not None:
            return v[0] if isinstance(v, tuple) else v
    if ip in _NAT64_PREFIX:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return None


def _ip_in(ip, nets) -> bool:
    """IP 가 대역 목록에 드는지 본다. IPv6 로 감싼 IPv4 도 벗겨서 함께 대조한다."""
    candidates = [ip]
    inner = _embedded_ipv4(ip)
    if inner is not None:
        candidates.append(inner)
    for cand in candidates:
        for net in nets:
            if cand.version == net.version and cand in net:
                return True
    return False


def _authorize_web_target(
    url: str, policy: WebTestPolicy | None = None, *, resolver=None
) -> tuple[bool, str, tuple[str, ...]]:
    """웹 GET 대상을 인가한다(방어선3). 반환: (허용여부, 라벨/사유, 핀 IP 목록).

    판정 순서: 스킴 → host/userinfo/비ASCII → 포트 하드 denylist → (화이트리스트 모드면
    대상 매칭) → IP 리터럴 denylist → 호스트명 DNS 해석 + denylist 재확인(rebinding 방어).
    DNS 해석 실패는 fail-closed(거부). resolver 는 테스트 결정성을 위해 주입 가능.
    """
    policy = policy or WebTestPolicy()
    resolver = resolver or socket.getaddrinfo
    raw = (url or "").strip()
    if not raw:
        return False, "빈 URL", ()
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()

    # 1) 스킴 — file/gopher/ssh 등 차단(방어선2와 이중)
    if scheme not in policy.allow_schemes:
        return False, f"스킴 {scheme!r} 은 허용되지 않습니다 ({list(policy.allow_schemes)}만)", ()

    # 2) host / userinfo / 비ASCII
    if parsed.username or parsed.password or "@" in (parsed.netloc or ""):
        return False, "URL 에 userinfo(@)가 포함되어 거부합니다", ()
    host = (parsed.hostname or "").lower()
    if not host:
        return False, f"URL {raw!r} 에서 호스트를 해석할 수 없습니다", ()
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        return False, "비ASCII 호스트명은 거부합니다(punycode 우회 방지)", ()

    # 3) 포트 하드 denylist
    try:
        port = parsed.port
    except ValueError:
        return False, f"URL {raw!r} 의 포트를 해석할 수 없습니다", ()
    effective_port = port if port is not None else _default_port(scheme)
    if effective_port in policy.deny_ports:
        return False, f"포트 {effective_port} 는 내부 인프라 포트로 항상 거부됩니다", ()

    # IP 리터럴 여부
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    # 4) 화이트리스트 모드(엄격 배포) — 지정 시 대상이 목록에 있어야 한다.
    if policy.has_whitelist:
        if literal is not None:
            if not _ip_in(literal, policy.allow_cidrs):
                return False, f"IP {host} 는 화이트리스트(allow_cidrs) 밖입니다", ()
        elif not (host in policy.allow_hosts
                  or _host_matches_suffix(host, policy.allow_host_suffixes)):
            return False, f"호스트 {host!r} 는 화이트리스트 밖입니다", ()

    # 5) IP 리터럴 denylist
    if literal is not None:
        if _ip_in(literal, policy.deny_cidrs):
            return False, f"IP {host} 는 하드 denylist(메타데이터·링크로컬) 대역입니다", ()
        return True, f"ip:{host}:{effective_port}", (str(literal),)

    # 6) 호스트명 DNS 해석 + denylist 재확인(split-horizon/rebinding 방어). 실패는 fail-closed.
    try:
        ips = _resolve_ips(host, resolver)
    except Exception as exc:  # noqa: BLE001 — 해석 실패는 사유 불문 거부
        return False, (
            f"호스트 {host!r} DNS 해석 실패로 거부합니다 ({type(exc).__name__})"
        ), ()
    if not ips:
        return False, f"호스트 {host!r} 가 어떤 IP 로도 해석되지 않아 거부합니다", ()
    for ip in ips:
        if _ip_in(ip, policy.deny_cidrs):
            return False, (
                f"호스트 {host!r} 가 하드 denylist IP({ip}) 로 해석되어 거부합니다 "
                "(메타데이터·내부 대역)"
            ), ()
    return True, f"host:{host}:{effective_port}", tuple(str(ip) for ip in ips)


def _normalize_method(method: str) -> str:
    """method 를 GET/HEAD 로 강제 정규화한다 — 변경 메서드 경로가 구조적으로 존재하지 않는다."""
    m = (method or "GET").strip().upper()
    return "HEAD" if m == "HEAD" else "GET"


def _headers_lower(headers) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        items = headers.items()
    except AttributeError:
        items = list(headers or [])
    for k, v in items:
        out[str(k).lower()] = str(v)
    return out


def _fetch(url: str, method: str, policy: WebTestPolicy, resolver, http_client):
    """GET/HEAD 요청을 리다이렉트 수동 추종으로 수행한다. 매 홉마다 SSRF 게이트 재실행.

    반환: {"chain": [...], "final": {...}} — 각 홉의 (url, status, label). 실패 시 WebTestError.
    """
    method = _normalize_method(method)
    client = http_client or _new_client(policy)
    chain: list[dict] = []
    pinned: tuple[str, ...] = ()
    try:
        current = url
        for hop in range(policy.max_redirects + 1):
            ok, label, pins = _authorize_web_target(current, policy, resolver=resolver)
            if not ok:
                raise WebTestError(label)
            pinned = pins
            started = time.perf_counter()
            resp = client.request(method, current)
            elapsed_ms = (time.perf_counter() - started) * 1000
            headers = _headers_lower(resp.headers)
            status = int(resp.status_code)
            chain.append({"url": current, "status": status, "label": label,
                          "elapsed_ms": round(elapsed_ms, 1)})
            location = headers.get("location")
            if status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                continue
            body = ""
            if method == "GET":
                text = getattr(resp, "text", "") or ""
                body = text[:policy.max_body]
            return {
                "chain": chain,
                "final": {
                    "url": current,
                    "status": status,
                    "headers": headers,
                    "content_type": headers.get("content-type", ""),
                    "content_length": headers.get("content-length"),
                    "body": body,
                    "body_len": len(getattr(resp, "text", "") or "") if method == "GET" else 0,
                    "elapsed_ms": round(chain[-1]["elapsed_ms"], 1),
                    "pinned": list(pinned),
                },
            }
        raise WebTestError(f"리다이렉트가 상한({policy.max_redirects})을 초과했습니다")
    finally:
        if http_client is None and hasattr(client, "close"):
            client.close()


def _new_client(policy: WebTestPolicy):
    import httpx

    return httpx.Client(follow_redirects=False, verify=False, timeout=policy.timeout)


# ---------- 보고 렌더링 헬퍼 ----------

def _eval_security_headers(headers: dict[str, str]) -> list[str]:
    lines = []
    for name in _SECURITY_HEADERS:
        val = headers.get(name)
        if val is None:
            lines.append(f"  - {name}: [누락]")
        else:
            lines.append(f"  - {name}: {val[:120]}")
    return lines


def _eval_cookies(headers: dict[str, str]) -> list[str]:
    """Set-Cookie 플래그(Secure/HttpOnly/SameSite)만 평가 — 쿠키 값은 노출하지 않는다."""
    raw = headers.get("set-cookie")
    if not raw:
        return ["  (Set-Cookie 없음)"]
    lines = []
    for cookie in raw.split("\n"):
        cookie = cookie.strip()
        if not cookie:
            continue
        name = cookie.split("=", 1)[0]
        low = cookie.lower()
        flags = []
        flags.append("Secure" if "secure" in low else "!Secure")
        flags.append("HttpOnly" if "httponly" in low else "!HttpOnly")
        m = re.search(r"samesite=(\w+)", low)
        flags.append(f"SameSite={m.group(1)}" if m else "!SameSite")
        lines.append(f"  - {name}: {', '.join(flags)}")
    return lines


def _redirect_chain_lines(chain: list[dict]) -> list[str]:
    if len(chain) <= 1:
        return []
    return ["리다이렉트 체인:"] + [
        f"  {i+1}. {h['status']} {h['url']}" for i, h in enumerate(chain)
    ]


def _probe_report(result: dict, method: str) -> str:
    final = result["final"]
    headers = final["headers"]
    lines = [
        f"[HTTP {final['status']} · {method} · {final['content_type'] or '?'}]",
        f"최종 URL: {final['url']}",
        f"응답시간: {final['elapsed_ms']}ms · 핀 IP: {final['pinned']}",
        f"본문 크기: content-length={final['content_length']} 실측={final['body_len']}",
    ]
    lines += _redirect_chain_lines(result["chain"])
    lines.append("보안 헤더:")
    lines += _eval_security_headers(headers)
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server or powered:
        lines.append(f"서버 정보노출: server={server!r} x-powered-by={powered!r}")
    if final["body"]:
        snippet = _mask(final["body"])[:_SNIPPET_CHARS]
        lines.append("본문 스니펫(마스킹):")
        lines.append(snippet)
    return "\n".join(lines)


def _security_report(result: dict) -> str:
    final = result["final"]
    headers = final["headers"]
    lines = [f"[보안 자세 점검 · HTTP {final['status']} · {final['url']}]"]
    lines.append("보안 헤더:")
    lines += _eval_security_headers(headers)
    lines.append("쿠키 플래그:")
    lines += _eval_cookies(headers)

    findings: list[str] = []
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        findings.append("[중] X-Content-Type-Options: nosniff 누락")
    if headers.get("strict-transport-security") is None:
        findings.append("[중] HSTS(Strict-Transport-Security) 누락")
    if headers.get("content-security-policy") is None:
        findings.append("[중] CSP(Content-Security-Policy) 누락")
    acao = headers.get("access-control-allow-origin")
    if acao == "*":
        findings.append("[상] CORS Access-Control-Allow-Origin: * (와일드카드 허용)")
    if headers.get("server"):
        findings.append(f"[하] Server 헤더 버전 정보노출: {headers['server'][:80]}")
    if headers.get("x-powered-by"):
        findings.append(f"[하] X-Powered-By 정보노출: {headers['x-powered-by'][:80]}")
    if urlparse(final["url"]).scheme == "http":
        findings.append("[중] 최종 응답이 평문 HTTP (HTTPS 강제·리다이렉트 부재 가능)")
    body = final.get("body") or ""
    for pat in _INFO_MARKERS:
        if pat.search(body):
            findings.append(f"[정보] 본문에 잠재 정보노출 마커 감지: {pat.pattern[:40]}")
            break

    lines.append("발견(심각도 힌트):")
    lines += [f"  - {f}" for f in findings] or ["  - (명백한 헤더 이슈 없음)"]
    return "\n".join(lines)


_LINK_RE = re.compile(
    r'(?:href|src|action)\s*=\s*["\']([^"\'>\s]{1,2000})["\']', re.I
)


def _links_report(result: dict) -> str:
    final = result["final"]
    base = final["url"]
    base_host = (urlparse(base).hostname or "").lower()
    body = final.get("body") or ""
    internal, external = set(), set()
    for m in _LINK_RE.finditer(body):
        raw = m.group(1).strip()
        if raw.startswith(("javascript:", "data:", "mailto:", "tel:", "#")):
            continue
        try:
            absolute = urljoin(base, raw)
        except ValueError:
            continue
        parsed = urlparse(absolute)
        if parsed.scheme not in ("http", "https"):
            continue
        host = (parsed.hostname or "").lower()
        if host == base_host:
            internal.add(absolute)
        else:
            external.add(absolute)
    cap = 100
    lines = [
        f"[링크 추출 · {base}]",
        f"내부 {len(internal)}개 · 외부 {len(external)}개 (각 최대 {cap} 표시)",
        "내부:",
    ]
    lines += [f"  - {u}" for u in sorted(internal)[:cap]] or ["  (없음)"]
    lines.append("외부:")
    lines += [f"  - {u}" for u in sorted(external)[:cap]] or ["  (없음)"]
    return "\n".join(lines)


# ---------- 도구 조립 ----------

def make_web_test_tools(*, policy: WebTestPolicy | None = None, audit=None,
                        resolver=None, http_client=None, allowed_targets: str = "") -> list:
    """웹 테스팅 도구를 조립한다. 팩토리 인자는 전부 기본값이 있어 하위호환된다.

    - allowed_targets: 콤마 구분 CIDR/host/`*.도메인` — 지정 시 화이트리스트 모드(엄격 배포).
    - resolver/http_client: 테스트 결정성을 위한 주입점(순수·무네트워크 게이트 단위테스트).
    """
    from langchain_core.tools import StructuredTool

    from . import verb_validator

    policy = policy or _build_policy(allowed_targets)

    verb_validator.register_tool("web_probe", "http-read", "web")
    verb_validator.register_tool("web_security_scan", "http-read", "web")
    verb_validator.register_tool("web_links", "http-read", "web")

    def _run(tool_name: str, url: str, render, *, method: str = "GET") -> str:
        args = {"url": url}
        if tool_name == "web_probe":
            args["method"] = method
        verdict = verb_validator.validate_tool_call(tool_name, args)
        if not verdict.allowed:
            if audit:
                audit.record(tool=tool_name, verb="http-read", resource="web",
                             allowed=False, reason=verdict.reason)
            return f"[거부됨 · web 정책] {verdict.reason}"
        started = time.perf_counter()
        try:
            result = _fetch(url, method, policy, resolver, http_client)
        except WebTestError as exc:
            if audit:
                audit.record(tool=tool_name, verb="http-read", resource="web",
                             allowed=False, reason=str(exc))
            return f"[거부됨 · SSRF/전송 정책] {exc}"
        except Exception as exc:  # noqa: BLE001 — 네트워크 오류가 조사 run 을 죽이지 않는다
            return f"[web 조회 오류] {type(exc).__name__}: {exc}"
        text = render(result)
        if audit:
            audit.record(tool=tool_name, verb="http-read", resource="web", allowed=True,
                         duration_ms=(time.perf_counter() - started) * 1000,
                         result_chars=len(text))
        return text

    def web_probe(url: str, method: str = "GET") -> str:
        """단일 URL 을 SSRF 안전하게 프로브한다. 상태코드·응답시간·content-type·본문 크기·
        보안 헤더·리다이렉트 체인·마스킹 스니펫을 반환한다. method 는 GET|HEAD 만."""
        m = _normalize_method(method)
        return _run("web_probe", url, lambda r: _probe_report(r, m), method=m)

    def web_security_scan(url: str) -> str:
        """보안 자세 점검 — 보안 헤더·Set-Cookie 플래그·CORS·정보노출·HTTPS 강제를 심각도
        힌트와 함께 목록화한다(값 유출 없이 헤더/플래그만 평가)."""
        return _run("web_security_scan", url, _security_report)

    def web_links(url: str) -> str:
        """HTML 에서 링크(a[href]/form action/script src)를 추출·절대화·중복제거하고
        내부/외부 호스트로 분류한다(1페이지만 조회, 크롤 안 함)."""
        return _run("web_links", url, _links_report)

    return [
        StructuredTool.from_function(func=web_probe, name="web_probe",
                                     description=web_probe.__doc__),
        StructuredTool.from_function(func=web_security_scan, name="web_security_scan",
                                     description=web_security_scan.__doc__),
        StructuredTool.from_function(func=web_links, name="web_links",
                                     description=web_links.__doc__),
    ]


def _build_policy(allowed_targets: str) -> WebTestPolicy:
    """allowed_targets(콤마 CIDR/host/`*.도메인`)를 파싱해 정책을 만든다. 비면 완화 모드."""
    cidrs, hosts, suffixes = [], [], []
    for raw in (allowed_targets or "").split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            cidrs.append(ipaddress.ip_network(item, strict=False))
            continue
        except ValueError:
            pass
        low = item.lower()
        if low.startswith("*."):
            suffixes.append(low[2:].strip("."))
        elif low.startswith("."):
            suffixes.append(low.strip("."))
        else:
            hosts.append(low)
    return WebTestPolicy(
        allow_cidrs=tuple(cidrs),
        allow_hosts=tuple(hosts),
        allow_host_suffixes=tuple(suffixes),
    )
