"""nexus-shell HTTP inspect 도구 — Keycloak 로그인 후 read-only API 조회.

각 환경(AWS/Azure/VM)의 nexus-shell 웹앱에 인가된 계정으로 로그인해 bff API 등을
read-only(GET)로 조사한다. 자격증명은 .env에서 환경별로 주입하며, **값은 절대 로그·응답·
위키에 노출하지 않는다**(로그인 자체는 도구 내부에서만 수행).

보안 원칙:
1. **자격증명 무노출**: username/password는 폼 전송에만 쓰이고 반환값·audit에 남지 않는다.
   응답 본문도 토큰/쿠키/Set-Cookie 류를 마스킹한다.
2. **GET-only 조사**: 로그인 플로우(oauth2-proxy→Keycloak 폼 POST) 외의 요청은 GET만 허용한다.
   앱 데이터를 변경하는 POST/PUT/DELETE 는 거부된다.
3. **호스트 화이트리스트**: 요청은 설정된 nexus-shell 베이스 URL과 그 인증 도메인으로 제한한다.
4. 로그인 세션은 메모리에만 유지(쿠키 파일 미기록).

.env 예:
  SHELL_ENVS=vm,aws
  SHELL_VM_BASE=https://nexus.vmlab.test
  SHELL_VM_USER=...
  SHELL_VM_PASSWORD=...
  SHELL_AWS_BASE=https://nexus.clouddev.dev.genians.kr
  SHELL_AWS_USER=...
  SHELL_AWS_PASSWORD=...
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

_PATH_RE = re.compile(r"^/[A-Za-z0-9._/\-]{0,300}$")
_MAX_BODY = 20_000
# 응답에서 마스킹할 민감 패턴
_MASK_PATTERNS = [
    # 키워드 뒤 값 (bearer/token은 뒤 토큰까지 함께)
    re.compile(r"(?i)\b(set-cookie|authorization|token|password|secret|session|api[-_]?key)\b"
               r"[\"'\s:=]+[^\s\"',;}]+"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]+"),  # Bearer <token>
    re.compile(r"eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*"),  # JWT (짧아도)
]


class ShellHttpError(RuntimeError):
    pass


@dataclass
class ShellEnv:
    name: str
    base_url: str
    user: str = ""
    password: str = ""
    _authed: bool = field(default=False, repr=False)

    def __repr__(self) -> str:  # 자격증명 유출 방지
        return f"ShellEnv(name={self.name!r}, base_url={self.base_url!r}, has_creds={bool(self.user)})"


def _mask(text: str) -> str:
    out = text
    # 1) 키워드=값 → 키워드=[REDACTED]
    out = _MASK_PATTERNS[0].sub(
        lambda m: re.split(r"[\"'\s:=]", m.group(0), 1)[0] + "=[REDACTED]", out
    )
    # 2) Bearer <token>, JWT → 통째로 [REDACTED]
    for pat in _MASK_PATTERNS[1:]:
        out = pat.sub("[REDACTED]", out)
    return out


def load_shell_envs(env: dict) -> dict[str, ShellEnv]:
    """.env(환경변수 dict)에서 SHELL_<NAME>_* 를 읽어 환경 맵을 만든다."""
    names = [n.strip().lower() for n in (env.get("SHELL_ENVS", "") or "").split(",") if n.strip()]
    envs: dict[str, ShellEnv] = {}
    for name in names:
        up = name.upper()
        base = env.get(f"SHELL_{up}_BASE", "")
        if not base:
            continue
        envs[name] = ShellEnv(
            name=name,
            base_url=base.rstrip("/"),
            user=env.get(f"SHELL_{up}_USER", ""),
            password=env.get(f"SHELL_{up}_PASSWORD", ""),
        )
    return envs


class ShellSession:
    """단일 nexus-shell 환경에 대한 로그인 세션 (메모리 쿠키)."""

    def __init__(self, env: ShellEnv, *, http_client=None, timeout: float = 20.0):
        self.env = env
        self._timeout = timeout
        self._client = http_client
        self._allowed_hosts = {urlparse(env.base_url).hostname}

    def _new_client(self):
        if self._client is not None:
            return self._client
        import httpx

        return httpx.Client(timeout=self._timeout, verify=False, follow_redirects=True)

    def _login(self, client) -> None:
        """oauth2-proxy → Keycloak 폼 로그인. 자격증명은 여기서만 쓰이고 반환되지 않는다."""
        if not (self.env.user and self.env.password):
            raise ShellHttpError(f"환경 '{self.env.name}' 자격증명이 .env에 없습니다")
        # 1) oauth2 start → keycloak 로그인 폼
        start = client.get(f"{self.env.base_url}/oauth2/start?rd=%2F")
        page = start.text
        # Keycloak 인증 도메인을 화이트리스트에 추가
        for m in re.finditer(r'action="([^"]+/login-actions/authenticate[^"]*)"', page):
            action = html.unescape(m.group(1))
            self._allowed_hosts.add(urlparse(action).hostname)
            # 2) 폼 POST (username/password) — 유일하게 허용되는 비-GET 요청
            resp = client.post(
                action,
                data={"username": self.env.user, "password": self.env.password,
                      "credentialId": ""},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            if resp.status_code >= 400:
                raise ShellHttpError(f"로그인 실패 (HTTP {resp.status_code})")
            self.env._authed = True
            return
        raise ShellHttpError("Keycloak 로그인 폼을 찾지 못했습니다 (인증 흐름 변경 가능성)")

    def get(self, path: str) -> dict:
        """로그인 세션으로 앱 경로를 GET 조회한다. path는 /로 시작하는 상대경로."""
        if not isinstance(path, str) or not _PATH_RE.match(path):
            raise ShellHttpError(f"허용되지 않는 경로: {path!r} (/로 시작하는 상대경로만)")
        client = self._new_client()
        try:
            if not self.env._authed:
                self._login(client)
            url = urljoin(self.env.base_url + "/", path.lstrip("/"))
            if urlparse(url).hostname not in self._allowed_hosts:
                raise ShellHttpError("요청 호스트가 화이트리스트 밖입니다")
            resp = client.get(url)
            ctype = resp.headers.get("content-type", "")
            body = resp.text[:_MAX_BODY]
            return {
                "status": resp.status_code,
                "content_type": ctype,
                "body": _mask(body),
                "truncated": len(resp.text) > _MAX_BODY,
            }
        finally:
            if self._client is None:
                client.close()


def make_shell_http_tools(envs: dict[str, ShellEnv], audit=None) -> list:
    if not envs:
        return []
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    sessions = {name: ShellSession(env) for name, env in envs.items()}
    verb_validator.register_tool("shell_http_get", "http-read", "nexus-shell")
    verb_validator.register_tool("shell_list_envs", "http-read", "nexus-shell")

    def shell_list_envs() -> str:
        """설정된 nexus-shell 환경 목록을 반환한다 (자격증명 값은 노출 안 함)."""
        return "\n".join(
            f"- {name}: {env.base_url} (creds: {'있음' if env.user else '없음'})"
            for name, env in envs.items()
        )

    def shell_http_get(env: str, path: str = "/api/auth/me") -> str:
        """지정 nexus-shell 환경에 로그인 후 경로를 GET 조회한다. env: vm|aws|azure 등."""
        session = sessions.get((env or "").lower())
        if session is None:
            return f"[거부됨] 환경 '{env}' 없음 (가능: {list(envs)})"
        started = time.perf_counter()
        try:
            result = session.get(path)
        except ShellHttpError as exc:
            if audit:
                audit.record(tool="shell_http_get", verb="http-read", resource="nexus-shell",
                             namespace=env, allowed=False, reason=str(exc))
            return f"[거부됨 · nexus-shell 조회 정책] {exc}"
        except Exception as exc:
            return f"[nexus-shell 조회 오류] {type(exc).__name__}: {exc}"
        if audit:
            audit.record(tool="shell_http_get", verb="http-read", resource="nexus-shell",
                         namespace=env, allowed=True,
                         duration_ms=(time.perf_counter() - started) * 1000,
                         result_chars=len(result["body"]))
        head = f"[{env} · HTTP {result['status']} · {result['content_type']}]"
        tail = "\n...[본문 잘림]" if result["truncated"] else ""
        return f"{head}\n{result['body']}{tail}"

    return [
        StructuredTool.from_function(
            func=shell_list_envs, name="shell_list_envs",
            description="설정된 nexus-shell 환경(vm/aws/azure) 목록을 조회한다.",
        ),
        StructuredTool.from_function(
            func=shell_http_get, name="shell_http_get",
            description="nexus-shell 웹앱에 로그인 후 API/페이지를 read-only(GET)로 조회한다. "
                        "env(vm|aws|azure)와 path(/api/... 상대경로)를 지정. bff API·상태 확인에 사용. "
                        "자격증명은 .env에서 주입되며 응답의 토큰/쿠키는 마스킹된다.",
        ),
    ]
