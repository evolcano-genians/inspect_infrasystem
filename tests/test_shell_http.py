"""nexus-shell HTTP inspect 도구 검증 — 자격증명 무노출·GET-only·마스킹 (mock httpx)."""

from __future__ import annotations

import pytest

from src.tools.shell_http import (
    ShellEnv,
    ShellHttpError,
    ShellSession,
    _mask,
    load_shell_envs,
    make_shell_http_tools,
)

LOGIN_HTML = (
    '<form action="https://kc.vmlab.test/realms/csm/login-actions/authenticate?session_code=abc'
    '&amp;execution=x" method="post"><input name="username"><input name="password"></form>'
)


def test_load_shell_envs_from_env():
    envs = load_shell_envs({
        "SHELL_ENVS": "vm,aws",
        "SHELL_VM_BASE": "https://nexus.vmlab.test/",
        "SHELL_VM_USER": "u1", "SHELL_VM_PASSWORD": "p1",
        "SHELL_AWS_BASE": "https://nexus.clouddev.dev.genians.kr",
        "SHELL_AWS_USER": "u2", "SHELL_AWS_PASSWORD": "p2",
    })
    assert set(envs) == {"vm", "aws"}
    assert envs["vm"].base_url == "https://nexus.vmlab.test"  # 끝 슬래시 제거


def test_credentials_never_in_repr():
    env = ShellEnv(name="vm", base_url="https://x", user="admin", password="s3cr3t")
    assert "s3cr3t" not in repr(env) and "admin" not in repr(env)
    assert "has_creds=True" in repr(env)


def test_mask_redacts_tokens_and_cookies():
    text = 'set-cookie: session=abc123; Authorization: Bearer eyJhbc.def.ghi; "password":"p"'
    masked = _mask(text)
    assert "abc123" not in masked and "eyJhbc.def.ghi" not in masked
    assert "REDACTED" in masked


class FakeResp:
    def __init__(self, text="", status=200, headers=None):
        self.text, self.status_code = text, status
        self.headers = headers or {"content-type": "text/html"}


class FakeClient:
    def __init__(self, get_map, post_status=200):
        self.get_map = get_map
        self.posts = []
        self.post_status = post_status

    def get(self, url, **kw):
        for frag, resp in self.get_map.items():
            if frag in url:
                return resp
        return FakeResp("{}", 200, {"content-type": "application/json"})

    def post(self, url, data=None, headers=None):
        self.posts.append({"url": url, "data": data})
        return FakeResp("", self.post_status)

    def close(self):
        pass


def test_login_flow_posts_credentials_only_to_keycloak():
    fake = FakeClient({
        "/oauth2/start": FakeResp(LOGIN_HTML),
        "/api/auth/me": FakeResp('{"user":"admin","token":"eyJx.y.z"}', 200,
                                 {"content-type": "application/json"}),
    })
    env = ShellEnv(name="vm", base_url="https://nexus.vmlab.test", user="admin", password="pw")
    session = ShellSession(env, http_client=fake)
    result = session.get("/api/auth/me")
    # 로그인 POST는 keycloak login-actions 로만
    assert len(fake.posts) == 1
    assert "login-actions/authenticate" in fake.posts[0]["url"]
    assert fake.posts[0]["data"]["password"] == "pw"  # 폼엔 실제값(전송 목적)
    # 응답의 토큰은 마스킹됨
    assert "eyJx.y.z" not in result["body"]
    assert result["status"] == 200


def test_get_rejects_bad_paths_and_non_relative():
    env = ShellEnv(name="vm", base_url="https://x", user="u", password="p")
    session = ShellSession(env, http_client=FakeClient({}))
    for bad in ("api/x", "../etc", "http://evil.com/x", "/x; rm", "/x`whoami`"):
        with pytest.raises(ShellHttpError):
            session.get(bad)


def test_missing_credentials_errors():
    env = ShellEnv(name="vm", base_url="https://x", user="", password="")
    session = ShellSession(env, http_client=FakeClient({"/oauth2/start": FakeResp(LOGIN_HTML)}))
    with pytest.raises(ShellHttpError, match="자격증명"):
        session.get("/api/auth/me")


def test_tools_registered_and_env_listing_hides_password():
    from src.tools import verb_validator

    envs = load_shell_envs({
        "SHELL_ENVS": "vm", "SHELL_VM_BASE": "https://nexus.vmlab.test",
        "SHELL_VM_USER": "admin", "SHELL_VM_PASSWORD": "topsecret",
    })
    tools = {t.name: t for t in make_shell_http_tools(envs)}
    assert set(tools) == {"shell_list_envs", "shell_http_get"}
    assert verb_validator.registered_tools()["shell_http_get"].verb == "http-read"
    listing = tools["shell_list_envs"].invoke({})
    assert "topsecret" not in listing and "vm" in listing


def test_unknown_env_rejected():
    envs = load_shell_envs({
        "SHELL_ENVS": "vm", "SHELL_VM_BASE": "https://x",
        "SHELL_VM_USER": "u", "SHELL_VM_PASSWORD": "p",
    })
    tools = {t.name: t for t in make_shell_http_tools(envs)}
    out = tools["shell_http_get"].invoke({"env": "nope", "path": "/api/auth/me"})
    assert "없음" in out


def test_platform_inspector_agent_loads():
    from pathlib import Path

    from src.agents import load_agents

    agents = load_agents(Path(__file__).resolve().parent.parent / ".agents")
    pi = agents.get("platform-inspector")
    assert pi is not None
    assert "shell_http_get" in pi.tools
    assert "GET(read-only)" in pi.instructions or "read-only" in pi.instructions
