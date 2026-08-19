"""Jira read-only 조회 도구 검증 — 키 추출·리비전 추출·GET only·마스킹·인젝션 방어."""

from __future__ import annotations

import pytest

from src.tools.jira_reader import (
    JiraClient,
    JiraConfig,
    JiraError,
    extract_issue_key,
    find_revisions,
    load_jira_config,
    make_jira_tools,
)


def test_extract_issue_key_from_url_and_bare():
    assert extract_issue_key("https://ims.cloud.genians.com/browse/CL-1415") == "CL-1415"
    assert extract_issue_key("CL-1678") == "CL-1678"
    assert extract_issue_key("  CL-9 ") == "CL-9"
    with pytest.raises(JiraError):
        extract_issue_key("not-an-issue")


def test_find_revisions_from_comment_text():
    text = "적용 완료: r7911 로 반영. revision 7915 확인. 재적용 r7911(중복)."
    revs = find_revisions(text)
    assert "r7911" in revs and "r7915" in revs
    assert revs.count("r7911") == 1  # 중복 제거


class FakeResp:
    def __init__(self, status, payload=None, headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class FakeClient:
    """GET 만 구현 — 다른 메서드는 존재하지 않아 write 가 구조적으로 불가능함을 보인다."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, url, params=None, headers=None):
        self.calls.append((url, params, headers))
        for suffix, resp in self.routes.items():
            if url.endswith(suffix):
                return resp
        return FakeResp(404)


def _client(routes):
    cfg = JiraConfig(base_url="https://jira.example.com", token="SECRET-PAT")
    return JiraClient(cfg, client=FakeClient(routes)), cfg


def test_get_issue_and_comments_shape():
    client, _ = _client({
        "/rest/api/2/issue/CL-1678": FakeResp(200, {
            "key": "CL-1678",
            "fields": {
                "summary": "helm 리비전 반영", "issuetype": {"name": "Task"},
                "status": {"name": "In Review"}, "priority": {"name": "High"},
                "assignee": {"displayName": "홍길동"}, "reporter": {"displayName": "김철수"},
                "labels": ["helm"], "components": [{"name": "cloud"}],
                "fixVersions": [{"name": "2026.08"}], "description": "values 태그 변경",
                "issuelinks": [], "subtasks": [],
            },
        }),
        "/rest/api/2/issue/CL-1678/comment": FakeResp(200, {
            "comments": [{"author": {"displayName": "홍길동"}, "created": "2026-08-18T10:00:00",
                          "body": "r7911 로 반영했습니다"}],
        }),
    })
    issue = client.get_issue("CL-1678")
    assert issue["summary"] == "helm 리비전 반영" and issue["status"] == "In Review"
    comments = client.get_comments("CL-1678")
    assert comments[0]["body"] == "r7911 로 반영했습니다"


def test_auth_header_bearer_vs_basic():
    fc = FakeClient({"/rest/api/2/issue/X-1": FakeResp(200, {"key": "X-1", "fields": {}})})
    JiraClient(JiraConfig(base_url="https://j", token="PAT"), client=fc).get_issue("X-1")
    assert fc.calls[0][2]["Authorization"] == "Bearer PAT"

    fc2 = FakeClient({"/rest/api/2/issue/X-1": FakeResp(200, {"key": "X-1", "fields": {}})})
    JiraClient(JiraConfig(base_url="https://j", token="tok", user="me"), client=fc2).get_issue("X-1")
    assert fc2.calls[0][2]["Authorization"].startswith("Basic ")


def test_cross_host_redirect_refused():
    client, _ = _client({
        "/rest/api/2/issue/CL-1": FakeResp(302, headers={"location": "https://evil.com/x"}),
    })
    with pytest.raises(JiraError, match="리다이렉트"):
        client.get_issue("CL-1")


def test_auth_errors_mapped():
    for status, msg in [(401, "인증"), (403, "권한"), (404, "찾을 수 없")]:
        client, _ = _client({"/rest/api/2/issue/CL-1": FakeResp(status)})
        with pytest.raises(JiraError, match=msg):
            client.get_issue("CL-1")


def test_auth_header_cookie_fallback():
    fc = FakeClient({"/rest/api/2/issue/X-1": FakeResp(200, {"key": "X-1", "fields": {}})})
    cfg = JiraConfig(base_url="https://j", cookie="JSESSIONID=abc123")
    JiraClient(cfg, client=fc).get_issue("X-1")
    assert fc.calls[0][2]["Cookie"] == "JSESSIONID=abc123"
    assert "Authorization" not in fc.calls[0][2]  # 쿠키가 있으면 토큰 헤더 미전송
    assert cfg.auth_kind() == "cookie"


def test_config_masks_token_in_repr():
    cfg = JiraConfig(base_url="https://j", token="SUPERSECRET", user="")
    assert "SUPERSECRET" not in repr(cfg)
    assert "bearer" in repr(cfg)
    # 쿠키·PAT 값 모두 repr에 노출되지 않아야 한다
    assert "JSESSIONID=zzz" not in repr(JiraConfig(base_url="https://j", cookie="JSESSIONID=zzz"))


def test_load_config_disabled_without_base_url():
    assert load_jira_config({}) is None
    cfg = load_jira_config({"JIRA_BASE_URL": "https://j", "JIRA_TOKEN": "t"})
    assert cfg and cfg.base_url == "https://j"


def test_tools_registered_readonly_and_redacts():
    from src.tools import verb_validator

    captured = {}

    def redactor(s):
        captured["called"] = True
        return s.replace("SECRET", "[REDACTED]")

    cfg = JiraConfig(base_url="https://j", token="t")
    tools = make_jira_tools(cfg, redactor=redactor)
    names = {t.name for t in tools}
    assert names == {"jira_get_issue", "jira_search"}
    for n in names:
        assert verb_validator.registered_tools()[n].verb == "jira-read"


def test_get_issue_tool_extracts_revisions_and_redacts(monkeypatch):
    cfg = JiraConfig(base_url="https://j", token="t")
    fc = FakeClient({
        "/rest/api/2/issue/CL-1678": FakeResp(200, {"key": "CL-1678", "fields": {
            "summary": "s", "description": "token=SECRET 반영", "issuetype": {"name": "Task"},
            "status": {"name": "Open"},
        }}),
        "/rest/api/2/issue/CL-1678/comment": FakeResp(200, {"comments": [
            {"author": {"displayName": "a"}, "created": "2026-08-18", "body": "r7911 반영"},
        ]}),
    })
    # make_jira_tools 는 자체 JiraClient 를 만들므로, 클라이언트 주입을 위해 패치
    import src.tools.jira_reader as jr
    monkeypatch.setattr(jr, "JiraClient", lambda config: JiraClient(config, client=fc))
    tools = {t.name: t for t in jr.make_jira_tools(cfg, redactor=lambda s: s.replace("SECRET", "[REDACTED]"))}
    out = tools["jira_get_issue"].invoke({"key": "https://ims.cloud.genians.com/browse/CL-1678"})
    assert "r7911" in out                 # 리비전 추출
    assert "SECRET" not in out and "[REDACTED]" in out  # 레다크션
