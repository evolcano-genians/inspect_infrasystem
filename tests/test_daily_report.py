"""일일 요약 크론 검증 — 날짜 필터·프로젝트 그룹핑·마크다운 변환·idempotent 게시."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from src.daily_report import (
    _local_date_str,
    _md_to_storage,
    collect_turns,
    group_by_project,
    publish,
    summarize,
)


def _write_turns(path, entries):
    path.write_text("\n".join(json.dumps(e, ensure_ascii=False) for e in entries) + "\n",
                    encoding="utf-8")


def test_collect_turns_filters_by_local_date(tmp_path):
    log = tmp_path / "devlog.jsonl"
    today = datetime.now().astimezone()
    yesterday = today - timedelta(days=1)
    _write_turns(log, [
        {"type": "turn", "timestamp": today.astimezone(timezone.utc).isoformat(),
         "thread_id": "t1", "question": "오늘 Q", "answer": "오늘 A"},
        {"type": "turn", "timestamp": yesterday.astimezone(timezone.utc).isoformat(),
         "thread_id": "t2", "question": "어제 Q", "answer": "어제 A"},
        {"type": "feedback", "timestamp": today.astimezone(timezone.utc).isoformat()},  # 무시
    ])
    day = today.strftime("%Y-%m-%d")
    turns = collect_turns(log, day)
    assert len(turns) == 1 and turns[0]["question"] == "오늘 Q"


def test_group_by_project_uses_session_project():
    class FakeSessions:
        def list_projects(self):
            return [type("P", (), {"id": "p1", "name": "Azure K8S"})()]

        def list(self):
            return [type("S", (), {"thread_id": "t1", "project_id": "p1"})(),
                    type("S", (), {"thread_id": "t2", "project_id": ""})()]

    turns = [{"thread_id": "t1", "question": "a"}, {"thread_id": "t2", "question": "b"},
             {"thread_id": "t9", "question": "c"}]  # 미등록 thread
    groups = group_by_project(turns, FakeSessions())
    assert "Azure K8S" in groups and len(groups["Azure K8S"]) == 1
    assert len(groups["(미분류)"]) == 2  # t2(빈 project) + t9(미등록)


def test_summarize_falls_back_without_model():
    groups = {"P": [{"question": "질문", "answer": "답변"}]}
    out = summarize(None, groups, "2026-08-19")  # 모델 없으면 원문 목록
    assert "질문" in out and "답변" in out


def test_summarize_uses_model_when_present():
    class FakeModel:
        def invoke(self, msgs):
            return type("R", (), {"content": "# 요약\n- 잘 정리됨"})()

    out = summarize(FakeModel(), {"P": [{"question": "q", "answer": "a"}]}, "2026-08-19")
    assert "잘 정리됨" in out


def test_md_to_storage_converts_headings_and_lists():
    md = "# 제목\n- 항목1\n- **강조** 항목2\n\n일반 문단"
    html = _md_to_storage(md)
    assert "<h1>제목</h1>" in html
    assert "<li>항목1</li>" in html
    assert "<strong>강조</strong>" in html
    assert "<p>일반 문단</p>" in html


def test_publish_creates_then_updates_idempotently():
    """같은 제목이 있으면 새로 만들지 않고 갱신(버전+1)한다."""
    calls = []

    class FakeResp:
        def __init__(self, status, payload):
            self.status_code = status
            self._p = payload
            self.text = ""

        def json(self):
            return self._p

    state = {"exists": False}

    class FakeClient:
        def __enter__(self): return self
        def __exit__(self, *a): return False

        def get(self, url, headers=None, params=None):
            calls.append(("GET", url, params))
            results = ([{"id": "123", "version": {"number": 3}}] if state["exists"] else [])
            return FakeResp(200, {"results": results})

        def post(self, url, headers=None, json=None):
            calls.append(("POST", url, json))
            state["exists"] = True
            return FakeResp(200, {"title": json["title"], "_links": {"webui": "/x"}})

        def put(self, url, headers=None, json=None):
            calls.append(("PUT", url, json))
            assert json["version"]["number"] == 4  # 3 + 1
            return FakeResp(200, {"title": json["title"], "_links": {"webui": "/x"}})

    import src.daily_report as dr
    orig = dr.httpx if hasattr(dr, "httpx") else None
    import httpx as _httpx
    _orig_client = _httpx.Client
    _httpx.Client = lambda *a, **k: FakeClient()
    try:
        r1 = publish("https://x", "u", "t", "~space", "제목", "<p>본문</p>")
        assert r1["action"] == "created"
        r2 = publish("https://x", "u", "t", "~space", "제목", "<p>본문2</p>")
        assert r2["action"] == "updated"
    finally:
        _httpx.Client = _orig_client
    assert any(c[0] == "POST" for c in calls) and any(c[0] == "PUT" for c in calls)


def test_local_date_str_handles_bad_input():
    assert _local_date_str("") == ""
    assert _local_date_str("not-a-date") == ""
