"""에이전트 카탈로그(.agents/*.md)와 세션별 작업 관리 검증.

- Claude Code의 .claude/agents 패턴: 파일 정의 로딩 + builtin 기본값
- 에이전트 지시는 플래너 프롬프트에만 주입 — 도구·권한 불변
- 세션 목록/이력/삭제 API와 세션별 context 유지
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from src.agents import load_agents
from src.llm import HeuristicPlannerModel, ScriptedChatModel
from src.nodes.planner import make_planner_node
from tests.conftest import StubReadOnlyClient
from tests.test_web_harness import _client, _fake_kubeconfig, _settings, _sse_events

AGENT_MD = """---
name: sre-triage
description: 장애 분류 특화
---
이벤트와 로그를 교차 검증하라.
"""


def test_load_agents_builtin_and_files(tmp_path):
    agents_dir = tmp_path / ".agents"
    agents_dir.mkdir()
    (agents_dir / "sre-triage.md").write_text(AGENT_MD, encoding="utf-8")

    agents = load_agents(agents_dir)
    assert "inspector" in agents and agents["inspector"].source == "builtin"
    triage = agents["sre-triage"]
    assert triage.description == "장애 분류 특화"
    assert "교차 검증" in triage.instructions
    # 디렉터리가 없어도 builtin은 항상 존재
    assert "inspector" in load_agents(tmp_path / "no-such-dir")


class RecordingModel(BaseChatModel):
    """플래너가 실제로 보낸 시스템 프롬프트를 기록하는 모의 모델."""

    @property
    def _llm_type(self) -> str:
        return "recording-fake"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        RecordingModel.last_system = str(messages[0].content)
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

    def bind_tools(self, tools, **kwargs):
        return self


def test_planner_injects_agent_instructions():
    planner = make_planner_node(RecordingModel(), tools=[])
    planner(
        {
            "messages": [HumanMessage("파드 봐줘")],
            "agent_instructions": "이벤트와 로그를 교차 검증하라.",
            "wiki_context": "",
        }
    )
    assert "[에이전트 특화 지시]" in RecordingModel.last_system
    assert "교차 검증" in RecordingModel.last_system

    planner({"messages": [HumanMessage("파드 봐줘")], "wiki_context": ""})
    assert "[에이전트 특화 지시]" not in RecordingModel.last_system


def _client_with_agents(tmp_path, model):
    from fastapi.testclient import TestClient

    from src.web import make_app

    settings = _settings(tmp_path, _fake_kubeconfig(tmp_path))
    settings.agents_dir.mkdir(exist_ok=True)
    (settings.agents_dir / "sre-triage.md").write_text(AGENT_MD, encoding="utf-8")
    app = make_app(settings=settings, model=model, k8s=StubReadOnlyClient())
    return TestClient(app)


def test_agents_api_lists_agents_and_readonly_tools(tmp_path):
    client = _client_with_agents(tmp_path, ScriptedChatModel(script=[]))
    data = client.get("/api/agents").json()
    names = {a["name"] for a in data["agents"]}
    assert {"inspector", "sre-triage"} <= names
    assert len(data["tools"]) >= 16
    assert all(t["verb"] not in ("create", "delete", "patch") for t in data["tools"])

    detail = client.get("/api/agents/sre-triage").json()
    assert "교차 검증" in detail["instructions"]
    assert client.get("/api/agents/nope").status_code == 404


def test_chat_rejects_unknown_agent(tmp_path):
    client = _client_with_agents(tmp_path, ScriptedChatModel(script=[]))
    res = client.post("/api/chat", json={"message": "hi", "thread_id": "t1", "agent": "nope"})
    events = _sse_events(res)
    assert events[0]["type"] == "error" and "nope" in events[0]["message"]


def test_codex_reasoning_effort_policy():
    """fast(minimal/none)와 ultra(xhigh) 추론 단계는 요청 생성 전에 거부된다."""
    import pytest

    from src.llm import make_codex_model

    for forbidden in ("minimal", "none", "xhigh", "ultra", "XHIGH"):
        with pytest.raises(ValueError, match="정책상|알 수 없는"):
            make_codex_model("gpt-5.6-sol", forbidden)

    model = make_codex_model("gpt-5.6-sol", "medium")
    assert model.reasoning_effort == "medium"
    for allowed in ("low", "high"):
        assert make_codex_model("gpt-5.6-sol", allowed).reasoning_effort == allowed


def test_reasoning_mode_selection_api(tmp_path):
    """codex-oauth에서는 low/medium/high 선택 가능, 금지값은 네트워크 이전에 거부."""
    from dataclasses import replace

    from fastapi.testclient import TestClient

    from src.web import make_app

    settings = replace(_settings(tmp_path, _fake_kubeconfig(tmp_path)), model_provider="codex-oauth")
    app = make_app(settings=settings, k8s=StubReadOnlyClient())  # model 미주입 → 단계별 그래프
    client = TestClient(app)

    health = client.get("/api/health").json()
    assert health["reasoning_options"] == ["low", "medium", "high"]
    assert health["reasoning_effort"] == "medium"

    res = client.post("/api/chat", json={"message": "hi", "thread_id": "r1", "reasoning": "xhigh"})
    events = _sse_events(res)
    assert events[0]["type"] == "error" and "xhigh" in events[0]["message"]
    res2 = client.post("/api/chat", json={"message": "hi", "thread_id": "r1", "reasoning": "minimal"})
    assert _sse_events(res2)[0]["type"] == "error"


def test_reasoning_field_ignored_for_non_codex_provider(tmp_path):
    client = _client_with_agents(tmp_path, HeuristicPlannerModel())
    res = client.post(
        "/api/chat",
        json={"message": "default 파드 봐줘", "thread_id": "r2", "reasoning": "high"},
    )
    events = _sse_events(res)
    start = next(e for e in events if e["type"] == "start")
    assert start["reasoning"] == ""  # codex-oauth가 아니므로 무시
    assert any(e["type"] == "final" for e in events)


def test_session_lifecycle_and_per_session_context(tmp_path):
    model = ScriptedChatModel(
        script=[
            AIMessage(content="첫 번째 답변입니다."),
            AIMessage(content="두 번째 답변입니다."),
            AIMessage(content="다른 세션의 답변입니다."),
        ]
    )
    client = _client_with_agents(tmp_path, model)

    # 세션 A: 두 턴 — context(메시지 이력)가 세션에 누적된다
    client.post("/api/chat", json={"message": "첫 질문", "thread_id": "sess-a", "agent": "sre-triage"})
    client.post("/api/chat", json={"message": "둘째 질문", "thread_id": "sess-a"})
    # 세션 B: 독립 세션
    client.post("/api/chat", json={"message": "B 질문", "thread_id": "sess-b"})

    sessions = client.get("/api/sessions").json()["sessions"]
    by_id = {s["thread_id"]: s for s in sessions}
    assert by_id["sess-a"]["turns"] == 2
    assert by_id["sess-a"]["title"] == "첫 질문"          # 제목은 첫 질문으로 고정
    assert by_id["sess-a"]["agent"] == "inspector"        # 마지막 턴의 에이전트로 갱신
    assert by_id["sess-b"]["turns"] == 1

    # 세션별 context 유지: A의 이력은 4개(질문2+답2), B는 2개 — 서로 섞이지 않는다
    hist_a = client.get("/api/sessions/sess-a/history").json()
    assert [t["role"] for t in hist_a["turns"]] == ["user", "assistant", "user", "assistant"]
    assert hist_a["turns"][0]["content"] == "첫 질문"
    assert "첫 번째" in hist_a["turns"][1]["content"]
    hist_b = client.get("/api/sessions/sess-b/history").json()
    assert len(hist_b["turns"]) == 2 and hist_b["turns"][0]["content"] == "B 질문"

    # 삭제하면 목록·이력(checkpoint 포함)에서 사라진다
    assert client.delete("/api/sessions/sess-b").json()["removed"] is True
    remaining = {s["thread_id"] for s in client.get("/api/sessions").json()["sessions"]}
    assert "sess-b" not in remaining
    assert client.get("/api/sessions/sess-b/history").json()["turns"] == []


def test_log_collector_agent_definition_loads():
    """log-collector 에이전트가 프로젝트 .agents/ 에서 로드된다."""
    from pathlib import Path

    agents = load_agents(Path(__file__).resolve().parent.parent / ".agents")
    lc = agents.get("log-collector")
    assert lc is not None
    assert "로그" in lc.description
    for marker in ("previous=True", "since_seconds", "loki", "이벤트 교차"):
        assert marker in lc.instructions, f"log-collector 지시문에 '{marker}' 누락"


def test_since_seconds_arg_validation():
    from src.tools import verb_validator
    from src.tools.k8s_read import make_tools
    from tests.conftest import StubReadOnlyClient

    make_tools(StubReadOnlyClient())
    ok = verb_validator.validate_tool_call(
        "k8s_get_pod_logs",
        {"namespace": "nexus-shell", "name": "loki-0", "since_seconds": 3600},
    )
    assert ok.allowed
    bad = verb_validator.validate_tool_call(
        "k8s_get_pod_logs",
        {"namespace": "nexus-shell", "name": "loki-0", "since_seconds": 10**9},
    )
    assert not bad.allowed
