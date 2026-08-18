"""자가 진화(self-evolution) 레이어 검증.

- 교훈 진화: 신호 감지 → 반성 → lessons append(레다크션) → 다음 run 플래너 주입
- 스킬 진화: 개선 제안 생성 → 사람 승인 게이트(API) 로만 적용
- 안전 불변식: 능력·권한은 진화하지 않는다 (reflector 쓰기 경로는 lessons/proposals 뿐)
"""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from src.graph import MAX_TOOL_CALLS_PER_RUN, build_graph
from src.llm import ScriptedChatModel
from src.nodes.reflector import (
    _parse_reflection,
    append_lesson,
    lessons_path,
    load_lessons,
    reflect_on_state,
    run_signals,
    write_proposal,
)
from tests.conftest import StubReadOnlyClient, ai_tool_call

REFLECTION_REPLY = (
    "LESSON: 전체 스캔 전에 k8s_list_namespaces로 후보를 좁히고 문제 신호가 있는 곳만 상세 조회한다.\n"
    "PROPOSAL:\n---\nname: inspector\ndescription: 개선판\n---\n\n네임스페이스를 먼저 좁혀라.\n"
)


def test_run_signals_detection():
    assert run_signals({"tool_trace": []}, 10) == []
    assert run_signals({"tool_trace": [{"tool": "x", "allowed": True}] * 10}, 10) == ["budget_exhausted"]
    assert "calls_rejected" in run_signals({"tool_trace": [{"tool": "x", "allowed": False}]}, 10)
    assert "tool_errors" in run_signals(
        {"tool_trace": [{"tool": "x", "allowed": True, "error": "ValidationError"}]}, 10
    )


def test_parse_reflection_and_lesson_redaction(tmp_path):
    lesson, proposal = _parse_reflection(REFLECTION_REPLY)
    assert lesson.startswith("전체 스캔 전에")
    assert "네임스페이스를 먼저 좁혀라" in proposal

    append_lesson(tmp_path, "inspector", "접속 password: Sup3rSec1 발견 시 즉시 보고", ["manual"])
    text = lessons_path(tmp_path, "inspector").read_text(encoding="utf-8")
    assert "Sup3rSec1" not in text and "[REDACTED]" in text  # 교훈도 레다크션 통과

    for i in range(12):
        append_lesson(tmp_path, "inspector", f"교훈 {i}", ["manual"])
    tail = load_lessons(tmp_path, "inspector")
    assert "교훈 11" in tail and "교훈 3" not in tail  # 최근 N개만 주입


def test_write_proposal_validates_name(tmp_path):
    assert write_proposal(tmp_path, "../evil", "x") is None
    assert write_proposal(tmp_path, "UPPER", "x") is None
    path = write_proposal(tmp_path, "inspector", "개선된 지시문")
    assert path and path.parent.name == "proposals" and path.name.startswith("inspector-")


def test_reflect_on_state_noop_without_signals(tmp_path):
    model = ScriptedChatModel(script=[AIMessage(content=REFLECTION_REPLY)])
    outcome = reflect_on_state(
        model, tmp_path / "wiki", tmp_path / ".agents",
        {"tool_trace": [{"tool": "x", "allowed": True}], "question": "q"},
        max_tool_calls=40,
    )
    assert outcome == {}  # 신호 없으면 LLM 호출 자체가 없다 (스크립트 미소모)
    assert model._cursor == 0


def test_graph_run_with_rejection_learns_lesson(wiki_dir):
    """거부 신호 → reflector가 교훈을 남기고 제안을 생성한다 (그래프 통합)."""
    model = ScriptedChatModel(
        script=[
            ai_tool_call("kubectl_delete_pod", {"namespace": "default", "name": "x"}),
            AIMessage(content="삭제는 불가능합니다."),
            AIMessage(content=REFLECTION_REPLY),
        ]
    )
    agents_dir = wiki_dir.parent / ".agents"
    graph = build_graph(
        model=model, k8s=StubReadOnlyClient(), wiki_dir=wiki_dir, agents_dir=agents_dir
    )
    result = graph.invoke(
        {"question": "x 지워줘", "session_id": "evo-1", "agent_name": "inspector",
         "messages": [HumanMessage("x 지워줘")]},
        config={"recursion_limit": 30},
    )
    assert "후보를 좁히고" in result["last_lesson"]
    lessons_file = wiki_dir / "lessons" / "inspector.md"
    assert lessons_file.is_file() and "calls_rejected" in lessons_file.read_text(encoding="utf-8")
    proposals = list((agents_dir / "proposals").glob("inspector-*.md"))
    assert len(proposals) == 1
    assert result["last_proposal"] == proposals[0].name


def test_next_run_injects_learned_lessons(wiki_dir):
    """배운 교훈이 다음 run의 시스템 프롬프트에 주입된다 — 진화 루프의 닫힘."""
    append_lesson(wiki_dir, "inspector", "전체 스캔 대신 네임스페이스를 먼저 좁힌다", ["manual"])

    from tests.test_agents import RecordingModel

    graph = build_graph(model=RecordingModel(), k8s=StubReadOnlyClient(), wiki_dir=wiki_dir)
    graph.invoke(
        {"question": "파드 봐줘", "session_id": "evo-2", "agent_name": "inspector",
         "messages": [HumanMessage("파드 봐줘")]},
        config={"recursion_limit": 30},
    )
    assert "[축적된 교훈" in RecordingModel.last_system
    assert "네임스페이스를 먼저 좁힌다" in RecordingModel.last_system


# ---------- 웹 API ----------

def _evo_client(tmp_path, model):
    from fastapi.testclient import TestClient

    from src.web import make_app
    from tests.test_web_harness import _fake_kubeconfig, _settings

    settings = _settings(tmp_path, _fake_kubeconfig(tmp_path))
    settings.agents_dir.mkdir(exist_ok=True)
    app = make_app(settings=settings, model=model, k8s=StubReadOnlyClient())
    return TestClient(app), settings


def test_web_sse_emits_evolution_event(tmp_path):
    from tests.test_web_harness import _sse_events

    model = ScriptedChatModel(
        script=[
            ai_tool_call("kubectl_delete_pod", {"namespace": "default", "name": "x"}),
            AIMessage(content="삭제 불가."),
            AIMessage(content=REFLECTION_REPLY),
        ]
    )
    client, settings = _evo_client(tmp_path, model)
    res = client.post("/api/chat", json={"message": "x 지워줘", "thread_id": "evo-web"})
    events = _sse_events(res)
    evo = [e for e in events if e["type"] == "evolution"]
    assert evo and "후보를 좁히고" in evo[0]["lesson"]
    assert evo[0]["proposal"].startswith("inspector-")


def test_manual_reflect_and_proposal_lifecycle(tmp_path):
    model = ScriptedChatModel(
        script=[
            AIMessage(content="정상 답변입니다."),
            AIMessage(content=REFLECTION_REPLY),
        ]
    )
    client, settings = _evo_client(tmp_path, model)
    client.post("/api/chat", json={"message": "파드 봐줘", "thread_id": "evo-man"})

    # 수동 반성 (신호 없어도 force)
    res = client.post("/api/sessions/evo-man/reflect")
    data = res.json()
    assert "후보를 좁히고" in data["lesson"]
    assert data["proposal_file"].startswith("inspector-")

    # 제안 목록/조회
    proposals = client.get("/api/proposals").json()["proposals"]
    assert proposals and proposals[0]["name"] == "inspector"
    detail = client.get(f"/api/proposals/{proposals[0]['file']}").json()
    assert "네임스페이스를 먼저 좁혀라" in detail["content"]

    # 승인 = 기존 에이전트 편집 API로 적용 → 제안 폐기
    assert client.put("/api/agents/inspector/raw", json={"content": detail["content"]}).status_code == 200
    assert client.delete(f"/api/proposals/{proposals[0]['file']}").json()["removed"] is True
    assert client.get("/api/proposals").json()["proposals"] == []
    assert client.get("/api/agents/inspector").json()["description"] == "개선판"

    # 경로 조작 차단
    assert client.get("/api/proposals/..%2Fevil.md").status_code in (400, 404)
