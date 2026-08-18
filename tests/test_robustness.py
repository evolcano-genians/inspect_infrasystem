"""적대적 리뷰에서 확정된 결함들에 대한 회귀 테스트.

- 필수 인자 누락 tool call → run이 죽지 않고 [도구 오류] ToolMessage로 계속 진행
- 도구 내부 예외(ConnectionError 등) → run이 죽지 않음
- 전송 가드 ReadOnlyViolation → 우아한 거부 (크래시 아님)
- 조사 한도(MAX_TOOL_CALLS_PER_RUN) 도달 → GraphRecursionError 없이 위키 기록 후 종료
- 같은 thread 재사용 시 observations/tool_trace가 과거 run과 중복 누적되지 않음
"""

from __future__ import annotations

import sqlite3

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from langgraph.checkpoint.sqlite import SqliteSaver

from src.graph import MAX_TOOL_CALLS_PER_RUN, build_graph
from src.llm import ScriptedChatModel
from src.tools.guarded_client import ReadOnlyViolation
from src.tools.k8s_read import make_tools
from tests.conftest import StubReadOnlyClient, ai_tool_call


def _invoke(graph, question, thread="rb-1", saver_config=None):
    config = saver_config or {"recursion_limit": 60}
    return graph.invoke(
        {"question": question, "session_id": thread, "messages": [HumanMessage(question)]},
        config=config,
    )


def test_missing_required_arg_does_not_kill_run(wiki_dir):
    model = ScriptedChatModel(
        script=[
            ai_tool_call("k8s_get_pod", {"namespace": "default"}),  # 'name' 누락
            AIMessage(content="인자가 부족해 조회에 실패했지만 조사는 계속됩니다."),
        ]
    )
    graph = build_graph(model=model, k8s=StubReadOnlyClient(), wiki_dir=wiki_dir)
    result = _invoke(graph, "파드 상태 알려줘")
    tool_errors = [
        m for m in result["messages"]
        if isinstance(m, ToolMessage) and "[도구 오류]" in str(m.content)
    ]
    assert tool_errors, "필수 인자 누락이 [도구 오류] ToolMessage로 처리되어야 합니다"
    assert result["final_answer"]


def test_tool_internal_exception_does_not_kill_run(wiki_dir):
    class BrokenStub(StubReadOnlyClient):
        def list_pods(self, namespace, label_selector="", field_selector=""):
            raise ConnectionError("connection refused")

    model = ScriptedChatModel(
        script=[
            ai_tool_call("k8s_list_pods", {"namespace": "default"}),
            AIMessage(content="클러스터 연결에 실패했습니다."),
        ]
    )
    graph = build_graph(model=model, k8s=BrokenStub(), wiki_dir=wiki_dir)
    result = _invoke(graph, "파드 목록")
    assert result["final_answer"]  # 크래시 없이 종료
    errors = [
        m for m in result["messages"]
        if isinstance(m, ToolMessage) and "오류" in str(m.content)
    ]
    assert errors


def test_transport_guard_violation_is_graceful_rejection(audit):
    class GuardTrippingStub(StubReadOnlyClient):
        def get_service(self, namespace, name):
            raise ReadOnlyViolation("금지된 경로 세그먼트 '/proxy' 차단")

    tools = {t.name: t for t in make_tools(GuardTrippingStub(), audit)}
    out = tools["k8s_get_service"].invoke({"namespace": "default", "name": "proxy"})
    assert isinstance(out, str) and "[거부됨" in out
    assert any(not e["allowed"] for e in audit.entries())


class AlwaysToolCallingModel(BaseChatModel):
    """도구 호출을 무한히 반복하는 모델 — 조사 한도 동작 검증용."""

    @property
    def _llm_type(self) -> str:
        return "always-tool-fake"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        n = sum(1 for m in messages if isinstance(m, ToolMessage))
        message = AIMessage(
            content="",
            tool_calls=[{
                "name": "k8s_list_pods",
                "args": {"namespace": "default"},
                "id": f"call_{n}",
                "type": "tool_call",
            }],
        )
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):
        return self


def test_sanitize_history_heals_dangling_tool_calls():
    """예산 차단으로 미실행된 tool_call이 남아도 다음 턴 요청 이력이 유효해야 한다."""
    from langchain_core.messages import HumanMessage as HM

    from src.nodes.planner import sanitize_history

    history = [
        HM("q1"),
        AIMessage(content="", tool_calls=[
            {"name": "k8s_list_pods", "args": {"namespace": "a"}, "id": "c1", "type": "tool_call"},
            {"name": "k8s_list_pods", "args": {"namespace": "b"}, "id": "c2", "type": "tool_call"},
        ]),
        ToolMessage(content="ok", tool_call_id="c1", name="k8s_list_pods"),  # c2는 미응답
        HM("q2"),
    ]
    healed = sanitize_history(history)
    # c2 취소 응답이 tool_calls 메시지 '직후'(다음 Human 이전)에 삽입된다
    idx_ai = next(i for i, m in enumerate(healed) if isinstance(m, AIMessage))
    cancels = [
        m for m in healed
        if isinstance(m, ToolMessage) and m.tool_call_id == "c2"
    ]
    assert len(cancels) == 1 and "[취소됨]" in str(cancels[0].content)
    assert healed.index(cancels[0]) > idx_ai
    assert healed.index(cancels[0]) < healed.index(history[3])
    # 응답이 이미 있는 c1은 중복 삽입되지 않는다
    assert sum(1 for m in healed if isinstance(m, ToolMessage) and m.tool_call_id == "c1") == 1
    # 미응답이 없으면 원본 그대로
    assert sanitize_history(healed) == healed


def test_budget_hit_session_can_continue(tmp_path, wiki_dir):
    """예산 도달로 끝난 세션에서 다음 질문이 정상 동작해야 한다 (dangling 회복)."""
    saver = SqliteSaver(sqlite3.connect(str(tmp_path / "ckpt.sqlite"), check_same_thread=False))
    config = {"configurable": {"thread_id": "budget-1"}, "recursion_limit": 300}

    graph1 = build_graph(model=AlwaysToolCallingModel(), k8s=StubReadOnlyClient(),
                         wiki_dir=wiki_dir, checkpointer=saver)
    r1 = _invoke(graph1, "전부 조사해줘", saver_config=config)
    assert "한도" in r1["final_answer"]

    # 같은 thread에서 두 번째 질의 — 이력에 미응답 tool_call이 있어도 실패하지 않아야 한다
    graph2 = build_graph(
        model=ScriptedChatModel(script=[AIMessage(content="이어서 답합니다.")]),
        k8s=StubReadOnlyClient(), wiki_dir=wiki_dir, checkpointer=saver,
    )
    r2 = _invoke(graph2, "요약만 해줘", saver_config=config)
    assert r2["final_answer"] == "이어서 답합니다."


def test_tool_call_budget_ends_run_without_losing_wiki(wiki_dir):
    stub = StubReadOnlyClient()
    graph = build_graph(model=AlwaysToolCallingModel(), k8s=stub, wiki_dir=wiki_dir)
    result = _invoke(graph, "default 네임스페이스 전부 조사해줘", saver_config={"recursion_limit": 200})
    assert len(result["tool_trace"]) == MAX_TOOL_CALLS_PER_RUN
    assert "한도" in result["final_answer"]
    # 관찰이 유실되지 않고 위키에 기록되었다
    assert (wiki_dir / "workloads" / "crashloop-demo.md").exists()


def test_thread_reuse_does_not_duplicate_observations(tmp_path, wiki_dir):
    saver = SqliteSaver(sqlite3.connect(str(tmp_path / "ckpt.sqlite"), check_same_thread=False))

    def scripted():
        return ScriptedChatModel(
            script=[
                ai_tool_call("k8s_list_pods", {"namespace": "default"}),
                AIMessage(content="crashloop-demo가 CrashLoopBackOff 상태입니다."),
            ]
        )

    config = {"configurable": {"thread_id": "reuse-1"}, "recursion_limit": 30}
    graph1 = build_graph(model=scripted(), k8s=StubReadOnlyClient(), wiki_dir=wiki_dir, checkpointer=saver)
    r1 = _invoke(graph1, "CrashLoopBackOff 파드 찾아줘", saver_config=config)
    graph2 = build_graph(model=scripted(), k8s=StubReadOnlyClient(), wiki_dir=wiki_dir, checkpointer=saver)
    r2 = _invoke(graph2, "CrashLoopBackOff 파드 찾아줘", saver_config=config)

    # run마다 리셋되므로 두 번째 run의 trace/관찰 수는 첫 run과 같아야 한다 (누적 금지)
    assert len(r1["tool_trace"]) == len(r2["tool_trace"]) == 1
    assert len(r1["observations"]) == len(r2["observations"])
    # 위키 관찰 이력은 run당 1회씩만 append — pod 관찰 라인이 정확히 2개
    body = (wiki_dir / "workloads" / "crashloop-demo.md").read_text(encoding="utf-8")
    assert body.count("phase=Running") == 2
