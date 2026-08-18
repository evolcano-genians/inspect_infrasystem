"""6-5 LangGraph 상태 재현성 — 동일 입력 + checkpointer 저장/재개 시 일관된 결과."""

from __future__ import annotations

import sqlite3

from langchain_core.messages import AIMessage, HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver

from src.graph import build_graph
from src.llm import ScriptedChatModel
from tests.conftest import StubReadOnlyClient, ai_tool_call

QUESTION = "default 네임스페이스에서 CrashLoopBackOff 상태인 파드 찾아줘"
FINAL = "결론: crashloop-demo 파드가 CrashLoopBackOff 상태입니다 (restarts=5)."


def _model():
    return ScriptedChatModel(
        script=[
            ai_tool_call("k8s_list_pods", {"namespace": "default"}),
            AIMessage(content=FINAL),
        ]
    )


def _input(thread: str) -> dict:
    return {"question": QUESTION, "session_id": thread, "messages": [HumanMessage(QUESTION)]}


def _config(thread: str) -> dict:
    return {"configurable": {"thread_id": thread}, "recursion_limit": 30}


def test_same_input_gives_same_result(tmp_path):
    finals, traces = [], []
    for run in ("a", "b"):
        wiki = tmp_path / f"wiki-{run}"
        wiki.mkdir()
        saver = SqliteSaver(sqlite3.connect(str(tmp_path / f"ckpt-{run}.sqlite"), check_same_thread=False))
        graph = build_graph(model=_model(), k8s=StubReadOnlyClient(), wiki_dir=wiki, checkpointer=saver)
        result = graph.invoke(_input(f"t-{run}"), config=_config(f"t-{run}"))
        finals.append(result["final_answer"])
        traces.append([t["tool"] for t in result["tool_trace"]])
    assert finals[0] == finals[1] == FINAL
    assert traces[0] == traces[1] == ["k8s_list_pods"]


def test_interrupt_and_resume_is_consistent(tmp_path):
    wiki = tmp_path / "wiki-resume"
    wiki.mkdir()
    conn = sqlite3.connect(str(tmp_path / "ckpt.sqlite"), check_same_thread=False)
    saver = SqliteSaver(conn)
    graph = build_graph(
        model=_model(),
        k8s=StubReadOnlyClient(),
        wiki_dir=wiki,
        checkpointer=saver,
        interrupt_before=["executor"],
    )
    thread = "resume-1"
    paused = graph.invoke(_input(thread), config=_config(thread))
    assert "final_answer" not in paused or not paused.get("final_answer")

    # 체크포인트가 실제로 저장되었는지 확인 후 재개
    assert graph.get_state(_config(thread)).next == ("executor",)
    resumed = graph.invoke(None, config=_config(thread))
    assert resumed["final_answer"] == FINAL
    assert [t["tool"] for t in resumed["tool_trace"]] == ["k8s_list_pods"]
