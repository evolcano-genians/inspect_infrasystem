"""수용 기준: 동일 질의를 두 세션에 걸쳐 실행하면, 두 번째 세션은 위키에 저장된
첫 세션의 관찰을 재사용해(재조사 없이) 답변에 반영해야 한다."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from src.graph import build_graph
from tests.conftest import StubReadOnlyClient

QUESTION = "default 네임스페이스에서 CrashLoopBackOff 상태인 파드 찾아줘"


class WikiAwareFakeModel(BaseChatModel):
    """위키 컨텍스트에 과거 관찰이 있으면 도구 없이 답하고, 없으면 재조사하는 규칙 기반 모델.

    결정론적 규칙이므로 '위키 재사용' 플럼빙(reader → planner 컨텍스트 주입)이 실제로
    동작하는지를 네트워크 없이 검증할 수 있다.
    """

    marker: str = "crashloop-demo"

    @property
    def _llm_type(self) -> str:
        return "wiki-aware-fake"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        system_text = str(messages[0].content) if messages else ""
        last = messages[-1] if messages else None
        if isinstance(last, ToolMessage):
            message = AIMessage(
                content="결론: crashloop-demo 파드가 CrashLoopBackOff 상태입니다 (라이브 재조사 결과)."
            )
        elif self.marker in system_text:
            message = AIMessage(
                content="위키에 기록된 과거 관찰에 따르면 crashloop-demo 파드가 "
                "CrashLoopBackOff 상태였습니다. (재조사 없이 위키 재사용)"
            )
        else:
            message = AIMessage(
                content="",
                tool_calls=[{
                    "name": "k8s_list_pods",
                    "args": {"namespace": "default"},
                    "id": "call_1",
                    "type": "tool_call",
                }],
            )
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools, **kwargs):
        return self


def _run_session(wiki_dir, session_id: str):
    stub = StubReadOnlyClient()
    graph = build_graph(model=WikiAwareFakeModel(), k8s=stub, wiki_dir=wiki_dir)
    result = graph.invoke(
        {"question": QUESTION, "session_id": session_id, "messages": [HumanMessage(QUESTION)]},
        config={"recursion_limit": 30},
    )
    return result, stub


def test_second_session_reuses_wiki_without_reinspection(wiki_dir):
    # 세션 1: 위키가 비어 있으므로 도구로 조사하고 관찰을 위키에 남긴다
    result1, stub1 = _run_session(wiki_dir, "s1")
    assert stub1.calls, "세션 1은 실제 조사를 수행해야 합니다"
    assert (wiki_dir / "workloads" / "crashloop-demo.md").exists()
    assert (wiki_dir / "patterns" / "crashloopbackoff.md").exists()
    assert "crashloop-demo" in result1["final_answer"]

    # 세션 2: 동일 질의 — 위키의 과거 관찰을 재사용하고 도구를 호출하지 않는다
    result2, stub2 = _run_session(wiki_dir, "s2")
    assert stub2.calls == [], f"세션 2가 재조사를 수행했습니다: {stub2.calls}"
    assert result2["tool_trace"] == []
    assert "위키" in result2["final_answer"]
    assert "crashloop-demo" in result2["final_answer"]
