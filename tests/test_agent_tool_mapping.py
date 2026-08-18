"""에이전트↔도구 매핑 검증 — 하네스가 정확히 걸리는지.

- 각 에이전트 정의의 tools: 가 실제 존재하는 도구만 가리키는지 (오타 = 죽은 매핑)
- 플래너가 에이전트별 서브셋만 LLM에 바인딩하는지
- 매핑이 있어도 실행기 검증층(verb·전송 가드)은 불변인지
"""

from __future__ import annotations

from pathlib import Path

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage
from langchain_core.outputs import ChatGeneration, ChatResult

from src.agents import load_agents
from src.nodes.planner import make_planner_node
from src.tools.k8s_read import make_tools
from tests.conftest import StubReadOnlyClient

PROJECT_AGENTS = Path(__file__).resolve().parent.parent / ".agents"


class WideStub(StubReadOnlyClient):
    def __getattr__(self, name):
        return lambda *a, **k: []


def _all_tool_names() -> set[str]:
    from src.tools.source_reader import SourceHost, make_source_tools

    k8s_tools = make_tools(WideStub())
    src_tools = make_source_tools(SourceHost("heejoon@172.29.70.161"))
    return {t.name for t in [*k8s_tools, *src_tools]}


def test_every_agent_tool_mapping_points_to_real_tools():
    """매핑 오타는 곧 '조용히 죽은 하네스'다 — 전 에이전트의 tools를 실제 도구와 대조."""
    available = _all_tool_names()
    agents = load_agents(PROJECT_AGENTS)
    assert len(agents) >= 6
    for agent in agents.values():
        unknown = [t for t in agent.tools if t not in available]
        assert not unknown, f"에이전트 '{agent.name}' 의 미존재 도구 매핑: {unknown}"


def test_specialist_agents_have_curated_subsets():
    agents = load_agents(PROJECT_AGENTS)
    # 전문 에이전트는 서브셋 매핑을 갖는다
    for name in ("sre-triage", "capacity-analyst", "network-debugger", "log-collector", "code-correlator"):
        assert agents[name].tools, f"{name} 에 tools 매핑이 없습니다"
    # inspector(범용)는 전체 도구 (매핑 없음)
    assert agents["inspector"].tools == ()
    # 역할 정합성 스팟 체크
    assert "k8s_top_pods" in agents["capacity-analyst"].tools
    assert "src_search" in agents["code-correlator"].tools
    assert "k8s_list_custom" in agents["network-debugger"].tools
    assert "src_search" not in agents["log-collector"].tools  # 로그 수집가는 소스 도구 불필요


class BindRecordingModel(BaseChatModel):
    """bind_tools 로 받은 도구 이름을 기록하는 모의 모델."""

    last_bound: list[str] = []

    @property
    def _llm_type(self) -> str:
        return "bind-recording"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        return ChatResult(generations=[ChatGeneration(message=AIMessage(content="ok"))])

    def bind_tools(self, tools, **kwargs):
        BindRecordingModel.last_bound = [t.name for t in tools]
        return self


def test_planner_binds_agent_subset_only():
    tools = make_tools(WideStub())
    # 생성 시 전체 바인딩 (매핑 없는 에이전트가 쓰는 bound_all)
    make_planner_node(BindRecordingModel(), tools)
    assert len(BindRecordingModel.last_bound) == len(tools)

    planner = make_planner_node(BindRecordingModel(), tools)
    planner({
        "messages": [HumanMessage("용량 봐줘")],
        "agent_tools": ["k8s_top_pods", "k8s_list_nodes", "no-such-tool"],
        "wiki_context": "",
    })
    assert set(BindRecordingModel.last_bound) == {"k8s_top_pods", "k8s_list_nodes"}  # 미존재는 무시


def test_executor_safety_unchanged_with_mapping(tmp_path):
    """매핑은 조준용일 뿐 — 서브셋 밖 도구를 불러도 실행기 검증은 그대로 동작한다."""
    from src.graph import build_graph
    from src.llm import ScriptedChatModel
    from tests.conftest import ai_tool_call

    stub = StubReadOnlyClient()
    model = ScriptedChatModel(script=[
        ai_tool_call("kubectl_delete_pod", {"namespace": "default", "name": "x"}),
        AIMessage(content="거부 확인"),
    ])
    graph = build_graph(model=model, k8s=stub, wiki_dir=tmp_path / "wiki")
    result = graph.invoke(
        {"question": "x 삭제", "session_id": "map-1", "agent_tools": ["k8s_list_pods"],
         "messages": [HumanMessage("x 삭제")]},
        config={"recursion_limit": 30},
    )
    from langchain_core.messages import ToolMessage
    assert any(isinstance(m, ToolMessage) and "[거부됨" in str(m.content) for m in result["messages"])
    assert stub.calls == []
