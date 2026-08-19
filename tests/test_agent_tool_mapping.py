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
    from src.sandbox.bash_exec import BashSandbox
    from src.sandbox.security_tools import make_security_tools
    from src.tools.source_reader import SourceHost, make_source_tools

    class _FakeDocker:
        @property
        def containers(self):
            return type("C", (), {"run": lambda *a, **k: None})()

    from src.tools.shell_http import load_shell_envs, make_shell_http_tools
    from src.tools.trino_reader import TrinoConfig, make_trino_tools

    k8s_tools = make_tools(WideStub())
    src_tools = make_source_tools(SourceHost("heejoon@172.29.70.161"))
    sec_tools = make_security_tools(
        bash_enabled=True, strix_enabled=True,
        sandbox=BashSandbox(network="none", docker_client=_FakeDocker()),
        runner=lambda *a, **k: None,
    )
    trino_tools = make_trino_tools(TrinoConfig(endpoint="http://trino:8080"))
    shell_tools = make_shell_http_tools(load_shell_envs({
        "SHELL_ENVS": "vm", "SHELL_VM_BASE": "https://x",
        "SHELL_VM_USER": "u", "SHELL_VM_PASSWORD": "p",
    }))
    from src.tools.multicluster import make_multicluster_tools
    multi_tools = make_multicluster_tools({"ctx-a": WideStub(), "ctx-b": WideStub()})
    from src.tools.jira_reader import JiraConfig, make_jira_tools
    jira_tools = make_jira_tools(JiraConfig(base_url="https://jira.example.com", token="t"))
    from src.tools.web_test import make_web_test_tools
    web_tools = make_web_test_tools()
    return {t.name for t in [
        *k8s_tools, *src_tools, *sec_tools, *trino_tools, *shell_tools, *multi_tools, *jira_tools,
        *web_tools,
    ]}


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
    # 신규 감사·라우팅 도구 스팟 체크
    assert "k8s_list_role_bindings" in agents["security-auditor"].tools
    assert "web_security_scan" in agents["security-auditor"].tools
    assert "k8s_list_endpoints" in agents["network-debugger"].tools
    assert "k8s_list_hpas" in agents["capacity-analyst"].tools


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


# 확장 도구별 대표 인자 — executor의 verb_validator 게이트를 통과해야 실제로 동작한다.
# (이 매핑이 비면 data-analyst/platform-inspector/security-auditor의 시그니처 도구가
#  그래프 경로에서 조용히 전부 거부된다 — 회귀 방지용 고정 케이스.)
_REPRESENTATIVE_ARGS: dict[str, dict] = {
    "trino_query": {"sql": "SELECT 1", "max_rows": 200},
    "trino_catalogs": {},
    "trino_schemas": {"catalog": "delta"},
    "trino_tables": {"catalog": "delta", "schema": "bronze"},
    "trino_describe": {"catalog": "delta", "schema": "bronze", "table": "events"},
    "trino_sample": {"catalog": "delta", "schema": "silver", "table": "events", "limit": 20},
    "trino_count": {"catalog": "delta", "schema": "silver", "table": "events"},
    "trino_profile": {"catalog": "delta", "schema": "silver", "table": "events", "column": "user_id"},
    "trino_table_profile": {"catalog": "delta", "schema": "silver", "table": "events"},
    "trino_freshness": {"catalog": "delta", "schema": "silver"},
    "k8s_list_contexts": {},
    "k8s_compare": {"resource": "deployments", "namespace": "nexus-lake"},
    "k8s_read_at": {"context": "aws-seoul-clouddev", "resource": "pods", "namespace": "default"},
    "shell_list_envs": {},
    "shell_http_get": {"env": "vm", "path": "/api/auth/me"},
    "jira_get_issue": {"key": "https://ims.cloud.genians.com/browse/CL-1415"},
    "jira_search": {"jql": "project=CL ORDER BY updated DESC", "max_results": 20},
    "sandbox_bash": {"command": "echo hi", "timeout": 30},
    "sandbox_pentest_strix": {"target": "127.0.0.1", "instruction": "scan", "mode": "quick"},
    # 웹 테스팅 도구 — url 형식·method enum 게이트 통과
    "web_probe": {"url": "https://nexus.vmlab.test/", "method": "GET"},
    "web_security_scan": {"url": "https://nexus.vmlab.test/"},
    "web_links": {"url": "https://nexus.vmlab.test/"},
    # 신규 k8s 감사 도구 — bool 인자(include_system) fail-closed 회귀 방지
    "k8s_list_cluster_role_bindings": {"include_system": False},
    "k8s_get_role": {"name": "admin", "namespace": ""},
    "k8s_oss_inventory": {"namespace": "", "include_internal": False},
}


def test_extended_tools_pass_executor_validation():
    """확장 도구가 대표 인자로 verb_validator(executor 게이트)를 통과하는지 — 실동작 보장."""
    # 모든 도구를 조립해 레지스트리에 등록시킨다 (make_*_tools가 register_tool 호출)
    _all_tool_names()
    from src.tools import verb_validator as vv

    for name, args in _REPRESENTATIVE_ARGS.items():
        verdict = vv.validate_tool_call(name, args)
        assert verdict.allowed, f"확장 도구 '{name}' 이 executor 검증에서 거부됨: {verdict.reason}"


def test_extended_tool_args_still_reject_injection():
    """확장 인자 허용이 방어선을 뚫지 않는지 — 위험 인자는 여전히 거부."""
    _all_tool_names()
    from src.tools import verb_validator as vv

    # SQL 인젝션형 식별자, 미등록 인자, 셸 메타문자 대상은 거부돼야 한다
    assert not vv.validate_tool_call("trino_describe",
                                     {"catalog": "a;DROP", "schema": "b", "table": "c"}).allowed
    assert not vv.validate_tool_call("sandbox_bash", {"command": "x", "evil": "1"}).allowed
    assert not vv.validate_tool_call("sandbox_pentest_strix", {"target": "a`b`"}).allowed
    assert not vv.validate_tool_call("shell_http_get", {"env": "v m"}).allowed  # 공백 불가
    # 웹 테스팅: 비-http 스킴·변경 메서드·미등록 인자는 형식 게이트에서 거부
    assert not vv.validate_tool_call("web_probe", {"url": "file:///etc/passwd"}).allowed
    assert not vv.validate_tool_call("web_probe", {"url": "https://x.test/", "method": "POST"}).allowed
    assert not vv.validate_tool_call("web_probe", {"url": "http://x.test/", "evil": "1"}).allowed
