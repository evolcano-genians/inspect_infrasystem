"""LangGraph StateGraph 조립 — 그래프·상태·체크포인팅을 전부 코드가 소유한다.

흐름 (README §4):
  START → wiki_reader → planner ─(tool_calls)→ executor → formatter → planner … (재조사 루프)
                          └─(도구 호출 없음)→ wiki_writer → END
"""

from __future__ import annotations

import json
from typing import Annotated, TypedDict

from langchain_core.messages import BaseMessage, ToolMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from .audit import AuditLogger
from .nodes.formatter import compact_text, formatter_node
from .nodes.planner import make_planner_node
from .nodes.wiki_reader import make_wiki_reader_node
from .nodes.wiki_writer import make_wiki_writer_node
from .tools import verb_validator
from .tools.guarded_client import ReadOnlyViolation
from .tools.k8s_read import make_tools

#: 한 번의 질의(run)에서 허용하는 최대 도구 호출 수. 초과 시 강제로 wiki_writer로 빠져
#: 그때까지의 관찰이 유실되지 않게 한다 (GraphRecursionError로 죽는 것을 방지).
MAX_TOOL_CALLS_PER_RUN = 24


class InspectorState(TypedDict, total=False):
    messages: Annotated[list[BaseMessage], add_messages]
    question: str
    session_id: str
    wiki_context: str
    raw_results: list
    # observations/tool_trace는 reducer 없이 노드가 전체 값을 관리한다.
    # (operator.add reducer를 쓰면 checkpointer로 같은 thread를 재사용할 때
    #  과거 run의 값이 계속 누적되어 위키에 중복 기록되는 버그가 있었다.)
    observations: list
    tool_trace: list
    final_answer: str
    agent_instructions: str  # 선택된 에이전트 정의(.agents/*.md)의 추가 시스템 지시


def make_executor_node(tools: list, audit: AuditLogger | None):
    """Verb Validator → Executor.

    도구 실행 직전 결정론적 검증(방어선 2)을 통과한 호출만 실행한다.
    거부는 subprocess/API 호출 없이 즉시 ToolMessage로 반환된다.
    (허용된 호출의 audit 기록은 도구 래퍼 내부에서 남는다 — 여기서는 거부만 기록해
    이중 기록을 피한다.)
    """
    tools_by_name = {t.name: t for t in tools}

    def executor(state: dict) -> dict:
        last = state["messages"][-1]
        tool_messages, raws = [], []
        trace = list(state.get("tool_trace") or [])
        for tc in getattr(last, "tool_calls", None) or []:
            name, args, tc_id = tc["name"], tc.get("args") or {}, tc["id"]
            verdict = verb_validator.validate_tool_call(name, args)
            tool = tools_by_name.get(name)
            if not verdict.allowed or tool is None:
                reason = verdict.reason if not verdict.allowed else f"도구 '{name}' 미탑재"
                if audit:
                    audit.record(
                        tool=name,
                        verb=verdict.spec.verb if verdict.spec else "(unknown)",
                        namespace=str(args.get("namespace", "")),
                        allowed=False,
                        reason=reason,
                    )
                trace.append({"tool": name, "allowed": False})
                tool_messages.append(
                    ToolMessage(
                        content=f"[거부됨 · read-only 정책] {reason}",
                        tool_call_id=tc_id,
                        name=name,
                    )
                )
                continue
            try:
                result = tool.invoke(args)  # 래퍼 내부에서 재검증 + audit 기록
            except ReadOnlyViolation as exc:
                # 전송 가드(방어선 3)가 잡은 요청 — 거부로 기록하고 계속 진행
                if audit:
                    audit.record(
                        tool=name, verb=verdict.spec.verb if verdict.spec else "(unknown)",
                        namespace=str(args.get("namespace", "")), allowed=False, reason=str(exc),
                    )
                trace.append({"tool": name, "allowed": False})
                tool_messages.append(
                    ToolMessage(content=f"[거부됨 · 전송 가드] {exc}", tool_call_id=tc_id, name=name)
                )
                continue
            except Exception as exc:  # 필수 인자 누락(pydantic) 등 — run 전체를 죽이지 않는다
                trace.append({"tool": name, "allowed": True, "error": type(exc).__name__})
                tool_messages.append(
                    ToolMessage(
                        content=f"[도구 오류] {type(exc).__name__}: {exc}",
                        tool_call_id=tc_id,
                        name=name,
                    )
                )
                continue
            raws.append({"tool": name, "args": args, "result": result})
            trace.append({"tool": name, "allowed": True})
            content = result if isinstance(result, str) else json.dumps(
                result, ensure_ascii=False, default=str
            )
            tool_messages.append(
                ToolMessage(content=compact_text(content), tool_call_id=tc_id, name=name)
            )
        return {"messages": tool_messages, "raw_results": raws, "tool_trace": trace}

    return executor


def route_after_planner(state: dict) -> str:
    last = state["messages"][-1]
    if not getattr(last, "tool_calls", None):
        return "wiki_writer"
    if len(state.get("tool_trace") or []) >= MAX_TOOL_CALLS_PER_RUN:
        return "wiki_writer"  # 조사 한도 도달 — 관찰 유실 없이 마무리 단계로
    return "executor"


def build_graph(
    *,
    model,
    k8s,
    wiki_dir,
    audit: AuditLogger | None = None,
    checkpointer=None,
    interrupt_before: list[str] | None = None,
    tools: list | None = None,
):
    tools = tools if tools is not None else make_tools(k8s, audit)
    graph = StateGraph(InspectorState)
    graph.add_node("wiki_reader", make_wiki_reader_node(wiki_dir))
    graph.add_node("planner", make_planner_node(model, tools))
    graph.add_node("executor", make_executor_node(tools, audit))
    graph.add_node("formatter", formatter_node)
    graph.add_node("wiki_writer", make_wiki_writer_node(wiki_dir))
    graph.add_edge(START, "wiki_reader")
    graph.add_edge("wiki_reader", "planner")
    graph.add_conditional_edges(
        "planner", route_after_planner, {"executor": "executor", "wiki_writer": "wiki_writer"}
    )
    graph.add_edge("executor", "formatter")
    graph.add_edge("formatter", "planner")
    graph.add_edge("wiki_writer", END)
    return graph.compile(checkpointer=checkpointer, interrupt_before=interrupt_before or [])
