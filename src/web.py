"""웹 대화 하네스 — 브라우저 채팅으로 read-only 에이전트를 사용한다.

    KUBECONFIG=.local/kind-kubeconfig.yaml MODEL_PROVIDER=heuristic \
      .venv/bin/python -m src.web
    → http://127.0.0.1:8787

설계 원칙:
- 웹 레이어는 그래프를 "감싸기만" 한다 — 새로운 K8s 접근 경로를 만들지 않으므로
  4중 방어선(read facade·verb validator·GET-only 가드·스파이)이 그대로 적용된다.
- 기본 바인딩은 127.0.0.1 (로컬 전용). 외부 노출은 지원하지 않는다.
- 입력 검증: 질문 길이 상한, thread_id 형식 제한 (경로 조작·주입 방지).
- 진행 상황(도구 호출/거부/최종 답변)은 SSE(text/event-stream)로 스트리밍한다.
- 대화 연속성: 같은 thread_id 는 SqliteSaver 체크포인트로 이어지고,
  세션을 넘긴 지식은 위키가 담당한다.
"""

from __future__ import annotations

import json
import re
import sqlite3
import threading
import uuid
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.errors import GraphRecursionError
from pydantic import BaseModel, Field

from .agents import load_agents
from .audit import AuditLogger
from .config import Settings, assert_safe_kubeconfig, load_settings
from .graph import build_graph
from .llm import make_model
from .sessions import SessionStore
from .tools import verb_validator
from .tools.k8s_read import make_tools

_STATIC = Path(__file__).resolve().parent / "static"
_THREAD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
MAX_QUESTION_CHARS = 2_000


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=MAX_QUESTION_CHARS)
    thread_id: str = Field(default="", max_length=64)
    agent: str = Field(default="", max_length=64)


def _sse(payload: dict) -> str:
    return f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"


def _tool_status(content: str) -> str:
    if content.startswith("[거부됨"):
        return "거부"
    if content.startswith(("[도구 오류]", "[도구 실행 오류]", "[K8s API 오류]")):
        return "오류"
    return "허용"


def make_app(
    *,
    settings: Settings | None = None,
    model=None,
    k8s=None,
    audit: AuditLogger | None = None,
    checkpointer=None,
) -> FastAPI:
    """앱 팩토리. 테스트는 model/k8s 스텁을 주입하고, 실행은 설정만으로 조립한다."""
    settings = settings or load_settings()
    assert_safe_kubeconfig(settings.kubeconfig)  # fail-fast: 마스터/prod 컨텍스트 차단

    if k8s is None:
        from .tools.k8s_read import ReadOnlyK8sClient

        k8s = ReadOnlyK8sClient(settings.kubeconfig)
    model = model or make_model(settings)
    audit = audit or AuditLogger(settings.logs_dir)
    if checkpointer is None:
        settings.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
        from langgraph.checkpoint.sqlite import SqliteSaver

        checkpointer = SqliteSaver(
            sqlite3.connect(str(settings.checkpoint_db), check_same_thread=False)
        )

    tools = make_tools(k8s, audit)
    graph = build_graph(
        model=model, k8s=k8s, wiki_dir=settings.wiki_dir, audit=audit,
        checkpointer=checkpointer, tools=tools,
    )
    sessions = SessionStore(settings.checkpoint_db.parent / "sessions.sqlite")
    agents = load_agents(settings.agents_dir)
    tool_specs = verb_validator.registered_tools()
    tool_listing = [
        {
            "name": t.name,
            "description": t.description,
            "verb": tool_specs[t.name].verb if t.name in tool_specs else "",
            "resource": tool_specs[t.name].resource if t.name in tool_specs else "",
        }
        for t in tools
    ]
    # 그래프 호출은 전역 락으로 직렬화한다 — 단일 사용자 로컬 도구이며,
    # 같은 thread_id 동시 호출과 sqlite 경합을 코드 레벨에서 차단한다.
    invoke_lock = threading.Lock()

    app = FastAPI(title="inspect-k8s web harness", docs_url=None, redoc_url=None)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC / "chat.html", media_type="text/html")

    @app.get("/api/health")
    def health() -> JSONResponse:
        return JSONResponse(
            {
                "ok": True,
                "model_provider": settings.model_provider,
                "model": settings.codex_model if settings.model_provider == "codex-oauth"
                else settings.model_provider,
                "kubeconfig": bool(settings.kubeconfig),
            }
        )

    # ---------- 에이전트/도구 카탈로그 (Claude Code의 .claude/agents 패턴) ----------
    # 에이전트는 플래너 프롬프트만 바꾼다 — 도구·verb 화이트리스트·전송 가드는 전 에이전트 동일.

    @app.get("/api/agents")
    def list_agents_api() -> JSONResponse:
        return JSONResponse(
            {
                "agents": [a.to_dict() for a in agents.values()],
                "default": "inspector",
                "tools": tool_listing,
            }
        )

    @app.get("/api/agents/{name}")
    def agent_detail(name: str) -> JSONResponse:
        agent = agents.get(name)
        if agent is None:
            return JSONResponse({"error": f"에이전트 '{name}' 없음"}, status_code=404)
        return JSONResponse(agent.to_dict(include_instructions=True))

    # ---------- 세션별 작업 관리 ----------
    # 대화 context는 thread_id별 checkpointer가 보존한다. 아래 API는 그 위의
    # 메타데이터(목록·제목·이력 복원)만 다룬다.

    @app.get("/api/sessions")
    def list_sessions() -> JSONResponse:
        return JSONResponse({"sessions": [s.to_dict() for s in sessions.list()]})

    @app.post("/api/sessions")
    def new_session() -> JSONResponse:
        return JSONResponse({"thread_id": "web-" + uuid.uuid4().hex[:8]})

    @app.get("/api/sessions/{thread_id}/history")
    def session_history(thread_id: str) -> JSONResponse:
        if not _THREAD_ID_RE.match(thread_id):
            return JSONResponse({"error": "thread_id 형식이 올바르지 않습니다"}, status_code=400)
        state = graph.get_state({"configurable": {"thread_id": thread_id}})
        turns: list[dict] = []
        for msg in (state.values or {}).get("messages") or []:
            if isinstance(msg, HumanMessage):
                turns.append({"role": "user", "content": str(msg.content)})
            elif isinstance(msg, AIMessage) and not msg.tool_calls and str(msg.content).strip():
                turns.append({"role": "assistant", "content": str(msg.content)})
        meta = sessions.get(thread_id)
        return JSONResponse(
            {"thread_id": thread_id, "turns": turns, "meta": meta.to_dict() if meta else None}
        )

    @app.delete("/api/sessions/{thread_id}")
    def remove_session(thread_id: str) -> JSONResponse:
        if not _THREAD_ID_RE.match(thread_id):
            return JSONResponse({"error": "thread_id 형식이 올바르지 않습니다"}, status_code=400)
        removed = sessions.remove(thread_id)
        if hasattr(checkpointer, "delete_thread"):  # 체크포인트(대화 context)도 함께 삭제
            with invoke_lock:
                checkpointer.delete_thread(thread_id)
        return JSONResponse({"removed": removed})

    @app.post("/api/chat")
    def chat(req: ChatRequest) -> StreamingResponse:
        thread = req.thread_id or uuid.uuid4().hex[:8]
        if not _THREAD_ID_RE.match(thread):
            return StreamingResponse(
                iter([_sse({"type": "error", "message": "thread_id 형식이 올바르지 않습니다"})]),
                media_type="text/event-stream",
            )
        question = req.message.strip()
        agent = agents.get(req.agent or "inspector")
        if agent is None:
            return StreamingResponse(
                iter([_sse({"type": "error", "message": f"에이전트 '{req.agent}' 없음"})]),
                media_type="text/event-stream",
            )
        sessions.touch(thread, title_candidate=question, agent=agent.name)

        def stream():
            payload = {
                "question": question,
                "session_id": thread,
                "messages": [HumanMessage(question)],
                "agent_instructions": agent.instructions,
            }
            config = {"configurable": {"thread_id": thread}, "recursion_limit": 60}
            yield _sse({"type": "start", "thread_id": thread})
            try:
                with invoke_lock:
                    for update in graph.stream(payload, config=config, stream_mode="updates"):
                        for node, out in update.items():
                            if not isinstance(out, dict):
                                continue
                            if node == "wiki_reader":
                                chars = len(out.get("wiki_context") or "")
                                if chars:
                                    yield _sse({"type": "wiki", "chars": chars})
                            elif node == "planner":
                                for msg in out.get("messages") or []:
                                    for tc in getattr(msg, "tool_calls", None) or []:
                                        yield _sse(
                                            {
                                                "type": "tool_call",
                                                "name": tc["name"],
                                                "args": tc.get("args") or {},
                                            }
                                        )
                            elif node == "executor":
                                for msg in out.get("messages") or []:
                                    content = str(msg.content)
                                    yield _sse(
                                        {
                                            "type": "tool_result",
                                            "name": str(getattr(msg, "name", "") or ""),
                                            "status": _tool_status(content),
                                            "preview": content[:400],
                                        }
                                    )
                            elif node == "wiki_writer":
                                yield _sse(
                                    {"type": "final", "answer": out.get("final_answer") or ""}
                                )
            except GraphRecursionError:
                yield _sse({"type": "error", "message": "그래프 재귀 한도 도달 — 새 세션으로 다시 시도하세요"})
            except Exception as exc:  # LLM 인증 실패 등 — 브라우저에 원인만 전달
                yield _sse({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
            yield _sse({"type": "done"})

        return StreamingResponse(stream(), media_type="text/event-stream")

    return app


def main() -> None:
    import os

    import uvicorn

    host = os.environ.get("WEB_HOST", "127.0.0.1")
    port = int(os.environ.get("WEB_PORT", "8787"))
    if host != "127.0.0.1":
        print("경고: 이 하네스는 로컬 전용으로 설계되었습니다 (인증 없음). 외부 바인딩은 권장하지 않습니다.")
    uvicorn.run(make_app(), host=host, port=port)


if __name__ == "__main__":
    main()
