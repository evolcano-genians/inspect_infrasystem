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
from .config import (
    ALLOWED_REASONING_EFFORTS,
    Settings,
    assert_safe_kubeconfig,
    load_settings,
)
from .graph import MAX_TOOL_CALLS_PER_RUN, build_graph
from .llm import make_codex_model, make_model
from .nodes.reflector import reflect_on_state
from .nodes.wiki_common import parse_page
from .nodes.wiki_writer import redact_text
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
    reasoning: str = Field(default="", max_length=16)  # low|medium|high (codex-oauth 전용)
    context: str = Field(default="", max_length=64)    # 조사 대상 클러스터 컨텍스트


_WIKI_PATH_RE = re.compile(r"^[A-Za-z0-9._\-/]{1,200}\.md$")
MAX_WIKI_PAGE_CHARS = 200_000


class WikiSaveRequest(BaseModel):
    path: str = Field(min_length=4, max_length=200)
    content: str = Field(max_length=MAX_WIKI_PAGE_CHARS)


_AGENT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")
MAX_AGENT_FILE_CHARS = 20_000

_AGENT_TEMPLATE = """---
name: {name}
description: (한 줄 설명)
---

(이 본문이 플래너 시스템 프롬프트에 추가되는 지시문/스킬이다.
도구·권한은 바뀌지 않는다 — 조사 방식과 답변 스타일만 특화된다.)
"""


class AgentSaveRequest(BaseModel):
    content: str = Field(min_length=1, max_length=MAX_AGENT_FILE_CHARS)


class AgentCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=41)
    content: str = Field(default="", max_length=MAX_AGENT_FILE_CHARS)


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
    context = settings.kube_context or None
    assert_safe_kubeconfig(
        settings.kubeconfig, context=context, allow_real=settings.allow_real_cluster
    )

    # 멀티 클러스터: 실 kubeconfig의 안전한 컨텍스트별로 read-only 클라이언트를 만든다.
    # (prod 마커 컨텍스트는 assert_safe_kubeconfig가 거부 → 목록에서 제외)
    available_contexts: list[str] = []
    if k8s is None:
        from .config import resolve_contexts
        from .tools.k8s_read import ReadOnlyK8sClient

        k8s = ReadOnlyK8sClient(settings.kubeconfig, context=context)
        if settings.allow_real_cluster:
            names, _current = resolve_contexts(settings.kubeconfig)
            for name in names:
                try:
                    assert_safe_kubeconfig(
                        settings.kubeconfig, context=name, allow_real=True
                    )
                except Exception:
                    continue  # prod 등 금지 컨텍스트는 노출하지 않는다
                available_contexts.append(name)
    audit = audit or AuditLogger(settings.logs_dir)
    if checkpointer is None:
        settings.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
        from langgraph.checkpoint.sqlite import SqliteSaver

        checkpointer = SqliteSaver(
            sqlite3.connect(str(settings.checkpoint_db), check_same_thread=False)
        )

    tools = make_tools(k8s, audit)
    # 소스 열람 도구 (SOURCE_SSH_HOST 설정 시) — SSH read-only, 명령 화이트리스트
    extra_tools: list = []
    if settings.source_ssh_host:
        from .tools.source_reader import SourceAccessError, SourceHost, make_source_tools

        try:
            extra_tools = make_source_tools(SourceHost(settings.source_ssh_host), audit)
        except SourceAccessError as exc:
            print(f"경고: 소스 열람 비활성화 — {exc}")
    # 보안 테스트 도구 (SANDBOX_BASH_ENABLED / STRIX_ENABLED 시)
    if settings.sandbox_bash_enabled or settings.strix_enabled:
        from .sandbox.security_tools import make_security_tools

        try:
            extra_tools = [*extra_tools, *make_security_tools(
                bash_enabled=settings.sandbox_bash_enabled,
                strix_enabled=settings.strix_enabled,
                audit=audit,
            )]
        except Exception as exc:
            print(f"경고: 보안 도구 비활성화 — {type(exc).__name__}: {exc}")
    # Trino 데이터 분석 도구 (TRINO_ENDPOINT 설정 시)
    if settings.trino_endpoint:
        from .tools.trino_reader import TrinoConfig, make_trino_tools

        try:
            extra_tools = [*extra_tools, *make_trino_tools(TrinoConfig(
                endpoint=settings.trino_endpoint, user=settings.trino_user,
                token=settings.trino_token, catalog=settings.trino_catalog,
                schema=settings.trino_schema,
            ), audit)]
        except Exception as exc:
            print(f"경고: Trino 도구 비활성화 — {type(exc).__name__}: {exc}")
    # nexus-shell HTTP 조사 도구 (SHELL_ENVS 설정 시)
    if settings.shell_envs:
        from .tools.shell_http import make_shell_http_tools

        try:
            extra_tools = [*extra_tools, *make_shell_http_tools(settings.shell_envs, audit)]
        except Exception as exc:
            print(f"경고: nexus-shell HTTP 도구 비활성화 — {type(exc).__name__}: {exc}")

    # 컨텍스트별 도구 세트 (클러스터 전환용). 기본 컨텍스트는 위에서 만든 k8s/tools 재사용.
    tools_by_context: dict[str, list] = {}
    if available_contexts:
        from .tools.k8s_read import ReadOnlyK8sClient as _ROClient

        for name in available_contexts:
            if name == (context or ""):
                tools_by_context[name] = tools
                continue
            try:
                tools_by_context[name] = make_tools(
                    _ROClient(settings.kubeconfig, context=name), audit
                )
            except Exception as exc:  # 접근 불가 컨텍스트는 조용히 제외
                print(f"경고: 컨텍스트 '{name}' 도구 생성 실패 — {type(exc).__name__}")

    def _graph_for(m, ctx_tools=None):
        return build_graph(
            model=m, k8s=k8s, wiki_dir=settings.wiki_dir, audit=audit,
            checkpointer=checkpointer, tools=ctx_tools or tools,
            agents_dir=settings.agents_dir, extra_tools=extra_tools,
        )

    # 추론 모드 선택: codex-oauth이고 모델이 주입되지 않았을 때만 단계별 그래프를 조립한다.
    # (허용 단계는 정책상 low|medium|high — fast/ultra는 여기서부터 존재하지 않는다.)
    graphs: dict = {}
    # 컨텍스트별 그래프 (기본 모델 기준) — 클러스터 전환 시 사용
    graphs_by_context: dict[str, object] = {}
    if model is None and settings.model_provider == "codex-oauth":
        models = {eff: make_codex_model(settings.codex_model, eff) for eff in ALLOWED_REASONING_EFFORTS}
        graphs = {eff: _graph_for(m) for eff, m in models.items()}
        default_effort = settings.codex_reasoning_effort
        graph = graphs[default_effort]
        reflect_model = models[default_effort]
        for name, ctx_tools in tools_by_context.items():
            graphs_by_context[name] = (
                graph if ctx_tools is tools else _graph_for(models[default_effort], ctx_tools)
            )
    else:
        model = model or make_model(settings)
        default_effort = ""
        graph = _graph_for(model)
        reflect_model = model
        for name, ctx_tools in tools_by_context.items():
            graphs_by_context[name] = graph if ctx_tools is tools else _graph_for(model, ctx_tools)
    sessions = SessionStore(settings.checkpoint_db.parent / "sessions.sqlite")
    from .devlog import DevLog

    devlog = DevLog(settings.logs_dir)
    agents = load_agents(settings.agents_dir)

    def _reload_agents() -> None:
        agents.clear()
        agents.update(load_agents(settings.agents_dir))
    tool_specs = verb_validator.registered_tools()
    tool_listing = [
        {
            "name": t.name,
            "description": t.description,
            "verb": tool_specs[t.name].verb if t.name in tool_specs else "",
            "resource": tool_specs[t.name].resource if t.name in tool_specs else "",
        }
        for t in [*tools, *extra_tools]
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
                "reasoning_effort": default_effort,
                "reasoning_options": list(ALLOWED_REASONING_EFFORTS) if graphs else [],
                "kubeconfig": bool(settings.kubeconfig),
                "context": context or "(current)",
                "context_options": available_contexts,
                "real_cluster": settings.allow_real_cluster,
                "source_host": bool(settings.source_ssh_host),
            }
        )

    # ---------- 자가 진화: 스킬 개선 제안 (사람 승인 게이트) ----------
    # reflector가 생성한 제안(.agents/proposals/)은 여기서 검토·적용·폐기된다.
    # 적용은 기존 PUT /api/agents/{name}/raw 를 통해서만 이뤄진다 (name 일치 강제).

    _PROPOSAL_FILE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}-\d{8}-\d{6}\.md$")

    def _proposal_path(file: str):
        if not _PROPOSAL_FILE_RE.match(file):
            return None
        return settings.agents_dir / "proposals" / file

    @app.get("/api/proposals")
    def list_proposals() -> JSONResponse:
        directory = settings.agents_dir / "proposals"
        items = []
        if directory.is_dir():
            for path in sorted(directory.glob("*.md"), reverse=True):
                if _PROPOSAL_FILE_RE.match(path.name):
                    frontmatter, _ = parse_page(path)
                    items.append(
                        {
                            "file": path.name,
                            "name": str(frontmatter.get("name") or path.name.rsplit("-", 2)[0]),
                            "proposed_at": str(frontmatter.get("proposed_at") or ""),
                        }
                    )
        return JSONResponse({"proposals": items})

    @app.get("/api/proposals/{file}")
    def proposal_detail(file: str) -> JSONResponse:
        path = _proposal_path(file)
        if path is None or not path.is_file():
            return JSONResponse({"error": f"제안 없음: {file}"}, status_code=404)
        frontmatter, _ = parse_page(path)
        return JSONResponse(
            {
                "file": file,
                "name": str(frontmatter.get("name") or ""),
                "content": path.read_text(encoding="utf-8"),
            }
        )

    @app.delete("/api/proposals/{file}")
    def remove_proposal(file: str) -> JSONResponse:
        path = _proposal_path(file)
        if path is None or not path.is_file():
            return JSONResponse({"error": f"제안 없음: {file}"}, status_code=404)
        path.unlink()
        return JSONResponse({"removed": True})

    @app.post("/api/sessions/{thread_id}/reflect")
    def reflect_session(thread_id: str) -> JSONResponse:
        """수동 반성 — 해당 세션의 마지막 run에서 교훈/제안을 도출한다."""
        if not _THREAD_ID_RE.match(thread_id):
            return JSONResponse({"error": "thread_id 형식이 올바르지 않습니다"}, status_code=400)
        state = graph.get_state({"configurable": {"thread_id": thread_id}})
        values = state.values or {}
        if not values.get("question"):
            return JSONResponse({"error": "반성할 run이 없습니다"}, status_code=404)
        with invoke_lock:
            outcome = reflect_on_state(
                reflect_model, settings.wiki_dir, settings.agents_dir, values,
                max_tool_calls=MAX_TOOL_CALLS_PER_RUN, force=True,
            )
        return JSONResponse(outcome or {"note": "학습할 내용이 도출되지 않았습니다"})

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

    def _agent_file(name: str):
        if not _AGENT_NAME_RE.match(name):
            return None
        return settings.agents_dir / f"{name}.md"

    def _validate_agent_content(name: str, content: str) -> str | None:
        """frontmatter를 파싱해 name 일치를 강제한다. 문제 있으면 사유 반환."""
        import io

        # parse_page는 Path를 받으므로 임시 사용 대신 직접 검사
        if not content.startswith("---\n"):
            return "파일은 '---' frontmatter로 시작해야 합니다 (name/description)"
        try:
            _, fm_text, _ = content.split("---\n", 2)
            import yaml as _yaml

            fm = _yaml.safe_load(io.StringIO(fm_text)) or {}
        except Exception:
            return "frontmatter YAML 파싱 실패"
        declared = str(fm.get("name") or "").strip()
        if declared != name:
            return f"frontmatter의 name('{declared}')이 파일 이름('{name}')과 일치해야 합니다"
        return None

    @app.get("/api/agents/{name}/raw")
    def agent_raw(name: str) -> JSONResponse:
        agent = agents.get(name)
        file = _agent_file(name)
        if file is None or (agent is None and not file.is_file()):
            return JSONResponse({"error": f"에이전트 '{name}' 없음"}, status_code=404)
        if file.is_file():
            content = file.read_text(encoding="utf-8")
            source = file.name
        else:  # builtin — 편집 시 파일로 구체화되도록 템플릿 제공
            content = _AGENT_TEMPLATE.format(name=name)
            source = "builtin (저장하면 파일로 오버라이드됨)"
        return JSONResponse({"name": name, "content": content, "source": source})

    @app.put("/api/agents/{name}/raw")
    def agent_save(name: str, req: AgentSaveRequest) -> JSONResponse:
        file = _agent_file(name)
        if file is None:
            return JSONResponse({"error": "에이전트 이름 형식: 소문자/숫자/하이픈"}, status_code=400)
        problem = _validate_agent_content(name, req.content)
        if problem:
            return JSONResponse({"error": problem}, status_code=400)
        settings.agents_dir.mkdir(parents=True, exist_ok=True)
        file.write_text(req.content, encoding="utf-8")
        _reload_agents()
        return JSONResponse({"saved": True, "name": name})

    @app.post("/api/agents/create")
    def agent_create(req: AgentCreateRequest) -> JSONResponse:
        name = req.name.strip().lower()
        file = _agent_file(name)
        if file is None:
            return JSONResponse({"error": "에이전트 이름 형식: 소문자/숫자/하이픈"}, status_code=400)
        if file.is_file() or name in agents:
            return JSONResponse({"error": f"'{name}' 은 이미 존재합니다"}, status_code=409)
        content = req.content or _AGENT_TEMPLATE.format(name=name)
        problem = _validate_agent_content(name, content)
        if problem:
            return JSONResponse({"error": problem}, status_code=400)
        settings.agents_dir.mkdir(parents=True, exist_ok=True)
        file.write_text(content, encoding="utf-8")
        _reload_agents()
        return JSONResponse({"created": True, "name": name})

    # ---------- 개발 피드백 로그 (하네스 개선용) ----------

    class FeedbackRequest(BaseModel):
        turn_id: str = Field(min_length=1, max_length=64)
        rating: str = Field(default="note", max_length=16)
        note: str = Field(default="", max_length=2000)

    @app.post("/api/feedback")
    def post_feedback(req: FeedbackRequest) -> JSONResponse:
        return JSONResponse(devlog.record_feedback(
            turn_id=req.turn_id, rating=req.rating, note=req.note))

    @app.get("/api/devlog/report")
    def devlog_report() -> JSONResponse:
        return JSONResponse(devlog.improvement_report())

    # ---------- 위키 보기/편집 ----------
    # 위키는 로컬 스크래치 지식 저장소다(클러스터 리소스 아님) — 브리프가 "사람이 직접
    # 읽고 수정할 수 있어야 한다"고 요구하므로 편집을 허용하되, 저장 전 레다크션 필터를
    # 통과시켜 "wiki/ 어디에도 시크릿 평문 없음" 불변식을 편집 경로에서도 유지한다.

    def _safe_wiki_path(rel: str):
        if not _WIKI_PATH_RE.match(rel) or ".." in rel or rel.startswith("/"):
            return None
        wiki_root = settings.wiki_dir.resolve()
        target = (wiki_root / rel).resolve()
        if wiki_root not in target.parents:
            return None
        return target

    @app.get("/api/wiki")
    def wiki_index() -> JSONResponse:
        wiki_root = settings.wiki_dir
        sections: dict[str, list[dict]] = {}
        for path in sorted(wiki_root.rglob("*.md")):
            rel = path.relative_to(wiki_root)
            section = rel.parts[0] if len(rel.parts) > 1 else "(루트)"
            frontmatter, _ = parse_page(path)
            sections.setdefault(section, []).append(
                {
                    "path": str(rel),
                    "name": path.stem,
                    "hint": str(
                        frontmatter.get("last_inspected") or frontmatter.get("date") or ""
                    ),
                }
            )
        return JSONResponse({"sections": sections})

    @app.get("/api/wiki/page")
    def wiki_page(path: str) -> JSONResponse:
        target = _safe_wiki_path(path)
        if target is None or not target.is_file():
            return JSONResponse({"error": f"페이지 없음: {path}"}, status_code=404)
        return JSONResponse({"path": path, "content": target.read_text(encoding="utf-8")})

    @app.put("/api/wiki/page")
    def wiki_save(req: WikiSaveRequest) -> JSONResponse:
        target = _safe_wiki_path(req.path)
        if target is None:
            return JSONResponse({"error": "잘못된 경로입니다"}, status_code=400)
        if not target.is_file():
            return JSONResponse(
                {"error": "존재하는 페이지만 편집할 수 있습니다 (새 페이지는 조사가 만든다)"},
                status_code=404,
            )
        redacted_content = redact_text(req.content)
        target.write_text(redacted_content, encoding="utf-8")
        return JSONResponse(
            {"saved": True, "path": req.path, "redacted": redacted_content != req.content}
        )

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
        # 추론 모드 선택 (codex-oauth 전용). 금지값(minimal/xhigh 등)은 graphs에 없어 거부된다.
        effort = (req.reasoning or "").strip().lower()
        if graphs:
            effort = effort or default_effort
            selected_graph = graphs.get(effort)
            if selected_graph is None:
                return StreamingResponse(
                    iter([_sse({
                        "type": "error",
                        "message": f"추론 모드 '{effort}' 미지원 — 허용: {list(graphs)} "
                                   "(fast/ultra는 정책상 배제)",
                    })]),
                    media_type="text/event-stream",
                )
        else:
            effort = ""
            selected_graph = graph
        # 클러스터(컨텍스트) 선택 — 지정 없으면 서버 기본 컨텍스트
        target_ctx = (req.context or "").strip()
        if target_ctx:
            if target_ctx not in graphs_by_context:
                return StreamingResponse(
                    iter([_sse({
                        "type": "error",
                        "message": f"컨텍스트 '{target_ctx}' 사용 불가 — 가능: {available_contexts}",
                    })]),
                    media_type="text/event-stream",
                )
            if target_ctx != (context or ""):
                selected_graph = graphs_by_context[target_ctx]
        sessions.touch(thread, title_candidate=question, agent=agent.name)

        def stream():
            payload = {
                "question": question,
                "session_id": thread,
                "messages": [HumanMessage(question)],
                "agent_instructions": agent.instructions,
                "agent_name": agent.name,
                "agent_tools": list(agent.tools),
            }
            config = {"configurable": {"thread_id": thread}, "recursion_limit": 60}
            yield _sse({
                "type": "start", "thread_id": thread, "reasoning": effort,
                "context": target_ctx or context or "",
            })
            last_usage: dict = {}
            try:
                with invoke_lock:
                    for update in selected_graph.stream(payload, config=config, stream_mode="updates"):
                        for node, out in update.items():
                            if not isinstance(out, dict):
                                continue
                            if node == "wiki_reader":
                                chars = len(out.get("wiki_context") or "")
                                if chars:
                                    yield _sse({"type": "wiki", "chars": chars})
                            elif node == "planner":
                                usage = out.get("usage") or {}
                                if usage.get("total_tokens"):
                                    last_usage = usage
                                    yield _sse({"type": "usage", **usage})
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
                                final_answer = out.get("final_answer") or ""
                                turn_id = ""
                                try:
                                    st = selected_graph.get_state(config).values or {}
                                    turn_id = devlog.record_turn(
                                        thread_id=thread, agent=agent.name,
                                        context=target_ctx or context or "",
                                        question=question, answer=final_answer,
                                        tool_trace=st.get("tool_trace") or [],
                                        usage=st.get("usage") or {}, reasoning=effort,
                                    )
                                except Exception:
                                    pass
                                yield _sse({"type": "final", "answer": final_answer, "turn_id": turn_id})
                            elif node == "reflector":
                                if out.get("last_lesson") or out.get("last_proposal"):
                                    yield _sse(
                                        {
                                            "type": "evolution",
                                            "lesson": out.get("last_lesson") or "",
                                            "proposal": out.get("last_proposal") or "",
                                        }
                                    )
            except GraphRecursionError:
                yield _sse({"type": "error", "message": "그래프 재귀 한도 도달 — 새 세션으로 다시 시도하세요"})
            except Exception as exc:  # LLM 인증 실패 등 — 브라우저에 원인만 전달
                yield _sse({"type": "error", "message": f"{type(exc).__name__}: {exc}"})
            if last_usage:
                sessions.add_usage(
                    thread,
                    last_usage.get("input_tokens", 0),
                    last_usage.get("output_tokens", 0),
                )
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
