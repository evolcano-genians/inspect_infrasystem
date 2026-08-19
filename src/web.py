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
from langchain_core.messages import AIMessage, HumanMessage, RemoveMessage, SystemMessage
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
from .graph import MAX_TOOL_CALLS_PER_RUN, build_graph, recommended_recursion_limit
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
    # 멀티모달 입력: data:image/...;base64,... URL 목록 (최대 4장, 각 ~7MB)
    images: list[str] = Field(default_factory=list, max_length=4)


_WIKI_PATH_RE = re.compile(r"^[A-Za-z0-9._\-/]{1,200}\.md$")
MAX_WIKI_PAGE_CHARS = 200_000
_IMAGE_DATA_URL_RE = re.compile(r"^data:image/(png|jpeg|jpg|gif|webp);base64,[A-Za-z0-9+/=\s]+$")


def _message_text(content) -> tuple[str, int]:
    """메시지 content(문자열 또는 멀티모달 블록 리스트)에서 (표시 텍스트, 이미지 수)를 뽑는다."""
    if isinstance(content, str):
        return content, 0
    if isinstance(content, list):
        texts, images = [], 0
        for b in content:
            if isinstance(b, str):
                texts.append(b)
            elif isinstance(b, dict):
                if b.get("type") == "text":
                    texts.append(b.get("text", ""))
                elif b.get("type") in ("image_url", "image"):
                    images += 1
        return "\n".join(t for t in texts if t), images
    return str(content), 0


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


class MetapromptRequest(BaseModel):
    """Claude 세션으로 인계할 메타프롬프트 생성 요청."""

    topic: str = Field(default="", max_length=200)        # 좁힐 주제(네임스페이스·앱 이름 등)
    task: str = Field(default="", max_length=4000)        # Claude에게 시킬 작업
    session_note: str = Field(default="", max_length=4000)  # 이번 세션 메모


class DiagramRequest(BaseModel):
    """LLM이 만든 mermaid 다이어그램 저장/내보내기 요청."""

    code: str = Field(min_length=1, max_length=20_000)    # mermaid 소스
    title: str = Field(default="diagram", max_length=80)


class SettingsUpdateRequest(BaseModel):
    """외부 API 토큰 등 설정을 .env에 저장하는 요청 (카탈로그 키만 허용)."""

    updates: dict[str, str] = Field(default_factory=dict)  # {키: 값} — 시크릿 빈 값=유지
    clears: list[str] = Field(default_factory=list, max_length=32)  # 명시적으로 비울 키


class SettingsTestRequest(BaseModel):
    """외부 연동 연결을 실제 테스트한다. overrides로 폼의 미저장 값도 함께 검증한다."""

    group: str = Field(min_length=1, max_length=40)
    overrides: dict[str, str] = Field(default_factory=dict)  # 폼에 입력했으나 아직 저장 안 한 값


class ProjectCreateRequest(BaseModel):
    name: str = Field(default="새 프로젝트", max_length=80)


class ProjectRenameRequest(BaseModel):
    name: str = Field(min_length=1, max_length=80)


class SessionAssignRequest(BaseModel):
    project_id: str = Field(default="", max_length=64)  # "" = 미분류로 빼기


def _test_connection(group: str, env: dict) -> dict:
    """그룹별 최소 read 호출로 연결을 검증한다. .env 최신 값 기준(재시작 전에도 확인 가능)."""
    verify = str(env.get("JIRA_VERIFY_TLS", "1")).strip().lower() not in ("0", "false", "no")
    if group == "Jira":
        from .tools.jira_reader import JiraClient, JiraConfig

        cfg = JiraConfig(base_url=env.get("JIRA_BASE_URL", ""), token=env.get("JIRA_TOKEN", ""),
                         user=env.get("JIRA_USER", ""), cookie=env.get("JIRA_COOKIE", ""),
                         verify_tls=verify)
        if not cfg.base_url:
            return {"ok": False, "message": "JIRA_BASE_URL 이 비어 있습니다"}
        data = JiraClient(cfg)._get("/rest/api/2/myself")  # 현재 사용자 — read-only 인증 확인
        who = data.get("displayName") or data.get("name") or "OK"
        return {"ok": True, "message": f"연결 성공 · 로그인: {who} ({cfg.auth_kind()} 인증)"}

    if group == "Confluence":
        from .tools.confluence_reader import ConfluenceClient, load_confluence_config

        cfg = load_confluence_config(env)
        if not cfg:
            return {"ok": False, "message": "Jira(또는 Confluence) Base URL·토큰이 필요합니다"}
        me = ConfluenceClient(cfg)._get("/wiki/rest/api/user/current")
        return {"ok": True,
                "message": f"연결 성공 · 로그인: {me.get('displayName', 'OK')} (Jira 자격증명 공유)"}

    if group.startswith("FishEye"):
        from .tools.fisheye_reader import FisheyeClient, load_fisheye_config

        cfg = load_fisheye_config(env)
        if not cfg:
            return {"ok": False, "message": "FISHEYE_BASE_URL 이 비어 있습니다"}
        # 인증 확인용 최소 조회 — 열린 리뷰 목록(빈 결과여도 인증 자체는 검증된다)
        data = FisheyeClient(cfg)._get("/rest-service/reviews-v1/filter/allOpenReviews")
        reviews = data.get("reviewData") or data.get("review") or []
        n = len(reviews) if isinstance(reviews, list) else 1
        return {"ok": True, "message": f"연결 성공 ({cfg.auth_kind()} 인증) · 열린 리뷰 {n}건 조회"}

    if group.startswith("Trino"):
        from .tools.trino_reader import TrinoClient, TrinoConfig

        ep = env.get("TRINO_ENDPOINT", "")
        if not ep:
            return {"ok": False, "message": "TRINO_ENDPOINT 가 비어 있습니다"}
        cfg = TrinoConfig(endpoint=ep, user=env.get("TRINO_USER", "inspect-k8s"),
                          token=env.get("TRINO_TOKEN", ""), catalog=env.get("TRINO_CATALOG", ""),
                          schema=env.get("TRINO_SCHEMA", ""))
        res = TrinoClient(cfg).query("SHOW CATALOGS", max_rows=50)
        return {"ok": True, "message": f"연결 성공 · 카탈로그 {res.get('row_count', 0)}개"}

    if group == "소스 코드":
        from .tools.source_reader import SourceHost

        host = env.get("SOURCE_SSH_HOST", "")
        if not host:
            return {"ok": False, "message": "SOURCE_SSH_HOST 가 비어 있습니다"}
        out = SourceHost(host).list_dir("~")
        if out.startswith("[소스 조회 실패"):
            return {"ok": False, "message": out[:200]}
        return {"ok": True, "message": f"SSH 연결 성공 · 홈 디렉터리 조회 {len(out.splitlines())}줄"}

    if group == "샌드박스":
        from .sandbox.bash_exec import BashSandbox

        res = BashSandbox().run("echo ok", timeout=20)
        if res.exit_code == 0:
            return {"ok": True, "message": f"Docker 샌드박스 정상 (image={BashSandbox().image})"}
        return {"ok": False, "message": f"샌드박스 실행 실패 exit={res.exit_code}"}

    return {"ok": False, "message": f"연결 테스트를 지원하지 않는 그룹: {group}"}


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
        from .config import is_real_kubeconfig
        from .sandbox.security_tools import make_security_tools

        try:
            # strix 는 호스트에서 직접 돌기 때문에 대상 허용목록·하드 denylist·실 클러스터
            # 인터록을 설정에서 파생시켜 넘긴다 (security_tools 모듈 docstring 참고).
            # vm(인가된 실증 랩) 이외의 nexus-shell base 는 실 인프라이므로 deny 재료다.
            real_bases = tuple(
                env.base_url for name, env in (settings.shell_envs or {}).items()
                if name != "vm" and getattr(env, "base_url", "")
            )
            extra_tools = [*extra_tools, *make_security_tools(
                bash_enabled=settings.sandbox_bash_enabled,
                strix_enabled=settings.strix_enabled,
                audit=audit,
                strix_allowed_targets=settings.strix_allowed_targets,
                real_cluster_mode=(
                    settings.allow_real_cluster
                    or bool(settings.kubeconfig and is_real_kubeconfig(settings.kubeconfig))
                ),
                shell_env_bases=real_bases,
                kubeconfig=settings.kubeconfig,
            )]
        except Exception as exc:
            print(f"경고: 보안 도구 비활성화 — {type(exc).__name__}: {exc}")
    # 웹 보안 테스팅 도구 — 항상 노출한다. SSRF 게이트(_authorize_web_target)가 메타데이터·
    # 내부 API 포트를 차단하고 read-only(GET/HEAD)만 허용하므로 opt-in 설정 없이 안전하다.
    try:
        from .tools.web_test import make_web_test_tools

        extra_tools = [*extra_tools, *make_web_test_tools(audit=audit)]
    except Exception as exc:
        print(f"경고: 웹 테스트 도구 비활성화 — {type(exc).__name__}: {exc}")
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
    # Jira read-only 조회 도구 (JIRA_BASE_URL 설정 시) — 코드 리뷰 이슈 참고
    if settings.jira_base_url:
        from .tools.jira_reader import JiraConfig, make_jira_tools

        try:
            extra_tools = [*extra_tools, *make_jira_tools(JiraConfig(
                base_url=settings.jira_base_url, token=settings.jira_token,
                user=settings.jira_user, cookie=settings.jira_cookie,
                verify_tls=settings.jira_verify_tls,
            ), audit, redactor=redact_text)]
        except Exception as exc:
            print(f"경고: Jira 도구 비활성화 — {type(exc).__name__}: {exc}")
    # Confluence read-only 조회 (Jira 와 같은 Atlassian Cloud — 자격증명 공유, 별도 설정 불필요)
    import os as _os

    _conf_cfg = None
    try:
        from .tools.confluence_reader import load_confluence_config, make_confluence_tools

        _conf_cfg = load_confluence_config({**_os.environ, **{
            "JIRA_BASE_URL": settings.jira_base_url, "JIRA_USER": settings.jira_user,
            "JIRA_TOKEN": settings.jira_token,
        }})
        if _conf_cfg:
            extra_tools = [*extra_tools, *make_confluence_tools(_conf_cfg, audit, redactor=redact_text)]
    except Exception as exc:
        print(f"경고: Confluence 도구 비활성화 — {type(exc).__name__}: {exc}")
    # FishEye/Crucible 코드 리뷰 조회 (FISHEYE_BASE_URL 설정 시) — 온프레미스 별도 계정
    try:
        from .tools.fisheye_reader import load_fisheye_config, make_fisheye_tools

        _fe_cfg = load_fisheye_config(dict(_os.environ))
        if _fe_cfg:
            extra_tools = [*extra_tools, *make_fisheye_tools(_fe_cfg, audit, redactor=redact_text)]
    except Exception as exc:
        print(f"경고: FishEye 도구 비활성화 — {type(exc).__name__}: {exc}")

    # 컨텍스트별 도구 세트 (클러스터 전환용). 기본 컨텍스트는 위에서 만든 k8s/tools 재사용.
    tools_by_context: dict[str, list] = {}
    clients_by_context: dict[str, object] = {}  # 멀티 클러스터 비교용 read-only 클라이언트
    if available_contexts:
        from .tools.k8s_read import ReadOnlyK8sClient as _ROClient

        for name in available_contexts:
            if name == (context or ""):
                tools_by_context[name] = tools
                clients_by_context[name] = k8s
                continue
            try:
                _client = _ROClient(settings.kubeconfig, context=name)
                tools_by_context[name] = make_tools(_client, audit)
                clients_by_context[name] = _client
            except Exception as exc:  # 접근 불가 컨텍스트는 조용히 제외
                print(f"경고: 컨텍스트 '{name}' 도구 생성 실패 — {type(exc).__name__}")

    # 멀티 클러스터 비교 도구 (컨텍스트 2개 이상일 때만) — 두 k8s 상태를 나란히 대조.
    # 모든 그래프에서 공통으로 쓰도록 extra_tools에 합친다.
    if len(clients_by_context) >= 2:
        from .tools.multicluster import make_multicluster_tools

        try:
            extra_tools = [*extra_tools, *make_multicluster_tools(clients_by_context, audit)]
        except Exception as exc:
            print(f"경고: 멀티 클러스터 비교 도구 비활성화 — {type(exc).__name__}: {exc}")

    def _graph_for(m, ctx_tools=None):
        return build_graph(
            model=m, k8s=k8s, wiki_dir=settings.wiki_dir, audit=audit,
            checkpointer=checkpointer, tools=ctx_tools or tools,
            agents_dir=settings.agents_dir, extra_tools=extra_tools,
        )

    # 추론 모드 선택: codex-oauth이고 모델이 주입되지 않았을 때만 단계별 그래프를 조립한다.
    # (허용 단계는 정책상 low|medium|high — fast/ultra는 여기서부터 존재하지 않는다.)
    graphs: dict = {}
    # 컨텍스트별 그래프 — [컨텍스트][effort] 2단 매핑. 비기본 컨텍스트를 골라도 추론 모드가
    # 그대로 반영된다(과거엔 기본 effort로 조용히 덮여 high 선택이 medium으로 실행됐음).
    graphs_by_context: dict[str, dict[str, object]] = {}
    if model is None and settings.model_provider == "codex-oauth":
        models = {eff: make_codex_model(settings.codex_model, eff) for eff in ALLOWED_REASONING_EFFORTS}
        graphs = {eff: _graph_for(m) for eff, m in models.items()}
        default_effort = settings.codex_reasoning_effort
        graph = graphs[default_effort]
        reflect_model = models[default_effort]
        for name, ctx_tools in tools_by_context.items():
            if ctx_tools is tools:
                graphs_by_context[name] = dict(graphs)  # 기본 컨텍스트: effort별 그래프 재사용
            else:  # 다른 클러스터: effort별로 해당 컨텍스트 도구를 묶은 그래프 조립 (3개, 비용 미미)
                graphs_by_context[name] = {eff: _graph_for(m, ctx_tools) for eff, m in models.items()}
    else:
        model = model or make_model(settings)
        default_effort = ""
        graph = _graph_for(model)
        reflect_model = model
        for name, ctx_tools in tools_by_context.items():
            g = graph if ctx_tools is tools else _graph_for(model, ctx_tools)
            graphs_by_context[name] = {"": g}
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

    # 위키 큐레이터: durable 큐 + 주기 스케줄러 (CURATOR_ENABLED=1 시 백그라운드 실행)
    from .curator import CuratorQueue, run_cycle
    from .nodes.wiki_writer import redact_text as _redact

    curator_queue = CuratorQueue(settings.checkpoint_db.parent / "curator.sqlite")

    def _run_curator_cycle() -> dict:
        # LLM·wiki 편집이 얽히므로 그래프 락과 공유해 sqlite/파일 경합을 막는다.
        with invoke_lock:
            return run_cycle(curator_queue, settings.wiki_dir, reflect_model, redactor=_redact)

    app = FastAPI(title="inspect-k8s web harness", docs_url=None, redoc_url=None)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC / "chat.html", media_type="text/html")

    @app.get("/vendor/{filename}", response_model=None)
    def vendor_asset(filename: str):
        """로컬 번들 라이브러리(mermaid 등) 서빙 — 오프라인/CSP 환경에서도 동작한다."""
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", filename):  # 경로 순회 차단
            return JSONResponse({"error": "잘못된 파일명"}, status_code=400)
        target = (_STATIC / "vendor" / filename).resolve()
        vendor_root = (_STATIC / "vendor").resolve()
        if not str(target).startswith(str(vendor_root)) or not target.is_file():
            return JSONResponse({"error": "없는 파일"}, status_code=404)
        media = "application/javascript" if target.suffix == ".js" else "text/plain"
        return FileResponse(target, media_type=media)

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

    # ---------- 메타프롬프트 (Claude 세션 인계) ----------
    @app.post("/api/metaprompt")
    def metaprompt(req: MetapromptRequest) -> JSONResponse:
        """축적된 inspection 지식을 Claude 세션용 메타프롬프트로 합성한다."""
        from .metaprompt import build_metaprompt

        result = build_metaprompt(
            settings.wiki_dir,
            topic=req.topic,
            task=req.task,
            session_note=req.session_note,
        )
        return JSONResponse(result)

    # ---------- 설정 메뉴 (외부 API 토큰 .env 관리) ----------
    _env_path = settings.agents_dir.parent / ".env"

    @app.get("/api/settings")
    def settings_status() -> JSONResponse:
        from .settings_store import current_settings

        return JSONResponse({"groups": current_settings(_env_path)})

    @app.put("/api/settings")
    def settings_update(req: SettingsUpdateRequest) -> JSONResponse:
        """카탈로그 키만 .env에 저장한다. 시크릿 값은 저장만 하고 되돌려주지 않는다."""
        from .settings_store import SettingsError, apply_updates

        try:
            saved = apply_updates(_env_path, req.updates or {}, req.clears or [])
        except SettingsError as exc:
            return JSONResponse({"error": str(exc)}, status_code=400)
        # 설정은 프로세스 시작 시 읽히므로 재시작해야 적용된다.
        return JSONResponse({"saved": saved, "needs_restart": bool(saved)})

    @app.post("/api/settings/test")
    def settings_test(req: SettingsTestRequest) -> JSONResponse:
        """실효 설정으로 연결을 테스트한다. 우선순위: 폼 입력(overrides) > .env > 실행 env.

        overrides 덕분에 저장하기 전에도 방금 입력한 값으로 바로 확인할 수 있다.
        (카탈로그 키만 반영 — 임의 키 주입 차단.)
        """
        import os as _os

        from .settings_store import _CATALOG_BY_KEY, read_env_file

        overrides = {k: v for k, v in (req.overrides or {}).items()
                     if k in _CATALOG_BY_KEY and isinstance(v, str) and v.strip()}
        env = {**_os.environ, **read_env_file(_env_path), **overrides}
        try:
            return JSONResponse(_test_connection(req.group, env))
        except Exception as exc:  # 네트워크·인증·docker 오류를 사용자에게 그대로 전달
            return JSONResponse({"ok": False, "message": f"{type(exc).__name__}: {exc}"})

    # ---------- 위키 큐레이터 (LLM 주기 보정: 사실체크·폐기·중복정리) ----------
    @app.get("/api/curator")
    def curator_status() -> JSONResponse:
        return JSONResponse({
            "enabled": settings.curator_enabled,
            "interval_s": settings.curator_interval_s,
            "queue": curator_queue.stats(),
            "journal": curator_queue.journal(30),
        })

    @app.post("/api/curator/run")
    def curator_run() -> JSONResponse:
        """지금 한 사이클을 수동 실행한다(계획→큐잉→처리)."""
        try:
            return JSONResponse(_run_curator_cycle())
        except Exception as exc:
            return JSONResponse(
                {"error": f"{type(exc).__name__}: {exc}"}, status_code=502)

    @app.post("/api/curator/revive")
    def curator_revive() -> JSONResponse:
        """dead 잡을 되살린다(수동 회생)."""
        return JSONResponse({"revived": curator_queue.revive_dead()})

    # ---------- 세션별 작업 관리 ----------
    # 대화 context는 thread_id별 checkpointer가 보존한다. 아래 API는 그 위의
    # 메타데이터(목록·제목·이력 복원)만 다룬다.

    @app.get("/api/sessions")
    def list_sessions() -> JSONResponse:
        return JSONResponse({
            "sessions": [s.to_dict() for s in sessions.list()],
            "projects": [p.to_dict() for p in sessions.list_projects()],
        })

    @app.post("/api/sessions")
    def new_session() -> JSONResponse:
        return JSONResponse({"thread_id": "web-" + uuid.uuid4().hex[:8]})

    # ---- 프로젝트 (세션 묶음, Claude Desktop 스타일) ----
    @app.get("/api/projects")
    def list_projects() -> JSONResponse:
        return JSONResponse({"projects": [p.to_dict() for p in sessions.list_projects()]})

    @app.post("/api/projects")
    def create_project(req: ProjectCreateRequest) -> JSONResponse:
        return JSONResponse(sessions.create_project(req.name).to_dict())

    @app.put("/api/projects/{project_id}")
    def rename_project(project_id: str, req: ProjectRenameRequest) -> JSONResponse:
        ok = sessions.rename_project(project_id, req.name)
        return JSONResponse({"renamed": ok}, status_code=(200 if ok else 404))

    @app.delete("/api/projects/{project_id}")
    def delete_project(project_id: str) -> JSONResponse:
        # 프로젝트만 삭제 — 소속 세션은 미분류로 남는다(대화·체크포인트 보존).
        return JSONResponse({"removed": sessions.remove_project(project_id)})

    @app.put("/api/sessions/{thread_id}/project")
    def assign_session_project(thread_id: str, req: SessionAssignRequest) -> JSONResponse:
        if not _THREAD_ID_RE.match(thread_id):
            return JSONResponse({"error": "thread_id 형식이 올바르지 않습니다"}, status_code=400)
        ok = sessions.assign_project(thread_id, req.project_id)
        return JSONResponse({"assigned": ok}, status_code=(200 if ok else 404))

    @app.get("/api/sessions/{thread_id}/history")
    def session_history(thread_id: str) -> JSONResponse:
        if not _THREAD_ID_RE.match(thread_id):
            return JSONResponse({"error": "thread_id 형식이 올바르지 않습니다"}, status_code=400)
        state = graph.get_state({"configurable": {"thread_id": thread_id}})
        turns: list[dict] = []
        for msg in (state.values or {}).get("messages") or []:
            if isinstance(msg, HumanMessage):
                text, n_img = _message_text(msg.content)
                turns.append({"role": "user", "content": text, "images": n_img})
            elif isinstance(msg, AIMessage):
                # 이전 대화의 도구 활동도 접힌 형태로 복원할 수 있게 함께 내려준다.
                if msg.tool_calls:
                    turns.append({"role": "tools", "calls": [
                        {"name": tc.get("name", "?"), "args": tc.get("args") or {}}
                        for tc in msg.tool_calls
                    ]})
                if str(msg.content).strip():
                    turns.append({"role": "assistant", "content": str(msg.content)})
        meta = sessions.get(thread_id)
        return JSONResponse(
            {"thread_id": thread_id, "turns": turns, "meta": meta.to_dict() if meta else None}
        )

    @app.post("/api/sessions/{thread_id}/compact")
    def compact_session(thread_id: str) -> JSONResponse:
        """대화 이력을 요약으로 압축한다 (/compact) — 컨텍스트 윈도우 확보용.

        기존 메시지를 LLM으로 요약해 한 쌍(Human 요약 요청 / AI 요약)으로 대체한다.
        위키 장기 기억은 그대로이므로 조사 지식은 잃지 않는다.
        """
        if not _THREAD_ID_RE.match(thread_id):
            return JSONResponse({"error": "thread_id 형식이 올바르지 않습니다"}, status_code=400)
        config = {"configurable": {"thread_id": thread_id}}
        with invoke_lock:
            state = graph.get_state(config)
            messages = list((state.values or {}).get("messages") or [])
            if len(messages) < 4:
                return JSONResponse({"compacted": False, "note": "압축할 만큼 긴 대화가 아닙니다"})

            # 요약 대상: 사람이 읽을 수 있는 대화 흐름(도구 호출 원문은 제외해 비용을 낮춘다)
            transcript: list[str] = []
            for msg in messages:
                if isinstance(msg, HumanMessage):
                    transcript.append("[사용자] " + _message_text(msg.content)[0][:2000])
                elif isinstance(msg, AIMessage) and str(msg.content).strip():
                    transcript.append("[에이전트] " + str(msg.content)[:3000])
            joined = "\n\n".join(transcript)[-40_000:]

            try:
                summary_msg = reflect_model.invoke([
                    SystemMessage(content=(
                        "다음은 dev k8s 조사 세션의 대화 기록이다. 이후 대화가 이어질 수 있도록 "
                        "**압축 요약**을 작성하라. 반드시 보존할 것: 조사 대상(네임스페이스·워크로드), "
                        "확인된 사실과 수치, 내린 결론, 미해결 질문, 사용자의 선호·제약. "
                        "불필요한 서술은 버리되 사실은 왜곡하지 마라. 한국어 불릿으로 간결하게."
                    )),
                    HumanMessage(content=joined),
                ])
                summary = str(getattr(summary_msg, "content", "") or "").strip()
            except Exception as exc:
                return JSONResponse(
                    {"error": f"요약 실패: {type(exc).__name__}: {exc}"}, status_code=502
                )
            if not summary:
                return JSONResponse({"error": "요약이 비어 있습니다"}, status_code=502)

            # 기존 메시지를 모두 제거하고 요약 한 쌍으로 대체한다.
            removals = [RemoveMessage(id=m.id) for m in messages if getattr(m, "id", None)]
            graph.update_state(config, {"messages": [
                *removals,
                HumanMessage(content="(이전 대화 압축 요약)"),
                AIMessage(content=summary),
            ]})
        return JSONResponse({
            "compacted": True, "summary": summary,
            "before_messages": len(messages), "after_messages": 2,
        })

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
        # 이미지 입력 검증 (멀티모달) — data:image/{png,jpeg,gif,webp};base64,...만 허용
        valid_images: list[str] = []
        for img in (req.images or [])[:4]:
            if not isinstance(img, str) or not _IMAGE_DATA_URL_RE.match(img):
                return StreamingResponse(
                    iter([_sse({"type": "error",
                                "message": "이미지는 data:image/(png|jpeg|gif|webp);base64 형식만 가능합니다"})]),
                    media_type="text/event-stream",
                )
            if len(img) > 10_000_000:  # base64 팽창 포함 ~7.5MB 원본 상한
                return StreamingResponse(
                    iter([_sse({"type": "error", "message": "이미지 한 장이 너무 큽니다(최대 ~7MB)"})]),
                    media_type="text/event-stream",
                )
            valid_images.append(img)
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
                # 선택한 추론 모드(effort)를 유지한 채 대상 컨텍스트 그래프를 고른다.
                ctx_graphs = graphs_by_context[target_ctx]
                selected_graph = (
                    ctx_graphs.get(effort)
                    or ctx_graphs.get(default_effort)
                    or next(iter(ctx_graphs.values()))
                )
        sessions.touch(thread, title_candidate=question, agent=agent.name)

        # 이미지가 있으면 멀티모달 HumanMessage(content 블록 리스트)로 구성한다.
        # (llm._install_multimodal_patch 가 이 블록을 Codex input_image 로 변환한다)
        if valid_images:
            human_content: list = [{"type": "text", "text": question}]
            for img in valid_images:
                human_content.append({"type": "image_url", "image_url": {"url": img}})
            human_msg: HumanMessage = HumanMessage(content=human_content)
        else:
            human_msg = HumanMessage(question)

        def stream():
            payload = {
                "question": question,
                "session_id": thread,
                "messages": [human_msg],
                "agent_instructions": agent.instructions,
                "agent_name": agent.name,
                "agent_tools": list(agent.tools),
            }
            config = {"configurable": {"thread_id": thread},
                      "recursion_limit": recommended_recursion_limit()}
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

    # 큐레이터 주기 스케줄러 (opt-in) — 백그라운드 데몬 스레드로 사이클을 반복한다.
    # 실패한 잡은 durable 큐가 백오프로 흡수하므로 스레드가 죽지 않는 한 언젠가 완료된다.
    if settings.curator_enabled:
        stop_event = threading.Event()

        def _curator_loop() -> None:
            # 시작 직후 한 번 짧게 대기(서버 안정화) 후 주기 실행
            if stop_event.wait(60):
                return
            while not stop_event.is_set():
                try:
                    summary = _run_curator_cycle()
                    print(f"[curator] 사이클 완료 — {summary}")
                except Exception as exc:  # 사이클 전체 실패도 다음 주기에 재시도
                    print(f"[curator] 사이클 오류(다음 주기 재시도): {type(exc).__name__}: {exc}")
                stop_event.wait(max(60, settings.curator_interval_s))

        threading.Thread(target=_curator_loop, name="wiki-curator", daemon=True).start()

        @app.on_event("shutdown")
        def _stop_curator() -> None:
            stop_event.set()
            curator_queue.close()

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
