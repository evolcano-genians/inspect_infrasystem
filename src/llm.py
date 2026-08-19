"""LLM 프로바이더 팩토리.

- ``codex-oauth``: ChatGPT Plus/Pro 구독의 Codex OAuth 세션 재사용 (`langchain-codex-oauth`).
  OpenAI API 키는 어디에서도 사용·요구하지 않는다. 1회 로그인:
  ``langchain-codex-oauth auth login`` (자격증명은 ~/.langchain-codex-oauth/ 저장).
  ⚠️ ChatGPT 소비자 백엔드 경유이므로 개인 개발/로컬 실증 용도로만 사용한다.
- ``fake``: 네트워크를 쓰지 않는 결정론적 모의 모델 (테스트/오프라인 재현용).
"""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from pydantic import PrivateAttr

from .config import Settings


class ScriptedChatModel(BaseChatModel):
    """미리 정의된 AIMessage 시퀀스를 순서대로 반환하는 결정론적 모의 모델.

    tool_calls를 포함한 AIMessage를 script에 넣으면 LangGraph 도구 루프를
    네트워크 없이 재현할 수 있다. 같은 script → 같은 출력 (재현성 테스트용).
    """

    script: list[AIMessage]
    _cursor: int = PrivateAttr(default=0)

    @property
    def _llm_type(self) -> str:
        return "scripted-fake"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        if self._cursor < len(self.script):
            message = self.script[self._cursor]
            self._cursor += 1
        else:
            message = AIMessage(content="(스크립트 소진 — 추가 응답 없음)")
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools: Any, **kwargs: Any):
        # 스크립트가 tool_calls를 직접 포함하므로 도구 스키마 바인딩은 no-op.
        return self


class HeuristicPlannerModel(BaseChatModel):
    """LLM 없이 동작하는 결정론적 데모 플래너 (``MODEL_PROVIDER=heuristic``).

    질문 키워드로 read 도구 1개를 고르고, 도구 결과를 규칙 기반으로 요약한다.
    Codex OAuth 로그인 없이 웹 하네스/CLI를 실증하기 위한 오프라인 모드이며,
    답변에 데모 모드임을 명시한다. 실사용은 codex-oauth 프로바이더를 쓴다.
    """

    @property
    def _llm_type(self) -> str:
        return "heuristic-planner"

    # ---- 계획 규칙 ----

    @staticmethod
    def _namespace_of(question: str) -> str:
        import re

        m = re.search(r"([a-z0-9][a-z0-9-]*)\s*네임스페이스", question)
        if not m:
            m = re.search(r"(?:namespace|ns)\s+([a-z0-9][a-z0-9-]*)", question, re.IGNORECASE)
        return m.group(1) if m else "default"

    @staticmethod
    def _entity_of(question: str) -> str:
        import re

        candidates = re.findall(r"\b[a-z0-9]+(?:-[a-z0-9]+)+\b", question)
        blocked = {"read-only", "k8s-inspector-sandbox"}
        for c in candidates:
            if c not in blocked and not c.endswith("네임스페이스"):
                return c
        return ""

    def _plan(self, question: str) -> dict:
        q = question.lower()
        ns = self._namespace_of(q)
        entity = self._entity_of(q)
        if ("로그" in q or "log" in q) and entity:
            return {"name": "k8s_get_pod_logs", "args": {"namespace": ns, "name": entity, "tail_lines": 100}}
        if "롤아웃" in q or "rollout" in q or "이력" in q:
            if entity:
                return {"name": "k8s_rollout_history", "args": {"namespace": ns, "name": entity}}
            return {"name": "k8s_list_deployments", "args": {"namespace": ns}}
        if "deployment" in q or "디플로이" in q:
            return {"name": "k8s_list_deployments", "args": {"namespace": ns}}
        if "서비스" in q or "service" in q:
            if entity:
                return {"name": "k8s_get_service", "args": {"namespace": ns, "name": entity}}
            return {"name": "k8s_list_services", "args": {"namespace": ns}}
        if "노드" in q or "node" in q:
            return {"name": "k8s_list_nodes", "args": {}}
        if "네임스페이스 목록" in q or "namespaces" in q:
            return {"name": "k8s_list_namespaces", "args": {}}
        if entity and ("상태" in q or "왜" in q or "describe" in q):
            return {"name": "k8s_get_pod", "args": {"namespace": ns, "name": entity}}
        # 리소스 사용량 질문 포함 기본값: 파드 목록 (requests/limits·상태 포함)
        return {"name": "k8s_list_pods", "args": {"namespace": ns}}

    # ---- 요약 규칙 ----

    @staticmethod
    def _summarize(tool_name: str, content: str, question: str) -> str:
        import json as _json

        prefix = "🔎 (휴리스틱 데모 모드 — LLM 미사용, 규칙 기반 요약)\n\n"
        if content.startswith("["):
            try:
                data = _json.loads(content)
            except ValueError:
                data = None
            if isinstance(data, list) and data and isinstance(data[0], dict) and "phase" in data[0]:
                lines, problems = [], []
                for pod in data:
                    waits = [
                        c["state"].get("waiting")
                        for c in pod.get("containers", [])
                        if c.get("state", {}).get("waiting")
                    ]
                    restarts = sum(c.get("restart_count", 0) for c in pod.get("containers", []))
                    req = pod.get("containers", [{}])[0].get("resources", {}).get("requests", {})
                    mark = "⚠️" if waits or restarts else "✅"
                    lines.append(
                        f"- {mark} `{pod['name']}` phase={pod.get('phase')}"
                        + (f", waiting={','.join(waits)}" if waits else "")
                        + (f", restarts={restarts}" if restarts else "")
                        + (f", requests={req}" if req and ("리소스" in question or "사용량" in question) else "")
                    )
                    if waits or restarts:
                        problems.append(pod["name"])
                head = (
                    f"결론: 파드 {len(data)}개 중 문제 상태 {len(problems)}개"
                    + (f" ({', '.join(problems)})" if problems else "")
                    + ".\n\n"
                )
                return prefix + head + "\n".join(lines)
            if isinstance(data, list):
                return prefix + f"조회 결과 {len(data)}건:\n```json\n{content[:1500]}\n```"
        if tool_name == "k8s_get_pod_logs":
            tail = "\n".join(content.splitlines()[-15:])
            return prefix + f"로그 tail:\n```\n{tail[:1500]}\n```"
        return prefix + f"조회 결과:\n```\n{content[:1500]}\n```"

    def _generate(self, messages: list[BaseMessage], stop=None, run_manager=None, **kwargs) -> ChatResult:
        from langchain_core.messages import HumanMessage, ToolMessage

        question = next(
            (str(m.content) for m in reversed(messages) if isinstance(m, HumanMessage)), ""
        )
        last = messages[-1] if messages else None
        if isinstance(last, ToolMessage):
            message = AIMessage(
                content=self._summarize(str(last.name or ""), str(last.content), question)
            )
        else:
            plan = self._plan(question)
            message = AIMessage(
                content="",
                tool_calls=[{"name": plan["name"], "args": plan["args"], "id": "heuristic_1", "type": "tool_call"}],
            )
        return ChatResult(generations=[ChatGeneration(message=message)])

    def bind_tools(self, tools: Any, **kwargs: Any):
        return self


def make_model(settings: Settings) -> BaseChatModel:
    if settings.model_provider == "fake":
        return ScriptedChatModel(
            script=[AIMessage(content="(fake 프로바이더) 스크립트가 주입되지 않았습니다.")]
        )
    if settings.model_provider == "heuristic":
        return HeuristicPlannerModel()
    if settings.model_provider == "codex-oauth":
        return make_codex_model(settings.codex_model, settings.codex_reasoning_effort)
    raise ValueError(
        f"알 수 없는 MODEL_PROVIDER '{settings.model_provider}' (codex-oauth | heuristic | fake)"
    )


_MULTIMODAL_PATCHED = False


def _install_multimodal_patch() -> None:
    """어댑터의 입력 변환기가 이미지(멀티모달) 메시지를 처리하도록 보정한다.

    langchain-codex-oauth v1.0.0 의 ``_to_input_items`` 는 모든 메시지 content 를
    ``str()`` 로 뭉개 텍스트 블록만 만든다 — HumanMessage.content 가 블록 리스트
    (예: [{"type":"text"}, {"type":"image_url"}])면 이미지가 문자열로 깨진다.
    Codex/Responses 백엔드는 ``input_image`` 블록을 지원하므로(실측: gpt-5.6-sol이
    이미지 색상을 정확히 인식), human 메시지의 리스트 content 를 input_text/input_image
    블록으로 변환하는 버전으로 교체한다. 나머지 처리는 원본과 동일하다. site-packages 는
    건드리지 않고 모듈 함수만 우리 쪽에서 감싼다(기존 complete_with_response 보정과 동일 원칙).
    """
    global _MULTIMODAL_PATCHED
    if _MULTIMODAL_PATCHED:
        return
    import langchain_codex_oauth.chat_models as cm
    from langchain_core.messages import ToolMessage

    def _human_blocks(content) -> list[dict]:
        """HumanMessage.content(list) → Responses input 블록. 이미지 없으면 빈 리스트."""
        blocks: list[dict] = []
        for b in content:
            if isinstance(b, str) and b:
                blocks.append({"type": "input_text", "text": b})
            elif isinstance(b, dict):
                t = b.get("type")
                if t == "text":
                    blocks.append({"type": "input_text", "text": b.get("text", "")})
                elif t in ("image_url", "image"):
                    url = b.get("image_url") or b.get("url") or b.get("image")
                    if isinstance(url, dict):
                        url = url.get("url", "")
                    if isinstance(url, str) and url:
                        blocks.append({"type": "input_image", "image_url": url})
        return blocks

    def _to_input_items(messages, *, system_prompt_mode="default"):
        items: list = []
        mode = system_prompt_mode
        if mode == "strict":
            system_texts = cm._extract_system_texts(messages)
            if system_texts:
                items.append(cm.message_item(
                    "developer", cm._format_system_prompt_strict(system_texts)))
            to_process = [m for m in messages if m.type not in {"system", "developer"}]
        elif mode == "disabled":
            to_process = [m for m in messages if m.type not in {"system", "developer"}]
        else:
            to_process = list(messages)

        for message in to_process:
            if mode == "default" and message.type in {"system", "developer"}:
                items.append(cm.message_item("developer", str(message.content)))
                continue
            if message.type in {"human", "user"}:
                if isinstance(message.content, list):
                    blocks = _human_blocks(message.content)
                    if blocks:
                        items.append({"type": "message", "role": "user", "content": blocks})
                        continue
                items.append(cm.message_item("user", str(message.content)))
                continue
            if isinstance(message, ToolMessage) or message.type == "tool":
                tool_call_id = getattr(message, "tool_call_id", None)
                if isinstance(tool_call_id, str) and tool_call_id:
                    items.append(cm.function_call_output_item(tool_call_id, message.content))
                continue
            assistant_text = str(message.content) if message.content else ""
            if assistant_text:
                items.append(cm.message_item("assistant", assistant_text))
            tool_calls = getattr(message, "tool_calls", None)
            if isinstance(tool_calls, list):
                for tc in cm._ensure_tool_call_ids(tool_calls):
                    name, args, call_id = tc.get("name"), tc.get("args"), tc.get("id")
                    if not isinstance(name, str) or not name:
                        continue
                    if not isinstance(call_id, str) or not call_id:
                        continue
                    if not isinstance(args, dict):
                        args = {}
                    items.append(cm.function_call_item(call_id=call_id, name=name, args=args))
        return items

    cm._to_input_items = _to_input_items
    _MULTIMODAL_PATCHED = True


def make_codex_model(model_name: str, reasoning_effort: str = "medium") -> BaseChatModel:
    """백엔드 호환 보정이 적용된 ChatCodexOAuth 를 만든다.

    추론 단계는 low|medium|high 만 허용한다 — "minimal"/"none"(fast 모드)과
    "xhigh"/"ultra"는 정책상 요청 자체를 거부한다 (codex CLI의 xhigh 설정과 무관하게
    이 에이전트는 항상 중간 수준 추론으로 동작).

    2026-08 현재 신형 모델(gpt-5.6-sol 등)에서 ChatGPT/Codex 백엔드가
    종료 이벤트(response.completed)의 ``response.output`` 을 비워 보내는데,
    어댑터 v1.0.0 의 ``complete_with_response`` 는 종료 이벤트만 파싱하므로
    본문·tool call 이 전부 유실된다. 스트림 중 ``response.output_item.done``
    아이템을 누적해 비어 있는 output 을 보정한다 (어댑터 README 의
    "백엔드는 불안정하다" 경고에 해당하는 케이스 — site-packages 는 건드리지 않고
    우리 쪽 서브클래스로 해결한다).
    """
    from codex_oauth.client import CodexClient
    from codex_oauth.response import CompletionResult, parse_assistant_message
    from codex_oauth.sse import is_terminal_event
    from langchain_codex_oauth import ChatCodexOAuth

    from .config import ALLOWED_REASONING_EFFORTS, FORBIDDEN_REASONING_EFFORTS

    effort = (reasoning_effort or "medium").strip().lower()
    if effort in FORBIDDEN_REASONING_EFFORTS:
        raise ValueError(
            f"추론 단계 '{effort}' 는 정책상 사용하지 않습니다 — "
            f"fast(minimal/none)와 ultra(xhigh)는 배제되며, 허용값: {ALLOWED_REASONING_EFFORTS}"
        )
    if effort not in ALLOWED_REASONING_EFFORTS:
        raise ValueError(
            f"알 수 없는 추론 단계 '{effort}' — 허용값: {ALLOWED_REASONING_EFFORTS}"
        )

    _install_multimodal_patch()

    class _CompatCodexClient(CodexClient):
        def complete_with_response(self, **kwargs) -> CompletionResult:
            items: list[dict] = []
            last_response = None
            for event in self.stream_events(**kwargs):
                if event.get("type") == "response.output_item.done":
                    item = event.get("item")
                    if isinstance(item, dict):
                        items.append(item)
                if is_terminal_event(event):
                    last_response = event.get("response")
                    break
            if isinstance(last_response, dict):
                if not last_response.get("output") and items:
                    last_response = {**last_response, "output": items}
            elif last_response is None and items:
                last_response = {"output": items}
            return CompletionResult(
                parsed=parse_assistant_message(last_response), response=last_response
            )

    model = ChatCodexOAuth(model=model_name, reasoning_effort=effort)
    # 어댑터가 만든 동기 클라이언트에 보정 로직을 입힌다 (상태·설정은 그대로 유지).
    model._client.__class__ = _CompatCodexClient
    return model
