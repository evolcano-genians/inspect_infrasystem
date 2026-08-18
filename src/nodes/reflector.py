"""Reflector 노드 — 자가 진화(self-evolution) 레이어.

에이전트는 세 층위로 진화한다. **능력·권한은 절대 진화하지 않는다** (구조적 불변 —
도구 목록·verb 화이트리스트·전송 가드는 이 모듈이 건드릴 수 없다):

1. 지식: 위키 관찰 축적 (wiki_writer가 담당)
2. 교훈: run의 신호(예산 소진·호출 거부·도구 오류)를 반성해 ``wiki/lessons/<agent>.md``에
   축적하고, 다음 run의 플래너 프롬프트에 주입한다 — 경험이 행동을 바꾼다.
3. 스킬: 에이전트 정의 개선안을 ``.agents/proposals/``에 **제안**만 한다 —
   사람이 검토·승인해야 실제 에이전트 정의에 적용된다.

이 모듈이 쓰기 가능한 경로는 위 두 곳뿐이며, 모든 기록은 레다크션 필터를 통과하고
git으로 버전관리되어 사람이 검토·되돌릴 수 있다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage

from .wiki_common import dump_page, parse_page
from .wiki_writer import redact_text

#: 플래너에 주입하는 최근 교훈 수
MAX_LESSONS_INJECTED = 8

_REFLECT_SYSTEM = """당신은 read-only Kubernetes 조사 에이전트의 자기개선(reflection) 모듈이다.
방금 끝난 조사 run의 기록을 보고, 다음에 유사한 질의가 왔을 때 조사를 더 잘하기 위한
교훈을 도출하라.

규칙:
- 출력 첫 줄은 반드시 `LESSON: ` 으로 시작하는 1~2문장의 구체적 교훈이어야 한다.
  (예: "LESSON: 전체 네임스페이스 스캔 전에 k8s_list_namespaces로 후보를 좁히고
   문제 신호가 있는 곳만 상세 조회한다.")
- 에이전트 정의(지시문) 자체를 고치는 편이 낫다고 판단되면, 그 아래에
  `PROPOSAL:` 한 줄을 쓰고 이어서 개선된 지시문 전체를 작성하라 (선택 사항).
- 도구 추가·권한 변경·쓰기 기능은 제안할 수 없다 — 조사 전략과 답변 방식만 개선하라.
- 교훈은 이 클러스터/질의 유형에 특화된 실행 가능한 내용이어야 한다. 일반론 금지."""


def run_signals(state: dict, max_tool_calls: int) -> list[str]:
    """run에서 '학습 가치'가 있는 신호를 결정론적으로 감지한다."""
    signals: list[str] = []
    trace = state.get("tool_trace") or []
    if len(trace) >= max_tool_calls:
        signals.append("budget_exhausted")
    if any(not t.get("allowed") for t in trace):
        signals.append("calls_rejected")
    if any(t.get("error") for t in trace):
        signals.append("tool_errors")
    return signals


def lessons_path(wiki_dir: Path, agent_name: str) -> Path:
    safe = re.sub(r"[^a-z0-9-]", "-", (agent_name or "inspector").lower())[:64]
    return Path(wiki_dir) / "lessons" / f"{safe}.md"


def load_lessons(wiki_dir: Path, agent_name: str, limit: int = MAX_LESSONS_INJECTED) -> str:
    """플래너 주입용 — 해당 에이전트의 최근 교훈 bullet 최대 limit개."""
    path = lessons_path(wiki_dir, agent_name)
    if not path.is_file():
        return ""
    _, body = parse_page(path)
    bullets = [line for line in body.splitlines() if line.startswith("- ")]
    return "\n".join(bullets[-limit:])


def append_lesson(wiki_dir: Path, agent_name: str, lesson: str, signals: list[str]) -> Path:
    """교훈을 append-only로 기록한다 (레다크션 강제, 히스토리 불삭제)."""
    path = lessons_path(wiki_dir, agent_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    line = f"- {date} [{','.join(signals) or 'manual'}] {redact_text(lesson.strip())}\n"
    if not path.exists():
        frontmatter = {"type": "lessons", "agent": agent_name}
        body = f"\n# 축적된 교훈: {agent_name}\n\n스스로 반성해 배운 조사 전략 (append-only).\n\n{line}"
        path.write_text(dump_page(frontmatter, body), encoding="utf-8")
    else:
        frontmatter, body = parse_page(path)
        path.write_text(dump_page(frontmatter, body.rstrip("\n") + "\n" + line), encoding="utf-8")
    return path


_PROPOSAL_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$")


def _split_frontmatter(text: str) -> tuple[dict, str]:
    if text.startswith("---\n") or text.startswith("---\r\n"):
        try:
            import yaml

            _, fm_text, body = text.split("---\n", 2)
            fm = yaml.safe_load(fm_text) or {}
            if isinstance(fm, dict):
                return fm, body
        except (ValueError, Exception):
            pass
    return {}, text


def write_proposal(agents_dir: Path, agent_name: str, instructions: str) -> Path | None:
    """스킬 개선 제안을 저장한다 — 적용은 사람 승인(웹 UI)으로만 이뤄진다.

    모델이 frontmatter까지 제안한 경우 description은 존중하되 name은 대상 에이전트로
    강제한다 (다른 에이전트를 가장한 제안 방지).
    """
    if not _PROPOSAL_NAME_RE.match(agent_name or ""):
        return None
    proposed_fm, body = _split_frontmatter(instructions.strip())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = Path(agents_dir) / "proposals" / f"{agent_name}-{stamp}.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    frontmatter = {
        "name": agent_name,
        "description": str(proposed_fm.get("description") or "(자가 진화 제안 — 검토 후 적용)"),
        "proposed_at": stamp,
    }
    path.write_text(
        dump_page(frontmatter, "\n" + redact_text(body.strip()) + "\n"), encoding="utf-8"
    )
    return path


def _parse_reflection(text: str) -> tuple[str, str]:
    """모델 출력에서 (lesson, proposal instructions)를 파싱한다."""
    lesson, proposal = "", ""
    m = re.search(r"^LESSON:\s*(.+?)(?=^PROPOSAL:|\Z)", text, re.MULTILINE | re.DOTALL)
    if m:
        lesson = " ".join(m.group(1).split())[:500]
    p = re.search(r"^PROPOSAL:\s*(.+)\Z", text, re.MULTILINE | re.DOTALL)
    if p:
        proposal = p.group(1).strip()[:8000]
    return lesson, proposal


def reflect_on_state(
    model,
    wiki_dir: Path,
    agents_dir: Path,
    state: dict,
    *,
    max_tool_calls: int,
    force: bool = False,
) -> dict:
    """run 상태를 반성해 교훈/제안을 기록한다. 반환: {lesson, proposal_file, signals}."""
    signals = run_signals(state, max_tool_calls)
    if not signals and not force:
        return {}
    agent_name = str(state.get("agent_name") or "inspector")
    trace = state.get("tool_trace") or []
    trace_summary = ", ".join(
        f"{t.get('tool')}({'허용' if t.get('allowed') else '거부'}"
        + (f",오류:{t['error']}" if t.get("error") else "") + ")"
        for t in trace[:30]
    )
    payload = (
        f"[에이전트] {agent_name}\n"
        f"[신호] {', '.join(signals) or '(수동 요청)'}\n"
        f"[질문] {state.get('question', '')}\n"
        f"[도구 호출 {len(trace)}회] {trace_summary}\n"
        f"[최종 답변(요약)] {str(state.get('final_answer', ''))[:800]}\n"
        f"[기존 교훈]\n{load_lessons(wiki_dir, agent_name) or '(없음)'}"
    )
    try:
        response = model.invoke([SystemMessage(_REFLECT_SYSTEM), HumanMessage(payload)])
    except Exception:
        return {}  # 반성 실패는 조사 결과에 영향을 주지 않는다
    lesson, proposal = _parse_reflection(str(response.content))
    result: dict = {"signals": signals}
    if lesson:
        append_lesson(wiki_dir, agent_name, lesson, signals)
        result["lesson"] = lesson
    if proposal:
        path = write_proposal(agents_dir, agent_name, proposal)
        if path:
            result["proposal_file"] = path.name
    return result if (lesson or proposal) else {}


def make_reflector_node(model, wiki_dir: Path, agents_dir: Path, max_tool_calls: int):
    def reflector(state: dict) -> dict:
        outcome = reflect_on_state(
            model, wiki_dir, agents_dir, state, max_tool_calls=max_tool_calls
        )
        if not outcome:
            return {}
        return {"last_lesson": outcome.get("lesson", ""), "last_proposal": outcome.get("proposal_file", "")}

    return reflector
