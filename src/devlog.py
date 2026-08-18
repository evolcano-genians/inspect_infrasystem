"""개발 피드백 로그 — 프로그램(하네스) 자체를 개선하기 위한 대화 기록.

audit 로그(도구 호출 감사)·wiki(클러스터 지식)와 별개로, **이 하네스를 우리가 함께
디버그·개선하기 위한** 기록을 남긴다: 각 턴의 질문·최종 답변·도구 트레이스·환경, 그리고
사용자가 남긴 피드백(👍/👎/메모). 이 기록으로 "어떤 질문에서 하네스가 약했는지"를 찾아
도구·에이전트·프롬프트를 개선한다.

저장: logs/devlog.jsonl (append-only JSONL). 민감값은 레다크션 필터를 통과시킨다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from .nodes.wiki_writer import redact_text


class DevLog:
    def __init__(self, logs_dir: Path | str):
        self._dir = Path(logs_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._path = self._dir / "devlog.jsonl"

    def record_turn(
        self,
        *,
        thread_id: str,
        agent: str,
        context: str,
        question: str,
        answer: str,
        tool_trace: list,
        usage: dict,
        reasoning: str = "",
    ) -> str:
        turn_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
        entry = {
            "id": turn_id,
            "type": "turn",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "thread_id": thread_id,
            "agent": agent,
            "context": context,
            "reasoning": reasoning,
            "question": redact_text(question or "")[:4000],
            "answer": redact_text(answer or "")[:8000],
            "tools": [
                {"name": t.get("tool"), "allowed": t.get("allowed"), "error": t.get("error")}
                for t in (tool_trace or [])
            ],
            "tool_count": len(tool_trace or []),
            "rejected": sum(1 for t in (tool_trace or []) if not t.get("allowed")),
            "errored": sum(1 for t in (tool_trace or []) if t.get("error")),
            "usage": usage or {},
        }
        self._append(entry)
        return turn_id

    def record_feedback(self, *, turn_id: str, rating: str, note: str = "") -> dict:
        """사용자 피드백(good|bad|note)을 해당 턴에 연결해 남긴다 — 개선 신호."""
        rating = (rating or "").strip().lower()
        if rating not in ("good", "bad", "note"):
            rating = "note"
        entry = {
            "id": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f"),
            "type": "feedback",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "turn_id": turn_id,
            "rating": rating,
            "note": redact_text(note or "")[:2000],
        }
        self._append(entry)
        return entry

    def _append(self, entry: dict) -> None:
        with open(self._path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def entries(self, limit: int = 200) -> list[dict]:
        if not self._path.exists():
            return []
        out = [json.loads(x) for x in self._path.read_text(encoding="utf-8").splitlines() if x.strip()]
        return out[-limit:]

    def improvement_report(self) -> dict:
        """하네스 개선용 요약: 약점 신호(거부·오류·부정 피드백·예산소진)를 집계한다."""
        entries = self.entries(limit=10_000)
        turns = [e for e in entries if e["type"] == "turn"]
        feedback = [e for e in entries if e["type"] == "feedback"]
        bad_ids = {f["turn_id"] for f in feedback if f["rating"] == "bad"}
        weak = [
            {
                "id": t["id"], "agent": t["agent"], "context": t.get("context"),
                "question": t["question"][:120],
                "signals": [
                    *(["거부"] if t["rejected"] else []),
                    *(["도구오류"] if t["errored"] else []),
                    *(["부정피드백"] if t["id"] in bad_ids else []),
                    *(["예산소진"] if "한도" in t.get("answer", "") else []),
                ],
            }
            for t in turns
            if t["rejected"] or t["errored"] or t["id"] in bad_ids or "한도" in t.get("answer", "")
        ]
        by_agent: dict[str, int] = {}
        for t in turns:
            by_agent[t["agent"]] = by_agent.get(t["agent"], 0) + 1
        return {
            "total_turns": len(turns),
            "total_feedback": len(feedback),
            "good": sum(1 for f in feedback if f["rating"] == "good"),
            "bad": len(bad_ids),
            "turns_by_agent": by_agent,
            "weak_turns": weak[-50:],
        }
