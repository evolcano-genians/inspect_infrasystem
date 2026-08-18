"""append-only audit 로거.

모든 도구 호출 시도(검증 통과/거부 불문)를 구조화된 JSON Lines로 기록한다.
보안 감사 목적이므로 파이썬 logging 모듈의 레벨 설정과 무관하게 항상 기록된다
(직접 파일 append — 끌 수 있는 설정 경로가 존재하지 않는다).

`logs/`(audit)와 `wiki/`(장기 기억)는 역할이 다르다: audit은 원시·불변·감사용,
위키는 합성·편집 가능·재사용용이다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


class AuditLogger:
    def __init__(self, logs_dir: Path | str):
        self._dir = Path(logs_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def _path(self) -> Path:
        return self._dir / f"audit-{datetime.now(timezone.utc):%Y%m%d}.jsonl"

    def record(
        self,
        *,
        tool: str,
        verb: str,
        resource: str = "",
        namespace: str = "",
        allowed: bool,
        reason: str = "",
        duration_ms: float = 0.0,
        result_chars: int = 0,
    ) -> dict:
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tool": tool,
            "verb": verb,
            "resource": resource,
            "namespace": namespace,
            "allowed": allowed,
            "reason": reason,
            "duration_ms": round(duration_ms, 2),
            "result_chars": result_chars,
        }
        with open(self._path(), "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def entries(self) -> list[dict]:
        """기록된 전체 엔트리 (테스트·세션 요약용 읽기 헬퍼)."""
        out: list[dict] = []
        for path in sorted(self._dir.glob("audit-*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.append(json.loads(line))
        return out
