"""세션 레지스트리 — 웹 하네스의 세션별 작업 관리.

대화 context 자체는 LangGraph SqliteSaver 체크포인트(thread_id별)가 보존한다.
이 모듈은 그 위에 얹히는 가벼운 메타데이터 저장소다: 세션 목록/제목(첫 질문)/
최근 활동 시각/턴 수를 관리해 UI가 세션을 나열·전환할 수 있게 한다.

별도 sqlite 파일을 사용해 checkpointer의 DB와 경합하지 않는다.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class SessionMeta:
    thread_id: str
    title: str
    created_at: str
    updated_at: str
    turns: int
    agent: str

    def to_dict(self) -> dict:
        return asdict(self)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SessionStore:
    def __init__(self, db_path: Path | str):
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    thread_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    turns INTEGER NOT NULL DEFAULT 0,
                    agent TEXT NOT NULL DEFAULT 'inspector'
                )
                """
            )
            # 구버전 DB 마이그레이션: agent 컬럼이 없으면 추가
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(sessions)").fetchall()}
            if "agent" not in cols:
                self._conn.execute(
                    "ALTER TABLE sessions ADD COLUMN agent TEXT NOT NULL DEFAULT 'inspector'"
                )
            self._conn.commit()

    def touch(self, thread_id: str, title_candidate: str = "", agent: str = "") -> SessionMeta:
        """세션 활동을 기록한다 — 없으면 생성, 있으면 turns/updated_at/agent 갱신.

        제목은 첫 질문(title_candidate)으로 한 번만 설정되고 이후 변하지 않는다.
        agent는 매 턴 최신 선택으로 갱신된다 (세션 중 에이전트 전환 허용).
        """
        now = _now()
        title = (title_candidate or "").strip().replace("\n", " ")[:80]
        agent_name = (agent or "inspector").strip()[:64]
        with self._lock:
            row = self._conn.execute(
                "SELECT title FROM sessions WHERE thread_id = ?", (thread_id,)
            ).fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO sessions (thread_id, title, created_at, updated_at, turns, agent) "
                    "VALUES (?, ?, ?, ?, 1, ?)",
                    (thread_id, title, now, now, agent_name),
                )
            else:
                self._conn.execute(
                    "UPDATE sessions SET updated_at = ?, turns = turns + 1, agent = ?, "
                    "title = CASE WHEN title = '' THEN ? ELSE title END "
                    "WHERE thread_id = ?",
                    (now, agent_name, title, thread_id),
                )
            self._conn.commit()
        meta = self.get(thread_id)
        assert meta is not None
        return meta

    def get(self, thread_id: str) -> SessionMeta | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT thread_id, title, created_at, updated_at, turns, agent "
                "FROM sessions WHERE thread_id = ?",
                (thread_id,),
            ).fetchone()
        return SessionMeta(*row) if row else None

    def list(self, limit: int = 100) -> list[SessionMeta]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT thread_id, title, created_at, updated_at, turns, agent "
                "FROM sessions ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [SessionMeta(*row) for row in rows]

    def remove(self, thread_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions WHERE thread_id = ?", (thread_id,))
            self._conn.commit()
        return cur.rowcount > 0
