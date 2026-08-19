"""세션 레지스트리 — 웹 하네스의 세션별 작업 관리.

대화 context 자체는 LangGraph SqliteSaver 체크포인트(thread_id별)가 보존한다.
이 모듈은 그 위에 얹히는 가벼운 메타데이터 저장소다: 세션 목록/제목(첫 질문)/
최근 활동 시각/턴 수를 관리해 UI가 세션을 나열·전환할 수 있게 한다.

별도 sqlite 파일을 사용해 checkpointer의 DB와 경합하지 않는다.
"""

from __future__ import annotations

import sqlite3
import threading
import uuid
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
    tokens_in: int
    tokens_out: int
    project_id: str = ""   # 소속 프로젝트 id ("" = 미분류)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class ProjectMeta:
    id: str
    name: str
    created_at: str
    sort_order: int

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
                    agent TEXT NOT NULL DEFAULT 'inspector',
                    tokens_in INTEGER NOT NULL DEFAULT 0,
                    tokens_out INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS projects (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    sort_order INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            # 구버전 DB 마이그레이션: 없는 컬럼 추가
            cols = {r[1] for r in self._conn.execute("PRAGMA table_info(sessions)").fetchall()}
            migrations = {
                "agent": "ALTER TABLE sessions ADD COLUMN agent TEXT NOT NULL DEFAULT 'inspector'",
                "tokens_in": "ALTER TABLE sessions ADD COLUMN tokens_in INTEGER NOT NULL DEFAULT 0",
                "tokens_out": "ALTER TABLE sessions ADD COLUMN tokens_out INTEGER NOT NULL DEFAULT 0",
                "project_id": "ALTER TABLE sessions ADD COLUMN project_id TEXT NOT NULL DEFAULT ''",
            }
            for col, ddl in migrations.items():
                if col not in cols:
                    self._conn.execute(ddl)
            self._conn.commit()

    # ---- 프로젝트 (세션 묶음) ----
    def create_project(self, name: str) -> ProjectMeta:
        pid = "p-" + uuid.uuid4().hex[:10]
        now = _now()
        clean = (name or "새 프로젝트").strip().replace("\n", " ")[:80] or "새 프로젝트"
        with self._lock:
            nxt = self._conn.execute(
                "SELECT COALESCE(MAX(sort_order), 0) + 1 FROM projects"
            ).fetchone()[0]
            self._conn.execute(
                "INSERT INTO projects (id, name, created_at, sort_order) VALUES (?, ?, ?, ?)",
                (pid, clean, now, nxt),
            )
            self._conn.commit()
        return ProjectMeta(id=pid, name=clean, created_at=now, sort_order=nxt)

    def rename_project(self, project_id: str, name: str) -> bool:
        clean = (name or "").strip().replace("\n", " ")[:80]
        if not clean:
            return False
        with self._lock:
            cur = self._conn.execute(
                "UPDATE projects SET name = ? WHERE id = ?", (clean, project_id)
            )
            self._conn.commit()
        return cur.rowcount > 0

    def remove_project(self, project_id: str) -> bool:
        """프로젝트를 삭제한다. 소속 세션은 미분류(project_id='')로 되돌린다(세션은 유지)."""
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET project_id = '' WHERE project_id = ?", (project_id,)
            )
            cur = self._conn.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            self._conn.commit()
        return cur.rowcount > 0

    def list_projects(self) -> list[ProjectMeta]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, name, created_at, sort_order FROM projects "
                "ORDER BY sort_order, created_at"
            ).fetchall()
        return [ProjectMeta(*row) for row in rows]

    def assign_project(self, thread_id: str, project_id: str) -> bool:
        """세션을 프로젝트로 옮긴다. project_id='' 이면 미분류로 뺀다."""
        with self._lock:
            if project_id:
                exists = self._conn.execute(
                    "SELECT 1 FROM projects WHERE id = ?", (project_id,)
                ).fetchone()
                if not exists:
                    return False
            cur = self._conn.execute(
                "UPDATE sessions SET project_id = ? WHERE thread_id = ?",
                (project_id, thread_id),
            )
            self._conn.commit()
        return cur.rowcount > 0

    def add_usage(self, thread_id: str, tokens_in: int, tokens_out: int) -> None:
        """run 종료 후 세션 누적 토큰 사용량을 더한다."""
        with self._lock:
            self._conn.execute(
                "UPDATE sessions SET tokens_in = tokens_in + ?, tokens_out = tokens_out + ? "
                "WHERE thread_id = ?",
                (max(0, int(tokens_in)), max(0, int(tokens_out)), thread_id),
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
                "SELECT thread_id, title, created_at, updated_at, turns, agent, tokens_in, tokens_out, project_id "
                "FROM sessions WHERE thread_id = ?",
                (thread_id,),
            ).fetchone()
        return SessionMeta(*row) if row else None

    def list(self, limit: int = 100) -> list[SessionMeta]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT thread_id, title, created_at, updated_at, turns, agent, tokens_in, tokens_out, project_id "
                "FROM sessions ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [SessionMeta(*row) for row in rows]

    def remove(self, thread_id: str) -> bool:
        with self._lock:
            cur = self._conn.execute("DELETE FROM sessions WHERE thread_id = ?", (thread_id,))
            self._conn.commit()
        return cur.rowcount > 0
