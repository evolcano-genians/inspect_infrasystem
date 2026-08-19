"""위키 큐레이터 — LLM으로 위키 지식을 주기적으로 보정하는 durable job 시스템.

목적: 조사로 축적된 위키(장기 기억)는 시간이 지나면 (1) 사실이 바뀌어 폐기될 지식,
(2) 여러 페이지에 흩어진 중복 지식이 생긴다. 이 모듈은 그것을 주기적으로 정리한다.

설계 (nous-research/hermes-agent 의 cron 스케줄러 + 지속 메모리 + 크로스세션 회상 패턴 참고):
- **durable job queue** (SQLite): 프로세스가 죽어도 큐가 보존된다. 실패한 잡은 지수 백오프로
  재큐되어 "언젠가는 완료"된다(일시적 오류는 항상 회복). 과도한 poison 잡만 dead로 격리하되
  에러를 보존해 수동 회생 가능.
- **큐레이터 메모리**: 페이지별 마지막 큐레이션 시각 + 수행한 조치의 저널(journal)을 남겨
  이전 실행을 기억하고 같은 작업을 반복하지 않는다.
- **보수적 편집**: LLM 제안을 그대로 덮어쓰지 않는다 — 레다크션을 다시 적용하고, 원본을
  저널에 남기며, 과도한 삭제(내용 급감)는 사람 검토가 필요하다고 표시만 한다.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

# 지수 백오프: base * 2^attempts, cap 로 상한. "언젠가 완료"를 위해 max_attempts는 넉넉히.
_BACKOFF_BASE_S = 30.0
_BACKOFF_CAP_S = 6 * 3600.0  # 최대 6시간 간격
_DEFAULT_MAX_ATTEMPTS = 50
# 페이지가 이 시간 안에 큐레이션됐으면 다시 큐잉하지 않는다 (기본 24시간)
_MIN_RECURATE_S = 24 * 3600.0
# 보수적 편집 가드: 정리 후 길이가 원본의 이 비율 미만이면 자동 적용하지 않고 검토 표시
_MIN_KEEP_RATIO = 0.5


@dataclass(frozen=True)
class Job:
    id: int
    kind: str
    target: str
    payload: dict
    status: str
    attempts: int
    max_attempts: int
    last_error: str
    next_run_at: float


class CuratorQueue:
    """SQLite 기반 durable 잡 큐 — 재시도·백오프·dead-letter."""

    def __init__(self, db_path: str | Path):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init()

    def _init(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT NOT NULL,
                target TEXT NOT NULL,
                payload TEXT NOT NULL DEFAULT '{}',
                status TEXT NOT NULL DEFAULT 'pending',  -- pending|running|done|dead
                attempts INTEGER NOT NULL DEFAULT 0,
                max_attempts INTEGER NOT NULL DEFAULT 50,
                last_error TEXT NOT NULL DEFAULT '',
                created_at REAL NOT NULL,
                next_run_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_jobs_runnable ON jobs(status, next_run_at);
            CREATE TABLE IF NOT EXISTS page_state (
                page TEXT PRIMARY KEY,
                last_curated_at REAL NOT NULL,
                last_result TEXT NOT NULL DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                at REAL NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                detail TEXT NOT NULL DEFAULT ''
            );
            """
        )
        self._conn.commit()

    # ---- 큐 조작 ----
    def enqueue(self, kind: str, target: str, payload: dict | None = None,
                *, max_attempts: int = _DEFAULT_MAX_ATTEMPTS, dedupe: bool = True,
                now: float | None = None) -> int | None:
        """잡을 큐에 넣는다. dedupe=True면 같은 (kind,target)의 미완료 잡이 있으면 건너뛴다."""
        now = time.time() if now is None else now
        if dedupe:
            row = self._conn.execute(
                "SELECT id FROM jobs WHERE kind=? AND target=? AND status IN ('pending','running')",
                (kind, target),
            ).fetchone()
            if row:
                return None
        cur = self._conn.execute(
            "INSERT INTO jobs(kind,target,payload,status,attempts,max_attempts,created_at,"
            "next_run_at,updated_at) VALUES(?,?,?,?,0,?,?,?,?)",
            (kind, target, json.dumps(payload or {}, ensure_ascii=False), "pending",
             max_attempts, now, now, now),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def claim_next(self, now: float | None = None) -> Job | None:
        """실행 가능한(pending, next_run_at<=now) 잡 하나를 running으로 잠그고 반환한다."""
        now = time.time() if now is None else now
        row = self._conn.execute(
            "SELECT id,kind,target,payload,status,attempts,max_attempts,last_error,next_run_at "
            "FROM jobs WHERE status='pending' AND next_run_at<=? ORDER BY next_run_at LIMIT 1",
            (now,),
        ).fetchone()
        if not row:
            return None
        self._conn.execute("UPDATE jobs SET status='running',updated_at=? WHERE id=?", (now, row[0]))
        self._conn.commit()
        return Job(id=row[0], kind=row[1], target=row[2], payload=json.loads(row[3] or "{}"),
                   status="running", attempts=row[5], max_attempts=row[6],
                   last_error=row[7], next_run_at=row[8])

    def complete(self, job_id: int, result: str = "", now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._conn.execute(
            "UPDATE jobs SET status='done',last_error=?,updated_at=? WHERE id=?",
            (result[:2000], now, job_id))
        self._conn.commit()

    def fail(self, job_id: int, error: str, now: float | None = None) -> str:
        """실패 처리 — 재시도 여지가 있으면 백오프 후 pending, 아니면 dead. 상태를 반환."""
        now = time.time() if now is None else now
        row = self._conn.execute(
            "SELECT attempts,max_attempts FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not row:
            return "missing"
        attempts = row[0] + 1
        if attempts >= row[1]:
            self._conn.execute(
                "UPDATE jobs SET status='dead',attempts=?,last_error=?,updated_at=? WHERE id=?",
                (attempts, error[:2000], now, job_id))
            self._conn.commit()
            return "dead"
        delay = min(_BACKOFF_BASE_S * (2 ** (attempts - 1)), _BACKOFF_CAP_S)
        self._conn.execute(
            "UPDATE jobs SET status='pending',attempts=?,last_error=?,next_run_at=?,updated_at=? "
            "WHERE id=?", (attempts, error[:2000], now + delay, now, job_id))
        self._conn.commit()
        return "requeued"

    def revive_dead(self, now: float | None = None) -> int:
        """dead 잡을 pending으로 되살린다(수동 회생). 되살린 개수 반환."""
        now = time.time() if now is None else now
        cur = self._conn.execute(
            "UPDATE jobs SET status='pending',attempts=0,next_run_at=?,updated_at=? WHERE status='dead'",
            (now, now))
        self._conn.commit()
        return cur.rowcount

    def stats(self) -> dict:
        rows = self._conn.execute("SELECT status,COUNT(*) FROM jobs GROUP BY status").fetchall()
        return {s: c for s, c in rows}

    # ---- 큐레이터 메모리 (이전 실행 기억) ----
    def last_curated(self, page: str) -> float | None:
        row = self._conn.execute(
            "SELECT last_curated_at FROM page_state WHERE page=?", (page,)).fetchone()
        return row[0] if row else None

    def mark_curated(self, page: str, result: str = "", now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._conn.execute(
            "INSERT INTO page_state(page,last_curated_at,last_result) VALUES(?,?,?) "
            "ON CONFLICT(page) DO UPDATE SET last_curated_at=?,last_result=?",
            (page, now, result[:2000], now, result[:2000]))
        self._conn.commit()

    def record(self, action: str, target: str, detail: str = "", now: float | None = None) -> None:
        now = time.time() if now is None else now
        self._conn.execute(
            "INSERT INTO journal(at,action,target,detail) VALUES(?,?,?,?)",
            (now, action, target, detail[:4000]))
        self._conn.commit()

    def journal(self, limit: int = 50) -> list[dict]:
        rows = self._conn.execute(
            "SELECT at,action,target,detail FROM journal ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{"at": r[0], "action": r[1], "target": r[2], "detail": r[3]} for r in rows]

    def close(self) -> None:
        self._conn.close()


# ── 큐레이션 로직 ─────────────────────────────────────────────────────────

CURATOR_SYSTEM = """당신은 dev k8s 조사 위키의 **큐레이터**다. 아래 위키 페이지와 관련 페이지를
검토해, 지식의 사실관계·최신성·중복을 정리한다. 클러스터를 새로 조사하지는 말고, 주어진
텍스트만 근거로 판단하라.

정리 기준:
1. **폐기 대상**: 다른 페이지의 더 최신 관찰과 모순되거나, 시점상 오래돼 더는 유효하지 않을
   가능성이 높은 서술. (삭제하지 말고 "⚠️ 재확인 필요(YYYY-MM-DD 관찰, 최신성 불확실)"로 표시)
2. **중복**: 다른 페이지에 이미 있는 내용은 요약·참조로 줄인다.
3. **모순**: 한 페이지 안/페이지 간 상충하는 서술은 함께 명시하고 어느 쪽이 최신인지 표기.
4. 비밀·토큰·비밀번호 값이 남아 있으면 [REDACTED]로 바꾼다.

반드시 아래 JSON 한 개만 출력하라(다른 텍스트 금지):
{"summary":"한 줄 요약","stale_claims":["..."],"duplicates":["..."],
 "contradictions":["..."],"revised_markdown":"정리된 전체 페이지 마크다운(프론트매터 제외 본문)",
 "confidence":0.0~1.0}
revised_markdown 은 원본의 사실을 보존하되 위 기준으로 다듬은 것이어야 한다. 확신이 낮으면
confidence 를 낮추고 revised_markdown 은 원본과 거의 동일하게 두라."""


def _parse_frontmatter(text: str) -> tuple[str, str]:
    if text.startswith("---\n"):
        end = text.find("\n---\n", 4)
        if end != -1:
            return text[: end + 5], text[end + 5:]
    return "", text


def curate_page(model, wiki_dir: str | Path, page: str, queue: CuratorQueue,
                *, related_limit: int = 4, apply: bool = True,
                redactor=None, now: float | None = None) -> dict:
    """한 페이지를 큐레이션한다. LLM 제안을 보수적으로 적용하고 저널에 남긴다.

    Returns: {"page", "applied", "summary", "stale_claims", "duplicates", "contradictions",
              "confidence", "reason"}
    """
    from langchain_core.messages import HumanMessage, SystemMessage

    now = time.time() if now is None else now
    wiki_dir = Path(wiki_dir)
    target = wiki_dir / page
    if not target.is_file():
        raise FileNotFoundError(f"위키 페이지 없음: {page}")

    original = target.read_text(encoding="utf-8")
    frontmatter, body = _parse_frontmatter(original)

    # 관련 페이지(같은 섹션)를 중복 판단 컨텍스트로 제공
    section = Path(page).parent
    related: list[str] = []
    for sib in sorted((wiki_dir / section).glob("*.md")):
        rel = str(sib.relative_to(wiki_dir))
        if rel == page or sib.name == "_index.md":
            continue
        related.append(f"### (관련) {rel}\n{_parse_frontmatter(sib.read_text(encoding='utf-8'))[1][:1500]}")
        if len(related) >= related_limit:
            break

    user = f"# 대상 페이지: {page}\n{body}\n\n## 같은 섹션의 다른 페이지들\n" + (
        "\n\n".join(related) or "(없음)")
    resp = model.invoke([SystemMessage(content=CURATOR_SYSTEM), HumanMessage(content=user[:30_000])])
    raw = str(getattr(resp, "content", "") or "").strip()

    # JSON 파싱(관대하게) — 코드펜스·앞뒤 텍스트 제거
    data = _extract_json(raw)
    if data is None:
        queue.record("parse_failed", page, raw[:500], now=now)
        raise ValueError("큐레이터 응답 JSON 파싱 실패")

    revised = str(data.get("revised_markdown") or "").strip()
    confidence = float(data.get("confidence") or 0.0)
    result = {
        "page": page, "applied": False,
        "summary": str(data.get("summary") or ""),
        "stale_claims": data.get("stale_claims") or [],
        "duplicates": data.get("duplicates") or [],
        "contradictions": data.get("contradictions") or [],
        "confidence": confidence, "reason": "",
    }

    # 보수적 가드: 과도한 삭제·저확신·빈 결과는 적용하지 않고 검토만 기록
    if not revised:
        result["reason"] = "revised_markdown 없음"
    elif confidence < 0.4:
        result["reason"] = f"확신 낮음({confidence:.2f}) — 검토 필요"
    elif len(revised) < len(body) * _MIN_KEEP_RATIO:
        result["reason"] = "내용 급감 — 자동 적용 보류(검토 필요)"
    elif not apply:
        result["reason"] = "dry-run"
    else:
        new_body = redactor(revised) if redactor else revised
        target.write_text(frontmatter + new_body + "\n", encoding="utf-8")
        result["applied"] = True
        result["reason"] = "적용됨"

    queue.mark_curated(page, result["summary"], now=now)
    queue.record("curated", page,
                 f"applied={result['applied']} conf={confidence:.2f} "
                 f"stale={len(result['stale_claims'])} dup={len(result['duplicates'])} "
                 f"reason={result['reason']}", now=now)
    return result


def _extract_json(raw: str) -> dict | None:
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("```", 2)[1] if raw.count("```") >= 2 else raw
        raw = raw[raw.find("\n") + 1:] if "\n" in raw else raw
    start, end = raw.find("{"), raw.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None
    try:
        return json.loads(raw[start:end + 1])
    except Exception:
        return None


def plan_cycle(queue: CuratorQueue, wiki_dir: str | Path,
               *, min_recurate_s: float = _MIN_RECURATE_S, now: float | None = None) -> int:
    """오래 안 다듬어진 페이지들에 대해 curate 잡을 큐잉한다. 큐잉한 개수를 반환."""
    now = time.time() if now is None else now
    wiki_dir = Path(wiki_dir)
    queued = 0
    for path in sorted(wiki_dir.rglob("*.md")):
        if path.name == "_index.md":
            continue
        page = str(path.relative_to(wiki_dir))
        last = queue.last_curated(page)
        if last is not None and (now - last) < min_recurate_s:
            continue
        if queue.enqueue("curate", page, now=now) is not None:
            queued += 1
    return queued


def run_pending(queue: CuratorQueue, wiki_dir: str | Path, model,
                *, max_jobs: int = 20, redactor=None, now_fn=time.time) -> list[dict]:
    """실행 가능한 잡을 최대 max_jobs개 처리한다. 각 잡의 결과 목록을 반환.

    실패한 잡은 큐가 백오프로 재큐하므로 이 호출에서 끝나지 않아도 다음 사이클에서 재시도된다.
    """
    results: list[dict] = []
    for _ in range(max_jobs):
        job = queue.claim_next(now=now_fn())
        if job is None:
            break
        try:
            if job.kind == "curate":
                res = curate_page(model, wiki_dir, job.target, queue,
                                  redactor=redactor, now=now_fn())
                queue.complete(job.id, res.get("summary", ""), now=now_fn())
                results.append(res)
            else:
                queue.fail(job.id, f"알 수 없는 잡 종류: {job.kind}", now=now_fn())
        except Exception as exc:  # 실패는 큐가 재시도로 흡수 — 잡을 잃지 않는다
            state = queue.fail(job.id, f"{type(exc).__name__}: {exc}", now=now_fn())
            results.append({"page": job.target, "applied": False,
                            "reason": f"실패({state}): {exc}"})
    return results


def run_cycle(queue: CuratorQueue, wiki_dir: str | Path, model,
              *, redactor=None, max_jobs: int = 20) -> dict:
    """한 큐레이션 사이클: 계획(큐잉) → 실행. 스케줄러/CLI가 호출한다."""
    queued = plan_cycle(queue, wiki_dir)
    results = run_pending(queue, wiki_dir, model, max_jobs=max_jobs, redactor=redactor)
    applied = sum(1 for r in results if r.get("applied"))
    return {"queued": queued, "processed": len(results), "applied": applied,
            "stats": queue.stats()}


def main() -> None:
    """CLI 엔트리포인트 — OS cron이 주기적으로 호출할 수 있다.

    예) */30 * * * *  cd /path && .venv/bin/python -m src.curator
    """
    from .config import load_settings
    from .llm import make_model
    from .nodes.wiki_writer import redact_text

    settings = load_settings()
    queue = CuratorQueue(settings.checkpoint_db.parent / "curator.sqlite")
    model = make_model(settings)
    summary = run_cycle(queue, settings.wiki_dir, model, redactor=redact_text)
    print(f"[curator] 큐잉 {summary['queued']} · 처리 {summary['processed']} · "
          f"적용 {summary['applied']} · 큐상태 {summary['stats']}")
    queue.close()


if __name__ == "__main__":
    main()
