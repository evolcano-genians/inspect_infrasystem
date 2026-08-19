"""위키 큐레이터 검증 — durable 큐(재시도·백오프·기억) + 보수적 큐레이션."""

from __future__ import annotations

import json

from langchain_core.messages import AIMessage

from src.curator import (
    CuratorQueue,
    _extract_json,
    curate_page,
    plan_cycle,
    run_pending,
)
from src.llm import ScriptedChatModel


# ---- durable 큐 ----

def test_enqueue_dedupes_and_claims(tmp_path):
    q = CuratorQueue(tmp_path / "c.sqlite")
    assert q.enqueue("curate", "a.md", now=100) is not None
    assert q.enqueue("curate", "a.md", now=100) is None  # 중복 미완료 잡 → 스킵
    job = q.claim_next(now=100)
    assert job and job.target == "a.md" and job.status == "running"
    assert q.claim_next(now=100) is None  # running은 다시 안 잡힘


def test_fail_requeues_with_backoff_then_dead(tmp_path):
    q = CuratorQueue(tmp_path / "c.sqlite")
    q.enqueue("curate", "a.md", max_attempts=3, now=0)
    # 1차 실패 → 백오프 후 재큐 (즉시엔 안 잡힘)
    j = q.claim_next(now=0); assert j
    assert q.fail(j.id, "boom", now=0) == "requeued"
    assert q.claim_next(now=0) is None            # 백오프 대기중
    # 반복 실패(claim→fail) → 결국 dead. 잡을 잃지 않고 에러 보존.
    j = q.claim_next(now=10_000); assert j
    assert q.fail(j.id, "boom", now=10_000) == "requeued"   # attempts=2
    j = q.claim_next(now=100_000); assert j
    assert q.fail(j.id, "boom", now=100_000) == "dead"      # attempts=3 → dead
    assert q.stats().get("dead", 0) == 1
    # dead 회생
    assert q.revive_dead(now=200_000) == 1
    assert q.stats().get("pending", 0) == 1


def test_memory_survives_reopen(tmp_path):
    db = tmp_path / "c.sqlite"
    q = CuratorQueue(db)
    q.enqueue("curate", "keep.md", now=5)
    q.mark_curated("keep.md", "done once", now=5)
    q.record("curated", "keep.md", "detail", now=5)
    q.close()
    # 프로세스 재시작 시뮬레이션 — 큐·메모리가 보존돼야 한다
    q2 = CuratorQueue(db)
    assert q2.last_curated("keep.md") == 5
    assert q2.journal(10)[0]["target"] == "keep.md"
    assert q2.claim_next(now=10) is not None  # pending 잡도 보존


def test_plan_cycle_skips_recent(tmp_path):
    wiki = tmp_path / "wiki"
    (wiki / "ns").mkdir(parents=True)
    (wiki / "ns" / "a.md").write_text("---\n---\n# a\n내용", encoding="utf-8")
    (wiki / "ns" / "b.md").write_text("---\n---\n# b\n내용", encoding="utf-8")
    (wiki / "_index.md").write_text("# idx", encoding="utf-8")
    q = CuratorQueue(tmp_path / "c.sqlite")
    assert plan_cycle(q, wiki, now=1000) == 2      # 둘 다 처음 → 큐잉
    q.mark_curated("ns/a.md", now=1000)            # a는 방금 큐레이션됨
    # 재계획: a는 최근이라 스킵(단 이미 큐에 b가 pending이면 dedupe로 0), 시간 경과로 확인
    assert plan_cycle(q, wiki, min_recurate_s=100, now=1050) == 0  # a 최근·b 이미 큐잉


# ---- 큐레이션 로직 ----

def _model(payload: dict):
    return ScriptedChatModel(script=[AIMessage(content=json.dumps(payload, ensure_ascii=False))])


def _wiki(tmp_path):
    wiki = tmp_path / "wiki"
    (wiki / "namespaces").mkdir(parents=True)
    (wiki / "namespaces" / "app.md").write_text(
        "---\nlast_inspected: 2026-01-01\n---\n# app\n"
        "파드가 3개 있다. password: leaked123 라는 값이 있었다.\n" * 3,
        encoding="utf-8")
    return wiki


def test_curate_applies_revision_and_redacts(tmp_path):
    wiki = _wiki(tmp_path)
    q = CuratorQueue(tmp_path / "c.sqlite")
    revised = "# app\n파드 3개 관찰(2026-01-01). ⚠️ 재확인 필요.\n" * 3
    model = _model({"summary": "정리함", "stale_claims": ["파드 수"], "duplicates": [],
                    "contradictions": [], "revised_markdown": revised, "confidence": 0.9})

    def redactor(t):  # 시크릿 마스킹 시뮬레이션
        return t.replace("leaked123", "[REDACTED]")

    res = curate_page(model, wiki, "namespaces/app.md", q, redactor=redactor, now=1)
    assert res["applied"] is True
    saved = (wiki / "namespaces" / "app.md").read_text(encoding="utf-8")
    assert saved.startswith("---\n")                 # 프론트매터 보존
    assert "재확인 필요" in saved
    assert q.last_curated("namespaces/app.md") == 1  # 기억됨


def test_curate_low_confidence_not_applied(tmp_path):
    wiki = _wiki(tmp_path)
    q = CuratorQueue(tmp_path / "c.sqlite")
    original = (wiki / "namespaces" / "app.md").read_text(encoding="utf-8")
    model = _model({"summary": "불확실", "revised_markdown": "# app\n완전히 다른 짧은 내용",
                    "confidence": 0.2})
    res = curate_page(model, wiki, "namespaces/app.md", q, now=1)
    assert res["applied"] is False and "확신 낮음" in res["reason"]
    assert (wiki / "namespaces" / "app.md").read_text(encoding="utf-8") == original  # 원본 보존


def test_curate_guards_massive_deletion(tmp_path):
    wiki = _wiki(tmp_path)
    q = CuratorQueue(tmp_path / "c.sqlite")
    model = _model({"summary": "축소", "revised_markdown": "# app\n짧음", "confidence": 0.95})
    res = curate_page(model, wiki, "namespaces/app.md", q, now=1)
    assert res["applied"] is False and "급감" in res["reason"]


def test_run_pending_absorbs_failure_and_requeues(tmp_path):
    wiki = _wiki(tmp_path)
    q = CuratorQueue(tmp_path / "c.sqlite")
    q.enqueue("curate", "namespaces/app.md", now=0)
    # JSON이 아닌 응답 → 파싱 실패 → 큐가 재시도로 흡수(잡을 잃지 않음)
    bad_model = ScriptedChatModel(script=[AIMessage(content="이건 JSON이 아님")])
    results = run_pending(q, wiki, bad_model, max_jobs=5, now_fn=lambda: 0)
    assert results and "실패" in results[0]["reason"]
    assert q.stats().get("pending", 0) == 1  # 재큐됨


def test_extract_json_tolerates_fences():
    assert _extract_json('```json\n{"a":1}\n```') == {"a": 1}
    assert _extract_json('앞 텍스트 {"a":2} 뒤 텍스트') == {"a": 2}
    assert _extract_json("not json") is None
