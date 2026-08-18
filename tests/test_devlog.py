"""개발 피드백 로그 검증 — 턴 기록·피드백 연결·약점 리포트·레다크션."""

from __future__ import annotations

from src.devlog import DevLog


def _turn(log, q="질문", a="답변", trace=None, agent="inspector"):
    return log.record_turn(
        thread_id="t1", agent=agent, context="aws-seoul-clouddev",
        question=q, answer=a, tool_trace=trace or [], usage={"total_tokens": 100},
    )


def test_record_turn_and_feedback(tmp_path):
    log = DevLog(tmp_path)
    tid = _turn(log, trace=[{"tool": "k8s_list_pods", "allowed": True}])
    log.record_feedback(turn_id=tid, rating="good")
    entries = log.entries()
    assert entries[0]["type"] == "turn" and entries[0]["tool_count"] == 1
    assert entries[1]["type"] == "feedback" and entries[1]["rating"] == "good"


def test_devlog_redacts_secrets(tmp_path):
    log = DevLog(tmp_path)
    _turn(log, q="password: hunter2Secret 왜 안돼", a="token=eyJa.bc.de 문제")
    text = (tmp_path / "devlog.jsonl").read_text(encoding="utf-8")
    assert "hunter2Secret" not in text and "eyJa.bc.de" not in text
    assert "REDACTED" in text


def test_feedback_rating_normalized(tmp_path):
    log = DevLog(tmp_path)
    fb = log.record_feedback(turn_id="x", rating="INVALID")
    assert fb["rating"] == "note"


def test_improvement_report_flags_weak_turns(tmp_path):
    log = DevLog(tmp_path)
    # 정상 턴
    _turn(log, q="정상", trace=[{"tool": "k8s_list_pods", "allowed": True}])
    # 거부 신호
    t_rej = _turn(log, q="삭제해줘", trace=[{"tool": "kubectl_delete", "allowed": False}])
    # 도구 오류
    _turn(log, q="오류", trace=[{"tool": "k8s_get_pod", "allowed": True, "error": "ValidationError"}])
    # 예산 소진 답변
    _turn(log, q="전부", a="(조사 단계 한도 도달) 관찰 139건")
    # 부정 피드백
    t_ok = _turn(log, q="애매", trace=[{"tool": "x", "allowed": True}])
    log.record_feedback(turn_id=t_ok, rating="bad", note="답이 틀림")

    report = log.improvement_report()
    assert report["total_turns"] == 5
    assert report["bad"] == 1
    weak_ids = {w["id"] for w in report["weak_turns"]}
    assert t_rej in weak_ids and t_ok in weak_ids
    # 신호 라벨 확인
    signals = {s for w in report["weak_turns"] for s in w["signals"]}
    assert {"거부", "도구오류", "예산소진", "부정피드백"} <= signals
    assert report["turns_by_agent"]["inspector"] == 5
