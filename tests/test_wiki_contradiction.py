"""6-8 위키 모순 처리 — 기존 기록을 덮어쓰지 않고 날짜 찍힌 모순 노트를 append."""

from __future__ import annotations

from src.nodes.wiki_common import parse_page
from src.nodes.wiki_writer import write_observations


def _obs(replicas: int, observed_at: str) -> dict:
    return {
        "entity_type": "workload",
        "entity": "healthy-web",
        "namespace": "default",
        "observed_at": observed_at,
        "summary": f"Deployment replicas desired={replicas} ready={replicas} available={replicas}",
        "facts": {"kind": "Deployment", "replicas": replicas, "ready": replicas, "images": []},
    }


def test_contradiction_is_appended_not_overwritten(wiki_dir):
    write_observations(wiki_dir, [_obs(3, "2026-08-11T09:00:00+00:00")])
    page = wiki_dir / "workloads" / "healthy-web.md"
    first_text = page.read_text(encoding="utf-8")
    assert "desired=3" in first_text

    write_observations(wiki_dir, [_obs(1, "2026-08-18T09:00:00+00:00")])
    frontmatter, body = parse_page(page)

    # 1) 기준선(baseline)은 최초 관찰값 그대로 유지된다
    assert frontmatter["baseline"]["replicas"] == 3
    # 2) 과거 관찰 라인이 삭제되지 않았다
    assert "2026-08-11T09:00:00+00:00" in body and "desired=3" in body
    # 3) 새 관찰도 기록되었다
    assert "2026-08-18T09:00:00+00:00" in body and "desired=1" in body
    # 4) 날짜가 찍힌 모순 노트가 append되었다
    assert "모순 노트 (2026-08-18)" in body
    assert "관찰값 1" in body and "기준선 3" in body
    # 5) last_inspected만 갱신된다
    assert frontmatter["last_inspected"] == "2026-08-18"


def test_repeated_consistent_observations_do_not_create_notes(wiki_dir):
    write_observations(wiki_dir, [_obs(3, "2026-08-11T09:00:00+00:00")])
    write_observations(wiki_dir, [_obs(3, "2026-08-12T09:00:00+00:00")])
    _, body = parse_page(wiki_dir / "workloads" / "healthy-web.md")
    assert "모순 노트" not in body
    assert body.count("desired=3") == 2
