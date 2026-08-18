"""메타프롬프트 빌더 검증 — inspection 지식을 Claude 세션용 프롬프트로."""

from __future__ import annotations

from src.metaprompt import build_metaprompt


def _wiki(tmp_path):
    (tmp_path / "lessons").mkdir()
    (tmp_path / "namespaces").mkdir()
    (tmp_path / "lessons" / "inspector.md").write_text(
        "---\nagent: inspector\n---\n# 교훈\n- nexus-lake는 silver 스키마를 먼저 본다\n",
        encoding="utf-8",
    )
    (tmp_path / "namespaces" / "nexus-lake.md").write_text(
        "---\nlast_inspected: 2026-08-18\n---\n# nexus-lake\nbronze-ingestor 파드가 있다\n",
        encoding="utf-8",
    )
    (tmp_path / "namespaces" / "kube-system.md").write_text(
        "---\n---\n# kube-system\nCalico 네트워크\n", encoding="utf-8"
    )
    (tmp_path / "_index.md").write_text("# index\n", encoding="utf-8")
    return tmp_path


def test_builds_prompt_with_lessons_and_pages(tmp_path):
    r = build_metaprompt(_wiki(tmp_path))
    assert r["chars"] > 0
    assert "역할과 규칙" in r["prompt"]
    assert "인프라 환경 맵" in r["prompt"]
    assert "교훈" in r["prompt"]  # lessons 포함
    assert "_index.md" not in r["sources"]  # 인덱스는 제외


def test_topic_filters_relevant_pages(tmp_path):
    r = build_metaprompt(_wiki(tmp_path), topic="nexus-lake")
    # nexus-lake 페이지가 상위에, kube-system은 매칭 0이라 제외
    assert any("nexus-lake" in s for s in r["sources"])
    assert not any("kube-system" in s for s in r["sources"])


def test_task_is_embedded(tmp_path):
    r = build_metaprompt(_wiki(tmp_path), task="silver 정합성 검토해줘")
    assert "silver 정합성 검토해줘" in r["prompt"]


def test_secret_lines_defended(tmp_path):
    (tmp_path).mkdir(exist_ok=True)
    (tmp_path / "namespaces").mkdir(parents=True)
    (tmp_path / "namespaces" / "leak.md").write_text(
        "---\n---\n# leak\npassword: hunter2SECRET\n정상 라인\n", encoding="utf-8"
    )
    r = build_metaprompt(tmp_path, topic="leak")
    assert "hunter2SECRET" not in r["prompt"]
    assert "정상 라인" in r["prompt"]


def test_empty_wiki_graceful(tmp_path):
    r = build_metaprompt(tmp_path / "does-not-exist")
    assert "역할과 규칙" in r["prompt"]
    assert r["sources"] == []


def test_max_chars_truncates(tmp_path):
    w = _wiki(tmp_path)
    big = "가" * 5000
    for i in range(10):
        (w / "namespaces" / f"big{i}.md").write_text(f"---\n---\n# big{i}\n{big}\n", encoding="utf-8")
    r = build_metaprompt(w, max_chars=6000)
    assert r["chars"] <= 6200
    assert "절단됨" in r["prompt"]
