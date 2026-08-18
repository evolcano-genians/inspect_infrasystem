"""Wiki Read Node — 질의와 관련된 위키 페이지를 플래너 컨텍스트에 주입한다.

매칭은 파일명·frontmatter(entity/namespace/tags) 기반이다 (브리프 1.1).
페이지 수가 크게 늘면 로컬 임베딩으로 확장한다 — 외부 벡터DB/임베딩 API는 쓰지 않는다.
"""

from __future__ import annotations

import re
from pathlib import Path

from .wiki_common import parse_page

_MAX_PAGES = 6
_MAX_CHARS = 8_000
_TOKEN_RE = re.compile(r"[a-z0-9][a-z0-9._-]{2,}")


def _question_tokens(question: str) -> set[str]:
    return set(_TOKEN_RE.findall(question.lower()))


def _expand(key: str) -> set[str]:
    """'crashloop-demo' → {'crashloop-demo', 'crashloop', 'demo'} — 서브토큰 매칭용."""
    parts = {p for p in re.split(r"[-._]", key) if len(p) >= 3}
    return {key} | parts


def _page_keys(path: Path, frontmatter: dict) -> set[str]:
    keys = _expand(path.stem.lower())
    for field in ("entity", "namespace"):
        value = str(frontmatter.get(field, "")).lower()
        if value:
            keys |= _expand(value)
    for tag in frontmatter.get("tags") or []:
        keys |= _expand(str(tag).lower())
    return keys


def relevant_pages(wiki_dir: Path, question: str) -> list[Path]:
    tokens = _question_tokens(question)
    matched: list[tuple[int, Path]] = []
    for path in sorted(wiki_dir.rglob("*.md")):
        if path.name == "_index.md":
            continue
        fm, _ = parse_page(path)
        keys = _page_keys(path, fm)
        score = len(keys & tokens)
        # 접두사 일치("crashloopbackoff" ↔ "crashloop")도 약한 신호로 인정
        if not score and any(
            (t.startswith(k) or k.startswith(t))
            for t in tokens
            for k in keys
            if len(t) >= 5 and len(k) >= 5
        ):
            score = 1
        if score:
            matched.append((score, path))
    matched.sort(key=lambda pair: (-pair[0], str(pair[1])))
    return [p for _, p in matched[:_MAX_PAGES]]


def make_wiki_reader_node(wiki_dir: Path):
    def wiki_reader(state: dict) -> dict:
        question = state.get("question", "")
        chunks: list[str] = []
        total = 0
        for path in relevant_pages(wiki_dir, question):
            text = path.read_text(encoding="utf-8")
            chunk = f"### {path.relative_to(wiki_dir)}\n{text}"
            if total + len(chunk) > _MAX_CHARS:
                break
            chunks.append(chunk)
            total += len(chunk)
        # run 시작 노드이므로 per-run 채널(observations/tool_trace)을 여기서 리셋한다 —
        # 같은 thread를 재사용하는 다음 질의에서 과거 run의 관찰이 중복 기록되지 않게.
        return {"wiki_context": "\n\n".join(chunks), "observations": [], "tool_trace": []}

    return wiki_reader
