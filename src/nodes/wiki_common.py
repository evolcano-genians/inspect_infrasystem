"""위키 페이지 공용 유틸 — YAML frontmatter가 있는 일반 Markdown.

위키는 에이전트의 로컬 스크래치 공간이다. K8s 클러스터 리소스가 아니므로
여기에 쓰는 행위는 read-only 제약과 무관하다. 사람이 직접 읽고 수정할 수 있어야
하므로 에이전트 전용 포맷을 쓰지 않는다.
"""

from __future__ import annotations

from pathlib import Path

import yaml

_DELIM = "---"


def parse_page(path: Path) -> tuple[dict, str]:
    """(frontmatter dict, body str) 반환. frontmatter가 없으면 ({}, 전체)."""
    text = path.read_text(encoding="utf-8")
    if text.startswith(_DELIM + "\n"):
        try:
            _, fm_text, body = text.split(_DELIM + "\n", 2)
            fm = yaml.safe_load(fm_text) or {}
            if isinstance(fm, dict):
                return fm, body
        except ValueError:
            pass
    return {}, text


def dump_page(frontmatter: dict, body: str) -> str:
    fm_text = yaml.safe_dump(frontmatter, allow_unicode=True, sort_keys=True, default_flow_style=False)
    return f"{_DELIM}\n{fm_text}{_DELIM}\n{body}"
