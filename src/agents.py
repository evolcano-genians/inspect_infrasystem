"""에이전트 정의 로더 — Claude Code의 `.claude/agents` 패턴.

`.agents/*.md` 파일(YAML frontmatter + 본문)을 에이전트 정의로 읽는다:

    ---
    name: sre-triage
    description: 장애 파드 원인 분석 특화
    ---
    (플래너 시스템 프롬프트에 추가되는 지시 본문)

보안 불변식: 에이전트 정의는 **플래너의 관점(프롬프트)만** 바꾼다. 도구 목록·verb
화이트리스트·전송 가드 등 4중 방어선은 어떤 에이전트를 선택해도 동일하게 적용된다 —
정의 파일이 도구를 추가하거나 권한을 바꿀 수 있는 통로는 존재하지 않는다.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .nodes.wiki_common import parse_page

#: 항상 존재하는 기본 에이전트 (파일이 하나도 없어도 동작)
_BUILTIN = {
    "name": "inspector",
    "description": "범용 클러스터 조사 에이전트 (기본값)",
    "instructions": "",
}


@dataclass(frozen=True)
class AgentDef:
    name: str
    description: str
    instructions: str
    source: str  # "builtin" 또는 파일명

    def to_dict(self, include_instructions: bool = False) -> dict:
        data = asdict(self)
        if not include_instructions:
            data.pop("instructions")
        return data


def load_agents(agents_dir: Path) -> dict[str, AgentDef]:
    """`.agents/*.md`를 읽어 {name: AgentDef}를 만든다. 기본 inspector는 항상 포함."""
    agents: dict[str, AgentDef] = {
        _BUILTIN["name"]: AgentDef(**_BUILTIN, source="builtin")
    }
    if agents_dir.is_dir():
        for path in sorted(agents_dir.glob("*.md")):
            frontmatter, body = parse_page(path)
            name = str(frontmatter.get("name") or path.stem).strip()
            if not name:
                continue
            agents[name] = AgentDef(
                name=name,
                description=str(frontmatter.get("description") or "").strip(),
                instructions=body.strip(),
                source=path.name,
            )
    return agents
