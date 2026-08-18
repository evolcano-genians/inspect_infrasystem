"""Wiki Write Node + 레다크션(redaction) 필터.

새 관찰을 엔티티 페이지에 반영한다. 핵심 규칙 (브리프 1.1):
- 기존 기록과 모순되는 관찰은 **덮어쓰지 않고** 날짜가 찍힌 모순 노트로 append한다.
  위키는 히스토리를 지우지 않는다.
- 위키에 쓰기 전 모든 텍스트/값은 결정론적 레다크션 필터를 통과한다.
  ConfigMap 등의 data 값은 애초에 facade가 노출하지 않지만(구조적), 혹시 다른 경로로
  섞여 들어온 시크릿성 값을 위한 별도 방어선이다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from langchain_core.messages import AIMessage

from .wiki_common import dump_page, parse_page

REDACTED = "[REDACTED]"

# 민감 키워드 (브리프: password|token|secret|key|credential 등 + 한글 표기).
# 경계는 \b 대신 커스텀 lookaround를 쓴다 — '_'는 \w에 포함되어 \b로는
# DB_PASSWORD / API_TOKEN 같은 SCREAMING_SNAKE_CASE(K8s에서 가장 흔한 시크릿 표기)를
# 놓치기 때문이다.
_KEYWORDS = (
    r"(?:password|passwd|pwd|token|secret|api[-_]?key|credential|cert|auth|key"
    r"|비밀번호|암호|패스워드|토큰|시크릿|자격증명|인증키|인증서)"
)
_LB = r"(?<![A-Za-z0-9])"   # 키워드 왼쪽: 영숫자 금지 ('_'는 경계로 취급)
_RB = r"(?![A-Za-z0-9])"    # 키워드 오른쪽: 영숫자 금지 (한글 조사는 연결자에서 처리)
_SENSITIVE_KEY_RE = re.compile(f"(?i){_LB}{_KEYWORDS}{_RB}")

# 키:값 패턴 — 연결자는 [:=], 한글 조사(는/은/이/가)+공백, " is " 를 지원하고
# 값은 따옴표로 묶인 전체 문자열 또는 공백·따옴표·세미콜론 전까지의 토큰(쉼표 포함).
_CONNECT = r"(?:\s*[:=]\s*|(?:는|은|이|가)\s+|\s+is\s+)"
_VALUE = r"(\"[^\"\n]{1,200}\"|'[^'\n]{1,200}'|[^\s\"';]+)"
_KV_RE = re.compile(f"(?i){_LB}({_KEYWORDS})(s?)({_CONNECT}){_VALUE}")

# URL userinfo 자격증명 (postgres://admin:pw@host, https://user:tok@registry ...)
_URL_CRED_RE = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*://[^/\s@:]+:)([^@\s]{1,200})(?=@)")

# JWT
_JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}(?:\.[A-Za-z0-9_-]*)?")
# base64로 보이는 긴 문자열 후보 (24자 이상 연속 런, '='는 끝 패딩만 허용).
# 후보 중 대문자+소문자+숫자(또는 +/=)가 섞인 것만 치환한다 — K8s 리소스 이름(소문자-숫자-하이픈)과
# CamelCase 사유 문자열("CrashLoopBackOff")을 오탐으로 지우지 않기 위한 결정론적 판별이다.
_B64_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/_-]{24,}={0,2}")


def _redact_if_base64ish(match: re.Match) -> str:
    s = match.group(0)
    if re.search(r"[A-Z]", s) and re.search(r"[a-z]", s) and re.search(r"[0-9+/=]", s):
        return REDACTED
    return s

#: 모순 감지 대상 기준선(baseline) 필드
_BASELINE_KEYS = ("replicas",)
#: 패턴 페이지로 축적하는 실패 사유
_FAILURE_PATTERNS = ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "OOMKilled")


def redact_text(text: str) -> str:
    """결정론적 레다크션. O(len(text))."""
    out = _JWT_RE.sub(REDACTED, text)
    out = _URL_CRED_RE.sub(lambda m: f"{m.group(1)}{REDACTED}", out)
    out = _KV_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}", out)
    out = _B64_CANDIDATE_RE.sub(_redact_if_base64ish, out)
    return out


def redact_value(value):
    """중첩 dict/list를 재귀 순회하며 민감 키의 값과 시크릿성 문자열을 치환한다."""
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k in ("data", "stringData") or _SENSITIVE_KEY_RE.search(str(k)):
                # 리소스 data 필드 값은 위키에 절대 기록하지 않는다 (브리프 1.1)
                out[k] = REDACTED
            else:
                out[k] = redact_value(v)
        return out
    if isinstance(value, list):
        return [redact_value(v) for v in value]
    if isinstance(value, str):
        return redact_text(value)
    return value


def redact_observation(obs: dict) -> dict:
    return redact_value(dict(obs))


# ---------- 페이지 갱신 ----------

def _date_of(obs: dict) -> str:
    return (obs.get("observed_at") or datetime.now(timezone.utc).isoformat())[:10]


def _apply_workload(wiki_dir: Path, obs: dict) -> None:
    page = wiki_dir / "workloads" / f"{obs['entity']}.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    date = _date_of(obs)
    facts = obs.get("facts") or {}
    if not isinstance(facts, dict):  # 레다크션이 통째로 치환한 경우
        facts = {}

    if not page.exists():
        frontmatter = {
            "entity": obs["entity"],
            "namespace": obs.get("namespace", ""),
            "type": "workload",
            "kind": facts.get("kind", ""),
            "created": date,
            "last_inspected": date,
        }
        baseline = {k: facts[k] for k in _BASELINE_KEYS if facts.get(k) is not None}
        if baseline:
            frontmatter["baseline"] = baseline
        body = (
            f"\n# {obs['entity']}\n\n"
            f"네임스페이스 `{obs.get('namespace', '')}` 의 {facts.get('kind', '워크로드')}.\n\n"
            f"## 관찰 이력\n\n- {obs['observed_at']}: {obs['summary']}\n"
        )
        page.write_text(dump_page(frontmatter, body), encoding="utf-8")
    else:
        frontmatter, body = parse_page(page)
        frontmatter["last_inspected"] = date
        additions = [f"- {obs['observed_at']}: {obs['summary']}"]
        baseline = frontmatter.get("baseline") or {}
        for key in _BASELINE_KEYS:
            old, new = baseline.get(key), facts.get(key)
            if old is not None and new is not None and old != new:
                additions.append(
                    f"> ⚠️ 모순 노트 ({date}): `{key}` 관찰값 {new} — 기존 기준선 {old} 과 다름. "
                    f"기준선과 과거 기록은 유지하며 히스토리를 지우지 않는다."
                )
        body = body.rstrip("\n") + "\n" + "\n".join(additions) + "\n"
        page.write_text(dump_page(frontmatter, body), encoding="utf-8")

    for reason in facts.get("waiting_reasons") or []:
        if reason in _FAILURE_PATTERNS:
            _apply_pattern(wiki_dir, reason, obs)


def _apply_pattern(wiki_dir: Path, reason: str, obs: dict) -> None:
    page = wiki_dir / "patterns" / f"{reason.lower()}.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    line = f"- {obs['observed_at']}: [[{obs['entity']}]] (ns `{obs.get('namespace', '')}`)\n"
    if not page.exists():
        frontmatter = {"type": "pattern", "tags": [reason]}
        body = f"\n# {reason} 관찰 기록\n\n{line}"
        page.write_text(dump_page(frontmatter, body), encoding="utf-8")
    else:
        frontmatter, body = parse_page(page)
        page.write_text(dump_page(frontmatter, body.rstrip("\n") + "\n" + line), encoding="utf-8")


def _apply_namespace(wiki_dir: Path, obs: dict) -> None:
    page = wiki_dir / "namespaces" / f"{obs['entity']}.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    line = f"- {obs['observed_at']}: {obs['summary']}\n"
    date = _date_of(obs)
    if not page.exists():
        frontmatter = {"namespace": obs["entity"], "type": "namespace", "last_inspected": date}
        body = f"\n# 네임스페이스: {obs['entity']}\n\n## 관찰 이력\n\n{line}"
        page.write_text(dump_page(frontmatter, body), encoding="utf-8")
    else:
        frontmatter, body = parse_page(page)
        frontmatter["last_inspected"] = date
        page.write_text(dump_page(frontmatter, body.rstrip("\n") + "\n" + line), encoding="utf-8")


def _write_session_page(wiki_dir: Path, state: dict, final_answer: str) -> None:
    session_id = state.get("session_id") or "session"
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    page = wiki_dir / "sessions" / f"{date}-{session_id}.md"
    page.parent.mkdir(parents=True, exist_ok=True)
    trace_lines = [
        f"- `{t.get('tool')}` → {'허용' if t.get('allowed') else '거부'}"
        for t in state.get("tool_trace") or []
    ]
    frontmatter = {"type": "session", "session_id": session_id, "date": date}
    body = (
        f"\n# 세션 {session_id} ({date})\n\n"
        f"## 질문\n\n{redact_text(state.get('question', ''))}\n\n"
        f"## 결론\n\n{redact_text(final_answer)}\n\n"
        f"## 도구 호출 (audit 로그 상위 요약 — 원본은 logs/)\n\n"
        + ("\n".join(trace_lines) if trace_lines else "- (도구 호출 없음 — 위키 재사용)")
        + "\n"
    )
    page.write_text(dump_page(frontmatter, body), encoding="utf-8")


def _rebuild_index(wiki_dir: Path) -> None:
    Path(wiki_dir).mkdir(parents=True, exist_ok=True)
    lines = ["# 위키 인덱스", ""]
    for section in ("namespaces", "workloads", "patterns", "sessions"):
        directory = wiki_dir / section
        pages = sorted(directory.glob("*.md")) if directory.exists() else []
        if not pages:
            continue
        lines.append(f"## {section}")
        for page in pages:
            fm, _ = parse_page(page)
            hint = fm.get("last_inspected") or fm.get("date") or ""
            lines.append(f"- [{page.stem}]({section}/{page.name}) {hint}".rstrip())
        lines.append("")
    (wiki_dir / "_index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_observations(wiki_dir: Path, observations: list[dict]) -> None:
    """관찰 목록을 레다크션 후 위키에 반영한다. (테스트에서 직접 호출 가능)"""
    for raw in observations:
        obs = redact_observation(raw)
        if not obs.get("entity"):
            continue
        if obs.get("entity_type") == "namespace":
            _apply_namespace(wiki_dir, obs)
        else:
            _apply_workload(wiki_dir, obs)
    _rebuild_index(wiki_dir)


def make_wiki_writer_node(wiki_dir: Path):
    def wiki_writer(state: dict) -> dict:
        final_answer = ""
        for message in reversed(state.get("messages") or []):
            if isinstance(message, AIMessage) and not message.tool_calls:
                final_answer = str(message.content)
                break
        if not final_answer:
            # 조사 한도(MAX_TOOL_CALLS_PER_RUN) 도달 등으로 최종 답이 없는 경우 —
            # 관찰을 버리지 않고 결정론적 요약으로 마무리한다.
            observations = state.get("observations") or []
            problems = [
                o for o in observations
                if (o.get("facts") or {}).get("waiting_reasons")
                or ((o.get("facts") or {}).get("restarts") or 0) > 0
            ]
            lines = [
                f"- `{o.get('namespace','')}/{o.get('entity','')}`: {o.get('summary','')}"
                for o in problems[:8]
            ]
            final_answer = (
                f"(조사 단계 한도 도달) 관찰 {len(observations)}건을 위키에 기록했습니다.\n\n"
                + (
                    f"한도 전까지 발견한 문제 리소스 {len(problems)}건 (상위 8건):\n"
                    + "\n".join(lines)
                    if problems
                    else "한도 전까지 문제 상태의 리소스는 발견되지 않았습니다."
                )
                + "\n\n질문을 특정 네임스페이스/워크로드로 좁혀 다시 시도해 주세요 — "
                "이번 관찰은 위키에 저장되어 재조사 없이 재사용됩니다."
            )
        write_observations(wiki_dir, state.get("observations") or [])
        _write_session_page(wiki_dir, state, final_answer)
        _rebuild_index(wiki_dir)
        return {"final_answer": final_answer}

    return wiki_writer
