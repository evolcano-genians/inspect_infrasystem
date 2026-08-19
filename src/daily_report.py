"""일일 대화 요약 → Confluence 비공개 게시 (에이전트 크론).

하루 동안 이 프로젝트에서 오간 질문/답변(devlog)을 LLM으로 요약해, Atlassian Confluence의
**개인 스페이스(비공개)**에 매일 문서로 올린다. 프로젝트별로 그룹핑해 정리한다.

설계:
- 데이터: logs/devlog.jsonl 의 오늘(로컬 타임존) 'turn' 레코드. 질문·답변은 이미 레다크션됨.
- 프로젝트: SessionStore(sessions.sqlite)의 thread_id→project 매핑으로 묶는다.
- 요약: reflect_model(Codex) 로 하루 활동을 프로젝트별 불릿으로 압축.
- 게시: Confluence 개인 스페이스에 하루 1건. **같은 날 재실행하면 새 문서를 만들지 않고
  기존 문서를 갱신**한다(idempotent). 개인 스페이스는 기본 비공개다.

구동:
- CLI: `python -m src.daily_report` (OS cron 으로 매일 15:50 실행 — scripts/install-daily-cron.sh)
- 옵션: `--dry-run`(게시 없이 본문만 출력), `--date YYYY-MM-DD`(특정 날짜).
"""

from __future__ import annotations

import argparse
import base64
import html
import json
import sys
from datetime import datetime
from pathlib import Path


def _local_date_str(dt_iso: str) -> str:
    """UTC ISO 타임스탬프를 로컬 날짜(YYYY-MM-DD)로."""
    try:
        dt = datetime.fromisoformat(dt_iso.replace("Z", "+00:00"))
        return dt.astimezone().strftime("%Y-%m-%d")
    except Exception:
        return ""


def collect_turns(devlog_path: Path, day: str) -> list[dict]:
    """지정 날짜(로컬)의 turn 레코드만 모은다."""
    if not devlog_path.exists():
        return []
    out = []
    for line in devlog_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("type") == "turn" and _local_date_str(e.get("timestamp", "")) == day:
            out.append(e)
    return out


def group_by_project(turns: list[dict], sessions) -> dict[str, list[dict]]:
    """thread_id → 프로젝트명으로 턴을 묶는다. 프로젝트 없으면 '(미분류)'."""
    proj_of = {}
    try:
        pid_name = {p.id: p.name for p in sessions.list_projects()}
        for s in sessions.list():
            proj_of[s.thread_id] = pid_name.get(s.project_id, "(미분류)")
    except Exception:
        pass
    groups: dict[str, list[dict]] = {}
    for t in turns:
        name = proj_of.get(t.get("thread_id"), "(미분류)")
        groups.setdefault(name, []).append(t)
    return groups


_SUMMARY_SYSTEM = """당신은 하루치 작업을 **다음 날 그대로 이어갈 수 있게** 정리하는 인계(handoff)
서기다. 아래는 오늘 이 프로젝트에서 오간 질문과 답변 기록이다. 목적은 '어제 뭘 하다 말았는지,
무엇부터 다시 시작해야 하는지'를 빠르게 복귀하는 것이다. 아래 구조로 한국어 마크다운만 써라:

## ⏭️ 내일 이어서 할 일
- (가장 먼저 손댈 것부터. 각 항목은 '무엇을 → 어떻게/어디서'가 드러나게. 구체적 명령·경로·
  대상이 있으면 포함. 이게 이 문서에서 제일 중요하다.)

## 🚧 진행 중 / 미해결
- (끝나지 않은 조사·막힌 지점. 왜 막혔는지 한 줄. 재현·확인에 필요한 정보도.)

## ✅ 오늘 확정한 사실·결정
- (다시 조사하지 않도록 오늘 확인한 결론·수치·결정. 프로젝트별로 묶어라.)

규칙: 사소한 반복은 합치고, 추측은 사실처럼 쓰지 마라. 비밀값·토큰·비밀번호는 절대 옮기지 마라.
내용이 적으면 섹션을 비워도 된다(빈 섹션은 생략)."""


def summarize(model, groups: dict[str, list[dict]], day: str) -> str:
    """LLM으로 프로젝트별 요약 마크다운을 만든다. 모델이 없으면 결정론적 목록으로 폴백."""
    # LLM 입력: 프로젝트별 질문/답변(길이 절제)
    parts = [f"# {day} 대화 기록"]
    for proj, turns in groups.items():
        parts.append(f"\n## 프로젝트: {proj} ({len(turns)}건)")
        for t in turns:
            q = (t.get("question") or "").strip().replace("\n", " ")[:300]
            a = (t.get("answer") or "").strip().replace("\n", " ")[:600]
            parts.append(f"- Q: {q}\n  A: {a}")
    raw = "\n".join(parts)[:40_000]

    if model is None:
        return raw  # 폴백: 원문 목록
    try:
        from langchain_core.messages import HumanMessage, SystemMessage

        resp = model.invoke([SystemMessage(content=_SUMMARY_SYSTEM), HumanMessage(content=raw)])
        text = str(getattr(resp, "content", "") or "").strip()
        return text or raw
    except Exception as exc:
        return raw + f"\n\n(요약 실패, 원문 표시: {type(exc).__name__})"


def _md_to_storage(md: str) -> str:
    """아주 단순한 마크다운 → Confluence storage(XHTML) 변환(제목·불릿·문단)."""
    lines = md.splitlines()
    out: list[str] = []
    in_ul = False

    def close_ul():
        nonlocal in_ul
        if in_ul:
            out.append("</ul>")
            in_ul = False

    for ln in lines:
        s = ln.rstrip()
        if not s.strip():
            close_ul()
            continue
        m = None
        for lvl in (3, 2, 1):
            if s.startswith("#" * lvl + " "):
                m = (lvl, s[lvl + 1:]); break
        if m:
            close_ul()
            out.append(f"<h{m[0]}>{html.escape(m[1])}</h{m[0]}>")
        elif s.lstrip().startswith(("- ", "* ")):
            if not in_ul:
                out.append("<ul>"); in_ul = True
            out.append(f"<li>{_inline(s.lstrip()[2:])}</li>")
        else:
            close_ul()
            out.append(f"<p>{_inline(s)}</p>")
    close_ul()
    return "".join(out)


def _inline(text: str) -> str:
    import re
    s = html.escape(text)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    return s


def _auth_header(user: str, token: str) -> dict:
    a = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
    return {"Authorization": a, "Accept": "application/json", "Content-Type": "application/json"}


def ensure_folder(base_url: str, user: str, token: str, space_key: str, folder_title: str,
                  *, verify_tls: bool = True) -> str:
    """개인 스페이스에 전용 부모 페이지(폴더)를 보장하고 그 id를 반환한다. 없으면 생성."""
    import httpx

    H = _auth_header(user, token)
    with httpx.Client(timeout=30, verify=verify_tls) as c:
        found = c.get(f"{base_url}/wiki/rest/api/content", headers=H,
                      params={"spaceKey": space_key, "title": folder_title})
        res = (found.json().get("results") or []) if found.status_code == 200 else []
        if res:
            return res[0]["id"]
        intro = ("<p>inspect-k8s 하네스가 매일 자동으로 올리는 <strong>작업 복귀용 일일 요약</strong> "
                 "모음입니다. 이 개인 스페이스는 비공개이며 본인만 볼 수 있습니다.</p>")
        r = c.post(f"{base_url}/wiki/rest/api/content", headers=H, json={
            "type": "page", "title": folder_title, "space": {"key": space_key},
            "body": {"storage": {"value": intro, "representation": "storage"}},
        })
        if r.status_code not in (200, 201):
            raise RuntimeError(f"폴더 생성 실패 status={r.status_code}: {r.text[:200]}")
        return r.json()["id"]


def publish(base_url: str, user: str, token: str, space_key: str, title: str,
            storage_html: str, *, parent_id: str = "", verify_tls: bool = True) -> dict:
    """개인 스페이스(전용 폴더 하위)에 하루 1건 게시(있으면 갱신). 반환: {url, action}."""
    import httpx

    H = _auth_header(user, token)
    with httpx.Client(timeout=40, verify=verify_tls) as c:
        # 같은 제목의 문서가 이미 있으면 갱신(버전+1)
        found = c.get(f"{base_url}/wiki/rest/api/content",
                      headers=H, params={"spaceKey": space_key, "title": title,
                                         "expand": "version"})
        existing = (found.json().get("results") or []) if found.status_code == 200 else []
        body = {"storage": {"value": storage_html, "representation": "storage"}}
        if existing:
            page = existing[0]
            ver = (page.get("version") or {}).get("number", 1) + 1
            payload = {"id": page["id"], "type": "page", "title": title,
                       "space": {"key": space_key}, "version": {"number": ver}, "body": body}
            if parent_id:
                payload["ancestors"] = [{"id": parent_id}]
            r = c.put(f"{base_url}/wiki/rest/api/content/{page['id']}", headers=H, json=payload)
            action = "updated"
        else:
            payload = {"type": "page", "title": title, "space": {"key": space_key}, "body": body}
            if parent_id:
                payload["ancestors"] = [{"id": parent_id}]
            r = c.post(f"{base_url}/wiki/rest/api/content", headers=H, json=payload)
            action = "created"
        if r.status_code not in (200, 201):
            raise RuntimeError(f"게시 실패 status={r.status_code}: {r.text[:300]}")
        d = r.json()
        return {"url": base_url + "/wiki" + (d.get("_links") or {}).get("webui", ""),
                "action": action, "title": d.get("title", title)}


def _personal_space_key(base_url: str, user: str, token: str, verify_tls: bool = True) -> str:
    import httpx

    auth = "Basic " + base64.b64encode(f"{user}:{token}".encode()).decode()
    with httpx.Client(timeout=25, verify=verify_tls) as c:
        me = c.get(f"{base_url}/wiki/rest/api/user/current",
                   headers={"Authorization": auth, "Accept": "application/json"}).json()
    aid = me.get("accountId", "")
    return "~" + aid.replace(":", "").replace("-", "")


def run(*, day: str | None = None, dry_run: bool = False) -> dict:
    from .config import load_settings
    from .sessions import SessionStore

    settings = load_settings()
    day = day or datetime.now().astimezone().strftime("%Y-%m-%d")

    turns = collect_turns(settings.logs_dir / "devlog.jsonl", day)
    if not turns:
        return {"ok": True, "skipped": True, "reason": f"{day} 대화 기록 없음"}

    sessions = SessionStore(settings.checkpoint_db.parent / "sessions.sqlite")
    groups = group_by_project(turns, sessions)

    # 요약 모델 (codex-oauth일 때만; 아니면 원문 폴백)
    model = None
    if settings.model_provider == "codex-oauth":
        try:
            from .llm import make_codex_model
            model = make_codex_model(settings.codex_model, settings.codex_reasoning_effort)
        except Exception:
            model = None

    summary_md = summarize(model, groups, day)
    header = (f"> 🤖 inspect-k8s 일일 자동 요약 · {day} · 대화 {len(turns)}건 / "
              f"프로젝트 {len(groups)}개 · 생성 {datetime.now().astimezone().strftime('%H:%M')}\n\n")
    storage = _md_to_storage(header + summary_md)
    title = f"[일일요약] inspect-k8s {day}"

    if dry_run:
        print(header + summary_md)
        return {"ok": True, "dry_run": True, "turns": len(turns), "projects": len(groups)}

    # Confluence 자격증명 (Jira 와 공유; 정규 도메인 필수)
    base = settings.jira_base_url or "https://geni-works.atlassian.net"
    if base.rstrip("/").endswith("/wiki"):
        base = base.rstrip("/")[:-5]
    user, token = settings.jira_user, settings.jira_token
    if not (user and token):
        return {"ok": False, "error": "JIRA_USER/JIRA_TOKEN(Confluence 공유)이 필요합니다"}

    space = _personal_space_key(base, user, token, settings.jira_verify_tls)
    # 전용 폴더(부모 페이지) 하위에 넣어 워크스페이스를 깔끔하게 유지 (개인 스페이스라 비공개)
    folder_id = ensure_folder(base, user, token, space, "inspect-k8s 일일요약",
                              verify_tls=settings.jira_verify_tls)
    res = publish(base, user, token, space, title, storage,
                  parent_id=folder_id, verify_tls=settings.jira_verify_tls)
    return {"ok": True, "turns": len(turns), "projects": len(groups), "folder_id": folder_id, **res}


def main() -> int:
    ap = argparse.ArgumentParser(description="일일 대화 요약 → Confluence 비공개 게시")
    ap.add_argument("--date", help="YYYY-MM-DD (기본: 오늘, 로컬)")
    ap.add_argument("--dry-run", action="store_true", help="게시하지 않고 본문만 출력")
    args = ap.parse_args()
    res = run(day=args.date, dry_run=args.dry_run)
    print(f"[daily_report] {json.dumps(res, ensure_ascii=False)}")
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
