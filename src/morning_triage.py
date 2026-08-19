"""아침 클러스터 트리아지 — AWS/Azure를 read-only로 점검해 '확인해야 할 이슈'를 Slack DM으로.

매일 아침, Botkube가 채널에 흘리는 이슈(CrashLoopBackOff·readiness 실패·시크릿 없음·스케줄
불가 등)와 전날 대비 변경(이미지 태그·레플리카)을 한 번에 정리해 개인 Slack DM으로 받는다.

동작:
1. 두 클러스터(aws-seoul-clouddev / azure-uae-gsp)를 read-only 조회(GET만) — 기존 4중 방어선 적용.
2. 이슈를 **결정론적으로 탐지**: 파드 phase/컨테이너 상태(CrashLoop·ImagePull·not-ready·재시작
   폭증), 최근 Warning 이벤트(FailedScheduling·FailedMount·Unhealthy 등).
3. 전날 스냅샷과 비교해 배포 **변경**(이미지 태그·replica) 감지. 스냅샷은 .local/triage-snapshots/.
4. (codex-oauth면) Codex로 '오늘 먼저 볼 것' 우선순위 요약을 덧붙인다.
5. Slack DM 전송.

구동: launchd/cron 07:30 (scripts/install-triage-cron.sh). 요약은 Mac(Codex·kubeconfig)에서 수행.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

_CONTEXTS = ("aws-seoul-clouddev", "azure-uae-gsp")
# 정상으로 보지 않는 컨테이너 waiting/terminated 사유
_BAD_WAITING = ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull", "CreateContainerConfigError",
                "CreateContainerError", "InvalidImageName", "RunContainerError")
_WARN_KEYWORDS = ("Failed", "Unhealthy", "BackOff", "Error", "Evicted", "OOMKilling",
                  "FailedScheduling", "FailedMount", "NotFound")
_RESTART_ALERT = 5  # 재시작 이 이상이면 경고
# nexus-lake(데이터레이크하우스) 관련 워크로드 판별 키워드 — 이슈·변경을 전용 섹션으로 뽑는다.
_LAKE_KEYWORDS = ("trino", "bronze", "silver", "gold", "hive", "metastore", "spark",
                  "registry", "lake", "kafka", "delta", "minio", "fuseki")


def _is_lake(obj: str) -> bool:
    o = (obj or "").lower()
    return any(k in o for k in _LAKE_KEYWORDS)


def _safe(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Exception as exc:  # 권한 없음/일시 오류는 항목별로 흡수
        return {"_error": f"{type(exc).__name__}: {str(exc)[:80]}"}


def scan_cluster(client) -> dict:
    """한 클러스터를 read-only 점검해 이슈·현재 스냅샷을 만든다."""
    issues: list[dict] = []
    snapshot: dict[str, dict] = {}   # "ns/name" -> {image, replicas}
    rollouts: list[dict] = []        # 롤아웃 진행 중인 배포

    nss = _safe(client.list_namespaces)
    ns_names = [n.get("name") for n in nss] if isinstance(nss, list) else []

    for ns in ns_names:
        pods = _safe(client.list_pods, ns)
        if isinstance(pods, list):
            for p in pods:
                name = p.get("name", "")
                phase = p.get("phase", "")
                for c in p.get("containers", []):
                    st = c.get("state") or {}
                    waiting = st.get("waiting")
                    if waiting in _BAD_WAITING:
                        issues.append({"sev": "high", "ns": ns, "obj": f"pod/{name}",
                                       "kind": waiting,
                                       "detail": (st.get("message") or "").strip()[:200]})
                    elif c.get("restart_count", 0) >= _RESTART_ALERT:
                        issues.append({"sev": "med", "ns": ns, "obj": f"pod/{name}",
                                       "kind": "재시작 폭증",
                                       "detail": f"{c['name']} restarts={c['restart_count']}"})
                if phase in ("Pending", "Failed", "Unknown"):
                    issues.append({"sev": "high" if phase == "Failed" else "med",
                                   "ns": ns, "obj": f"pod/{name}", "kind": f"phase={phase}",
                                   "detail": ""})

        deps = _safe(client.list_deployments, ns)
        if isinstance(deps, list):
            for d in deps:
                name = d.get("name")
                key = f"{ns}/{name}"
                img = (d.get("images") or [""])[0] if d.get("images") else d.get("image", "")
                rep = d.get("replicas") or {}
                snapshot[key] = {"image": img,
                                 "desired": rep.get("desired") if isinstance(rep, dict) else rep}
                if isinstance(rep, dict) and rep.get("desired"):
                    des = rep["desired"]
                    upd = rep.get("updated", des)
                    avail = rep.get("available", des)
                    ready = rep.get("ready", des)
                    # 롤아웃 진행 중: 새 버전이 아직 전부 안 올라옴(updated<desired) 또는 가용 부족
                    if upd < des or avail < des:
                        reason = ""
                        for c in (d.get("conditions") or []):
                            if c.get("type") == "Progressing":
                                reason = c.get("reason", "")
                        rollouts.append({"ns": ns, "name": name,
                                         "updated": upd, "desired": des, "available": avail,
                                         "reason": reason})
                    if ready is not None and ready < des:
                        issues.append({"sev": "med", "ns": ns, "obj": f"deploy/{name}",
                                       "kind": "레플리카 미충족",
                                       "detail": f"ready {ready}/{des}"})

        events = _safe(client.list_events, ns)
        if isinstance(events, list):
            for e in events:
                etype = e.get("type", "")
                reason = e.get("reason", "")
                if etype == "Warning" and any(k in reason for k in _WARN_KEYWORDS):
                    issues.append({"sev": "med", "ns": ns,
                                   "obj": e.get("involved_object") or e.get("object") or reason,
                                   "kind": f"event:{reason}",
                                   "detail": (e.get("message") or "").strip()[:200]})

    return {"issues": issues, "snapshot": snapshot, "rollouts": rollouts,
            "namespaces": len(ns_names)}


def diff_snapshots(prev: dict, cur: dict) -> list[dict]:
    """전날 대비 배포 변경(이미지·replica)을 찾는다.

    첫 실행(prev 비어 있음)은 기준선만 세우고 변경을 보고하지 않는다 — 전체가 '신규'로
    잡혀 노이즈가 되기 때문. 다음 실행부터 실제 변경만 보고한다.
    """
    if not prev:
        return []
    changes = []
    for key, now in cur.items():
        old = prev.get(key)
        if old is None:
            changes.append({"obj": key, "kind": "신규 배포", "detail": now.get("image", "")})
            continue
        if old.get("image") != now.get("image"):
            def _tag(i): return i.rsplit(":", 1)[-1] if ":" in (i or "") else "-"
            changes.append({"obj": key, "kind": "이미지 변경",
                            "detail": f"{_tag(old.get('image'))} → {_tag(now.get('image'))}"})
        if old.get("desired") != now.get("desired"):
            changes.append({"obj": key, "kind": "replica 변경",
                            "detail": f"{old.get('desired')} → {now.get('desired')}"})
    for key in prev:
        if key not in cur:
            changes.append({"obj": key, "kind": "배포 삭제", "detail": ""})
    return changes


def scan_lake_data(settings, snap_dir: Path) -> list[dict]:
    """(옵션) Trino가 설정돼 있으면 nexus-lake 테이블 행수 변화를 감지한다.

    TRINO_ENDPOINT 미설정이거나 접근 불가면 조용히 빈 목록 — k8s 워크로드 변경은 이미
    _lake_section 이 보고하므로, 이 함수는 '데이터가 실제로 얼마나 바뀌었나'를 더한다.
    """
    if not getattr(settings, "trino_endpoint", ""):
        return []
    try:
        from .tools.trino_reader import TrinoClient, TrinoConfig
        cfg = TrinoConfig(endpoint=settings.trino_endpoint, user=settings.trino_user,
                          token=settings.trino_token, catalog=settings.trino_catalog,
                          schema=settings.trino_schema)
        client = TrinoClient(cfg)
        cat = settings.trino_catalog or "delta"
        sch = settings.trino_schema or "silver"
        tables = client.query(f"SHOW TABLES FROM {cat}.{sch}", max_rows=200)
        cur: dict[str, int] = {}
        for row in tables.get("rows", []):
            t = row[0]
            try:
                c = client.query(f"SELECT COUNT(*) FROM {cat}.{sch}.{t}", max_rows=1)
                cur[t] = int(c["rows"][0][0])
            except Exception:
                continue
    except Exception:
        return []

    snap_path = snap_dir / "trino-rowcounts.json"
    prev = _load_snapshot(snap_path)
    snap_path.write_text(json.dumps(cur, ensure_ascii=False), encoding="utf-8")
    if not prev:
        return []  # 첫 실행: 기준선만
    out = []
    for t, n in cur.items():
        if t not in prev:
            out.append(f"신규 테이블 `{t}` ({n:,}행)")
        elif prev[t] != n:
            out.append(f"`{t}` {prev[t]:,} → {n:,}행 ({n - prev[t]:+,})")
    for t in prev:
        if t not in cur:
            out.append(f"테이블 사라짐 `{t}`")
    return out


def _load_snapshot(path: Path) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def _sev_icon(sev: str) -> str:
    return {"high": "🔴", "med": "🟡"}.get(sev, "⚪")


def _lake_section(per_ctx: dict, lake_data: list[dict]) -> list[str]:
    """nexus-lake 전용 섹션 — 레이크하우스 워크로드 이슈·변경 + (있으면) 데이터 변경."""
    lines: list[str] = []
    lake_issues, lake_changes = [], []
    for ctx, r in per_ctx.items():
        for it in r.get("issues", []):
            if _is_lake(f"{it['ns']}/{it['obj']}"):
                lake_issues.append((ctx, it))
        for ch in r.get("changes", []):
            if _is_lake(ch["obj"]):
                lake_changes.append((ctx, ch))
    if not (lake_issues or lake_changes or lake_data):
        return lines
    lines.append(f"\n*📦 nexus-lake* — 이슈 {len(lake_issues)} · 워크로드 변경 {len(lake_changes)}"
                 + (f" · 데이터 변경 {len(lake_data)}" if lake_data else ""))
    for ctx, it in lake_issues[:8]:
        d = f" — {it['detail']}" if it.get("detail") else ""
        lines.append(f"  {_sev_icon(it['sev'])} [{ctx[:3]}] `{it['ns']}/{it['obj']}` {it['kind']}{d}")
    for ctx, ch in lake_changes[:8]:
        lines.append(f"  🔄 [{ctx[:3]}] `{ch['obj']}` {ch['kind']} {ch['detail']}")
    for dch in lake_data[:12]:
        lines.append(f"  📊 {dch}")
    return lines


def _rollout_section(per_ctx: dict) -> list[str]:
    """shell-app 롤아웃(진행 중) + 업데이트된 앱(이미지 변경) 섹션."""
    lines: list[str] = []
    rollouts, updates = [], []
    for ctx, r in per_ctx.items():
        for ro in r.get("rollouts", []):
            rollouts.append((ctx, ro))
        for ch in r.get("changes", []):
            if ch["kind"] in ("이미지 변경", "신규 배포"):
                updates.append((ctx, ch))
    if not (rollouts or updates):
        return lines
    lines.append(f"\n*🚀 shell-app 업데이트·롤아웃* — 업데이트 {len(updates)} · 진행중 {len(rollouts)}")
    for ctx, ch in updates[:12]:
        label = "신규" if ch["kind"] == "신규 배포" else "업데이트"
        lines.append(f"  ⬆️ [{ctx[:3]}] `{ch['obj']}` {label} {ch['detail']}")
    if len(updates) > 12:
        lines.append(f"  … 업데이트 외 {len(updates) - 12}건")
    for ctx, ro in rollouts[:12]:
        rs = f" ({ro['reason']})" if ro.get("reason") else ""
        lines.append(f"  🔁 [{ctx[:3]}] `{ro['ns']}/{ro['name']}` 롤아웃 진행 "
                     f"updated {ro['updated']}/{ro['desired']}, avail {ro['available']}{rs}")
    if len(rollouts) > 12:
        lines.append(f"  … 진행중 외 {len(rollouts) - 12}건")
    return lines


def build_message(per_ctx: dict, day: str, lake_data: list[dict] | None = None) -> str:
    """Slack용 텍스트를 만든다(이슈·변경 요약)."""
    lines = [f"*🌅 dev k8s 아침 트리아지 · {day}*"]
    total_issues = sum(len(v["issues"]) for v in per_ctx.values())
    if total_issues == 0:
        lines.append("✅ 확인이 필요한 이슈가 없습니다.")
    # shell-app 업데이트·롤아웃 (사용자 요청) → nexus-lake 순으로 맨 위에
    lines += _rollout_section(per_ctx)
    lines += _lake_section(per_ctx, lake_data or [])
    for ctx, r in per_ctx.items():
        issues = r["issues"]
        changes = r.get("changes", [])
        head = f"\n*{ctx}* — 이슈 {len(issues)} · 변경 {len(changes)}"
        lines.append(head)
        # 심각도·유형별로 묶어 상위 12개만
        for it in sorted(issues, key=lambda x: 0 if x["sev"] == "high" else 1)[:12]:
            d = f" — {it['detail']}" if it.get("detail") else ""
            lines.append(f"  {_sev_icon(it['sev'])} `{it['ns']}/{it['obj']}` {it['kind']}{d}")
        if len(issues) > 12:
            lines.append(f"  … 외 {len(issues) - 12}건")
        for ch in changes[:10]:
            lines.append(f"  🔄 `{ch['obj']}` {ch['kind']} {ch['detail']}")
        if len(changes) > 10:
            lines.append(f"  … 변경 외 {len(changes) - 10}건")
    return "\n".join(lines)


_SUMMARY_SYSTEM = """당신은 dev k8s 운영 조력자다. 아래는 오늘 아침 두 클러스터에서 자동 탐지된
이슈·변경·앱 업데이트/롤아웃 목록이다. **오늘 사람이 먼저 확인·조치해야 할 것**을 우선순위로
3~6줄 한국어 불릿으로 정리하라. 같은 근본원인(예: 한 노드/AZ 문제로 여러 파드 Pending)은 묶고,
새로 업데이트된 shell-app이나 진행 중인 롤아웃이 있으면 '정상 완료됐는지 확인'을 한 줄 넣어라.
추측은 표시하고, 비밀값은 옮기지 마라. 마크다운 없이 Slack 평문(불릿은 •)으로."""


def summarize_priority(model, message: str) -> str:
    if model is None:
        return ""
    try:
        from langchain_core.messages import HumanMessage, SystemMessage
        resp = model.invoke([SystemMessage(content=_SUMMARY_SYSTEM), HumanMessage(content=message[:12000])])
        return str(getattr(resp, "content", "") or "").strip()
    except Exception:
        return ""


def run(*, dry_run: bool = False) -> dict:
    from .config import assert_safe_kubeconfig, load_settings
    from .slack_notify import SlackError, load_slack_config, send_slack
    from .tools.k8s_read import ReadOnlyK8sClient

    settings = load_settings()
    day = datetime.now().astimezone().strftime("%Y-%m-%d")
    snap_dir = settings.checkpoint_db.parent / "triage-snapshots"
    snap_dir.mkdir(parents=True, exist_ok=True)

    per_ctx: dict[str, dict] = {}
    for ctx in _CONTEXTS:
        try:
            assert_safe_kubeconfig(settings.kubeconfig, context=ctx, allow_real=True)
            client = ReadOnlyK8sClient(settings.kubeconfig, context=ctx)
            r = scan_cluster(client)
        except Exception as exc:
            per_ctx[ctx] = {"issues": [], "changes": [], "error": f"{type(exc).__name__}: {exc}"}
            continue
        snap_path = snap_dir / f"{ctx}.json"
        r["changes"] = diff_snapshots(_load_snapshot(snap_path), r["snapshot"])
        snap_path.write_text(json.dumps(r["snapshot"], ensure_ascii=False), encoding="utf-8")
        per_ctx[ctx] = r

    lake_data = scan_lake_data(settings, snap_dir)  # (옵션) Trino 데이터 변경
    message = build_message(per_ctx, day, lake_data)

    # Codex 우선순위 요약(가능하면)
    model = None
    if settings.model_provider == "codex-oauth":
        try:
            from .llm import make_codex_model
            model = make_codex_model(settings.codex_model, settings.codex_reasoning_effort)
        except Exception:
            model = None
    priority = summarize_priority(model, message)
    full = (("*⏱ 우선 확인*\n" + priority + "\n\n") if priority else "") + message

    if dry_run:
        print(full)
        return {"ok": True, "dry_run": True,
                "issues": sum(len(v["issues"]) for v in per_ctx.values())}

    slack = load_slack_config(_env_dict(settings))
    if slack is None:
        return {"ok": False, "error": "Slack 미설정 — SLACK_WEBHOOK_URL 을 설정하세요"}
    try:
        res = send_slack(slack, full)
    except SlackError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "issues": sum(len(v["issues"]) for v in per_ctx.values()),
            "changes": sum(len(v.get("changes", [])) for v in per_ctx.values()), **res}


def _env_dict(settings) -> dict:
    import os

    from .settings_store import read_env_file
    return {**os.environ, **read_env_file(settings.agents_dir.parent / ".env")}


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="아침 k8s 트리아지 → Slack DM")
    ap.add_argument("--dry-run", action="store_true", help="Slack 전송 없이 본문 출력")
    args = ap.parse_args()
    res = run(dry_run=args.dry_run)
    print(f"[morning_triage] {json.dumps(res, ensure_ascii=False)}")
    return 0 if res.get("ok") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
