"""아침 트리아지·Slack 검증 — 이슈 탐지·변경 diff·nexus-lake 섹션·SSRF 호스트잠금."""

from __future__ import annotations

import pytest

from src.morning_triage import (
    _is_lake,
    build_message,
    diff_snapshots,
    scan_cluster,
)
from src.slack_notify import SlackConfig, SlackError, load_slack_config, send_slack


class FakeK8s:
    def list_namespaces(self):
        return [{"name": "nexus-shell"}, {"name": "default"}]

    def list_pods(self, ns):
        if ns == "nexus-shell":
            return [{
                "name": "bronze-ingestor-abc", "phase": "Running",
                "containers": [{"name": "bronze-ingestor", "restart_count": 0,
                                "state": {"waiting": "CrashLoopBackOff", "message": "boom"}}],
            }]
        return [{"name": "web-1", "phase": "Pending",
                 "containers": [{"name": "web", "restart_count": 0, "state": {}}]}]

    def list_deployments(self, ns):
        if ns == "nexus-shell":
            return [{"name": "trino", "images": ["trinodb/trino:440"],
                     "replicas": {"desired": 1, "ready": 1}}]
        return [{"name": "web", "images": ["web:v1"], "replicas": {"desired": 2, "ready": 1}}]

    def list_events(self, ns, field_selector=""):
        return [{"type": "Warning", "reason": "FailedScheduling",
                 "involved_object": "pod/web-1", "message": "no nodes"}]


def test_scan_detects_issues_and_builds_snapshot():
    r = scan_cluster(FakeK8s())
    kinds = {i["kind"] for i in r["issues"]}
    assert "CrashLoopBackOff" in kinds          # 컨테이너 waiting
    assert any("phase=Pending" in k for k in kinds)
    assert any("event:FailedScheduling" in k for k in kinds)
    assert any("레플리카 미충족" in k for k in kinds)
    assert "nexus-shell/trino" in r["snapshot"]  # 배포 스냅샷


def test_first_run_diff_is_baseline_only():
    cur = {"ns/a": {"image": "x:1", "desired": 1}}
    assert diff_snapshots({}, cur) == []          # 첫 실행은 변경 보고 안 함


def test_diff_detects_image_and_replica_changes():
    prev = {"ns/a": {"image": "x:1", "desired": 2}, "ns/gone": {"image": "y:1", "desired": 1}}
    cur = {"ns/a": {"image": "x:2", "desired": 1}, "ns/new": {"image": "z:1", "desired": 1}}
    ch = diff_snapshots(prev, cur)
    kinds = {c["kind"] for c in ch}
    assert "이미지 변경" in kinds and "replica 변경" in kinds
    assert "신규 배포" in kinds and "배포 삭제" in kinds


def test_lake_section_appears_for_lake_workloads():
    per_ctx = {"aws-seoul-clouddev": {
        "issues": [{"sev": "high", "ns": "nexus-shell", "obj": "pod/bronze-ingestor-x",
                    "kind": "CrashLoopBackOff", "detail": "boom"}],
        "changes": [{"obj": "nexus-shell/trino", "kind": "이미지 변경", "detail": "440 → 441"}],
    }}
    msg = build_message(per_ctx, "2026-08-19")
    assert "📦 nexus-lake" in msg
    assert "bronze-ingestor" in msg and "trino" in msg


def test_is_lake_keywords():
    assert _is_lake("nexus-shell/pod/bronze-ingestor-x")
    assert _is_lake("nexus-shell/trino")
    assert not _is_lake("default/pod/web-1")


# ---- Slack ----

class FakeHttp:
    def __init__(self, status=200, text="ok", payload=None):
        self.status = status; self.text_ = text; self.payload = payload; self.posts = []

    def post(self, url, json=None, headers=None):
        self.posts.append((url, json, headers))
        payload = self.payload
        text = self.text_
        status = self.status

        class R:
            status_code = status
            text = ""
            headers = {"content-type": "application/json"} if payload else {}

            def json(self):
                return payload
        r = R(); r.text = text
        return r

    def close(self): pass


def test_slack_webhook_send():
    fake = FakeHttp(200, "ok")
    cfg = SlackConfig(webhook_url="https://hooks.slack.com/services/T/B/x")
    res = send_slack(cfg, "hi", client=fake)
    assert res["ok"] and res["mode"] == "webhook"
    assert fake.posts[0][0].startswith("https://hooks.slack.com/")


def test_slack_rejects_non_slack_host():
    cfg = SlackConfig(webhook_url="https://evil.com/hook")
    with pytest.raises(SlackError, match="호스트"):
        send_slack(cfg, "hi", client=FakeHttp())


def test_slack_bot_mode():
    fake = FakeHttp(200, "", payload={"ok": True, "ts": "1.2"})
    cfg = SlackConfig(bot_token="xoxb-x", dm_channel="U123")
    res = send_slack(cfg, "hi", client=fake)
    assert res["mode"] == "bot"
    assert fake.posts[0][0] == "https://slack.com/api/chat.postMessage"
    assert fake.posts[0][2]["Authorization"] == "Bearer xoxb-x"


def test_slack_config_masks_and_loads():
    assert load_slack_config({}) is None
    cfg = load_slack_config({"SLACK_WEBHOOK_URL": "https://hooks.slack.com/x"})
    assert cfg and cfg.mode() == "webhook"
    assert "hooks.slack.com" not in repr(cfg)  # URL(시크릿) 미노출
