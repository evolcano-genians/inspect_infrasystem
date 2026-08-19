"""Slack 알림 전송 — 개인 DM으로 트리아지 결과를 보낸다.

두 방식 지원(둘 중 하나만 설정하면 됨):
1. **Incoming Webhook** (권장·가장 간단): SLACK_WEBHOOK_URL 하나만 있으면 된다. Slack 앱에서
   웹훅 생성 시 대상으로 본인 DM을 고르면 개인 메시지로 온다. 스코프 설정 불필요.
2. **Bot token**: SLACK_BOT_TOKEN(xoxb-) + SLACK_DM_CHANNEL(본인 멤버 ID U…). chat:write 필요.

안전:
- 호스트 잠금: hooks.slack.com / slack.com 으로만 POST. 그 외 URL은 거부한다(자격증명 오유출 방지).
- 자격증명은 .env / 전역 파일에서만 읽고 마스킹한다. dev k8s 에는 절대 넣지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

_ALLOWED_HOSTS = {"hooks.slack.com", "slack.com", "www.slack.com"}
_TIMEOUT = 20


class SlackError(RuntimeError):
    pass


@dataclass
class SlackConfig:
    webhook_url: str = ""
    bot_token: str = ""
    dm_channel: str = ""   # bot 방식일 때 대상(본인 U… 멤버 ID)

    def mode(self) -> str:
        if self.webhook_url:
            return "webhook"
        if self.bot_token and self.dm_channel:
            return "bot"
        return "none"

    def __repr__(self) -> str:  # 자격증명 유출 방지
        return f"SlackConfig(mode={self.mode()})"


def load_slack_config(env: dict) -> SlackConfig | None:
    cfg = SlackConfig(
        webhook_url=(env.get("SLACK_WEBHOOK_URL") or "").strip(),
        bot_token=(env.get("SLACK_BOT_TOKEN") or "").strip(),
        dm_channel=(env.get("SLACK_DM_CHANNEL") or "").strip(),
    )
    return cfg if cfg.mode() != "none" else None


def _check_host(url: str) -> None:
    host = urlparse(url).hostname or ""
    if host not in _ALLOWED_HOSTS:
        raise SlackError(f"허용되지 않은 Slack 호스트: {host!r}")


def send_slack(cfg: SlackConfig, text: str, *, blocks: list | None = None,
               client=None) -> dict:
    """Slack으로 메시지를 보낸다. 반환: {ok, mode}. client는 테스트 주입용."""
    import httpx

    mode = cfg.mode()
    if mode == "none":
        raise SlackError("SLACK_WEBHOOK_URL 또는 SLACK_BOT_TOKEN+SLACK_DM_CHANNEL 가 필요합니다")

    owns = client is None
    if owns:
        client = httpx.Client(timeout=_TIMEOUT)
    try:
        if mode == "webhook":
            _check_host(cfg.webhook_url)
            payload = {"text": text}
            if blocks:
                payload["blocks"] = blocks
            r = client.post(cfg.webhook_url, json=payload)
            if r.status_code != 200 or (r.text or "").strip() not in ("ok", ""):
                raise SlackError(f"웹훅 전송 실패 status={r.status_code}: {(r.text or '')[:200]}")
            return {"ok": True, "mode": "webhook"}
        # bot token
        url = "https://slack.com/api/chat.postMessage"
        _check_host(url)
        payload = {"channel": cfg.dm_channel, "text": text}
        if blocks:
            payload["blocks"] = blocks
        r = client.post(url, json=payload,
                        headers={"Authorization": f"Bearer {cfg.bot_token}"})
        data = r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
        if not data.get("ok"):
            raise SlackError(f"chat.postMessage 실패: {data.get('error', r.status_code)}")
        return {"ok": True, "mode": "bot", "ts": data.get("ts")}
    finally:
        if owns:
            client.close()
