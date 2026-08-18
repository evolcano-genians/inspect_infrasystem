#!/usr/bin/env python3
"""codex CLI 세션(~/.codex/auth.json)을 langchain-codex-oauth 자격증명 저장소로 이식한다.

브리프 0.1의 "이미 로그인된 Codex 세션의 OAuth 인증을 그대로 재사용" 요구를 구현한다 —
`langchain-codex-oauth auth login`(대화형 브라우저 로그인) 없이, codex CLI가 이미 보유한
액세스/리프레시 토큰을 어댑터 포맷(~/.langchain-codex-oauth/auth/openai.json)으로 변환한다.

- 토큰 값은 절대 stdout/로그에 출력하지 않는다.
- 만료시각은 access 토큰(JWT)의 exp 클레임에서 복원한다 (서명 검증 불필요 — 로컬 변환용).
- 이후 갱신은 어댑터가 refresh 토큰으로 자체 수행한다.

사용법: .venv/bin/python scripts/bootstrap-codex-auth.py
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path


def _jwt_exp_ms(token: str) -> int:
    try:
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return int(payload.get("exp", 0)) * 1000
    except Exception:
        return 0


def main() -> int:
    codex_auth = Path.home() / ".codex" / "auth.json"
    if not codex_auth.exists():
        print("오류: ~/.codex/auth.json 이 없습니다. 먼저 `codex` CLI로 로그인하세요.")
        return 1

    data = json.loads(codex_auth.read_text(encoding="utf-8"))
    tokens = data.get("tokens") or {}
    access = tokens.get("access_token") or ""
    refresh = tokens.get("refresh_token") or ""
    account_id = tokens.get("account_id") or ""
    if not (access and refresh and account_id):
        print("오류: codex auth.json 에 필요한 토큰 필드가 없습니다.")
        return 1

    expires_ms = _jwt_exp_ms(access)
    if not expires_ms:
        print("경고: access 토큰에서 만료시각을 읽지 못했습니다 — 어댑터가 즉시 refresh를 시도합니다.")
        expires_ms = 1  # 과거 시각 → 어댑터가 refresh 토큰으로 갱신

    from codex_oauth.store import AuthStore, OAuthCredentials

    store = AuthStore()
    store.save(
        OAuthCredentials(access=access, refresh=refresh, expires=expires_ms, account_id=account_id)
    )
    print(f"완료: codex CLI 세션을 이식했습니다 → {store.auth_path}")
    print("확인: .venv/bin/langchain-codex-oauth auth status")
    return 0


if __name__ == "__main__":
    sys.exit(main())
