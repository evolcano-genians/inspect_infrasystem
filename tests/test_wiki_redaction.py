"""6-7 위키 레다크션 — 시크릿성 값이 wiki/ 어디에도 평문으로 남지 않아야 한다."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage

from src.nodes.wiki_writer import (
    REDACTED,
    make_wiki_writer_node,
    redact_observation,
    redact_text,
    write_observations,
)

SECRETS = {
    "password_value": "hunter2-Sup3rSecret",
    "base64_blob": "c2VjcmV0LXZhbHVlLTEyMzQ1Njc4OTBhYmNkZWY=",
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c",
}


def _grep_wiki(wiki_dir, needle: str) -> list[str]:
    return [
        str(p) for p in wiki_dir.rglob("*.md") if needle in p.read_text(encoding="utf-8")
    ]


def test_redact_text_masks_sensitive_patterns():
    text = (
        f"db password: {SECRETS['password_value']} 이고 "
        f"토큰은 token={SECRETS['jwt']} 이며 인코딩 값은 {SECRETS['base64_blob']} 이다"
    )
    redacted = redact_text(text)
    for value in SECRETS.values():
        assert value not in redacted
    assert REDACTED in redacted


def test_redact_text_preserves_normal_k8s_strings():
    text = "healthy-web-6d9f8c7b45-xk2p9 파드가 waiting=CrashLoopBackOff, restarts=5 상태"
    assert redact_text(text) == text


def test_redact_text_masks_snake_case_env_keys():
    """DB_PASSWORD 등 SCREAMING_SNAKE_CASE — \\b 경계로는 놓치던 케이스 (리뷰 확정 결함)."""
    cases = [
        "DB_PASSWORD=hunter2-Sup3r",
        "MYSQL_ROOT_PASSWORD=abc123",
        "API_TOKEN: tok-12345",
        "AWS_SECRET_ACCESS_KEY=shortval1",
    ]
    for text in cases:
        out = redact_text(text)
        assert REDACTED in out, f"미치환: {text} -> {out}"
        assert text.split("=")[-1].split(":")[-1].strip() not in out


def test_redact_text_masks_url_credentials():
    out = redact_text("접속 정보: postgres://admin:Sup3rSecretPw@db.internal:5432/app")
    assert "Sup3rSecretPw" not in out
    assert "postgres://admin:" in out  # 사용자명·호스트 구조는 보존


def test_redact_text_masks_korean_keywords():
    cases = [
        ("비밀번호: topSecret9 입니다", "topSecret9"),
        ("비밀번호는 hunter2x 입니다", "hunter2x"),
        ("토큰=ghp-shortTok12", "ghp-shortTok12"),
    ]
    for text, secret in cases:
        out = redact_text(text)
        assert secret not in out, f"미치환: {text} -> {out}"


def test_redact_text_masks_quoted_and_comma_values():
    out1 = redact_text('password: "correct horse battery staple"')
    assert "horse battery staple" not in out1
    out2 = redact_text("token: abc123,def456ghi")
    assert "def456ghi" not in out2


def test_redact_value_masks_snake_case_dict_keys():
    from src.nodes.wiki_writer import redact_value

    clean = redact_value({"DB_PASSWORD": "hunter2", "SECRET_KEY": "abc", "API_TOKEN": "tok"})
    assert all(v == REDACTED for v in clean.values()), clean
    # 비민감 키는 보존
    assert redact_value({"data_keys": ["APP_MODE"], "restarts": 3}) == {
        "data_keys": ["APP_MODE"], "restarts": 3,
    }


def test_redact_observation_drops_configmap_data_values():
    obs = {
        "entity_type": "workload",
        "entity": "demo-config",
        "namespace": "default",
        "observed_at": "2026-08-18T00:00:00+00:00",
        "summary": f"ConfigMap 확인, api_key={SECRETS['password_value']}",
        "facts": {
            "kind": "ConfigMap",
            "data": {"DB_PASSWORD": SECRETS["password_value"]},
            "stringData": {"TOKEN": SECRETS["jwt"]},
        },
    }
    clean = redact_observation(obs)
    assert clean["facts"]["data"] == REDACTED
    assert clean["facts"]["stringData"] == REDACTED
    assert SECRETS["password_value"] not in str(clean)
    assert SECRETS["jwt"] not in str(clean)


def test_wiki_pages_never_contain_secrets(wiki_dir):
    """가짜 관찰 결과를 Wiki Write Node에 흘려보내고 wiki/ 전체를 grep한다."""
    observations = [
        {
            "entity_type": "workload",
            "entity": "leaky-app",
            "namespace": "default",
            "observed_at": "2026-08-18T00:00:00+00:00",
            "summary": f"환경변수에 password: {SECRETS['password_value']} 노출 의심",
            "facts": {"kind": "Pod", "phase": "Running", "waiting_reasons": [], "restarts": 0,
                      "env_dump": SECRETS["base64_blob"]},
        },
        {
            "entity_type": "namespace",
            "entity": "default",
            "namespace": "default",
            "observed_at": "2026-08-18T00:00:00+00:00",
            "summary": f"token={SECRETS['jwt']} 가 로그에 보임",
            "facts": {},
        },
    ]
    write_observations(wiki_dir, observations)

    for value in SECRETS.values():
        assert not _grep_wiki(wiki_dir, value), f"위키에 시크릿 평문 잔존: {value[:12]}…"
    assert _grep_wiki(wiki_dir, REDACTED), "[REDACTED] 치환 흔적이 없습니다"


def test_session_page_is_redacted(wiki_dir):
    node = make_wiki_writer_node(wiki_dir)
    state = {
        "question": f"configmap의 password: {SECRETS['password_value']} 가 왜 안 먹지?",
        "session_id": "redact-test",
        "messages": [
            HumanMessage("질문"),
            AIMessage(content=f"원인: token={SECRETS['jwt']} 이 만료되었습니다."),
        ],
        "observations": [],
        "tool_trace": [],
    }
    node(state)
    for value in SECRETS.values():
        assert not _grep_wiki(wiki_dir, value)
