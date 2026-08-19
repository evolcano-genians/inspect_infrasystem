"""설정 저장소 검증 — 카탈로그 화이트리스트·시크릿 무반출·.env 보존 편집·인젝션 차단."""

from __future__ import annotations

import pytest

from src.settings_store import (
    SettingsError,
    apply_updates,
    current_settings,
    read_env_file,
)


def test_current_settings_hides_secret_values(tmp_path):
    env = tmp_path / ".env"
    env.write_text("JIRA_BASE_URL=https://j\nJIRA_TOKEN=SUPERSECRET\n", encoding="utf-8")
    groups = current_settings(env)
    flat = {f["key"]: f for g in groups for f in g["fields"]}
    # 비시크릿은 값 노출, 시크릿은 상태만
    assert flat["JIRA_BASE_URL"]["value"] == "https://j"
    assert flat["JIRA_BASE_URL"]["is_set"] is True
    assert flat["JIRA_TOKEN"]["value"] == ""          # 시크릿 값 무반출
    assert flat["JIRA_TOKEN"]["is_set"] is True        # 상태만 노출
    assert flat["JIRA_TOKEN"]["secret"] is True


def test_apply_updates_writes_catalog_keys(tmp_path):
    env = tmp_path / ".env"
    saved = apply_updates(env, {"JIRA_BASE_URL": "https://ims", "JIRA_TOKEN": "PAT123"})
    assert set(saved) == {"JIRA_BASE_URL", "JIRA_TOKEN"}
    data = read_env_file(env)
    assert data["JIRA_BASE_URL"] == "https://ims" and data["JIRA_TOKEN"] == "PAT123"
    assert env.stat().st_mode & 0o777 == 0o600         # chmod 600


def test_apply_rejects_unknown_key(tmp_path):
    env = tmp_path / ".env"
    with pytest.raises(SettingsError, match="허용되지 않는"):
        apply_updates(env, {"EVIL_KEY": "x"})
    with pytest.raises(SettingsError, match="허용되지 않는"):
        apply_updates(env, {}, clears=["EVIL_KEY"])


def test_apply_rejects_newline_injection(tmp_path):
    env = tmp_path / ".env"
    with pytest.raises(SettingsError, match="개행"):
        apply_updates(env, {"JIRA_TOKEN": "a\nMALICIOUS=1"})


def test_secret_blank_keeps_existing(tmp_path):
    env = tmp_path / ".env"
    apply_updates(env, {"JIRA_TOKEN": "keepme"})
    # 시크릿에 빈 값 → 유지(덮어쓰지 않음)
    apply_updates(env, {"JIRA_TOKEN": "", "JIRA_BASE_URL": "https://j"})
    data = read_env_file(env)
    assert data["JIRA_TOKEN"] == "keepme"
    assert data["JIRA_BASE_URL"] == "https://j"


def test_preserves_comments_and_other_keys(tmp_path):
    env = tmp_path / ".env"
    env.write_text(
        "# 내 주석\nKUBECONFIG=/home/me/.kube/config\nJIRA_TOKEN=old\n# 끝\n",
        encoding="utf-8",
    )
    apply_updates(env, {"JIRA_TOKEN": "new", "TRINO_ENDPOINT": "http://trino:8080"})
    text = env.read_text(encoding="utf-8")
    assert "# 내 주석" in text and "# 끝" in text           # 주석 보존
    assert "KUBECONFIG=/home/me/.kube/config" in text        # 비카탈로그 키 보존
    data = read_env_file(env)
    assert data["JIRA_TOKEN"] == "new"                       # 교체
    assert data["TRINO_ENDPOINT"] == "http://trino:8080"     # 신규 추가


def test_clear_removes_key(tmp_path):
    env = tmp_path / ".env"
    apply_updates(env, {"JIRA_TOKEN": "x", "JIRA_BASE_URL": "https://j"})
    apply_updates(env, {}, clears=["JIRA_TOKEN"])
    data = read_env_file(env)
    assert "JIRA_TOKEN" not in data
    assert data["JIRA_BASE_URL"] == "https://j"
