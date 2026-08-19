"""외부 API 연동 설정(.env) 관리 — UI 설정 메뉴의 백엔드.

보안 원칙:
- **카탈로그 화이트리스트**: SETTINGS_CATALOG 에 정의된 키만 읽고/쓴다. 임의 env 주입 불가.
- **시크릿 무반출**: 토큰·비밀번호·쿠키 값은 UI로 절대 돌려보내지 않는다 — "설정됨/없음"
  상태만 노출한다. 비시크릿(예: base URL, 카탈로그명)만 값을 보여준다.
- **.env 보존 편집**: 기존 주석·비카탈로그 키를 유지하며 대상 키만 갱신한다(전체 덮어쓰기 금지).
- **인젝션 차단**: 값에 개행/제어문자가 있으면 거부(.env 라인 오염 방지). 파일은 chmod 600.
- 적용 시점: 설정은 프로세스 시작 시 읽히므로, 저장 후 백엔드 재시작이 필요하다(needs_restart).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SettingField:
    key: str          # env 키
    label: str        # UI 표시명
    group: str        # 묶음(연동 대상)
    secret: bool = False   # True면 값 무반출(마스킹), 쓰기 전용
    placeholder: str = ""
    help: str = ""


#: UI에 노출·저장 가능한 설정 카탈로그. 여기 없는 키는 읽지도 쓰지도 않는다(화이트리스트).
SETTINGS_CATALOG: tuple[SettingField, ...] = (
    # Jira (코드 리뷰 이슈 참고)
    SettingField("JIRA_BASE_URL", "Base URL", "Jira", placeholder="https://ims.cloud.genians.com",
                 help="Jira 인스턴스 주소"),
    SettingField("JIRA_TOKEN", "Personal Access Token", "Jira", secret=True,
                 help="프로필 > Personal Access Tokens 에서 발급 (권장 인증)"),
    SettingField("JIRA_USER", "User (basic 인증 시)", "Jira",
                 help="비우면 PAT(Bearer). Cloud/basic이면 이메일"),
    SettingField("JIRA_COOKIE", "세션 쿠키 (SSO 폴백)", "Jira", secret=True,
                 help="PAT 미지원 시에만: 브라우저 세션 쿠키. 만료되면 갱신 필요"),
    # Trino (nexus-lake 데이터 분석)
    SettingField("TRINO_ENDPOINT", "Endpoint", "Trino (nexus-lake)",
                 placeholder="http://trino:8080"),
    SettingField("TRINO_USER", "User", "Trino (nexus-lake)", placeholder="inspect-k8s"),
    SettingField("TRINO_TOKEN", "Token", "Trino (nexus-lake)", secret=True),
    SettingField("TRINO_CATALOG", "기본 카탈로그", "Trino (nexus-lake)", placeholder="delta"),
    SettingField("TRINO_SCHEMA", "기본 스키마", "Trino (nexus-lake)", placeholder="silver"),
    # 원격 소스 (SSH read-only)
    SettingField("SOURCE_SSH_HOST", "SSH 대상 (user@host)", "소스 코드",
                 placeholder="heejoon@172.29.70.161", help="소스·SVN read-only 조회 대상"),
    # 샌드박스 실증
    SettingField("SANDBOX_IMAGE", "샌드박스 이미지", "샌드박스",
                 placeholder="python:3.12-slim", help="code-reviewer 코드 재현 런타임"),
    SettingField("STRIX_ALLOWED_TARGETS", "strix 허용 대상", "샌드박스",
                 help="콤마 구분 CIDR/호스트/*.도메인 (하드 denylist는 불변)"),
)

_CATALOG_BY_KEY = {f.key: f for f in SETTINGS_CATALOG}
# 값에 허용하지 않는 문자 — 개행·제어문자(.env 라인 오염 방지)
_BAD_VALUE_RE = re.compile(r"[\r\n\x00]")


class SettingsError(ValueError):
    pass


def read_env_file(env_path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if env_path.exists():
        for line in env_path.read_text(encoding="utf-8").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and "=" in s:
                k, v = s.split("=", 1)
                data[k.strip()] = v.strip()
    return data


def current_settings(env_path: Path) -> list[dict]:
    """카탈로그 각 필드의 상태를 반환한다. 시크릿 값은 절대 포함하지 않는다."""
    data = read_env_file(env_path)
    groups: dict[str, list[dict]] = {}
    for f in SETTINGS_CATALOG:
        val = data.get(f.key, "")
        entry = {
            "key": f.key, "label": f.label, "secret": f.secret,
            "placeholder": f.placeholder, "help": f.help,
            "is_set": bool(val),
            # 비시크릿만 값 노출. 시크릿은 절대 반출하지 않음(상태만).
            "value": ("" if f.secret else val),
        }
        groups.setdefault(f.group, []).append(entry)
    return [{"group": g, "fields": fs} for g, fs in groups.items()]


def apply_updates(env_path: Path, updates: dict[str, str], clears: list[str] | None = None) -> list[str]:
    """카탈로그 키만 .env에 반영한다(주석·기타 키 보존). 반영된 키 목록을 반환.

    - updates: {키: 값}. 시크릿 필드에 빈 값이면 '기존 유지'(덮어쓰지 않음).
    - clears: 명시적으로 비울 키 목록(시크릿 삭제 등).
    """
    clears = clears or []
    to_write: dict[str, str] = {}

    for key, value in (updates or {}).items():
        if key not in _CATALOG_BY_KEY:
            raise SettingsError(f"허용되지 않는 설정 키: {key!r}")
        if not isinstance(value, str):
            raise SettingsError(f"'{key}' 값은 문자열이어야 합니다")
        if _BAD_VALUE_RE.search(value):
            raise SettingsError(f"'{key}' 값에 허용되지 않는 문자(개행/제어문자)가 있습니다")
        field = _CATALOG_BY_KEY[key]
        v = value.strip()
        if field.secret and v == "":
            continue  # 시크릿 빈 값 = 기존 유지 (마스킹된 채로 안 건드림)
        to_write[key] = v

    for key in clears:
        if key not in _CATALOG_BY_KEY:
            raise SettingsError(f"허용되지 않는 설정 키: {key!r}")
        to_write[key] = ""  # 빈 값으로 명시적 삭제

    if not to_write:
        return []

    _rewrite_env(env_path, updates=to_write)
    return sorted(to_write)


def _rewrite_env(env_path: Path, *, updates: dict[str, str]) -> None:
    """기존 라인(주석·비카탈로그 키)을 보존하며 대상 키만 교체/추가하고 chmod 600."""
    lines: list[str] = []
    seen: set[str] = set()
    if env_path.exists():
        for raw in env_path.read_text(encoding="utf-8").splitlines():
            s = raw.strip()
            if s and not s.startswith("#") and "=" in s:
                k = s.split("=", 1)[0].strip()
                if k in updates:
                    seen.add(k)
                    if updates[k] == "":
                        continue  # 삭제: 해당 라인 제거
                    lines.append(f"{k}={updates[k]}")
                    continue
            lines.append(raw)
    # 파일에 없던 키는 끝에 추가 (빈 삭제 요청은 무시)
    for k, v in updates.items():
        if k not in seen and v != "":
            lines.append(f"{k}={v}")

    env_path.parent.mkdir(parents=True, exist_ok=True)
    env_path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8")
    try:
        env_path.chmod(0o600)  # 소유자만 읽기/쓰기
    except OSError:
        pass
