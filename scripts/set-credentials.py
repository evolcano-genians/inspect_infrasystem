#!/usr/bin/env python3
"""nexus-shell 환경별 자격증명을 .env에 안전하게 저장하는 CLI.

사용:
  # 대화형 (비밀번호는 화면에 안 보임)
  .venv/bin/python scripts/set-credentials.py vm --base https://nexus.vmlab.test
  .venv/bin/python scripts/set-credentials.py aws --base https://nexus.clouddev.dev.genians.kr
  .venv/bin/python scripts/set-credentials.py azure --base https://nexus.gsp.genians.com

  # 목록 확인 (비밀번호 값은 표시 안 함)
  .venv/bin/python scripts/set-credentials.py --list

.env는 gitignore되어 커밋되지 않는다. 비밀번호는 getpass로 입력받아 화면·쉘 히스토리에
남지 않는다.
"""

from __future__ import annotations

import argparse
import getpass
import re
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
_NAME_RE = re.compile(r"^[a-z][a-z0-9]{0,15}$")


def _read_env() -> dict[str, str]:
    data: dict[str, str] = {}
    if ENV_PATH.exists():
        for line in ENV_PATH.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                data[k.strip()] = v
    return data


def _write_env(data: dict[str, str]) -> None:
    lines = [f"{k}={v}" for k, v in data.items()]
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ENV_PATH.chmod(0o600)  # 소유자만 읽기/쓰기


def main() -> int:
    p = argparse.ArgumentParser(description="nexus-shell 자격증명 .env 관리")
    p.add_argument("name", nargs="?", help="환경 이름 (vm|aws|azure 등, 소문자)")
    p.add_argument("--base", help="nexus-shell 베이스 URL (예: https://nexus.vmlab.test)")
    p.add_argument("--user", help="계정 ID (미지정 시 대화형 입력)")
    p.add_argument("--list", action="store_true", help="설정된 환경 목록 (비밀번호 미표시)")
    args = p.parse_args()

    data = _read_env()

    if args.list or not args.name:
        names = sorted({
            k[len("SHELL_"):].split("_")[0].lower()
            for k in data if k.startswith("SHELL_") and k.endswith("_BASE")
        })
        print("설정된 nexus-shell 환경:")
        for n in names:
            up = n.upper()
            print(f"  - {n}: {data.get(f'SHELL_{up}_BASE','')} "
                  f"(user: {data.get(f'SHELL_{up}_USER','(없음)')}, "
                  f"password: {'설정됨' if data.get(f'SHELL_{up}_PASSWORD') else '없음'})")
        print(f"\nSHELL_ENVS={data.get('SHELL_ENVS','(비어있음)')}")
        return 0

    name = args.name.lower()
    if not _NAME_RE.match(name):
        print(f"오류: 환경 이름 형식(소문자 영숫자): {name!r}")
        return 1
    up = name.upper()

    base = args.base or data.get(f"SHELL_{up}_BASE") or input(f"[{name}] 베이스 URL: ").strip()
    user = args.user or input(f"[{name}] 계정 ID: ").strip()
    password = getpass.getpass(f"[{name}] 비밀번호(화면 미표시): ")
    if not (base and user and password):
        print("오류: base/user/password 모두 필요")
        return 1

    data[f"SHELL_{up}_BASE"] = base
    data[f"SHELL_{up}_USER"] = user
    data[f"SHELL_{up}_PASSWORD"] = password
    # SHELL_ENVS에 name 추가
    envs = [x for x in (data.get("SHELL_ENVS", "") or "").split(",") if x.strip()]
    if name not in envs:
        envs.append(name)
    data["SHELL_ENVS"] = ",".join(envs)
    _write_env(data)
    print(f"✓ '{name}' 자격증명을 {ENV_PATH} 에 저장했습니다 (권한 600, gitignore됨).")
    print("  서버를 재시작하면 shell_http_get 도구로 조사할 수 있습니다.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
