"""SSH 소스 열람 도구 — 개발 서버의 소스코드를 read-only 로 조회한다.

구조적 안전장치 (임의 명령 실행 도구는 존재하지 않는다):
1. **명령 화이트리스트**: ls / sed -n(읽기) / grep -rn / find / git log·show 의
   5가지 고정 형태만 원격에서 실행된다. verb 를 문자열로 받는 실행형 도구는 없다.
2. **인자 검증 + 인용**: 경로·패턴은 결정론적 검증(".." 금지, 셸 메타문자 금지) 후
   shlex.quote 로 감싼다 — 셸 인젝션이 성립하지 않는다.
3. **BatchMode SSH**: 비대화형 키 인증만. 대상(user@host)은 환경변수로만 주입.
4. 모든 호출은 audit 로그에 기록된다 (k8s_read 와 동일 체계).
"""

from __future__ import annotations

import re
import shlex
import subprocess

_TARGET_RE = re.compile(r"^[a-z0-9_][a-z0-9_.\-]{0,31}@[A-Za-z0-9.\-]{1,253}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9._/\-~]{1,300}$")
_FILENAME_RE = re.compile(r"^[A-Za-z0-9.*_\-]{1,100}$")
_PATTERN_RE = re.compile(r"^[^\n'\"`\\]{1,300}$")
_GLOB_RE = re.compile(r"^[A-Za-z0-9.*_\-]{0,50}$")
_MAX_OUTPUT = 30_000
_SSH_TIMEOUT = 30


class SourceAccessError(RuntimeError):
    pass


def _check_path(path: str) -> str:
    if not _PATH_RE.match(path) or ".." in path or path.startswith("-"):
        raise SourceAccessError(f"허용되지 않는 경로: {path!r}")
    return path


def _quote_path(path: str) -> str:
    """경로를 셸 인용하되 선행 ~/ 는 틸드 확장을 위해 인용 밖에 둔다.

    shlex.quote('~/x') → '~/x'(리터럴) 라 원격에서 홈 확장이 안 되므로,
    선행 ~ 만 분리해 ~/ + quote(나머지) 형태로 만든다. 경로는 이미 _check_path 로
    검증되어(.. 금지·화이트리스트 문자만) 인젝션 여지가 없다.
    """
    checked = _check_path(path)
    if checked == "~":
        return "~"
    if checked.startswith("~/"):
        return "~/" + shlex.quote(checked[2:])
    return shlex.quote(checked)


class SourceHost:
    """user@host 로 read-only 소스 열람만 수행하는 핸들."""

    def __init__(self, target: str, *, runner=subprocess.run):
        if not _TARGET_RE.match(target or ""):
            raise SourceAccessError(f"SOURCE_SSH_HOST 형식 오류(user@host): {target!r}")
        self.target = target
        self._runner = runner

    def _ssh(self, remote_cmd: str, timeout: int = _SSH_TIMEOUT) -> str:
        proc = self._runner(
            [
                "ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout=6",
                "-o", "StrictHostKeyChecking=accept-new", self.target, remote_cmd,
            ],
            capture_output=True, text=True, timeout=timeout, shell=False,
        )
        out = (proc.stdout or "")
        if proc.returncode != 0 and not out.strip():
            err = (proc.stderr or "").strip()[-400:]
            return f"[소스 조회 실패 rc={proc.returncode}] {err}"
        return out[:_MAX_OUTPUT]

    # ---- 고정된 read-only 조회 5종 ----

    def list_dir(self, path: str = "~") -> str:
        p = _quote_path(path)
        return self._ssh(f"ls -la {p} | head -100")

    def read_file(self, path: str, start: int = 1, lines: int = 200) -> str:
        p = _quote_path(path)
        start = max(1, int(start))
        end = start + max(1, min(int(lines), 2000)) - 1
        return self._ssh(f"sed -n {start},{end}p {p}")

    def search(self, path: str, pattern: str, glob: str = "", max_results: int = 50) -> str:
        if not _PATTERN_RE.match(pattern):
            raise SourceAccessError(f"허용되지 않는 검색 패턴: {pattern!r}")
        if glob and not _GLOB_RE.match(glob):
            raise SourceAccessError(f"허용되지 않는 glob: {glob!r}")
        p = _quote_path(path)
        n = max(1, min(int(max_results), 500))
        include = f" --include={shlex.quote(glob)}" if glob else ""
        return self._ssh(
            f"grep -rnI -m 3{include} -e {shlex.quote(pattern)} {p} "
            f"--exclude-dir=node_modules --exclude-dir=.git | head -{n}"
        )

    def find_files(self, path: str, filename: str) -> str:
        if not _FILENAME_RE.match(filename):
            raise SourceAccessError(f"허용되지 않는 파일명 패턴: {filename!r}")
        p = _quote_path(path)
        return self._ssh(
            f"find {p} -maxdepth 6 -type f -name {shlex.quote(filename)} "
            f"-not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null | head -60"
        )

    def repo_log(self, path: str, limit: int = 10) -> str:
        p = _quote_path(path)
        n = max(1, min(int(limit), 100))
        return self._ssh(f"git -C {p} log --oneline -n {n} 2>&1; git -C {p} status -s 2>&1 | head -20")


def make_source_tools(host: SourceHost, audit=None) -> list:
    """소스 열람 도구를 만든다 — verb 는 전부 source-read (read 전용)."""
    import time

    from langchain_core.tools import StructuredTool

    from . import verb_validator

    def _guarded(tool_name: str, fn):
        verb_validator.register_tool(tool_name, "source-read", "source")

        def wrapper(**kwargs):
            verdict = verb_validator.validate_tool_call(tool_name, kwargs)
            if not verdict.allowed:
                if audit:
                    audit.record(tool=tool_name, verb="source-read", resource="source",
                                 allowed=False, reason=verdict.reason)
                return f"[거부됨 · read-only 정책] {verdict.reason}"
            started = time.perf_counter()
            try:
                result = fn(**kwargs)
            except SourceAccessError as exc:
                if audit:
                    audit.record(tool=tool_name, verb="source-read", resource="source",
                                 allowed=False, reason=str(exc))
                return f"[거부됨 · 소스 접근 정책] {exc}"
            except Exception as exc:
                result = f"[소스 조회 오류] {type(exc).__name__}: {exc}"
            if audit:
                audit.record(tool=tool_name, verb="source-read", resource="source",
                             allowed=True, duration_ms=(time.perf_counter() - started) * 1000,
                             result_chars=len(str(result)))
            return result

        return wrapper

    specs = [
        ("src_list_dir",
         "개발 서버(SSH)의 디렉터리를 나열한다. 주요 소스 경로: "
         "~/WebstormProjects/nexus-shell (shell 프론트/앱), ~/nexus-ai (AI 어시스턴트/MCP), "
         "~/nexus-lake (데이터레이크: trino/spark/bronze), ~/WebstormProjects/gsp-service-logs, "
         "~/GolandProjects/k8sSettup (helm 차트/배포).",
         lambda path="~": host.list_dir(path)),
        ("src_read_file",
         "소스 파일의 일부를 읽는다 (start 줄부터 lines 줄, 기본 1~200). "
         "먼저 src_find_files/src_search로 정확한 경로를 찾은 뒤 읽어라.",
         lambda path, start=1, lines=200: host.read_file(path, start, lines)),
        ("src_search",
         "소스에서 문자열/심볼을 재귀 검색한다 (grep -rn). glob(예: *.ts)로 파일 범위를 좁힐 수 있다. "
         "에러 메시지·함수명·설정 키를 클러스터 로그와 대조할 때 사용.",
         lambda path, pattern, glob="", max_results=50: host.search(path, pattern, glob, max_results)),
        ("src_find_files",
         "파일명 패턴으로 소스 파일을 찾는다 (find -name, 예: *.Dockerfile, values.yaml).",
         lambda path, filename: host.find_files(path, filename)),
        ("src_repo_log",
         "git 저장소의 최근 커밋 이력과 작업트리 상태를 조회한다 (읽기 전용).",
         lambda path, limit=10: host.repo_log(path, limit)),
    ]

    tools = []
    for tool_name, description, fn in specs:
        tools.append(
            StructuredTool.from_function(
                func=_make_typed(fn, _guarded(tool_name, fn)),
                name=tool_name,
                description=description,
            )
        )
    return tools


def _make_typed(original, guarded):
    """StructuredTool 스키마 추론을 위해 원본 람다 시그니처를 래퍼에 입힌다."""
    import inspect

    sig = inspect.signature(original)

    def typed(**kwargs):
        return guarded(**kwargs)

    typed.__signature__ = sig  # type: ignore[attr-defined]
    typed.__annotations__ = {
        name: (int if isinstance(p.default, int) and not isinstance(p.default, bool) else str)
        for name, p in sig.parameters.items()
    }
    return typed
