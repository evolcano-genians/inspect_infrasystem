"""보안 테스트 도구 — 샌드박스 격리 bash + strix pentest (opt-in).

권한 맥락: 사용자는 자사 dev 인프라에 대한 인가된 보안 테스터이며, 이 도구들은 **로컬
샌드박스에 복제한 대상**에만 사용한다(실 aws/azure 클러스터·외부 자산 대상 금지).
구조적으로 BashSandbox(자격증명 무마운트·네트워크 격리)를 통해서만 실행된다.

노출은 opt-in이다:
- SANDBOX_BASH_ENABLED=1 → sandbox_bash 도구
- STRIX_ENABLED=1 (+ strix CLI) → sandbox_pentest_strix 도구
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import time
from urllib.parse import urlparse

from langchain_core.tools import StructuredTool

from ..tools import verb_validator
from .bash_exec import BashSandbox, SandboxExecError

#: strix pentest 대상으로 허용하는 형태 — 로컬 소스 디렉터리(/work, 상대) 또는 루프백/사설 IP만.
_LOCAL_DIR_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def _is_sandbox_target(target: str) -> tuple[bool, str]:
    """strix 대상이 샌드박스(로컬/사설)인지 판정한다. 공개 자산은 거부."""
    t = (target or "").strip()
    if not t:
        return False, "빈 대상"
    # URL 이면 host 추출
    host = t
    if "://" in t:
        parsed = urlparse(t)
        host = parsed.hostname or ""
    # 로컬 디렉터리 경로 (소스 코드 대상 pentest)
    if t.startswith("/work") or (not host.count(".") and _LOCAL_DIR_RE.match(t) and "://" not in t):
        return True, "local"
    if host in ("localhost", "127.0.0.1", "::1"):
        return True, "loopback"
    try:
        ip = ipaddress.ip_address(host)
        if any(ip in net for net in _PRIVATE_NETS):
            return True, "private"
        return False, f"공개 IP {host} 는 대상이 될 수 없습니다 (샌드박스/사설만 허용)"
    except ValueError:
        # .svc.cluster.local, kind 서비스명 등 사설 DNS만 허용
        if host.endswith((".svc", ".svc.cluster.local", ".local")) or host.endswith("-sandbox"):
            return True, "cluster-dns"
        return False, f"공개 도메인 {host!r} 은 대상이 될 수 없습니다 (샌드박스만 허용)"


def make_security_tools(
    *,
    bash_enabled: bool,
    strix_enabled: bool,
    sandbox: BashSandbox | None = None,
    audit=None,
    runner=subprocess.run,
) -> list:
    tools: list = []

    def _record(name, verb, allowed, reason="", duration_ms=0.0, chars=0):
        if audit:
            audit.record(tool=name, verb=verb, resource="sandbox", allowed=allowed,
                         reason=reason, duration_ms=duration_ms, result_chars=chars)

    if bash_enabled:
        sb = sandbox or BashSandbox()
        verb_validator.register_tool("sandbox_bash", "sandbox-exec", "sandbox")

        def sandbox_bash(command: str, timeout: int = 120) -> str:
            """격리 샌드박스 컨테이너에서 bash 명령을 실행한다 (자격증명·실 인프라 접근 불가)."""
            verdict = verb_validator.validate_tool_call("sandbox_bash", {})
            started = time.perf_counter()
            try:
                res = sb.run(command, timeout=int(timeout))
            except SandboxExecError as exc:
                _record("sandbox_bash", "sandbox-exec", False, str(exc))
                return f"[샌드박스 실행 거부] {exc}"
            dur = (time.perf_counter() - started) * 1000
            _record("sandbox_bash", "sandbox-exec", True, duration_ms=dur, chars=len(res.output))
            status = f"exit={res.exit_code}" + (" (timeout)" if res.timed_out else "")
            body = res.output + ("\n...[출력 잘림]" if res.truncated else "")
            return f"[{status}]\n{body}"

        tools.append(StructuredTool.from_function(
            func=sandbox_bash, name="sandbox_bash",
            description="격리된 샌드박스 컨테이너에서 셸 명령을 실행한다 (네트워크는 샌드박스 한정, "
                        "호스트 자격증명·실 클라우드 접근 불가). 보안 점검·재현·스크립트 실행용.",
        ))

    if strix_enabled:
        strix_path = shutil.which("strix")
        verb_validator.register_tool("sandbox_pentest_strix", "sandbox-exec", "sandbox")

        def sandbox_pentest_strix(target: str, instruction: str = "", mode: str = "quick") -> str:
            """strix 멀티에이전트 pentest 를 샌드박스 대상에만 실행한다 (공개 자산 거부)."""
            ok, why = _is_sandbox_target(target)
            if not ok:
                _record("sandbox_pentest_strix", "sandbox-exec", False, why)
                return f"[거부됨 · 대상 제한] {why}"
            if not strix_path:
                return "[불가] strix CLI 가 설치되어 있지 않습니다"
            if mode not in ("quick", "standard", "deep"):
                mode = "quick"
            args = [strix_path, "-t", target, "-n", "-m", mode]
            if instruction:
                args += ["--instruction", instruction[:1000]]
            started = time.perf_counter()
            try:
                proc = runner(args, capture_output=True, text=True, timeout=1800, shell=False)
            except Exception as exc:
                _record("sandbox_pentest_strix", "sandbox-exec", False, str(exc))
                return f"[strix 실행 오류] {type(exc).__name__}: {exc}"
            dur = (time.perf_counter() - started) * 1000
            out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-30_000:]
            _record("sandbox_pentest_strix", "sandbox-exec", True, f"target={why}", dur, len(out))
            return f"[strix {mode} · 대상 {why}]\n{out}"

        tools.append(StructuredTool.from_function(
            func=sandbox_pentest_strix, name="sandbox_pentest_strix",
            description="strix 멀티에이전트 침투 테스트를 실행한다. 대상은 반드시 샌드박스"
                        "(로컬 소스 디렉터리·루프백·사설 IP·클러스터 내부 DNS)여야 하며 "
                        "공개 자산은 거부된다. mode: quick|standard|deep.",
        ))

    return tools
