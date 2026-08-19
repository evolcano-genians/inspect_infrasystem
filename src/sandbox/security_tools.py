"""보안 테스트 도구 — 샌드박스 격리 bash + strix pentest (opt-in).

권한 맥락: 사용자는 자사 dev 인프라에 대한 인가된 보안 테스터다. 다만 이 파일의 두 도구는
**격리 등급이 서로 다르며**, 그 차이를 정확히 알고 써야 한다:

- ``sandbox_bash`` → BashSandbox(일회용 컨테이너·자격증명 무마운트·네트워크 화이트리스트·
  non-root·read-only rootfs)에서만 실행된다. 호스트 파일시스템·자격증명에 도달할 수 없다.
- ``sandbox_pentest_strix`` → **호스트에서 subprocess 로 직접 실행된다.** strix 자체가 도커
  컨테이너를 띄워 멀티에이전트를 굴리는 오케스트레이터라, 도커 소켓도 볼륨도 없는
  BashSandbox(alpine·read-only) 안에서는 구조적으로 돌릴 수 없기 때문이다. 대신 다음
  4겹으로 방어한다:

  1. **env default-deny**: 호스트 환경변수를 상속하지 않고 화이트리스트(PATH/LANG/…·
     ``STRIX_*``)로 새로 조립한다 → KUBECONFIG·AWS_*·AZURE_*·OPENAI_*·TRINO_TOKEN·
     SHELL_*_PASSWORD 는 자식 프로세스에 존재하지 않는다.
  2. **HOME/cwd 전용 격리**: HOME 과 cwd 를 ``<root>/.local/pentest`` 하위 전용 트리로
     바꾼다 → 자식의 HOME 에 ``.kube/.aws/.azure/.docker/.ssh`` 가 경로로 존재하지 않아
     kubectl/aws CLI 류의 기본 경로 탐색이 실패하고, 리포 루트의 ``.env``·
     ``.local/kind-kubeconfig.yaml`` 을 상대경로로 읽을 수도 없다.
  3. **대상 허용목록 + 하드 denylist**: 루프백·로컬 kind(172.18/16)·인가된 실증 랩
     (``*.vmlab.test``)·전용 작업 디렉터리만 허용한다. 사설 대역 전체(10/8·192.168/16)와
     클러스터 내부 DNS(``.svc``/``.local``)는 기본 거부다. 나아가 해석된 IP 가 링크로컬·
     CGNAT 또는 **설정에서 파생한 실 인프라**(kubeconfig 의 API 서버, 실 nexus-shell base)
     에 걸리면 이름이 허용목록에 있어도 거부한다(split-horizon DNS 방어).
  4. **실 클러스터 인터록**: 실 dev 클러스터 read-only 조사 모드에서는 이 도구가 호출 시
     전면 거부된다 — "조사 모드"와 "능동 pentest 모드"는 코드로 상호 배타다.

  **보증 수준(정직하게)**: strix 는 운영자 UID 로 호스트 파일시스템 읽기와 호스트 네트워크
  도달성을 그대로 가진다. 이 코드가 보증하는 것은 "자격증명 무상속 + 허용목록 밖 대상 거부"
  이지 "실 인프라 도달 불가"가 **아니다**.

노출은 opt-in이다:
- SANDBOX_BASH_ENABLED=1 → sandbox_bash 도구
- STRIX_ENABLED=1 (+ strix CLI) → sandbox_pentest_strix 도구
- STRIX_ALLOWED_TARGETS → 랩 환경에 맞춰 허용목록 치환(하드 denylist 는 못 푼다)

잔여 위험(설계상 남는 것): **★ Docker 소켓 = 호스트 root 등가.** strix 는 컨테이너를 띄우려
호스트 도커 데몬(/var/run/docker.sock)에 접근하며, 이는 사실상 호스트 root 권한이라 env/HOME
격리를 이론적으로 우회할 수 있다(적대검증 확인) — 즉 이 도구는 **strix 를 신뢰할 수 있는 도구로
전제**하며, strix 가 도커 소켓을 악용하지 않는다는 가정 위에 선다. 그 외: 호스트 파일시스템
절대경로 읽기 가능(HOME/cwd 격리는 기본 탐색 경로만 차단); DNS TOCTOU(사전 검증 후 재해석);
호스트 라우팅 불변(설정에 드러나지 않은 VPN 은 인터록이 못 잡지만, 대상 게이트+하드 denylist 가
실 클러스터 IP 는 차단); strix 자체 컨테이너의 네트워크·부수 스캔은 통제 밖; 인가된 VM 내부
횡적 이동. 근본 해소는 strix 자체를 rootless/전용 저권한 UID 또는 **격리된 전용 VM 에서 실행**
하는 것이며 이번 범위 밖이다 — 따라서 STRIX_ENABLED 는 **버릴 수 있는 랩 환경에서만** 켤 것.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from langchain_core.tools import StructuredTool

from ..config import PROJECT_ROOT
from ..tools import verb_validator
from .bash_exec import BashSandbox, SandboxExecError, assert_no_credential_env

#: layer1(형태 필터)이 인식하는 로컬 디렉터리 모양.
_LOCAL_DIR_RE = re.compile(r"^[A-Za-z0-9._/\-]{1,200}$")
#: layer1 이 "2차 심사 진입"을 허용하는 대역. **허용 대역이 아니라 심사 진입 대역**이다 —
#: 실제 인가는 `_authorize_strix_target`(layer2)의 policy.allow_cidrs 가 결정한다.
_PRIVATE_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

#: strix 자식 프로세스에 넘기는 env 화이트리스트(default-deny). LLM 키는 상속하지 않는다 —
#: 필요하면 운영자가 전용 `STRIX_LLM_*` 키를 넣고 그것만 `STRIX_` 접두사로 통과한다.
_STRIX_ENV_KEEP: tuple[str, ...] = ("PATH", "LANG", "LC_ALL", "TERM", "TZ")
_STRIX_ENV_KEEP_PREFIXES: tuple[str, ...] = ("STRIX_",)

#: 기본 허용 대역 — 루프백 + 로컬 kind 도커 네트워크(실측 172.18.0.0/16).
#: (선택 확장: 구동 시 `docker network inspect kind` 로 실제 서브넷을 1회 읽어 갱신할 수
#:  있으나, 대상 검사 경로를 docker 하드 의존으로 만들지 않으려고 상수로 둔다.)
_DEFAULT_ALLOW_CIDRS: tuple = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("172.18.0.0/16"),
    ipaddress.ip_network("fc00:f853:ccd:e793::/64"),
)
#: 항상 거부하는 하드 denylist 대역 — 클라우드 메타데이터(169.254.169.254)·CGNAT/tailscale.
#: `STRIX_ALLOWED_TARGETS` 로도 풀 수 없다.
_DEFAULT_DENY_CIDRS: tuple = (
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("100.64.0.0/10"),
)
#: 기본 전용 작업 디렉터리(gitignore 된 .local 하위).
_DEFAULT_WORKDIR: Path = PROJECT_ROOT / ".local" / "pentest"


def _is_sandbox_target(target: str) -> tuple[bool, str]:
    """대상 문자열의 **형태**를 싸게 거르는 1차 필터(layer1).

    여기서 True 는 '인가'가 아니라 '2차 심사 대상'을 뜻한다. 실제 허용 판정은
    `_authorize_strix_target`(layer2)가 하며, 도구가 실제로 거는 게이트도 layer2 다.
    이 함수는 순수·무네트워크로 유지된다(테스트 결정성).
    """
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
        # 사설/실증 DNS만 허용: .test(실증 VM)·.local·클러스터 내부 DNS·kind
        if (host.endswith((".test", ".svc", ".svc.cluster.local", ".local", ".localhost"))
                or host.endswith("-sandbox")):
            return True, "sandbox-dns"
        return False, f"공개 도메인 {host!r} 은 대상이 될 수 없습니다 (샌드박스/실증만 허용)"


# ---------------------------------------------------------------------------
# layer2 — 실제 인가 게이트
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StrixPolicy:
    """strix 대상 인가 정책. allow 는 설정으로 조정 가능하지만 deny 는 항상 우선한다."""

    allow_cidrs: tuple = _DEFAULT_ALLOW_CIDRS
    allow_hosts: tuple[str, ...] = ("localhost",)
    allow_host_suffixes: tuple[str, ...] = ("vmlab.test", "localhost")
    allow_ports: tuple[int, ...] = (80, 443, 8080, 8443)
    deny_cidrs: tuple = _DEFAULT_DENY_CIDRS
    deny_hosts: tuple[str, ...] = ()
    workdirs: tuple[Path, ...] = field(default_factory=lambda: (_DEFAULT_WORKDIR,))


def _as_local_path(target: str) -> Path | None:
    """대상이 '경로 형태'이면 절대경로로 정규화해 돌려준다. 아니면 None.

    경로로 취급하는 조건을 `/`·`.`·`~` 로 시작하는 경우로 좁혀, `nexus.vmlab.test/app`
    같은 호스트+경로 표기가 디렉터리로 오분류되지 않게 한다.
    """
    t = (target or "").strip()
    if not t or "://" in t or not t.startswith(("/", ".", "~")):
        return None
    try:
        p = Path(t).expanduser()
        return (p if p.is_absolute() else (PROJECT_ROOT / p)).resolve()
    except (OSError, ValueError, RuntimeError):
        return None


def _split_target(target: str) -> tuple[str, str, int | None]:
    """대상을 (scheme, host, port) 로 분해한다. 해석 불가면 host 가 빈 문자열."""
    t = (target or "").strip()
    if "://" in t:
        parsed = urlparse(t)
        scheme = (parsed.scheme or "").lower()
        try:
            port = parsed.port
        except ValueError:
            return scheme, "", None
        return scheme, (parsed.hostname or "").lower(), port
    # 스킴 없는 형태: IPv6 리터럴(`::1`)이 urlparse 를 깨뜨리므로 IP 를 먼저 본다.
    try:
        ipaddress.ip_address(t)
        return "", t.lower(), None
    except ValueError:
        pass
    try:
        parsed = urlparse("//" + t)
        port = parsed.port
    except ValueError:
        return "", "", None
    return "", (parsed.hostname or "").lower(), port


def _host_matches_suffix(host: str, suffixes: tuple[str, ...]) -> bool:
    """라벨 경계를 지키는 접미사 매칭 — `vmlab.test` 는 `nexus.vmlab.test` 만 잡는다."""
    h = (host or "").lower().rstrip(".")
    for suffix in suffixes:
        s = (suffix or "").lower().strip(".")
        if s and (h == s or h.endswith("." + s)):
            return True
    return False


def _resolve_ips(host: str, resolver) -> list:
    """호스트명을 IP 목록으로 해석한다. resolver 는 getaddrinfo 형태 또는 문자열 목록 반환."""
    ips = []
    for info in resolver(host, None) or []:
        raw = info
        if not isinstance(info, str):
            sockaddr = info[4]
            raw = sockaddr[0] if isinstance(sockaddr, (tuple, list)) else str(sockaddr)
        raw = str(raw).split("%", 1)[0]  # IPv6 zone id 제거
        try:
            ips.append(ipaddress.ip_address(raw))
        except ValueError:
            continue
    return ips


def _ip_denied(ip, policy: StrixPolicy) -> bool:
    return any(ip in net for net in policy.deny_cidrs)


def _ip_allowed(ip, policy: StrixPolicy) -> bool:
    return any(ip in net for net in policy.allow_cidrs)


def _authorize_strix_target(
    target: str, policy: StrixPolicy | None = None, *, resolver=None
) -> tuple[bool, str, tuple[str, ...]]:
    """strix 대상을 실제로 인가한다(layer2). 반환: (허용여부, 라벨/사유, 핀 IP 목록).

    판정 순서: 전용 작업 디렉터리 → 스킴 → 하드 denylist(이름) → layer1 형태 필터 →
    포트 → IP 리터럴/호스트명 허용목록 → DNS 해석 + 하드 denylist(IP).
    DNS 해석 실패는 **fail-closed**(거부)다. resolver 는 테스트 결정성을 위해 주입 가능.
    """
    policy = policy or StrixPolicy()
    resolver = resolver or socket.getaddrinfo
    t = (target or "").strip()
    if not t:
        return False, "빈 대상", ()

    # 1) 전용 작업 디렉터리(로컬 소스 pentest) — `../` 탈출·리포 루트는 여기서 걸린다.
    local = _as_local_path(t)
    if local is not None:
        for workdir in policy.workdirs:
            wd = Path(workdir).resolve()
            if local == wd or wd in local.parents:
                return True, f"workdir:{local}", ()
        allowed = ", ".join(str(Path(w)) for w in policy.workdirs)
        return False, f"경로 대상 {t!r} 은 전용 작업 디렉터리({allowed}) 하위가 아닙니다", ()

    scheme, host, port = _split_target(t)

    # 2) 스킴 — file:/ssh:/gopher: 등 차단
    if scheme not in ("", "http", "https"):
        return False, f"스킴 {scheme!r} 은 허용되지 않습니다 (http/https/무스킴만)", ()
    if not host:
        return False, f"대상 {t!r} 에서 호스트를 해석할 수 없습니다", ()

    # 3) 하드 denylist(이름) — allow 보다 항상 우선하며 설정으로 못 푼다.
    if host in policy.deny_hosts or _host_matches_suffix(host, policy.deny_hosts):
        return False, f"호스트 {host!r} 는 하드 denylist(실 인프라)로 항상 거부됩니다", ()

    # 4) layer1 형태 필터
    ok1, why1 = _is_sandbox_target(t)
    if not ok1:
        return False, why1, ()

    # 5) 포트 — 6443/2379/22/10250 등 인프라 포트를 구조적으로 배제
    if port is not None and port not in policy.allow_ports:
        return False, f"포트 {port} 는 허용 포트 {list(policy.allow_ports)} 밖입니다", ()

    # 6) IP 리터럴
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _ip_denied(literal, policy):
            return False, f"IP {host} 는 하드 denylist 대역입니다", ()
        if not _ip_allowed(literal, policy):
            return False, (
                f"IP {host} 는 허용 대역 밖입니다 "
                "(기본 허용: 루프백·로컬 kind 172.18/16; 사설 대역 전체는 실 클러스터 "
                "라우팅 위험 때문에 기본 거부)"
            ), ()
        return True, f"ip:{host}", (str(literal),)

    # 7) 호스트명 허용목록 — .svc/.local/임의 .test/사설 호스트명은 여기서 떨어진다.
    if not (host in policy.allow_hosts or _host_matches_suffix(host, policy.allow_host_suffixes)):
        return False, (
            f"호스트 {host!r} 는 사전 등록 허용목록 밖입니다 "
            f"(허용: {list(policy.allow_hosts)} + *.{'/*.'.join(policy.allow_host_suffixes) or '-'})"
        ), ()

    # 8) DNS 해석 + 하드 denylist 재확인 (split-horizon DNS 방어). 실패는 fail-closed.
    try:
        ips = _resolve_ips(host, resolver)
    except Exception as exc:  # noqa: BLE001 — 해석 실패는 사유 불문 거부
        return False, (
            f"호스트 {host!r} DNS 해석에 실패해 거부합니다 ({type(exc).__name__}) — "
            "도달 가능한 IP 를 직접 지정하세요"
        ), ()
    if not ips:
        return False, f"호스트 {host!r} 가 어떤 IP 로도 해석되지 않아 거부합니다", ()
    for ip in ips:
        if _ip_denied(ip, policy):
            return False, (
                f"호스트 {host!r} 가 하드 denylist IP({ip}) 로 해석되어 거부합니다 "
                "(실 인프라·메타데이터 대역)"
            ), ()
    return True, f"host:{host}", tuple(str(ip) for ip in ips)


# ---------------------------------------------------------------------------
# 정책 조립 (설정에서 파생하는 하드 denylist 포함)
# ---------------------------------------------------------------------------


def _parse_allowed_targets(spec: str) -> tuple[tuple, tuple[str, ...], tuple[str, ...]]:
    """`STRIX_ALLOWED_TARGETS`(콤마 구분 CIDR/호스트/`*.도메인`)를 파싱한다."""
    cidrs, hosts, suffixes = [], [], []
    for raw in (spec or "").split(","):
        item = raw.strip()
        if not item:
            continue
        try:
            cidrs.append(ipaddress.ip_network(item, strict=False))
            continue
        except ValueError:
            pass
        low = item.lower()
        if low.startswith("*."):
            suffixes.append(low[2:].strip("."))
        elif low.startswith("."):
            suffixes.append(low.strip("."))
        else:
            hosts.append(low)
    return tuple(cidrs), tuple(hosts), tuple(suffixes)


def _kubeconfig_server_hosts(kubeconfig: str | None) -> tuple[str, ...]:
    """kubeconfig 의 clusters[].cluster.server 호스트를 뽑는다 (시크릿 값은 읽지 않는다)."""
    if not kubeconfig:
        return ()
    try:
        import yaml

        data = yaml.safe_load(Path(kubeconfig).expanduser().read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001 — 파싱 실패는 deny 조립을 막지 않는다
        return ()
    hosts: list[str] = []
    for entry in data.get("clusters", []) or []:
        if not isinstance(entry, dict):
            continue
        cluster = entry.get("cluster")
        server = (cluster or {}).get("server", "") if isinstance(cluster, dict) else ""
        host = urlparse(str(server)).hostname
        if host:
            hosts.append(host.lower())
    return tuple(hosts)


def _is_loopback_host(host: str) -> bool:
    if host in ("localhost", "::1"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_strix_policy(
    *,
    allowed_targets: str = "",
    shell_env_bases: tuple[str, ...] = (),
    kubeconfig: str | None = None,
    workdirs: tuple[Path, ...] | None = None,
    resolver=None,
) -> StrixPolicy:
    """설정에서 strix 대상 정책을 조립한다.

    - `allowed_targets`(STRIX_ALLOWED_TARGETS)가 있으면 allow 부분을 **치환**한다.
    - 하드 denylist 는 상수 대역 + 설정 파생(실 nexus-shell base, kubeconfig API 서버)로
      만들어지며 allow 보다 항상 우선한다 → 환경이 늘어나면 자동으로 따라 넓어진다.
    - deny 호스트의 IP 는 생성 시 1회 best-effort 로만 해석한다(실패해도 이름 deny 유지).
    """
    base = StrixPolicy(workdirs=tuple(workdirs) if workdirs else (_DEFAULT_WORKDIR,))
    allow_cidrs, allow_hosts, allow_suffixes = base.allow_cidrs, base.allow_hosts, base.allow_host_suffixes
    parsed_cidrs, parsed_hosts, parsed_suffixes = _parse_allowed_targets(allowed_targets)
    if parsed_cidrs or parsed_hosts or parsed_suffixes:
        allow_cidrs, allow_hosts, allow_suffixes = parsed_cidrs, parsed_hosts, parsed_suffixes

    deny_hosts: list[str] = []
    for item in shell_env_bases:
        raw = (item or "").strip()
        host = urlparse(raw).hostname if "://" in raw else raw
        if host and not _is_loopback_host(host.lower()):
            deny_hosts.append(host.lower())
    for host in _kubeconfig_server_hosts(kubeconfig):
        # 로컬 kind 의 API 는 127.0.0.1 이라 deny 하면 정상 워크플로가 깨진다 → 제외.
        if not _is_loopback_host(host):
            deny_hosts.append(host)
    deny_hosts = list(dict.fromkeys(deny_hosts))

    deny_cidrs = list(base.deny_cidrs)
    getter = resolver or socket.getaddrinfo
    for host in deny_hosts:
        try:
            for ip in _resolve_ips(host, getter):
                deny_cidrs.append(ipaddress.ip_network(ip))
        except Exception:  # noqa: BLE001 — 해석 실패해도 이름 기반 deny 는 남는다
            continue

    return StrixPolicy(
        allow_cidrs=allow_cidrs,
        allow_hosts=allow_hosts,
        allow_host_suffixes=allow_suffixes,
        allow_ports=base.allow_ports,
        deny_cidrs=tuple(dict.fromkeys(deny_cidrs)),
        deny_hosts=tuple(deny_hosts),
        workdirs=base.workdirs,
    )


# ---------------------------------------------------------------------------
# strix 자식 프로세스 환경 (default-deny)
# ---------------------------------------------------------------------------


def _build_strix_env(home: Path, source: dict | None = None) -> dict[str, str]:
    """호스트 env 를 상속하지 않고 화이트리스트로 새로 조립한다 (결함 #2 방어의 1차선).

    `assert_no_credential_env` 는 조립 결과에 대한 **보조 최종 어서션**일 뿐이다 — 접두사
    denylist 는 TRINO_TOKEN/SHELL_VM_PASSWORD 를 못 잡으므로, 진짜 방어는 이 화이트리스트다.
    """
    src = source if source is not None else dict(os.environ)
    env = {k: str(src[k]) for k in _STRIX_ENV_KEEP if k in src}
    env.update({k: str(v) for k, v in src.items() if k.startswith(_STRIX_ENV_KEEP_PREFIXES)})
    env["HOME"] = str(home)
    env["TMPDIR"] = str(home / "tmp")
    assert_no_credential_env(env)  # 누수 시 fail-closed
    return env


def _prepare_strix_home(run_dir: Path) -> Path:
    """strix 전용 HOME 트리를 만든다. `.kube/.aws/.ssh` 가 경로로 존재하지 않는 게 핵심.

    **의도적으로 실제 ~/.strix 를 심볼릭 링크하지 않는다.** 과거 구현은 `home/.strix →
    ~/.strix` 링크를 만들었으나, 이는 (1) `$HOME/.strix/../.aws` 처럼 `..` 로 실제 홈을
    빠져나가는 한 홉 통로가 되고, (2) 실제 `~/.strix/cli-config.json` 의 `env` 맵이
    _build_strix_env 화이트리스트를 우회해 자식 환경을 재구성하는 경로가 된다
    (적대검증에서 확인된 격리 구멍). 링크를 제거하면 strix 는 이 격리 HOME 안의 **새 .strix**
    상태로 동작하므로 두 우회가 동시에 닫힌다. strix 바이너리는 PATH(shutil.which)로 찾고,
    인증·설정이 필요하면 운영자가 STRIX_* env(화이트리스트 통과)로 주입한다.
    """
    home = run_dir / "home"
    (home / "tmp").mkdir(parents=True, exist_ok=True)
    for path in (run_dir, home, home / "tmp"):
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return home


def make_security_tools(
    *,
    bash_enabled: bool,
    strix_enabled: bool,
    sandbox: BashSandbox | None = None,
    audit=None,
    runner=subprocess.run,
    strix_allowed_targets: str = "",
    real_cluster_mode: bool = False,
    shell_env_bases: tuple[str, ...] = (),
    kubeconfig: str | None = None,
    strix_run_dir: Path | None = None,
    strix_path: str | None = None,
    resolver=None,
) -> list:
    """도구 목록을 만든다. strix 관련 신규 인자는 전부 기본값이 있어 하위호환된다.

    - `real_cluster_mode`: 실 dev 클러스터 조사 모드. True 면 strix 는 **호출 시 항상 거부**
      한다(도구 인벤토리는 그대로 유지 — 목록을 단언하는 테스트/프롬프트 안정성).
    - `shell_env_bases`/`kubeconfig`: 하드 denylist 를 설정에서 파생시키기 위한 입력.
    """
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
        resolved_strix = strix_path or shutil.which("strix")
        run_dir = Path(strix_run_dir) if strix_run_dir else _DEFAULT_WORKDIR
        policy = build_strix_policy(
            allowed_targets=strix_allowed_targets,
            shell_env_bases=tuple(shell_env_bases),
            kubeconfig=kubeconfig,
            workdirs=(run_dir,),
            resolver=resolver,
        )
        verb_validator.register_tool("sandbox_pentest_strix", "sandbox-exec", "sandbox")

        def sandbox_pentest_strix(target: str, instruction: str = "", mode: str = "quick") -> str:
            """strix 멀티에이전트 pentest 를 사전 등록된 허용 대상에만 실행한다.

            **모든 거부는 runner 호출 전에** 끝난다 — 거부된 대상에서는 strix 프로세스가
            아예 생성되지 않아 자식이 호스트 자격증명을 볼 기회 자체가 없다.
            """
            # ① 실 클러스터 인터록 — 조사 모드와 능동 pentest 는 상호 배타
            if real_cluster_mode:
                why = ("실 dev 클러스터 read-only 조사 모드에서는 능동 pentest 를 실행할 수 "
                       "없습니다 (AGENT_ALLOW_REAL_CLUSTER / 실 kubeconfig 사용 중)")
                _record("sandbox_pentest_strix", "sandbox-exec", False, why)
                return f"[거부됨 · 실 클러스터 모드] {why}"
            # ② 대상 인가 (layer1 형태 필터 + layer2 허용목록/하드 denylist/DNS 핀)
            ok, label, pinned = _authorize_strix_target(target, policy, resolver=resolver)
            if not ok:
                _record("sandbox_pentest_strix", "sandbox-exec", False, label)
                return f"[거부됨 · 대상 제한] {label}"
            if not resolved_strix:
                return "[불가] strix CLI 가 설치되어 있지 않습니다"
            if mode not in ("quick", "standard", "deep"):
                mode = "quick"
            # ③ 전용 HOME/cwd 준비 + env default-deny 조립
            try:
                home = _prepare_strix_home(run_dir)
                env = _build_strix_env(home)
            except (OSError, SandboxExecError) as exc:
                why = f"실행 환경 준비 실패: {type(exc).__name__}: {exc}"
                _record("sandbox_pentest_strix", "sandbox-exec", False, why)
                return f"[거부됨 · 격리 준비 실패] {why}"
            args = [resolved_strix, "-t", target, "-n", "-m", mode]
            if instruction:
                args += ["--instruction", instruction[:1000]]
            started = time.perf_counter()
            try:
                proc = runner(
                    args, capture_output=True, text=True, timeout=1800, shell=False,
                    env=env, cwd=str(run_dir), stdin=subprocess.DEVNULL, start_new_session=True,
                )
            except Exception as exc:
                _record("sandbox_pentest_strix", "sandbox-exec", False, str(exc))
                return f"[strix 실행 오류] {type(exc).__name__}: {exc}"
            dur = (time.perf_counter() - started) * 1000
            out = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()[-30_000:]
            _record("sandbox_pentest_strix", "sandbox-exec", True,
                    f"target={label} pinned={list(pinned)}", dur, len(out))
            return f"[strix {mode} · 대상 {label}]\n{out}"

        tools.append(StructuredTool.from_function(
            func=sandbox_pentest_strix, name="sandbox_pentest_strix",
            description="strix 멀티에이전트 침투 테스트를 실행한다. 대상은 사전 등록 허용목록"
                        "(루프백·로컬 kind 네트워크·인가된 실증 랩 `*.vmlab.test`·전용 작업 "
                        "디렉터리)만 허용되며, 사설 대역 전체·클러스터 내부 DNS·공개 자산은 "
                        "거부된다. mode: quick|standard|deep.",
        ))

    return tools
