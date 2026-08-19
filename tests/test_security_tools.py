"""샌드박스 보안 도구 검증 — 구조적 격리·strix 대상 제한 (docker/subprocess mock)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.sandbox.bash_exec import (
    BashSandbox,
    SandboxExecError,
    _assert_safe_config,
    assert_no_credential_env,
)
from src.sandbox.security_tools import (
    StrixPolicy,
    _authorize_strix_target,
    _build_strix_env,
    _is_sandbox_target,
    build_strix_policy,
    make_security_tools,
)


# ---------- BashSandbox 구조적 안전장치 ----------

@pytest.mark.parametrize("network", ["host", "bridge", "my-net", ""])
def test_bash_rejects_unsafe_network(network):
    with pytest.raises(SandboxExecError):
        _assert_safe_config(network, None, None)


def test_bash_rejects_host_volume_and_credential_env():
    with pytest.raises(SandboxExecError):
        _assert_safe_config("none", {"/home/x": {"bind": "/x"}}, None)
    for cred in ("KUBECONFIG", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_SECRET", "DOCKER_HOST"):
        with pytest.raises(SandboxExecError):
            _assert_safe_config("none", None, {cred: "v"})


class FakeContainer:
    def __init__(self, code=0, logs=b"ok"):
        self._code, self._logs = code, logs
        self.removed = False

    def wait(self, timeout=None):
        return {"StatusCode": self._code}

    def logs(self, **kw):
        return self._logs

    def remove(self, force=False):
        self.removed = True


class FakeDocker:
    def __init__(self):
        self.run_kwargs = None
        self.container = FakeContainer(0, b"sandbox-output")

    class _C:
        pass

    @property
    def containers(self):
        parent = self

        class _Containers:
            def run(self, image, **kwargs):
                parent.run_kwargs = {"image": image, **kwargs}
                return parent.container
        return _Containers()


def test_bash_run_uses_isolated_container():
    fake = FakeDocker()
    sb = BashSandbox(network="kind", docker_client=fake)
    res = sb.run("echo hi", timeout=30)
    assert res.exit_code == 0 and "sandbox-output" in res.output
    kw = fake.run_kwargs
    # 격리 속성 강제 확인
    assert kw["network_mode"] == "kind"
    assert kw["user"] == "1000:1000"
    assert kw["read_only"] is True
    assert kw["cap_drop"] == ["ALL"]
    assert "no-new-privileges" in kw["security_opt"]
    assert "volumes" not in kw or not kw.get("volumes")  # 호스트 마운트 없음
    assert fake.container.removed  # 일회용


def test_bash_credential_env_blocked_at_run():
    sb = BashSandbox(network="none", docker_client=FakeDocker())
    with pytest.raises(SandboxExecError):
        sb.run("echo hi", environment={"KUBECONFIG": "/x"})


# ---------- strix 대상 제한 ----------

@pytest.mark.parametrize("target,expected", [
    ("http://localhost:8080", True),
    ("http://127.0.0.1:9000/app", True),
    ("10.96.0.10", True),
    ("192.168.1.5", True),
    ("nexus-shell.svc.cluster.local", True),
    ("https://nexus.vmlab.test/", True),              # 실증 VM(.test) 허용
    ("/work/cloned-src", True),
    ("http://nexus.clouddev.dev.genians.kr", False),  # 실 운영 도메인 거부
    ("8.8.8.8", False),                               # 공개 IP 거부
    ("https://example.com", False),
])
def test_strix_target_restriction(target, expected):
    ok, _why = _is_sandbox_target(target)
    assert ok is expected


def test_security_tools_gating():
    assert make_security_tools(bash_enabled=False, strix_enabled=False) == []
    tools = {t.name for t in make_security_tools(
        bash_enabled=True, strix_enabled=True,
        sandbox=BashSandbox(network="none", docker_client=FakeDocker()),
    )}
    assert tools == {"sandbox_bash", "sandbox_pentest_strix"}


def test_strix_tool_rejects_public_target():
    calls = []
    tools = {t.name: t for t in make_security_tools(
        bash_enabled=False, strix_enabled=True,
        runner=lambda *a, **k: calls.append(a) or type("P", (), {"stdout": "", "stderr": "", "returncode": 0})(),
    )}
    out = tools["sandbox_pentest_strix"].invoke({"target": "https://google.com"})
    assert "거부됨" in out
    assert calls == []  # 공개 대상은 strix 실행 자체를 안 함


def test_security_auditor_agent_maps_sandbox_tools():
    from src.agents import load_agents

    agents = load_agents(Path(__file__).resolve().parent.parent / ".agents")
    sa = agents.get("security-auditor")
    assert sa is not None
    assert "sandbox_bash" in sa.tools and "sandbox_pentest_strix" in sa.tools
    assert "실 운영 자산" in sa.instructions  # 실 인프라 금지 명시


# ---------- layer2 대상 인가 (_authorize_strix_target) ----------

def _mock_resolver(mapping: dict[str, list[str]]):
    """getaddrinfo 형태의 결정론적 mock resolver (미등록 호스트는 NXDOMAIN)."""

    def _resolve(host, _port=None, *_a, **_kw):
        try:
            ips = mapping[host]
        except KeyError:
            raise OSError(f"NXDOMAIN: {host}") from None
        return [(2, 1, 6, "", (ip, 0)) for ip in ips]

    return _resolve


#: 이 머신 실측 — *.vmlab.test 는 VPN 대역(172.29.70.161)으로 뜬다 (kind 서브넷 밖).
_VM_RESOLVER = _mock_resolver({
    "nexus.vmlab.test": ["172.29.70.161"],
    "localhost": ["127.0.0.1"],
})


@pytest.mark.parametrize("target", [
    "10.96.0.10",                    # 사설 IP지만 kind 서브넷 밖 → 실 클러스터 라우팅 위험
    "192.168.1.5",
    "nexus-shell.svc.cluster.local",  # 클러스터 내부 DNS
    "app.local",
    "internal-lb",                    # 점 없는 사설 호스트명 (로컬 디렉터리 오분류 방지)
    "src",                            # 리포 루트 상대명
    "file:///etc/passwd",             # 스킴
    "ssh://nexus.vmlab.test",
    "http://nexus.vmlab.test:6443",   # 포트 allowlist 밖 (k8s API)
    "nexus.vmlab.test:10250",
    "nexus.vmlab.test.attacker.kr",   # 접미 경계 우회 시도
    "https://google.com",
    "8.8.8.8",
])
def test_authorize_strix_target_rejects(target):
    ok, why, pinned = _authorize_strix_target(target, StrixPolicy(), resolver=_VM_RESOLVER)
    assert ok is False and why and pinned == ()


@pytest.mark.parametrize("target,expected_ips", [
    ("127.0.0.1", ("127.0.0.1",)),
    ("http://localhost:8080", ("127.0.0.1",)),
    ("172.18.0.5", ("172.18.0.5",)),                       # 로컬 kind 서브넷
    ("nexus.vmlab.test", ("172.29.70.161",)),              # 이름 매칭 + 하드 denylist 밖
    ("https://nexus.vmlab.test/app", ("172.29.70.161",)),
])
def test_authorize_strix_target_allows(target, expected_ips):
    ok, label, pinned = _authorize_strix_target(target, StrixPolicy(), resolver=_VM_RESOLVER)
    assert ok is True and label
    assert pinned == expected_ips


def test_authorize_rejects_hard_denylist_host():
    """설정에서 파생한 실 인프라 호스트는 이름만으로도 항상 거부된다."""
    policy = build_strix_policy(
        shell_env_bases=("https://nexus.clouddev.dev.genians.kr",),
        resolver=_mock_resolver({}),  # 해석 실패해도 이름 기반 deny 는 유지
    )
    assert "nexus.clouddev.dev.genians.kr" in policy.deny_hosts
    ok, why, _ = _authorize_strix_target(
        "http://nexus.clouddev.dev.genians.kr", policy, resolver=_VM_RESOLVER
    )
    assert ok is False and why


def test_authorize_split_horizon_dns_is_blocked(tmp_path):
    """허용목록 이름이라도 실 클러스터 IP 로 해석되면 거부한다 (split-horizon 방어)."""
    kubeconfig = tmp_path / "kubeconfig.yaml"
    kubeconfig.write_text(
        "clusters:\n"
        "- name: aws-seoul-clouddev\n"
        "  cluster:\n"
        "    server: https://api.seoul.example.internal:6443\n",
        encoding="utf-8",
    )
    resolver = _mock_resolver({
        "api.seoul.example.internal": ["10.7.0.9"],
        "nexus.vmlab.test": ["10.7.0.9"],  # 랩 이름이 실 API IP 로 뜨는 상황
    })
    policy = build_strix_policy(kubeconfig=str(kubeconfig), resolver=resolver)
    assert "api.seoul.example.internal" in policy.deny_hosts
    ok, why, _ = _authorize_strix_target("nexus.vmlab.test", policy, resolver=resolver)
    assert ok is False and "denylist" in why


def test_authorize_dns_failure_is_fail_closed():
    ok, why, _ = _authorize_strix_target(
        "nexus.vmlab.test", StrixPolicy(), resolver=_mock_resolver({})
    )
    assert ok is False and "DNS" in why


def test_strix_allowed_targets_replaces_allowlist_but_not_denylist():
    policy = build_strix_policy(
        allowed_targets="10.99.0.0/16, *.lab.test",
        shell_env_bases=("https://nexus.gsp.genians.com",),
        resolver=_mock_resolver({}),
    )
    resolver = _mock_resolver({"app.lab.test": ["10.99.0.7"]})
    assert _authorize_strix_target("10.99.0.5", policy, resolver=resolver)[0] is True
    assert _authorize_strix_target("app.lab.test", policy, resolver=resolver)[0] is True
    # layer1(형태 필터)과 하드 denylist 는 치환으로 못 넓힌다
    assert _authorize_strix_target("https://google.com", policy, resolver=resolver)[0] is False
    assert _authorize_strix_target("8.8.8.8", policy, resolver=resolver)[0] is False
    assert _authorize_strix_target(
        "http://nexus.gsp.genians.com", policy, resolver=resolver
    )[0] is False
    # 치환됐으므로 기본 랩 도메인은 더 이상 통과하지 않는다
    assert _authorize_strix_target("nexus.vmlab.test", policy, resolver=_VM_RESOLVER)[0] is False


def test_authorize_local_workdir_targets(tmp_path):
    policy = StrixPolicy(workdirs=(tmp_path,))
    (tmp_path / "app").mkdir()
    ok, label, _ = _authorize_strix_target(str(tmp_path / "app"), policy)
    assert ok is True and "workdir" in label
    for bad in ("../../etc", "/etc", "/work/cloned-src", "src", str(Path(__file__).parent.parent)):
        assert _authorize_strix_target(bad, policy)[0] is False


# ---------- strix env default-deny ----------

_DIRTY_ENV = {
    "PATH": "/usr/bin:/bin",
    "LANG": "ko_KR.UTF-8",
    "KUBECONFIG": "/home/x/.kube/config",
    "AWS_ACCESS_KEY_ID": "AKIA...",
    "AZURE_CLIENT_SECRET": "s3cr3t",
    "OPENAI_API_KEY": "sk-...",
    "TRINO_TOKEN": "jwt...",
    "SHELL_VM_PASSWORD": "pw",
    "SOURCE_SSH_HOST": "heejoon@172.29.70.161",
    "DOCKER_HOST": "tcp://1.2.3.4:2375",
    "STRIX_LLM_API_KEY": "lab-only",
}


def test_build_strix_env_is_default_deny(tmp_path):
    home = tmp_path / "home"
    env = _build_strix_env(home, _DIRTY_ENV)
    assert env["PATH"] == "/usr/bin:/bin"
    assert env["LANG"] == "ko_KR.UTF-8"
    assert env["STRIX_LLM_API_KEY"] == "lab-only"  # 전용 STRIX_ 키만 통과
    for leaked in ("KUBECONFIG", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_SECRET", "OPENAI_API_KEY",
                   "TRINO_TOKEN", "SHELL_VM_PASSWORD", "SOURCE_SSH_HOST", "DOCKER_HOST"):
        assert leaked not in env
    # 화이트리스트 밖 키는 아예 존재하지 않는다 (HOME/TMPDIR 은 코드가 새로 넣는다)
    assert set(env) <= {"PATH", "LANG", "LC_ALL", "TERM", "TZ", "HOME", "TMPDIR",
                        "STRIX_LLM_API_KEY"}
    assert env["HOME"] == str(home) and env["HOME"] != str(Path.home())
    assert env["TMPDIR"] == str(home / "tmp")


def test_assert_no_credential_env_is_shared():
    assert_no_credential_env({"PATH": "/bin", "STRIX_LLM_API_KEY": "x"})  # 통과
    for cred in ("KUBECONFIG", "AWS_SECRET_ACCESS_KEY", "AZURE_CLIENT_ID", "DOCKER_HOST"):
        with pytest.raises(SandboxExecError):
            assert_no_credential_env({cred: "v"})


# ---------- 실 클러스터 인터록 · 도구 호출 경로 ----------

def test_strix_disabled_in_real_cluster_mode(tmp_path):
    calls = []
    tools = {t.name: t for t in make_security_tools(
        bash_enabled=False, strix_enabled=True, real_cluster_mode=True,
        strix_run_dir=tmp_path, strix_path="/fake/strix",
        runner=lambda *a, **k: calls.append((a, k)),
    )}
    out = tools["sandbox_pentest_strix"].invoke({"target": "127.0.0.1"})
    assert "거부됨" in out and "실 클러스터" in out
    assert calls == []


def test_strix_tool_invocation_is_isolated(tmp_path):
    calls = []

    def _runner(args, **kwargs):
        calls.append((args, kwargs))
        return type("P", (), {"stdout": "done", "stderr": "", "returncode": 0})()

    tools = {t.name: t for t in make_security_tools(
        bash_enabled=False, strix_enabled=True, runner=_runner,
        strix_run_dir=tmp_path, strix_path="/fake/strix", resolver=_VM_RESOLVER,
    )}
    out = tools["sandbox_pentest_strix"].invoke({"target": "127.0.0.1"})
    assert "done" in out
    assert len(calls) == 1
    args, kwargs = calls[0]
    assert args[0] == "/fake/strix" and "127.0.0.1" in args
    assert kwargs["shell"] is False
    assert kwargs["cwd"] == str(tmp_path)
    assert kwargs.get("stdin") is subprocess.DEVNULL
    assert kwargs.get("start_new_session") is True
    env = kwargs["env"]
    for leaked in ("KUBECONFIG", "AWS_ACCESS_KEY_ID", "AZURE_CLIENT_SECRET", "OPENAI_API_KEY",
                   "TRINO_TOKEN", "SHELL_VM_PASSWORD", "DOCKER_HOST"):
        assert leaked not in env
    assert env["HOME"] == str(tmp_path / "home") != str(Path.home())
    assert (tmp_path / "home" / "tmp").is_dir()


def test_strix_tool_rejects_private_range_before_running(tmp_path):
    """사설 대역 전체 허용은 제거됐다 — runner 는 호출조차 되지 않는다."""
    calls = []
    tools = {t.name: t for t in make_security_tools(
        bash_enabled=False, strix_enabled=True, strix_run_dir=tmp_path,
        strix_path="/fake/strix", resolver=_VM_RESOLVER,
        runner=lambda *a, **k: calls.append((a, k)),
    )}
    for target in ("10.96.0.10", "192.168.1.5", "nexus-shell.svc.cluster.local"):
        assert "거부됨" in tools["sandbox_pentest_strix"].invoke({"target": target})
    assert calls == []


def test_security_auditor_prompt_documents_allowlist():
    """문서-코드 드리프트 재발 방지 — 프롬프트가 실제 허용목록/격리 등급을 반영해야 한다."""
    from src.agents import load_agents

    agents = load_agents(Path(__file__).resolve().parent.parent / ".agents")
    text = agents["security-auditor"].instructions
    assert "*.vmlab.test" in text
    assert "허용목록" in text
    assert "denylist" in text
    assert "호스트에서 직접 실행" in text  # strix 격리 등급 정직화
