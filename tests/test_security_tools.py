"""샌드박스 보안 도구 검증 — 구조적 격리·strix 대상 제한 (docker/subprocess mock)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.sandbox.bash_exec import BashSandbox, SandboxExecError, _assert_safe_config
from src.sandbox.security_tools import _is_sandbox_target, make_security_tools


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
    ("/work/cloned-src", True),
    ("http://nexus.clouddev.dev.genians.kr", False),  # 공개 도메인 거부
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
    assert "실 aws/azure" in sa.instructions  # 실 인프라 금지 명시
