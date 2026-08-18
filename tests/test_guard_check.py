"""6-6 마스터 크리덴셜 격리 네거티브 테스트.

guard-check.sh에 마스터 클러스터를 가리키도록 조작된 KUBECONFIG를 넣으면 즉시 실패해야 하고,
src/config.py의 fail-fast 가드도 동일하게 동작해야 한다.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
import yaml

from src.config import UnsafeKubeconfigError, assert_safe_kubeconfig

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GUARD = PROJECT_ROOT / "local-verify" / "guard-check.sh"


def write_kubeconfig(path: Path, server: str, name: str = "sandbox", ca: str = "c2FuZGJveC1jYQ=="):
    doc = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": name, "cluster": {"server": server, "certificate-authority-data": ca}}],
        "contexts": [{"name": name, "context": {"cluster": name, "user": name}}],
        "users": [{"name": name, "user": {}}],
        "current-context": name,
    }
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def run_guard(kubeconfig: Path | None, master: Path) -> subprocess.CompletedProcess:
    env = {k: v for k, v in os.environ.items() if k != "KUBECONFIG"}
    if kubeconfig is not None:
        env["KUBECONFIG"] = str(kubeconfig)
    env["GUARD_MASTER_KUBECONFIG"] = str(master)
    return subprocess.run([str(GUARD)], env=env, capture_output=True, text=True)


def test_guard_fails_on_server_overlap(tmp_path):
    master = write_kubeconfig(tmp_path / "master.yaml", "https://10.0.0.5:6443", "dev-master", "bWFzdGVyLWNh")
    sandbox = write_kubeconfig(tmp_path / "sandbox.yaml", "https://10.0.0.5:6443", "sandbox", "c2FuZGJveA==")
    result = run_guard(sandbox, master)
    assert result.returncode != 0, result.stdout + result.stderr
    assert "서버 주소" in result.stderr


def test_guard_fails_on_ca_overlap(tmp_path):
    shared_ca = "c2hhcmVkLWNhLWRhdGE="
    master = write_kubeconfig(tmp_path / "master.yaml", "https://10.0.0.5:6443", "dev-master", shared_ca)
    sandbox = write_kubeconfig(tmp_path / "sandbox.yaml", "https://127.0.0.1:60000", "sandbox", shared_ca)
    result = run_guard(sandbox, master)
    assert result.returncode != 0
    assert "CA 지문" in result.stderr


def test_guard_fails_when_kubeconfig_is_master_itself(tmp_path):
    master = write_kubeconfig(tmp_path / "master.yaml", "https://10.0.0.5:6443", "dev-master")
    result = run_guard(master, master)
    assert result.returncode != 0


def test_guard_fails_on_prod_context(tmp_path):
    master = write_kubeconfig(tmp_path / "master.yaml", "https://10.0.0.5:6443", "dev-master")
    sandbox = write_kubeconfig(tmp_path / "sandbox.yaml", "https://127.0.0.1:60000", "prod-cluster")
    result = run_guard(sandbox, master)
    assert result.returncode != 0
    assert "prod" in result.stderr.lower()


def test_guard_fails_without_kubeconfig(tmp_path):
    master = write_kubeconfig(tmp_path / "master.yaml", "https://10.0.0.5:6443", "dev-master")
    result = run_guard(None, master)
    assert result.returncode != 0


def test_guard_passes_on_isolated_sandbox(tmp_path):
    master = write_kubeconfig(tmp_path / "master.yaml", "https://10.0.0.5:6443", "dev-master", "bWFzdGVyLWNh")
    sandbox = write_kubeconfig(tmp_path / "sandbox.yaml", "https://127.0.0.1:60000", "kind-sandbox", "c2FuZGJveA==")
    result = run_guard(sandbox, master)
    assert result.returncode == 0, result.stdout + result.stderr


# ---------- src/config.py 앱 레벨 가드 ----------

def test_config_rejects_missing_kubeconfig():
    with pytest.raises(UnsafeKubeconfigError):
        assert_safe_kubeconfig(None)


def test_config_rejects_prod_context(tmp_path):
    cfg = write_kubeconfig(tmp_path / "kc.yaml", "https://127.0.0.1:60000", "team-production")
    with pytest.raises(UnsafeKubeconfigError):
        assert_safe_kubeconfig(str(cfg))


def test_config_rejects_master_kubeconfig_path(tmp_path):
    fake_home = tmp_path / "home"
    (fake_home / ".kube").mkdir(parents=True)
    master = write_kubeconfig(fake_home / ".kube" / "config", "https://10.0.0.5:6443", "dev-master")
    with pytest.raises(UnsafeKubeconfigError):
        assert_safe_kubeconfig(str(master), home=fake_home)
