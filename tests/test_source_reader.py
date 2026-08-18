"""SSH 소스 열람 도구 검증 — 명령 화이트리스트·인젝션 방어·틸드 확장 (mocked runner)."""

from __future__ import annotations

import pytest

from src.tools.source_reader import (
    SourceAccessError,
    SourceHost,
    _quote_path,
    make_source_tools,
)


class FakeProc:
    def __init__(self, rc=0, out="OUT", err=""):
        self.returncode, self.stdout, self.stderr = rc, out, err


def _host(capture):
    def runner(args, **kwargs):
        capture.append(args)
        return FakeProc()
    return SourceHost("heejoon@172.29.70.161", runner=runner), runner


def test_target_format_validation():
    with pytest.raises(SourceAccessError):
        SourceHost("not a target")
    with pytest.raises(SourceAccessError):
        SourceHost("user@host; rm -rf /")
    SourceHost("heejoon@172.29.70.161")  # 정상


def test_quote_path_tilde_expansion():
    # 선행 ~/ 는 인용 밖(홈 확장 가능), 나머지는 인용
    assert _quote_path("~") == "~"
    assert _quote_path("~/WebstormProjects/nexus-shell").startswith("~/")
    # .. 는 거부
    with pytest.raises(SourceAccessError):
        _quote_path("~/../etc")


def test_commands_are_fixed_readonly_forms():
    calls: list = []
    host, _ = _host(calls)
    host.list_dir("~/nexus-ai")
    host.read_file("~/nexus-ai/README.md", 1, 50)
    host.search("~/nexus-lake", "bronze", "*.py", 10)
    host.find_files("~/WebstormProjects/nexus-shell", "Dockerfile")
    host.repo_log("~/nexus-ai", 5)  # git/svn 자동 감지 조건문
    host.repo_log("~/scm/repo/svn/CLOUD", 3)
    # 원격에서 실행되는 건 ssh 마지막 인자(remote_cmd) — 전부 읽기 명령만
    remote_cmds = [c[-1] for c in calls]
    assert all(c.split()[0] in ("ls", "sed", "grep", "find", "git", "if") for c in remote_cmds)
    # repo_log(조건문)에는 git/svn 읽기 부속명령만 등장한다
    for c in remote_cmds:
        if c.startswith("if"):
            assert " svn log " in c and "git -C" in c
            assert not any(w in c for w in ("svn commit", "svn delete", "svn import", "git push"))
    # 쓰기/실행 흔적이 없어야 한다
    for c in remote_cmds:
        assert not any(w in c for w in ("rm ", "mv ", " > ", ">>", "chmod", "curl", "wget"))


def test_injection_defenses():
    calls: list = []
    host, _ = _host(calls)
    with pytest.raises(SourceAccessError):
        host.read_file("../../etc/passwd")
    with pytest.raises(SourceAccessError):
        host.search("~", "ok", glob="*.py; rm -rf /")  # glob 메타문자 거부
    with pytest.raises(SourceAccessError):
        host.find_files("~", "a`whoami`")  # 파일명 백틱 거부
    # 패턴에 셸 메타가 있어도 shlex 인용되어 grep 리터럴로 전달 (예외 없이 안전 처리)
    host.search("~/nexus-ai", "a && b")
    grep_cmd = calls[-1][-1]
    assert "'a && b'" in grep_cmd  # 통째로 인용됨


def test_tools_registered_as_source_read():
    from src.tools import verb_validator

    tools = make_source_tools(SourceHost("heejoon@172.29.70.161"))
    names = {t.name for t in tools}
    assert names == {"src_list_dir", "src_read_file", "src_search", "src_find_files", "src_repo_log"}
    reg = verb_validator.registered_tools()
    for n in names:
        assert reg[n].verb == "source-read"


def test_guarded_tool_rejects_bad_path():
    tools = {t.name: t for t in make_source_tools(SourceHost("heejoon@172.29.70.161"))}
    out = tools["src_read_file"].invoke({"path": "../../etc/passwd"})
    assert "[거부됨" in out


def test_code_correlator_agent_loads():
    from pathlib import Path

    from src.agents import load_agents

    agents = load_agents(Path(__file__).resolve().parent.parent / ".agents")
    cc = agents.get("code-correlator")
    assert cc is not None
    for marker in ("src_search", "nexus-shell", "read-only", "파일:줄"):
        assert marker in cc.instructions
