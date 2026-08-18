"""위키·에이전트 편집 API 검증.

- 위키: 목록/조회/편집(레다크션 강제, 경로 조작 차단, 신규 생성 불가)
- 에이전트: 원문 조회/편집/생성 (frontmatter name 일치 강제, 레지스트리 즉시 리로드)
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from src.llm import HeuristicPlannerModel
from src.web import make_app
from tests.conftest import StubReadOnlyClient
from tests.test_web_harness import _fake_kubeconfig, _settings

WIKI_PAGE = """---
entity: crashloop-demo
namespace: default
type: workload
---

# crashloop-demo

## 관찰 이력

- 2026-08-18T00:00:00+00:00: phase=Running, restarts=3
"""


def _editor_client(tmp_path) -> tuple[TestClient, object]:
    settings = _settings(tmp_path, _fake_kubeconfig(tmp_path))
    (settings.wiki_dir / "workloads").mkdir(parents=True, exist_ok=True)
    (settings.wiki_dir / "workloads" / "crashloop-demo.md").write_text(WIKI_PAGE, encoding="utf-8")
    settings.agents_dir.mkdir(exist_ok=True)
    (settings.agents_dir / "sre-triage.md").write_text(
        "---\nname: sre-triage\ndescription: 장애 분류\n---\n\n이벤트를 확인하라.\n",
        encoding="utf-8",
    )
    app = make_app(settings=settings, model=HeuristicPlannerModel(), k8s=StubReadOnlyClient())
    return TestClient(app), settings


# ---------- 위키 ----------

def test_wiki_list_and_read(tmp_path):
    client, _ = _editor_client(tmp_path)
    sections = client.get("/api/wiki").json()["sections"]
    assert any(p["path"] == "workloads/crashloop-demo.md" for p in sections.get("workloads", []))
    page = client.get("/api/wiki/page", params={"path": "workloads/crashloop-demo.md"}).json()
    assert "관찰 이력" in page["content"]


def test_wiki_edit_applies_redaction(tmp_path):
    client, settings = _editor_client(tmp_path)
    edited = WIKI_PAGE + "\n- 메모: db password: Sup3rSecret1 로 접속됨\n"
    res = client.put(
        "/api/wiki/page",
        json={"path": "workloads/crashloop-demo.md", "content": edited},
    )
    assert res.status_code == 200 and res.json()["redacted"] is True
    saved = (settings.wiki_dir / "workloads" / "crashloop-demo.md").read_text(encoding="utf-8")
    assert "Sup3rSecret1" not in saved and "[REDACTED]" in saved
    assert "관찰 이력" in saved  # 기존 내용 유지


def test_wiki_rejects_traversal_and_new_pages(tmp_path):
    client, _ = _editor_client(tmp_path)
    assert client.get("/api/wiki/page", params={"path": "../pyproject.toml"}).status_code == 404
    assert (
        client.put("/api/wiki/page", json={"path": "../evil.md", "content": "x"}).status_code == 400
    )
    # 존재하지 않는 페이지는 편집으로 만들 수 없다 (페이지 생성은 조사 플로우의 몫)
    assert (
        client.put("/api/wiki/page", json={"path": "workloads/new.md", "content": "x"}).status_code
        == 404
    )


# ---------- 에이전트 ----------

def test_agent_raw_view_edit_and_reload(tmp_path):
    client, settings = _editor_client(tmp_path)
    raw = client.get("/api/agents/sre-triage/raw").json()
    assert "이벤트를 확인하라" in raw["content"]

    new_content = "---\nname: sre-triage\ndescription: 장애 분류 v2\n---\n\n로그를 먼저 보라.\n"
    res = client.put("/api/agents/sre-triage/raw", json={"content": new_content})
    assert res.status_code == 200
    # 레지스트리 즉시 리로드 확인
    detail = client.get("/api/agents/sre-triage").json()
    assert detail["description"] == "장애 분류 v2"
    assert "로그를 먼저" in detail["instructions"]
    assert "로그를 먼저" in (settings.agents_dir / "sre-triage.md").read_text(encoding="utf-8")


def test_agent_edit_rejects_name_mismatch_and_bad_names(tmp_path):
    client, _ = _editor_client(tmp_path)
    res = client.put(
        "/api/agents/sre-triage/raw",
        json={"content": "---\nname: other-name\n---\n\nx\n"},
    )
    assert res.status_code == 400 and "일치" in res.json()["error"]
    assert client.get("/api/agents/../../etc/raw").status_code in (400, 404)
    assert client.put("/api/agents/UPPER/raw", json={"content": "x"}).status_code == 400


def test_agent_create_and_duplicate(tmp_path):
    client, settings = _editor_client(tmp_path)
    content = "---\nname: net-debug\ndescription: 네트워크 조사\n---\n\n서비스와 엔드포인트를 보라.\n"
    res = client.post("/api/agents/create", json={"name": "net-debug", "content": content})
    assert res.status_code == 200
    assert (settings.agents_dir / "net-debug.md").is_file()
    names = {a["name"] for a in client.get("/api/agents").json()["agents"]}
    assert "net-debug" in names
    # 중복 생성 거부
    assert client.post("/api/agents/create", json={"name": "net-debug"}).status_code == 409


def test_builtin_inspector_edit_materializes_file(tmp_path):
    client, settings = _editor_client(tmp_path)
    raw = client.get("/api/agents/inspector/raw").json()
    assert "builtin" in raw["source"]
    content = "---\nname: inspector\ndescription: 기본 조사자 커스텀\n---\n\n항상 결론 먼저.\n"
    assert client.put("/api/agents/inspector/raw", json={"content": content}).status_code == 200
    assert (settings.agents_dir / "inspector.md").is_file()
    assert client.get("/api/agents/inspector").json()["description"] == "기본 조사자 커스텀"
