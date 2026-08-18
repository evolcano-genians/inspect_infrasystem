"""웹 대화 하네스 검증 — SSE 스트림, 우회 시도 거부, 휴리스틱 데모 모드.

웹 레이어는 그래프를 감싸기만 하므로 4중 방어선이 그대로 적용되어야 한다.
"""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from langchain_core.messages import AIMessage

from src.config import Settings, UnsafeKubeconfigError
from src.llm import HeuristicPlannerModel, ScriptedChatModel
from src.web import make_app
from tests.conftest import StubReadOnlyClient, ai_tool_call


def _settings(tmp_path, kubeconfig: str) -> Settings:
    wiki = tmp_path / "wiki"
    wiki.mkdir(exist_ok=True)
    return Settings(
        kubeconfig=kubeconfig,
        model_provider="fake",
        codex_model="gpt-5.6-sol",
        wiki_dir=wiki,
        logs_dir=tmp_path / "logs",
        checkpoint_db=tmp_path / "ckpt" / "graph.sqlite",
        agents_dir=tmp_path / ".agents",
    )


def _fake_kubeconfig(tmp_path) -> str:
    from tests.test_guard_check import write_kubeconfig

    return str(write_kubeconfig(tmp_path / "kc.yaml", "https://127.0.0.1:60000", "kind-sandbox"))


def _client(tmp_path, model) -> TestClient:
    app = make_app(
        settings=_settings(tmp_path, _fake_kubeconfig(tmp_path)),
        model=model,
        k8s=StubReadOnlyClient(),
    )
    return TestClient(app)


def _sse_events(response) -> list[dict]:
    events = []
    for line in response.text.splitlines():
        if line.startswith("data: "):
            events.append(json.loads(line[len("data: "):]))
    return events


def test_index_serves_chat_page(tmp_path):
    client = _client(tmp_path, HeuristicPlannerModel())
    res = client.get("/")
    assert res.status_code == 200
    assert "inspect-k8s" in res.text and "read-only" in res.text


def test_chat_streams_tool_events_and_final_answer(tmp_path):
    model = ScriptedChatModel(
        script=[
            ai_tool_call("k8s_list_pods", {"namespace": "default"}),
            AIMessage(content="결론: crashloop-demo 파드가 CrashLoopBackOff 상태입니다."),
        ]
    )
    client = _client(tmp_path, model)
    res = client.post("/api/chat", json={"message": "CrashLoopBackOff 파드 찾아줘", "thread_id": "web-t1"})
    assert res.status_code == 200
    events = _sse_events(res)
    types = [e["type"] for e in events]
    assert types[0] == "start" and types[-1] == "done"
    assert "tool_call" in types and "tool_result" in types and "final" in types
    final = next(e for e in events if e["type"] == "final")
    assert "crashloop-demo" in final["answer"]
    result = next(e for e in events if e["type"] == "tool_result")
    assert result["status"] == "허용"


def test_chat_rejects_mutating_tool_call_via_web(tmp_path):
    model = ScriptedChatModel(
        script=[
            ai_tool_call("kubectl_delete_pod", {"namespace": "default", "name": "x"}),
            AIMessage(content="read-only 에이전트라 삭제할 수 없습니다."),
        ]
    )
    client = _client(tmp_path, model)
    res = client.post("/api/chat", json={"message": "x 파드 삭제해줘", "thread_id": "web-t2"})
    events = _sse_events(res)
    result = next(e for e in events if e["type"] == "tool_result")
    assert result["status"] == "거부"
    final = next(e for e in events if e["type"] == "final")
    assert "삭제" in final["answer"]


def test_chat_validates_thread_id_and_message(tmp_path):
    client = _client(tmp_path, HeuristicPlannerModel())
    res = client.post("/api/chat", json={"message": "hi", "thread_id": "../../etc/passwd"})
    events = _sse_events(res)
    assert events[0]["type"] == "error"
    res2 = client.post("/api/chat", json={"message": "", "thread_id": "ok"})
    assert res2.status_code == 422  # pydantic min_length


def test_heuristic_model_end_to_end(tmp_path):
    """LLM 로그인 없이도(heuristic) 조사→요약이 동작해야 한다."""
    client = _client(tmp_path, HeuristicPlannerModel())
    res = client.post(
        "/api/chat",
        json={"message": "default 네임스페이스에서 CrashLoopBackOff 파드 찾아줘", "thread_id": "web-t3"},
    )
    events = _sse_events(res)
    final = next(e for e in events if e["type"] == "final")
    assert "crashloop-demo" in final["answer"]
    assert "휴리스틱" in final["answer"]  # 데모 모드임이 명시된다


def test_usage_events_and_session_token_totals(tmp_path):
    """usage_metadata가 있는 모델이면 SSE usage 이벤트와 세션 누적 토큰이 기록된다."""
    model = ScriptedChatModel(
        script=[
            AIMessage(
                content="",
                tool_calls=[{"name": "k8s_list_pods", "args": {"namespace": "default"},
                             "id": "c1", "type": "tool_call"}],
                usage_metadata={"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
            ),
            AIMessage(
                content="결론: crashloop-demo 확인.",
                usage_metadata={"input_tokens": 200, "output_tokens": 30, "total_tokens": 230},
            ),
        ]
    )
    client = _client(tmp_path, model)
    res = client.post("/api/chat", json={"message": "토큰 테스트", "thread_id": "tok-1"})
    events = _sse_events(res)
    usage_events = [e for e in events if e["type"] == "usage"]
    assert usage_events, "usage 이벤트가 없습니다"
    final_usage = usage_events[-1]
    assert final_usage["input_tokens"] == 300
    assert final_usage["output_tokens"] == 50
    assert final_usage["total_tokens"] == 350
    assert final_usage["llm_calls"] == 2

    sess = client.get("/api/sessions").json()["sessions"][0]
    assert sess["tokens_in"] == 300 and sess["tokens_out"] == 50

    # 같은 세션 두 번째 턴 — 누적된다 (스크립트 소진 → 도구 없이 종료, usage 0 추가)
    client.post("/api/chat", json={"message": "한 번 더", "thread_id": "tok-1"})
    sess2 = client.get("/api/sessions").json()["sessions"][0]
    assert sess2["tokens_in"] == 300  # usage 없는 턴은 더해지지 않음


def test_usage_absent_for_models_without_metadata(tmp_path):
    """fake/heuristic처럼 usage_metadata가 없는 모델은 usage 이벤트를 내지 않는다."""
    client = _client(tmp_path, HeuristicPlannerModel())
    res = client.post("/api/chat", json={"message": "파드 봐줘", "thread_id": "tok-2"})
    assert not [e for e in _sse_events(res) if e["type"] == "usage"]


def test_make_app_refuses_master_kubeconfig(tmp_path, monkeypatch):
    """웹 레이어도 fail-fast 가드를 통과해야만 뜬다."""
    fake_home = tmp_path / "home"
    (fake_home / ".kube").mkdir(parents=True)
    from tests.test_guard_check import write_kubeconfig

    master = write_kubeconfig(fake_home / ".kube" / "config", "https://10.0.0.5:6443", "dev-master")
    monkeypatch.setattr("pathlib.Path.home", lambda: fake_home)
    with pytest.raises(UnsafeKubeconfigError):
        make_app(settings=_settings(tmp_path, str(master)), model=HeuristicPlannerModel(), k8s=StubReadOnlyClient())
