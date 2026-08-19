"""멀티모달 입력 검증 — 이미지 content 블록이 Codex input_image 로 변환되는지."""

from __future__ import annotations

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from src.llm import _install_multimodal_patch
from src.web import _message_text


def test_message_text_extracts_text_and_counts_images():
    text, n = _message_text("그냥 문자열")
    assert text == "그냥 문자열" and n == 0
    text, n = _message_text([
        {"type": "text", "text": "이 파드 로그 봐줘"},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,BBBB"}},
    ])
    assert text == "이 파드 로그 봐줘" and n == 2


def test_multimodal_patch_builds_input_image_blocks():
    _install_multimodal_patch()
    import langchain_codex_oauth.chat_models as cm

    msgs = [
        SystemMessage(content="시스템"),
        HumanMessage(content=[
            {"type": "text", "text": "무슨 색?"},
            {"type": "image_url", "image_url": {"url": "data:image/png;base64,ZZZ"}},
        ]),
    ]
    items = cm._to_input_items(msgs)
    user_items = [i for i in items if i.get("role") == "user"]
    assert user_items, "user 아이템이 있어야 한다"
    blocks = user_items[0]["content"]
    assert {"type": "input_text", "text": "무슨 색?"} in blocks
    assert any(b.get("type") == "input_image" and b.get("image_url", "").startswith("data:image/")
               for b in blocks)


def test_multimodal_patch_preserves_plain_text_and_tools():
    _install_multimodal_patch()
    import langchain_codex_oauth.chat_models as cm

    # 문자열 content(기존 경로)는 input_text 로, assistant tool_call 도 그대로 유지
    msgs = [
        HumanMessage(content="파드 목록"),
        AIMessage(content="", tool_calls=[{"id": "c1", "name": "k8s_list_pods", "args": {"namespace": "default"}}]),
    ]
    items = cm._to_input_items(msgs)
    kinds = [i.get("type") for i in items]
    assert "message" in kinds and "function_call" in kinds
    user = [i for i in items if i.get("role") == "user"][0]
    assert user["content"][0]["type"] == "input_text"


def test_multimodal_patch_text_only_list_falls_back():
    """이미지 없는 리스트 content 도 깨지지 않고 텍스트로 처리."""
    _install_multimodal_patch()
    import langchain_codex_oauth.chat_models as cm

    items = cm._to_input_items([HumanMessage(content=[{"type": "text", "text": "안녕"}])])
    user = [i for i in items if i.get("role") == "user"][0]
    assert any(b.get("text") == "안녕" for b in user["content"])
