"""자연어 질의 진입점.

    KUBECONFIG=.local/kind-kubeconfig.yaml python -m src.cli "CrashLoopBackOff 파드 찾아줘"
"""

from __future__ import annotations

import argparse
import sqlite3
import uuid

from langchain_core.messages import HumanMessage
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.errors import GraphRecursionError

from .audit import AuditLogger
from .config import assert_safe_kubeconfig, load_settings
from .graph import build_graph, recommended_recursion_limit
from .llm import make_model
from .tools.k8s_read import ReadOnlyK8sClient


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Read-only K8s inspection agent")
    parser.add_argument("question", help="자연어 질의")
    parser.add_argument("--thread", default=None, help="세션(thread) id — 재개 시 동일 값 사용")
    parser.add_argument(
        "--context",
        default=None,
        help="kubeconfig 컨텍스트 (실 클러스터 조사 시 필수, 예: aws-seoul-clouddev)",
    )
    args = parser.parse_args(argv)

    settings = load_settings()
    context = args.context or settings.kube_context or None
    # fail-fast: 실 kubeconfig는 opt-in+컨텍스트 필요, prod 컨텍스트는 어떤 모드에서도 거부
    assert_safe_kubeconfig(
        settings.kubeconfig, context=context, allow_real=settings.allow_real_cluster
    )

    thread = args.thread or uuid.uuid4().hex[:8]
    settings.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
    saver = SqliteSaver(sqlite3.connect(str(settings.checkpoint_db), check_same_thread=False))

    target = "실 클러스터(read-only)" if settings.allow_real_cluster else "샌드박스"
    print(f"[대상] {target} · 컨텍스트={context or '(current)'}\n", flush=True)
    graph = build_graph(
        model=make_model(settings),
        k8s=ReadOnlyK8sClient(settings.kubeconfig, context=context),
        wiki_dir=settings.wiki_dir,
        audit=AuditLogger(settings.logs_dir),
        checkpointer=saver,
    )
    try:
        result = graph.invoke(
            {"question": args.question, "session_id": thread, "messages": [HumanMessage(args.question)]},
            config={"configurable": {"thread_id": thread},
                    "recursion_limit": recommended_recursion_limit()},
        )
    except GraphRecursionError:
        print("오류: 그래프 재귀 한도에 도달했습니다. --thread 를 새 값으로 바꿔 다시 시도하세요.")
        raise SystemExit(1)
    except Exception as exc:  # LLM 인증 실패 등 — 원인만 짧게 보여주고 종료
        print(f"오류: 조사 실행에 실패했습니다 — {type(exc).__name__}: {exc}")
        raise SystemExit(1)
    print(result.get("final_answer") or "(답변 없음)")
    usage = result.get("usage") or {}
    if usage.get("total_tokens"):
        print(
            f"\n[토큰 사용량] in={usage.get('input_tokens', 0):,} "
            f"out={usage.get('output_tokens', 0):,} "
            f"total={usage.get('total_tokens', 0):,} (LLM 호출 {usage.get('llm_calls', 0)}회)"
        )


if __name__ == "__main__":
    main()
