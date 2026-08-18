"""Formatter/Summarizer 노드 — 결정론적 압축 및 구조화.

두 가지 역할:
1. ``compact_text``: 긴 YAML/JSON 도구 출력을 결정론적으로 잘라 LLM 컨텍스트를 보호한다.
   (executor가 ToolMessage 생성 시 사용)
2. ``formatter_node``: 도구 원시 결과(raw_results)에서 위키에 축적할 구조화된
   관찰(observation) 레코드를 추출한다. LLM을 쓰지 않으므로 항상 재현 가능하다.
"""

from __future__ import annotations

from datetime import datetime, timezone

MAX_TOOL_MESSAGE_CHARS = 4_000


def compact_text(text: str, limit: int = MAX_TOOL_MESSAGE_CHARS) -> str:
    """결정론적 head/tail 절단. O(limit)."""
    if len(text) <= limit:
        return text
    head = int(limit * 0.7)
    tail = limit - head
    omitted = len(text) - head - tail
    return f"{text[:head]}\n...[중략 {omitted}자]...\n{text[-tail:]}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def extract_observations(tool_name: str, args: dict, result) -> list[dict]:
    """도구 결과 1건에서 관찰 레코드를 추출한다 (결정론적)."""
    ts = _now()
    obs: list[dict] = []
    namespace = str(args.get("namespace", ""))

    if tool_name == "k8s_list_pods" and isinstance(result, list):
        unhealthy = 0
        for pod in result:
            waiting = [
                c["state"].get("waiting")
                for c in pod.get("containers", [])
                if c.get("state", {}).get("waiting")
            ]
            restarts = sum(c.get("restart_count", 0) for c in pod.get("containers", []))
            if waiting or pod.get("phase") not in ("Running", "Succeeded"):
                unhealthy += 1
            summary = f"phase={pod.get('phase')}"
            if waiting:
                summary += f", waiting={','.join(waiting)}"
            if restarts:
                summary += f", restarts={restarts}"
            obs.append(
                {
                    "entity_type": "workload",
                    "entity": pod["name"],
                    "namespace": pod.get("namespace") or namespace,
                    "observed_at": ts,
                    "summary": summary,
                    "facts": {
                        "kind": "Pod",
                        "phase": pod.get("phase"),
                        "waiting_reasons": waiting,
                        "restarts": restarts,
                    },
                }
            )
        if namespace:
            obs.append(
                {
                    "entity_type": "namespace",
                    "entity": namespace,
                    "namespace": namespace,
                    "observed_at": ts,
                    "summary": f"pods={len(result)}, unhealthy={unhealthy}",
                    "facts": {"pod_count": len(result), "unhealthy": unhealthy},
                }
            )

    elif tool_name in ("k8s_get_deployment", "k8s_list_deployments"):
        items = result if isinstance(result, list) else [result]
        for d in items:
            if not isinstance(d, dict) or "replicas" not in d:
                continue
            rep = d["replicas"]
            obs.append(
                {
                    "entity_type": "workload",
                    "entity": d["name"],
                    "namespace": d.get("namespace") or namespace,
                    "observed_at": ts,
                    "summary": (
                        f"Deployment replicas desired={rep['desired']} "
                        f"ready={rep['ready']} available={rep['available']}"
                    ),
                    "facts": {
                        "kind": "Deployment",
                        "replicas": rep["desired"],
                        "ready": rep["ready"],
                        "images": d.get("images", []),
                    },
                }
            )

    elif tool_name == "k8s_get_pod" and isinstance(result, dict):
        waiting = [
            c["state"].get("waiting")
            for c in result.get("containers", [])
            if c.get("state", {}).get("waiting")
        ]
        restarts = sum(c.get("restart_count", 0) for c in result.get("containers", []))
        obs.append(
            {
                "entity_type": "workload",
                "entity": result["name"],
                "namespace": result.get("namespace") or namespace,
                "observed_at": ts,
                "summary": f"phase={result.get('phase')}"
                + (f", waiting={','.join(waiting)}" if waiting else "")
                + (f", restarts={restarts}" if restarts else ""),
                "facts": {
                    "kind": "Pod",
                    "phase": result.get("phase"),
                    "waiting_reasons": waiting,
                    "restarts": restarts,
                },
            }
        )

    elif tool_name == "k8s_top_pods" and isinstance(result, list):
        for row in result:
            usage = ", ".join(
                f"{c['name']}: cpu={c['cpu']} mem={c['memory']}" for c in row.get("containers", [])
            )
            obs.append(
                {
                    "entity_type": "workload",
                    "entity": row["pod"],
                    "namespace": namespace,
                    "observed_at": ts,
                    "summary": f"리소스 사용량 — {usage}",
                    "facts": {"kind": "PodMetrics"},
                }
            )

    elif tool_name == "k8s_get_pod_logs":
        # 로그 본문은 위키에 기록하지 않는다 (민감정보 가능성). 조회 사실만 남긴다.
        obs.append(
            {
                "entity_type": "workload",
                "entity": str(args.get("name", "")),
                "namespace": namespace,
                "observed_at": ts,
                "summary": f"로그 조회함 ({len(str(result))}자, tail={args.get('tail_lines', 200)})",
                "facts": {"kind": "PodLogs"},
            }
        )

    return [o for o in obs if o.get("entity")]


def formatter_node(state: dict) -> dict:
    observations: list[dict] = list(state.get("observations") or [])
    for raw in state.get("raw_results") or []:
        observations.extend(
            extract_observations(raw["tool"], raw.get("args", {}), raw.get("result"))
        )
    return {"observations": observations, "raw_results": []}
