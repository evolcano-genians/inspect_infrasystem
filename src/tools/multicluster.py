"""멀티 클러스터 비교 도구 — 두 개 이상의 k8s 상태를 나란히 읽어 비교한다.

목적: 세션은 기본 컨텍스트 하나에 묶이지만, AWS(aws-seoul-clouddev)와
Azure(azure-uae-gsp)의 배포 상태를 한 조사에서 대조해야 할 때가 많다.
이 도구는 등록된 안전 컨텍스트별 ReadOnlyK8sClient를 그대로 재사용해
동일 리소스를 각 클러스터에서 읽어 side-by-side 로 돌려준다.

안전 불변식: 각 클라이언트는 GuardedApiClient(GET-only) 위에 세워진
read-only 파사드다 — 이 도구는 새 전송 경로를 만들지 않고 기존 list_* 조회
메서드만 호출하므로 '실 클러스터엔 GET만' 원칙이 그대로 유지된다.
"""

from __future__ import annotations

import time
from typing import Callable

from langchain_core.tools import StructuredTool

from . import verb_validator
from ..audit import AuditLogger

# 리소스 종류 → 각 클라이언트에서 읽는 방법 (namespace 인자 사용 여부 포함).
# 값이 (reader, needs_namespace). 전부 read-only list_* 메서드다.
_RESOURCE_READERS: dict[str, tuple[Callable, bool]] = {
    "namespaces": (lambda c, ns: c.list_namespaces(), False),
    "nodes": (lambda c, ns: c.list_nodes(), False),
    "crds": (lambda c, ns: c.list_crds(), False),
    "pods": (lambda c, ns: c.list_pods(ns), True),
    "deployments": (lambda c, ns: c.list_deployments(ns), True),
    "statefulsets": (lambda c, ns: c.list_statefulsets(ns), True),
    "daemonsets": (lambda c, ns: c.list_daemonsets(ns), True),
    "jobs": (lambda c, ns: c.list_jobs(ns), True),
    "cronjobs": (lambda c, ns: c.list_cronjobs(ns), True),
    "services": (lambda c, ns: c.list_services(ns), True),
    "ingresses": (lambda c, ns: c.list_ingresses(ns), True),
    "pvcs": (lambda c, ns: c.list_pvcs(ns), True),
    "configmaps": (lambda c, ns: c.list_configmaps(ns), True),
    "events": (lambda c, ns: c.list_events(ns), True),
}

#: k8s_compare/k8s_read_at 가 받는 resource enum — verb_validator 가 이 집합으로 검증
COMPARE_RESOURCES = frozenset(_RESOURCE_READERS)


def make_multicluster_tools(
    clients: dict[str, object], audit: AuditLogger | None = None
) -> list[StructuredTool]:
    """컨텍스트명 → ReadOnlyK8sClient 매핑으로 비교 도구를 만든다.

    clients 가 2개 미만이면 비교할 대상이 없으므로 빈 목록을 반환한다.
    """
    if not clients or len(clients) < 2:
        return []

    context_names = sorted(clients)

    def _record(tool: str, allowed: bool, reason: str = "", **extra):
        if audit:
            audit.record(tool=tool, verb="list", resource="multi-cluster",
                         allowed=allowed, reason=reason, **extra)

    def _guarded(tool_name: str, fn: Callable) -> Callable:
        # verb 는 list(read-only) — 레지스트리에 등록해 executor 검증을 통과시킨다.
        verb_validator.register_tool(tool_name, "list", "multi-cluster")

        def wrapper(**kwargs):
            verdict = verb_validator.validate_tool_call(tool_name, kwargs)
            if not verdict.allowed:
                _record(tool_name, False, verdict.reason)
                return f"[거부됨 · read-only 정책] {verdict.reason}"
            started = time.perf_counter()
            try:
                result = fn(**kwargs)
            except Exception as exc:  # 한 클러스터 오류가 전체 조사를 죽이지 않도록
                result = f"[비교 도구 오류] {type(exc).__name__}: {exc}"
            _record(tool_name, True, duration_ms=(time.perf_counter() - started) * 1000,
                    result_chars=len(str(result)))
            return result

        return wrapper

    def list_contexts() -> dict:
        """비교 가능한 클러스터 컨텍스트 목록을 반환한다."""
        return {"contexts": context_names, "count": len(context_names),
                "note": "k8s_compare(resource, namespace) 로 이 컨텍스트들을 한 번에 대조하라"}

    def compare(resource: str, namespace: str = "") -> dict:
        """동일 리소스를 등록된 모든 클러스터에서 읽어 side-by-side 로 반환한다.

        resource: namespaces/nodes/crds/pods/deployments/statefulsets/daemonsets/
                  jobs/cronjobs/services/ingresses/pvcs/configmaps/events
        namespace: 네임스페이스 스코프 리소스에 필요 (파드·디플로이먼트 등).
        """
        reader, needs_ns = _RESOURCE_READERS[resource]
        if needs_ns and not namespace:
            return {"error": f"'{resource}' 는 namespace 인자가 필요합니다"}
        by_context: dict[str, object] = {}
        for ctx in context_names:
            client = clients[ctx]
            try:
                items = reader(client, namespace)
                count = len(items) if isinstance(items, list) else None
                by_context[ctx] = {"count": count, "items": items}
            except Exception as exc:
                by_context[ctx] = {"error": f"{type(exc).__name__}: {exc}"}
        return {"resource": resource, "namespace": namespace or None, "by_context": by_context}

    def read_at(context: str, resource: str, namespace: str = "") -> dict:
        """특정 클러스터 하나에서만 리소스를 읽는다 (컨텍스트별로 네임스페이스가 다를 때).

        k8s_list_contexts 로 확인한 정확한 컨텍스트명을 써라.
        """
        if context not in clients:
            return {"error": f"알 수 없는 컨텍스트 {context!r}. 가능: {context_names}"}
        reader, needs_ns = _RESOURCE_READERS[resource]
        if needs_ns and not namespace:
            return {"error": f"'{resource}' 는 namespace 인자가 필요합니다"}
        try:
            items = reader(clients[context], namespace)
        except Exception as exc:
            return {"context": context, "error": f"{type(exc).__name__}: {exc}"}
        return {"context": context, "resource": resource, "namespace": namespace or None,
                "count": len(items) if isinstance(items, list) else None, "items": items}

    resources_doc = ", ".join(sorted(COMPARE_RESOURCES))
    specs = [
        ("k8s_list_contexts",
         "비교 가능한 k8s 클러스터 컨텍스트(예: aws-seoul-clouddev, azure-uae-gsp) 목록을 조회한다. "
         "두 클러스터를 대조하기 전에 먼저 호출해 정확한 컨텍스트명을 확인하라.",
         lambda: list_contexts()),
        ("k8s_compare",
         "동일 리소스를 등록된 모든 클러스터에서 한 번에 읽어 side-by-side로 반환한다 "
         "(AWS vs Azure 배포 상태 대조용). 반환의 by_context[컨텍스트]로 각 클러스터 결과를 "
         f"비교하라. resource ∈ {{{resources_doc}}}. 네임스페이스 스코프 리소스는 namespace 필수.",
         lambda resource, namespace="": compare(resource, namespace)),
        ("k8s_read_at",
         "특정 컨텍스트 하나에서만 리소스를 읽는다 (클러스터마다 네임스페이스 이름이 다를 때 유용). "
         f"resource ∈ {{{resources_doc}}}.",
         lambda context, resource, namespace="": read_at(context, resource, namespace)),
    ]

    tools: list[StructuredTool] = []
    for name, description, fn in specs:
        tools.append(StructuredTool.from_function(
            func=_make_typed(fn, _guarded(name, fn)), name=name, description=description,
        ))
    return tools


def _make_typed(original, guarded):
    """StructuredTool 스키마 추론을 위해 원본 람다 시그니처를 래퍼에 입힌다."""
    import inspect

    sig = inspect.signature(original)

    def typed(**kwargs):
        return guarded(**kwargs)

    typed.__signature__ = sig  # type: ignore[attr-defined]
    typed.__annotations__ = {name: str for name in sig.parameters}
    return typed
