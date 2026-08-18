"""GET-only 전송 가드 — 방어선 3.

`kubernetes.client.ApiClient`를 서브클래싱해, HTTP 요청이 네트워크로 나가기 직전의
단일 choke point인 ``request()``에서 다음을 차단한다.

1. HTTP 메서드가 GET이 아닌 모든 요청.
   Kubernetes API의 모든 mutation(create/update/patch/delete)은 POST/PUT/PATCH/DELETE이므로,
   상위 레이어(read facade, verb validator)가 전부 뚫리는 가상의 상황에서도
   쓰기 요청은 이 지점을 통과할 수 없다.
2. GET이더라도 read-only 정책상 금지된 경로:
   exec/attach(원격 실행), portforward, proxy(우회 통로), secrets(민감정보).

이 가드는 fail-closed다: 금지 여부가 애매한 경로(예: 우연히 이름이 "secrets"인 리소스)는
차단 쪽으로 판정된다. 오탐으로 조사가 한 번 실패하는 비용이,
미탐으로 쓰기/유출이 발생하는 비용보다 항상 싸다.
"""

from __future__ import annotations

import re

from kubernetes.client import ApiClient


class ReadOnlyViolation(RuntimeError):
    """read-only 정책을 위반하는 요청이 전송 직전에 감지되었다."""


#: GET이어도 차단하는 경로 세그먼트. (경로 경계 기준 매칭)
FORBIDDEN_PATH_SEGMENTS: tuple[str, ...] = (
    "exec",         # pod 원격 실행 (websocket upgrade가 GET으로 시작함)
    "attach",       # pod attach
    "portforward",  # 포트포워딩
    "proxy",        # API 프록시 (임의 백엔드로의 우회 통로)
    "secrets",      # Secret 리소스 — 이 에이전트의 범위 밖 (README §1)
    "eviction",     # eviction 서브리소스
    "finalize",     # namespace finalize
)

_FORBIDDEN_RE = re.compile(
    r"/(?:" + "|".join(FORBIDDEN_PATH_SEGMENTS) + r")(?:/|$)", re.IGNORECASE
)


def check_request_allowed(method: str, url: str) -> None:
    """요청 (method, url)이 read-only 정책에 부합하는지 검사. 위반 시 예외.

    결정론적 코드이며 LLM 판단이 개입하지 않는다. O(len(url)).
    """
    normalized = (method or "").strip().upper()
    if normalized != "GET":
        raise ReadOnlyViolation(
            f"read-only 정책 위반: HTTP {normalized} 요청이 차단되었습니다 (GET만 허용). url={url}"
        )
    path = url.split("?", 1)[0]
    match = _FORBIDDEN_RE.search(path)
    if match:
        raise ReadOnlyViolation(
            f"read-only 정책 위반: 금지된 경로 세그먼트 '{match.group(0)}' 가 포함된 "
            f"요청이 차단되었습니다. url={url}"
        )


class GuardedApiClient(ApiClient):
    """모든 HTTP 요청을 GET-only + 경로 화이트리스트로 강제하는 ApiClient."""

    def request(self, method, url, *args, **kwargs):  # noqa: D102 - 부모 시그니처 유지
        check_request_allowed(method, url)
        return super().request(method, url, *args, **kwargs)
