---
date: '2026-08-19'
session_id: web-bdf5edcd
type: session
---

# 세션 web-bdf5edcd (2026-08-19)

## 질문

원인 파악해서 해결 방법 알려줘

## 결론

**결론:** Botkube 오류가 아니라 Kubernetes의 실제 장애 이벤트입니다. `kafka-0`과 `bronze-ingestor`의 RWO 블록 볼륨이 **AWS `ap-northeast-2b`에 고정**되어 있는데, 해당 AZ에 배치 가능한 노드 2대가 스케줄 불가 상태여서 Pod가 계속 `Pending`입니다.  
Trino 알림은 기동 중 `/v1/info` 응답이 늦어 발생한 일시적 readiness timeout이며 현재는 정상 복구됐습니다. 우선 **2b 노드 복구/uncordon → Kafka → bronze-ingestor 순서**로 해결해야 합니다.

**관찰 결과** — AWS `aws-seoul-clouddev`, 2026-08-19 도구 응답 기준

| 대상 | 현재 상태 | 원인 판단 |
|---|---:|---|
| `kafka-0` | `Pending`, StatefulSet `0/1` | `data-kafka-0-2b` RWO 볼륨의 AZ와 정상 배치 가능 노드 불일치 |
| `bronze-ingestor-69b4bd79b8-22hcg` | `Pending`, Deployment `0/1` | `bronze-ingestor-runtime-2b` RWO 볼륨의 AZ 고정 |
| 스케줄러 | `2 unschedulable`, `3 affinity mismatch` | 2b 후보 노드 2대는 스케줄 불가, 나머지 3대는 볼륨 node affinity 불일치 |
| `trino-5cb78b57bb-lcv5v` | `Running`, Ready, 재시작 0 | 기동 중 readiness timeout 후 정상화 |
| Botkube | `Running`, Ready `1/1` | 이벤트를 정상 전달 중이며 Botkube 자체 장애 아님 |
| 클러스터 노드 | 5대 모두 `Ready` | `Ready`여도 cordon(`SchedulingDisabled`) 상태일 수 있어 확인 필요 |

```mermaid
flowchart LR
    AZ2B["ap-northeast-2b 블록 볼륨"] --> KPV["data-kafka-0-2b"]
    AZ2B --> BPV["bronze-ingestor-runtime-2b"]
    KPV --> K["kafka-0 Pending"]
    BPV --> B["bronze-ingestor Pending"]
    N["2b 노드 2대\ncordon/스케줄 불가 추정"] -. 배치 실패 .-> K
    N -. 배치 실패 .-> B
    K --> WI["bronze wait-runtime"]
    WI --> B
```

**해결 순서**

1. 2b 노드의 cordon 여부와 taint를 확인합니다.
   ```bash
   kubectl --context aws-seoul-clouddev get nodes \
     -L topology.kubernetes.io/zone
   kubectl --context aws-seoul-clouddev describe node <2b-node>
   ```
2. 유지보수 종료 후 정상 노드라면 `kubectl uncordon <2b-node>`로 최소 1대를 다시 스케줄 가능하게 합니다. 노드 장애라면 **`ap-northeast-2b`에 대체 워커를 추가**해야 합니다.
3. `kafka-0`이 먼저 `Running/Ready`가 되는지 확인합니다. `bronze-ingestor`는 init container에서 Kafka `9092` 연결을 기다리므로 Kafka가 복구되어야 기동할 수 있습니다.
4. 2b 노드를 사용할 수 없다면 기존 EBS를 다른 AZ로 직접 이동할 수 없으므로 **스냅샷 → 정상 AZ의 새 EBS/PV/PVC 생성 → 워크로드 연결 변경**이 필요합니다. 단순히 Pod affinity만 제거하면 볼륨 attach 단계에서 다시 실패합니다.
5. Trino는 현재 조치가 필요하지 않습니다. 같은 알림이 반복된다면 Helm의 Trino `readinessProbe`에 `startupProbe`를 추가하거나 `initialDelaySeconds`, `timeoutSeconds`, `failureThreshold`를 늘려 초기화 시간을 허용합니다.
6. Botkube 노이즈는 장애 해결 후 조정합니다. `botkube-configmap`의 `resource_config.yaml`에서 transient readiness 이벤트를 제한하되, `FailedScheduling`은 실제 서비스 중단 신호이므로 유지하는 편이 안전합니다.

Helm 차트 작업복사본은 SVN HEAD보다 오래된 상태(`r7915`, HEAD `r7917`)이므로 변경 전 `svn update`가 필요합니다. 저는 read-only 에이전트라 uncordon이나 볼륨 변경은 직접 실행할 수 없습니다.

## 도구 호출 (audit 로그 상위 요약 — 원본은 logs/)

- (도구 호출 없음 — 위키 재사용)
