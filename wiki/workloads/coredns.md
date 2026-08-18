---
baseline:
  replicas: 2
created: '2026-08-18'
entity: coredns
kind: Deployment
last_inspected: '2026-08-18'
namespace: kube-system
type: workload
---

# coredns

네임스페이스 `kube-system` 의 Deployment.

## 관찰 이력

- 2026-08-18T08:02:36+00:00: Deployment replicas desired=2 ready=2 available=2
- 2026-08-18T09:21:17+00:00: Deployment replicas desired=1 ready=1 available=1
> ⚠️ 모순 노트 (2026-08-18): `replicas` 관찰값 1 — 기존 기준선 2 과 다름. 기준선과 과거 기록은 유지하며 히스토리를 지우지 않는다.
