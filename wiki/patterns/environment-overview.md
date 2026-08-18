---
type: pattern
tags: [nexus-shell, shell-apps, aws-seoul-clouddev, environment, dev]
---

# dev 환경 개요 (aws-seoul-clouddev) — 사람이 확인해준 사실

> 사용자가 직접 알려준 환경 지식. 조사 시 전제로 사용하라.

- 이 dev 클러스터에는 **nexus-shell 플랫폼**이 배포돼 있다 (ns `nexus-shell`,
  helm 릴리스 `nexus-shell`·`backend-nexus-shell`·`shell-apps-*`).
- nexus-shell 위에 **각각의 shell app**이 배포된다 — 관찰된 구성요소:
  Kafka·Loki(StatefulSet), lake-trino, hive-metastore, kestra, lake-widget,
  bronze-ingestor, nexus-actions, BFF(nexus-shell-bff), oauth2-proxy, adminer.
- 라우팅은 표준 Ingress가 아니라 **Traefik CRD**(IngressRoute/Middleware,
  `traefik.io