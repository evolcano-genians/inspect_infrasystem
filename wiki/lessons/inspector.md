---
agent: inspector
type: lessons
---

# 축적된 교훈: inspector

스스로 반성해 배운 조사 전략 (append-only).

- 2026-08-18 [manual] `aws-seoul-clouddev`를 kind로 재현하는 요청에서는 20여 개 네임스페이스의 Pod를 전수 조회하지 말고, 먼저 사용자에게 재현할 애플리케이션/네임스페이스 범위를 확인한 뒤 해당 범위의 워크로드·이미지·서비스·설정·외부 의존성만 조사해야 한다. read-only 조사만으로 로컬 kind 환경을 직접 생성할 수 없으므로, 조사 결과와 함께 실행 가능한 재현 절차 및 클러스터 전용 의존성의 대체 방안을 명확히 제시한다.
- 2026-08-18 [budget_exhausted] `nexus-lake`의 silver 스키마·실제 쓰임 질의에서는 클러스터 전수 상태 점검을 생략하고, 저장소에서 silver 테이블/경로의 스키마 정의 → 적재 코드 → 조회·조인·집계 소비처를 역참조해 컬럼별 데이터 흐름을 먼저 정리해야 한다. Kubernetes 조회가 필요하면 코드에서 식별된 silver 관련 워크로드와 네임스페이스로 한정해 ConfigMap·환경 변수·최근 로그만 확인하고, 무관한 Pod 재시작은 보고하지 않는다.
- 2026-08-18 [calls_rejected] 실버 인벤토리 스키마 조사에서는 `src_search` 결과에 반환된 저장소·정확한 파일 경로만 `src_read_file`에 사용하고, 첫 거부 이후 추측 경로로 재시도하지 말고 테이블명·DDL 키워드(`CREATE TABLE`, `StructType`, `schema`)를 좁혀 검색한다. 최종 답변은 DDL/스키마 선언에서 직접 확인된 컬럼·타입과 적재 코드에서 추론한 공통 메타컬럼을 구분해 표시하고, 실측하지 못한 내용은 “일반 타입”으로 단정하지 않는다.
- 2026-08-18 [budget_exhausted] `nexus-lake` Silver가 tenant registry 기반 동적 스키마임을 확인한 즉시 반복적인 `src_repo_log`·디렉터리 탐색을 중단하고, 7개 확인 테이블명을 한 번에 검색해 resource/parser 정의에서 컬럼·타입을, `security-view-backend`의 SQL에서 조인 키와 방향을 추출해 관계 매트릭스를 작성한다. 최종 답변에서는 실제 SQL 조인으로 확인된 관계와 `resource_id`·도메인 식별자 이름만으로 추정한 관계를 구분하고, 예산이 부족하면 파이프라인 설명보다 테이블별 컬럼 및 관계 근거를 우선 제시한다.
- 2026-08-19 [budget_exhausted] Botkube 이슈 조사에서는 먼저 Pod 이름·라벨로 Botkube가 배포된 네임스페이스와 워크로드를 특정한 뒤, 해당 Pod의 상태·재시작·최근 이벤트·로그와 Deployment 설정만 연계 조회해야 한다. `nexus-shell`의 무관한 CrashLoopBackOff, 전체 노드, 소스 저장소 조사는 제외하고 호출 예산을 원인 증거와 설정별 해결책 정리에 우선 배분한다.
