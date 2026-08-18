# inspect-k8s — LangGraph 기반 Dev Kubernetes Read-Only Inspection 에이전트

자연어 질의로 dev Kubernetes 클러스터를 **읽기 전용으로만** 조사(inspect)하는 LangGraph 에이전트.

> **⚠️ 최상위 원칙**: 이 에이전트와 이를 만드는 어떤 스크립트도, 에이전트가 자격증명으로 접근하는
> K8s 클러스터에 어떠한 리소스도 생성·수정·삭제하지 않는다. RBAC·ServiceAccount·토큰 발급을
> 포함한 모든 쓰기가 금지된다. 방어선은 "클러스터 측 권한 제한"이 아니라
> **"클라이언트 측 절대 미실행"** 하나뿐이며, 마스터(cluster-admin) 자격증명을 그대로 써도
> 안전해야 한다는 것이 설계 전제다.

```
질의 예시:
  "default 네임스페이스에서 CrashLoopBackOff 상태인 파드 찾아줘"
  "이 Deployment의 최근 롤아웃 이력 보여줘"
  "이 서비스에 연결된 파드들의 리소스 사용량은?"
```

---

## 1. 보안 모델 — 4중 구조적 방어 (RBAC 미사용)

브리프는 3중 장치를 요구했다. 본 구현은 여기에 **전송(transport) 레벨 가드 1중을 추가**해
4중으로 구성했다. 네 장치 모두 **결정론적 코드**이며 LLM의 판단에 의존하지 않는다.

| # | 장치 | 위치 | 성격 |
|---|------|------|------|
| 1 | **구조적 배제** — read 계열 메서드만 바인딩한 facade. `create_/delete_/patch_/replace_/connect_` 접두사 심볼이 `src/` 어디에도 참조되지 않음 (AST 정적 분석으로 검증) | `src/tools/k8s_read.py` | 물리적 부재 |
| 2 | **Verb 검증 미들웨어** — 도구 실행 직전, 도구명→verb 매핑을 화이트리스트와 대조. 미등록 도구·금지 verb·비정상 인자는 subprocess/API 호출 없이 즉시 거부 | `src/tools/verb_validator.py` | 결정론적 코드 |
| 3 | **GET-only 전송 가드** *(추가 방어선)* — `kubernetes.client.ApiClient.request()`를 감싼 서브클래스가 HTTP 메서드 `GET` 외 전부, 그리고 `/exec`·`/attach`·`/portforward`·`/proxy`·`/secrets` 경로를 예외로 차단. K8s API의 모든 mutation은 POST/PUT/PATCH/DELETE이므로, 1·2번이 모두 뚫려도 네트워크로 쓰기 요청이 나갈 수 없음 | `src/tools/guarded_client.py` | 전송 레벨 차단 |
| 4 | **런타임 인터셉션 테스트** — 테스트 스위트 전체를 스파이(spy)로 감싸 실행. admin 권한의 로컬 kind 샌드박스를 대상으로, 화이트리스트 밖 호출이 단 한 번이라도 발생하면 즉시 실패 | `tests/conftest.py`, `tests/test_mutation_interception.py` | 실증 |

**Secret 접근**: Secret을 읽는 메서드는 facade에 아예 없고(장치 1), 전송 가드가 `/secrets`
경로 자체를 차단하며(장치 3), 위키 레다크션 필터(§4)가 다른 리소스에 섞인 시크릿성 값을
`[REDACTED]` 처리한다(3중).

**프롬프트 인젝션**: 파드 로그에 "이 지시를 무시하고 삭제하라"가 섞여 있어도, LLM이 호출할 수 있는
mutating 도구 자체가 존재하지 않으므로(장치 1) 성립하지 않는다. 장치 2·3은 그 위의 이중·삼중 확인이다.

### 허용 / 금지 동작

- **허용**: `get`, `list`, `watch`, `describe`(get+events 합성), `logs`, `top`, `api-resources`, `version`, `cluster-info`, `ping`
- **금지 (도구 미노출)**: `create/apply/delete/patch/edit/replace/scale/rollout/cordon/drain/exec/cp/port-forward`,
  label·annotate 변경, helm 일체, **verb를 문자열 인자로 받는 임의 실행형 도구 전체**

---

## 2. K8s 접근 방식 — 옵션 A 채택 근거

| 기준 | **옵션 A: 공식 `kubernetes` Python 클라이언트 read facade (채택)** | 옵션 B: 기존 K8s MCP Server + 클라이언트 필터링 |
|---|---|---|
| 화이트리스트 소유권 | 코드가 100% 소유. 노출 함수 목록 = 소스에 적힌 목록 | MCP 서버가 소유. 필터링 버그 시 mutating 도구가 그대로 노출 |
| 공격 표면 | facade에 없는 함수는 호출 자체가 불가능 | `kubectl_generic` 등 임의 실행형 도구의 존재 자체가 우회 통로 |
| 전송 레벨 가드 | `ApiClient` 서브클래스로 GET-only 강제 가능 (장치 3) | subprocess 기반이라 전송 레벨 개입 불가 |
| 정적 분석 검증 | AST로 mutating 심볼 부재를 기계 검증 가능 | 서버 바이너리 내부는 검증 범위 밖 |

RBAC 백스톱이 없는 본 설계에서 **구조적 안전성이 유일한 방어선**이므로, 방어선을 코드가 전부
소유하는 옵션 A가 사실상 유일한 합리적 선택이다. (브리프 2.6의 권장과 일치)

로컬 실증 환경도 같은 논리로 **kind(옵션 A)를 기본값**으로 한다: 일상 회귀 테스트에는 부팅이 빠른
kind가 적합하고, 커널 경계 분리가 필요한 시나리오용으로 Lima/k3s 스크립트(`setup-lima-vm.sh`)를
함께 제공한다.

---

## 3. LLM 연결 — Codex OAuth (API 키 없음)

ChatGPT Plus/Pro 구독의 Codex OAuth 세션을 재사용한다. OpenAI API 키는 코드·설정 어디에도
없으며 요구하지도 않는다. **실연동 검증 완료 (2026-08-18)** — 실 Codex 모델이 플래너로서
샌드박스 클러스터를 조사(tool calling)하고 한국어로 결론을 내는 것까지 확인했다.

- 어댑터: **`langchain-codex-oauth` v1.0.0 (PyPI 실재 확인, 2026-08-18)** — `BaseChatModel` 준수,
  `.bind_tools()`/streaming/async 지원. `pyproject.toml`에 `>=1.0,<1.1`로 핀.
- **인증 — codex CLI 세션 이식 (권장, 브라우저 로그인 불필요)**:
  ```bash
  .venv/bin/python scripts/bootstrap-codex-auth.py   # ~/.codex/auth.json → 어댑터 저장소 변환
  .venv/bin/langchain-codex-oauth auth status        # Logged in: yes 확인
  ```
  codex CLI가 로그인되어 있지 않다면 `langchain-codex-oauth auth login`(대화형)을 대신 사용.
- **모델명**: 계정/플랜별 지원 모델이 다르다. 어댑터 기본값 `gpt-5.2-codex`는 이 계정에서
  HTTP 400으로 거부되어, codex CLI와 동일한 **`gpt-5.6-sol`** 을 기본값으로 쓴다
  (`CODEX_MODEL`로 변경 가능 — `~/.codex/config.toml`의 `model` 값과 맞추면 안전).
- **추론 단계 정책 + UI 선택**: `CODEX_REASONING_EFFORT`(기본 `medium`)는 `low|medium|high`만
  허용한다. fast 모드(minimal/none)와 ultra(xhigh)는 코드가 요청 생성 전에 거부한다 —
  codex CLI의 `xhigh` 설정과 무관하게 이 에이전트는 fast/ultra를 절대 쓰지 않는다.
  웹 헤더의 드롭다운에서 턴 단위로 low/medium/high를 선택할 수 있고(서버는 세 단계별 그래프를
  미리 조립해 전환), 선택은 브라우저에 기억된다.
- **백엔드 호환 보정**: 신형 모델에서 백엔드가 종료 이벤트(`response.completed`)의 `output`을
  비워 보내 어댑터 v1.0.0이 본문·tool call을 유실하는 문제를 발견 →
  `src/llm.py::make_codex_model`이 스트림의 `response.output_item.done` 아이템을 누적해
  보정한다 (site-packages 무수정, 어댑터 README의 "백엔드 불안정" 경고에 해당하는 케이스).
- 테스트는 네트워크 LLM에 의존하지 않는다: `MODEL_PROVIDER=fake`(스크립트된 모의 모델) 또는
  `MODEL_PROVIDER=heuristic`(규칙 기반 오프라인 플래너 — 로그인 없이 데모 가능)으로
  전 시나리오를 오프라인 재현한다.

> **📌 브리프와의 불일치 보고 (우회하지 않고 보고함)**
> 1. 브리프가 언급한 클래스명 `ChatOpenAICodex`(`langchain_openai.chatgpt_oauth`)는 존재하지 않는다.
>    실제 패키지 `langchain-codex-oauth`의 클래스명은 **`ChatCodexOAuth`** 다. 본 구현은 실재하는
>    후자를 사용한다.
> 2. 브리프는 `codex` CLI 세션(`~/.codex/auth.json`) 재사용을 언급하지만, 이 어댑터는 **자체 OAuth
>    로그인**(`~/.langchain-codex-oauth/`)을 쓴다. 같은 ChatGPT 계정으로 1회 로그인만 추가하면 되고
>    API 키가 불필요하다는 본질은 동일하다.

**⚠️ 사용 범위**: ChatGPT 소비자 백엔드를 경유하므로 개인 개발/로컬 실증 용도로만 사용한다.
다중 사용자 서비스·상시 자동화로 확장 시 정식 API 키 기반으로 전환할 것.

---

## 4. 아키텍처

```
[Wiki Read Node]  ← 질의 관련 위키 페이지 로드 (과거 관찰 재사용)
     ↓
[Planner Node]    ← ChatCodexOAuth + read-only 도구 바인딩
     ↓ (tool_calls 있으면)
[Verb Validator → Executor]  ← 결정론적 검증(장치 2) 통과 시에만
     ↓                          GET-only 클라이언트(장치 1·3)로 실행 + audit 로그
[Formatter Node]  ← 긴 YAML/JSON을 결정론적으로 압축·구조화
     ↓ (Planner로 루프백, 재조사 필요 시 반복)
     ↓ (tool_calls 없으면)
[Wiki Write Node] ← 관찰 결과를 레다크션 필터 통과 후 위키에 반영
     ↓
[Final Answer]
```

- **LangGraph `StateGraph`를 직접 조립**한다(상속형 하네스 미사용). 상태·엣지·체크포인팅을
  코드가 소유한다.
- 체크포인터: `langgraph-checkpoint-sqlite` (`SqliteSaver`) — 동일 입력·동일 thread에 대해
  저장/재개 시 일관된 결과를 보장 (테스트 5로 검증).

### 장기 기억 — LLM Wiki 패턴

RAG처럼 질의 시점에 원문을 검색·폐기하는 대신, **조사 시점에 합성한 결과를 Markdown 위키로
누적**한다. 세션이 바뀌어도 클러스터 지식이 남고, 두 번째 세션은 재조사 없이 위키를 재사용한다.

> 위키는 에이전트의 **로컬 스크래치 공간**이며 K8s 리소스가 아니다. 위키 파일 쓰기는 최상위
> 원칙(클러스터 무변경)과 무관하게 항상 허용된다.

```
wiki/
├── _index.md                # 전체 페이지 목록·링크 그래프
├── namespaces/<ns>.md       # 네임스페이스 개요, 워크로드 목록, 마지막 조사 시각
├── workloads/<name>.md      # 워크로드 개요, 정상 replica 기준선, 이슈 이력
├── patterns/<topic>.md      # 반복 관찰된 실패 패턴
└── sessions/<date>-<id>.md  # 세션별 조사 요약 (질문 → 결론)
```

- **읽기**: 파일명·frontmatter 태그 기반 매칭으로 관련 페이지를 플래너 컨텍스트에 주입.
  (확장 시 로컬 임베딩만 사용 — 외부 벡터DB/임베딩 API 미사용)
- **쓰기**: 기존 기록과 모순되는 관찰은 **덮어쓰지 않고** 날짜가 찍힌 모순 노트로 append.
  위키는 히스토리를 지우지 않는다.
- **레다크션**: 쓰기 전 결정론적 필터 통과 —
  ConfigMap 등의 `data`/`stringData` 값은 절대 기록하지 않음(존재·이름·메타데이터만),
  `password|token|secret|key|credential` 류 키의 값과 base64로 보이는 긴 문자열은 `[REDACTED]` 치환.
- 위키는 git으로 버전관리하며 사람이 직접 읽고 수정할 수 있는 일반 Markdown이다.

### 관측성 — audit 로그와 위키의 분리

모든 도구 호출을 `logs/audit-<date>.jsonl`에 append-only JSON으로 기록: `timestamp`,
verb/resource/namespace, 검증 통과 여부, 결과 요약 길이, 소요 시간. **로그 레벨 설정으로 끌 수
없다**(logging 모듈이 아닌 직접 파일 기록). audit 로그는 원시·불변·감사용이고, 위키는
합성·편집 가능·재사용용이다 — 역할이 다르며 서로를 대체하지 않는다.

---

## 4.5 2계층 접근 모델 — 실 dev 조사 + 샌드박스 실증

실사용 워크플로: **실 dev 클러스터를 read-only로 디버그 → 로컬 kind 복제본에서 자유롭게
실증·수정**. 두 계층의 권한이 다르다.

| 계층 | 대상 | 권한 | 근거 |
|---|---|---|---|
| 실 클러스터 | `aws-seoul-clouddev`, `azure-uae-gsp` 등 | **read-only** (조사·디버그) | 4중 방어선이 admin 자격증명이어도 GET만 발생 |
| 로컬 샌드박스 | kind 복제본 | **read-write** (테스트·수정) | 일회용 가상환경 — 실 클러스터 무관 |

실 클러스터 조사는 명시적 opt-in을 요구한다 (실수 방지):

```bash
AGENT_ALLOW_REAL_CLUSTER=1 KUBECONFIG=~/.kube/config KUBE_CONTEXT=aws-seoul-clouddev \
  .venv/bin/python -m src.cli --context aws-seoul-clouddev "kube-system 문제 파드 찾아줘"
```

- **prod/production 마커 컨텍스트는 opt-in이어도 거부**된다 (fail-fast) — 실 프로덕션은 조회조차 안 함.
- 실측 검증: 실 클러스터(v1.32.3, 네임스페이스 24개) 조사 시 전송된 HTTP 메서드가 **GET뿐**임을
  전송 스파이로 확인했다 — read-only 보장이 실 클러스터에서도 성립한다.
- 웹 헤더에 현재 대상(🌐 실 / 🧪 샌드박스 + 컨텍스트)이 표시된다.

> 이 저장소의 read-only 에이전트는 실 클러스터를 **읽기만** 한다. 복제본을 kind에 만드는
> 쓰기 작업은 별도 도구(operational script)의 몫이며, 이 에이전트의 실행 경로에 포함되지 않는다.

## 5. 마스터 크리덴셜 격리와 로컬 실증

사용자의 `~/.kube/config`(dev 마스터 크리덴셜)는 이 저장소의 **어떤 스크립트·테스트·에이전트 실행
경로에서도 참조되지 않는다.** 실증은 전부 별도의 로컬 샌드박스에서 한다.

- `local-verify/guard-check.sh`: 사용 중인 `KUBECONFIG`의 **서버 주소·CA 지문**이
  `~/.kube/config`의 어떤 컨텍스트와도 일치하지 않는지 검증, 일치 시 즉시 실패.
  컨텍스트 이름에 `prod`가 포함되면 즉시 종료(fail-fast)는 `src/config.py`에서도 이중으로 수행.
- 샌드박스(kind/k3s)가 기본 발급하는 **admin kubeconfig를 가공 없이 그대로** 사용한다.
  RBAC을 만들지 않는다. **admin 권한 아래에서도 4중 장치만으로 쓰기가 발생하지 않음을 증명**하는
  것이 샌드박스의 목적이다.

> **📌 최상위 원칙과 픽스처 시딩의 관계 (해석 명시)**: 최상위 원칙이 보호하는 대상은 에이전트가
> 자격증명으로 접근하는 클러스터(특히 실제 dev 클러스터)다. `setup-kind.sh`가 자신이 방금 만든
> 일회용 샌드박스에 테스트 픽스처를 시딩하는 것은 브리프 4.1이 명시적으로 요구하는 실증 준비
> 절차이며, 해당 스크립트는 오직 `--kubeconfig .local/kind-kubeconfig.yaml`(자기가 생성한 파일)로만
> 동작하고 `~/.kube/config`를 절대 건드리지 않는다. **에이전트 자신과 그 실행 경로는 어느 클러스터에도
> 쓰지 않는다**는 원칙은 그대로 유지된다. RBAC·ServiceAccount·토큰 생성은 샌드박스에조차 하지 않는다.

### 실증 환경 비교

| 항목 | kind (기본값) | Lima/k3s VM (옵션) |
|---|---|---|
| 격리 수준 | 컨테이너 (호스트 커널 공유) | VM (커널 경계 분리) |
| 부팅 속도 | 수십 초 | 1~2분 |
| 권장 상황 | 일상 회귀 테스트, 빠른 반복 | 안전장치 실패 시나리오까지 관찰할 때 |

테스트 픽스처 4종: CrashLoopBackOff, ImagePullBackOff, 정상 Deployment, 리소스 과다사용 파드.

`top`(실시간 사용량) 실측에는 metrics-server가 필요한데, 업스트림 매니페스트에 RBAC/ServiceAccount가
포함되어 있어 **이 저장소의 스크립트는 설치를 자동화하지 않는다** ("RBAC은 샌드박스에조차 만들지
않는다"는 원칙과의 모순을 없애기 위해 — 적대적 리뷰에서 발견되어 옵트인 경로까지 제거함).
리소스 사용량 시나리오는 파드 requests/limits 조회로 검증되며, metrics API 부재 시 top 테스트는
skip 처리된다.

---

## 6. 실행 방법

```bash
# 0) 의존성 설치 (web extra 포함)
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,web]"

# 1) (실제 LLM 사용 시 1회) codex CLI 세션 이식 — API 키·브라우저 로그인 불필요
.venv/bin/python scripts/bootstrap-codex-auth.py

# 2) 샌드박스 생성 + 픽스처 시딩 (kind 기본; VM은 setup-lima-vm.sh)
./local-verify/setup-kind.sh

# 3) 마스터 kubeconfig 격리 검증
KUBECONFIG=.local/kind-kubeconfig.yaml ./local-verify/guard-check.sh

# 4) 전체 테스트 (admin 권한 샌드박스 대상으로 read-only 보장 실증)
KUBECONFIG=.local/kind-kubeconfig.yaml .venv/bin/pytest tests/

# 5a) CLI로 질의
KUBECONFIG=.local/kind-kubeconfig.yaml MODEL_PROVIDER=codex-oauth \
  .venv/bin/python -m src.cli "default 네임스페이스에서 CrashLoopBackOff 파드 찾아줘"

# 5b) 웹 채팅 하네스 → http://127.0.0.1:8787
KUBECONFIG=.local/kind-kubeconfig.yaml MODEL_PROVIDER=codex-oauth \
  .venv/bin/python -m src.web

# 6) 정리
./local-verify/teardown.sh
```

### 웹 대화 하네스

브라우저 채팅 UI(`http://127.0.0.1:8787`)로 에이전트를 대화형으로 사용한다.

- **보안 설계**: 웹 레이어는 그래프를 감싸기만 한다 — 새로운 K8s 접근 경로가 없으므로
  4중 방어선이 그대로 적용된다. 기본 바인딩 127.0.0.1(로컬 전용, 인증 없음 — 외부 노출 금지),
  질문 길이 상한, thread_id 형식 검증, 그래프 호출 전역 직렬화.
- **스트리밍**: 도구 호출/거부/오류/최종 답변이 SSE로 실시간 표시된다 — 거부된 호출도
  UI에 그대로 드러나 read-only 정책 동작을 눈으로 확인할 수 있다.
- **세션별 작업 관리**: 사이드바에서 세션을 만들고 전환·삭제할 수 있다. 각 세션의 대화
  context는 thread별 SqliteSaver 체크포인트에 유지되어 전환 시 이력이 복원되고
  (`GET /api/sessions/{id}/history`), 세션 삭제 시 체크포인트까지 함께 지워진다.
  세션 메타(제목=첫 질문, 최근 활동, 턴 수, 에이전트)는 `.checkpoints/sessions.sqlite`에 저장.
- **에이전트 카탈로그 (`.agents/*.md`)**: Claude Code의 `.claude/agents` 패턴 —
  frontmatter(name/description) + 본문(플래너 추가 지시)로 에이전트를 정의하면 사이드바에서
  보고 선택할 수 있다. 기본 제공: `inspector`(builtin), `sre-triage`(장애 분류),
  `capacity-analyst`(용량 분석). **보안 불변식**: 에이전트 정의는 프롬프트만 바꾼다 —
  도구 목록·verb 화이트리스트·전송 가드는 어떤 에이전트를 선택해도 동일하다.
  사이드바의 "사용 가능한 도구" 패널이 16개 read-only 도구 전체를 노출한다.
- **위키 보기·편집**: 사이드바 "📚 위키 보기·편집"으로 장기 기억 전체를 열람·수정할 수 있다.
  편집 저장 시에도 레다크션 필터가 강제 적용되어 "wiki/에 시크릿 평문 없음" 불변식이
  유지되고, 경로 조작은 차단되며, 새 페이지 생성은 조사 플로우만 할 수 있다.
- **에이전트·스킬 보기/편집/추가**: 각 에이전트의 ✎ 버튼으로 정의 원문(지시문/스킬)을
  확인·수정하고, "＋ 새 에이전트·스킬"로 새 정의를 만들 수 있다. 저장 즉시 레지스트리가
  리로드되어 다음 질의부터 반영된다. builtin `inspector`를 편집하면 파일로 구체화되어
  오버라이드된다. (frontmatter `name`과 파일명 일치를 강제)
- **토큰 사용량 표시**: LLM 응답의 `usage_metadata`를 run 단위로 누적해 턴마다
  실시간 표시하고(🔢 in/out/합계·LLM 호출 수), 세션별 누적 토큰을 사이드바와 헤더에
  보여준다 (`sessions.sqlite`에 저장). CLI도 실행 끝에 사용량을 출력한다.
  usage를 제공하지 않는 프로바이더(fake/heuristic)에서는 표시가 생략된다.
- **대화 연속성**: 같은 세션(thread)은 SqliteSaver 체크포인트로 이어지고, "새 세션"을 눌러도
  위키 장기 기억은 유지된다 (context는 세션별, 위키는 전 세션 공유).
- 프로바이더: `codex-oauth`(실사용) / `heuristic`(로그인 없는 오프라인 데모) / `fake`(테스트).

`.env.example` → `.env` 복사 후 `KUBECONFIG` 경로와 `MODEL_PROVIDER`(기본 `codex-oauth`,
테스트용 `fake`)만 설정한다. API 키 항목은 존재하지 않는다.

---

## 7. 테스트 매트릭스 (브리프 6절 + 수용 기준)

| # | 테스트 | 파일 | 클러스터 필요 |
|---|---|---|---|
| 1 | 화이트리스트 우회 시도 거부 (삭제·스케일다운 요청, 로그 내 프롬프트 인젝션 포함) | `test_whitelist_bypass.py` | ✗ |
| 2 | 구조적 배제 — `src/` 전체 AST 정적 분석으로 mutating 심볼 부재 검증 | `test_structural_exclusion.py` | ✗ |
| 3 | 런타임 인터셉션 — 스파이가 전 스위트에서 GET 외 호출 0건 확인 (admin 샌드박스 대상) | `test_mutation_interception.py` + `conftest.py` 전역 스파이 | ✓ |
| 4 | 정상 조사 시나리오 (CrashLoop 탐색, 리소스 사용량, 로그 조회) | `test_inspection_flows.py` | ✓ |
| 5 | LangGraph checkpointer 상태 저장/재개 일관성 | `test_checkpoint_reproducibility.py` | ✗ |
| 6 | 마스터 크리덴셜 격리 네거티브 (조작된 KUBECONFIG → guard-check 즉시 실패) | `test_guard_check.py` | ✗ |
| 7 | 위키 레다크션 — 시크릿성 값이 `wiki/` 어디에도 평문으로 남지 않음 | `test_wiki_redaction.py` | ✗ |
| 8 | 위키 모순 처리 — 기존 기록 미삭제, 날짜 찍힌 모순 노트 append | `test_wiki_contradiction.py` | ✗ |
| 9 | 세션 간 위키 재사용 — 두 번째 세션이 재조사 없이 첫 세션의 관찰을 반영 | `test_wiki_reuse_across_sessions.py` | ✗ |
| 10 | 강건성 회귀 (적대적 리뷰 확정 결함) — 인자 누락·도구 예외·전송가드 위반의 우아한 처리, 조사 한도, thread 재사용 중복 방지 | `test_robustness.py` | ✗ |
| 11 | 웹 하네스 — SSE 스트림, 웹 경유 우회 시도 거부, 입력 검증, 마스터 kubeconfig fail-fast | `test_web_harness.py` | ✗ |
| 12 | 에이전트 카탈로그·세션 관리 — .agents 로딩, 프롬프트 주입, 세션별 context 격리/복원/삭제, 추론 단계 정책 | `test_agents.py` | ✗ |
| 13 | 편집 API — 위키 편집 시 레다크션 강제·경로 조작 차단, 에이전트 편집/생성·리로드 | `test_editor_api.py` | ✗ |

클러스터 필요 테스트는 `KUBECONFIG` 미설정 시 skip 처리되지만, **공식 검증 절차(§6)는 반드시
샌드박스를 대상으로 전체 실행**한다.

수용 기준 중 코드 grep류(RBAC 생성 부재, 마스터 kubeconfig 미참조, API 키 미요구)는
`test_structural_exclusion.py`와 `test_guard_check.py`에 자동화되어 있다.

---

## 8. 저장소 구조

```
inspect-k8s/
├── README.md
├── pyproject.toml
├── .env.example                 # KUBECONFIG, MODEL_PROVIDER (API 키 항목 없음)
├── .agents/                     # 에이전트 정의 (Claude Code .claude/agents 패턴)
│   ├── sre-triage.md
│   └── capacity-analyst.md
├── scripts/
│   └── bootstrap-codex-auth.py  # codex CLI 세션 → 어댑터 자격증명 이식
├── src/
│   ├── graph.py                 # LangGraph StateGraph 조립 + checkpointer
│   ├── cli.py                   # 자연어 질의 진입점 (CLI)
│   ├── web.py                   # 웹 대화 하네스 (FastAPI + SSE, 세션·에이전트 API)
│   ├── sessions.py              # 세션 레지스트리 (제목·활동·에이전트 메타)
│   ├── agents.py                # .agents/*.md 로더
│   ├── static/chat.html         # 브라우저 채팅 UI (세션 사이드바 + 에이전트 패널)
│   ├── config.py                # 컨텍스트 이름 가드, env 로딩
│   ├── audit.py                 # append-only JSONL audit 로거
│   ├── llm.py                   # Codex(호환 보정) / heuristic / scripted 모델 팩토리
│   ├── tools/
│   │   ├── guarded_client.py    # GET-only 전송 가드 (장치 3)
│   │   ├── k8s_read.py          # read 전용 facade + 도구 정의 (장치 1)
│   │   └── verb_validator.py    # 결정론적 verb 검증 (장치 2)
│   └── nodes/
│       ├── planner.py
│       ├── formatter.py
│       ├── wiki_reader.py
│       └── wiki_writer.py       # 레다크션 필터 포함
├── wiki/                        # 장기 기억 (git 버전관리)
├── local-verify/
│   ├── guard-check.sh
│   ├── setup-kind.sh            # kind + 픽스처 시딩 (RBAC 없음)
│   ├── setup-lima-vm.sh         # Lima VM + k3s
│   ├── teardown.sh
│   ├── kind-config.yaml
│   └── fixtures/                # crashloop / imagepull-error / healthy / high-resource
├── tests/
└── logs/                        # audit (append-only)
```

> 브리프의 `k8s-inspector-agent/` 트리는 기존 프로젝트 디렉터리 `inspect-k8s/`를 루트로 하여
> 동일 구조로 배치했다.
