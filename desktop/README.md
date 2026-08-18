# inspect-k8s 데스크톱 앱 (Electron)

기존 웹 하네스(FastAPI + SSE UI)를 감싸는 Electron 셸. 앱을 켜면 파이썬 백엔드
(`src.web`)를 자동으로 띄우고 로컬 URL을 로드한다. Claude Code 유사 UX
(hiddenInset 타이틀바, 다크 우선).

## 실행 (개발)

```bash
cd desktop
npm install          # 최초 1회 (electron 다운로드)
# 환경변수는 부모 셸에서 상속된다 — 실 클러스터 조사 시:
AGENT_ALLOW_REAL_CLUSTER=1 KUBECONFIG=~/.kube/config KUBE_CONTEXT=aws-seoul-clouddev \
  SOURCE_SSH_HOST=heejoon@172.29.70.161 \
  npm start
```

앱이 `src.web`를 `127.0.0.1:8799`에 띄우고 창에 로드한다(포트는 `INSPECT_K8S_PORT`로 변경).

## 패키징 (.app)

```bash
cd desktop && npm run dist       # electron-builder --dir → dist/mac/inspect-k8s.app
```

## 설계 원칙

- 앱은 **자격증명을 저장하지 않는다** — 부모 셸의 환경변수(KUBECONFIG 등)를 그대로 상속한다.
- 백엔드는 127.0.0.1 전용, 외부 링크만 기본 브라우저로 연다.
- UI 로직은 전부 기존 `src/static/chat.html` 재사용 — 데스크톱은 창·수명주기만 담당한다.
