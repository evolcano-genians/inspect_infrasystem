# Slack 개인 DM 알림 설정 (아침 트리아지)

매일 아침 두 클러스터(AWS/Azure)의 이슈·변경과 nexus-lake 변경을 **개인 Slack DM**으로 받기 위한 설정.
가장 간단한 **Incoming Webhook** 방식을 권장합니다(스코프 설정 불필요, URL 하나만).

## 1. Incoming Webhook 만들기 (권장 · 3분)

1. https://api.slack.com/apps → **Create New App** → **From scratch**
   - App Name: `inspect-k8s-alerts` (아무 이름) · 워크스페이스: 지니언스 선택
2. 좌측 메뉴 **Incoming Webhooks** → 토글 **On**
3. 하단 **Add New Webhook to Workspace** 클릭
4. **채널 선택 화면에서 본인에게 DM** 을 고른다:
   - 채널 목록 상단/검색에서 **자기 이름(Direct Message)** 또는 `@본인`을 선택
   - (DM이 안 보이면, 워크스페이스에서 자신에게 DM을 한 번 보낸 뒤 다시 시도)
5. **Allow** → 생성된 **Webhook URL**(`https://hooks.slack.com/services/T…/B…/…`)을 복사

## 2. 토큰 입력 (Jira처럼 전역에서 사용)

**A. 앱 UI에서 (가장 쉬움)**
- inspect-k8s 앱 → **⚙️ 설정 → Slack** → *Incoming Webhook URL* 에 붙여넣기 → **🔌 연결 테스트**
  (테스트 누르면 실제로 DM이 하나 옵니다) → **💾 저장**

**B. 전역 파일에 직접** (Mac·원격 PC 공용)
```bash
# ~/.config/genians/atlassian.env 의 SLACK_WEBHOOK_URL= 뒤에 붙여넣기 (chmod 600)
```
- 이후 어디서나 테스트: `~/.config/genians/atlassian.sh slack "테스트"`

## 3. 아침 크론(07:30) 설치

```bash
cd ~/PycharmProjects/inspect-k8s
scripts/install-triage-launchd.sh           # 매일 07:30 (Mac 절전 시 깨어난 뒤 보충)
scripts/install-triage-launchd.sh --run     # 지금 즉시 한 번 보내보기(테스트)
scripts/install-triage-launchd.sh --status  # 상태 확인
```

## 대안: Bot Token 방식

웹훅 대신 봇을 쓰려면(여러 채널·리치 메시지 필요 시):
- Slack 앱 **OAuth & Permissions** → Bot Token Scopes에 `chat:write` 추가 → 워크스페이스에 설치
- `SLACK_BOT_TOKEN=xoxb-…` + `SLACK_DM_CHANNEL=<본인 멤버 ID U…>` 설정
  (멤버 ID: Slack 프로필 → 더보기 → "멤버 ID 복사")

## 무엇이 오나

- 🔴/🟡 **이슈**: CrashLoopBackOff·ImagePull 실패·재시작 폭증·phase=Pending/Failed·시크릿 없음·
  FailedScheduling 등 (Botkube가 채널에 흘리는 것과 같은 종류를 정리)
- 🔄 **변경**: 전날 대비 이미지 태그·replica 변경, 신규/삭제 배포
- 📦 **nexus-lake**: 레이크하우스 워크로드(trino·bronze·hive·kafka·registry 등) 이슈·변경.
  `TRINO_ENDPOINT` 설정 시 테이블 행수 변화(📊)까지.
- ⏱ **우선 확인**: Codex가 뽑은 "오늘 먼저 볼 것" 요약

## 보안

- Webhook URL·봇 토큰은 `.env`/전역 파일(chmod 600)에만. **dev k8s에 절대 넣지 않음**(Secret 금지).
- 전송은 `hooks.slack.com`/`slack.com` 으로만(호스트 잠금). 클러스터 조회는 read-only(GET) 그대로.
