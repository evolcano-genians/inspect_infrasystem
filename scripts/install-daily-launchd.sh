#!/usr/bin/env bash
# 일일 요약(Confluence 복귀 문서) launchd 에이전트 (macOS).
# 스케줄: 월~목 15:30, 금 11:30.
#
# cron 대신 launchd 를 쓰는 이유(사용자 환경): 이 Mac은 퇴근·휴가 시 절전/오프라인이 된다.
# launchd 의 StartCalendarInterval 은 **그 시각에 Mac이 잠들어 있었으면 깨어난 직후 놓친 실행을
# 한 번 보충**한다(cron 은 그냥 건너뜀). daily_report 는 자정을 넘겨 보충돼도 '최근 활동일'을
# 요약하므로 올바른 하루가 게시된다. (요약 대상 devlog·Codex 자격증명은 이 Mac에만 있어 요약은
# Mac에서만 가능하다 — 원격 PC로는 옮길 수 없다.)
#
# 사용:
#   scripts/install-daily-launchd.sh          # 설치(또는 갱신) + 로드
#   scripts/install-daily-launchd.sh --remove # 언로드 + 제거
#   scripts/install-daily-launchd.sh --status # 상태 확인
#   scripts/install-daily-launchd.sh --run    # 지금 즉시 한 번 실행(테스트)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$PROJECT_ROOT/.venv/bin/python"
LABEL="com.genians.inspect-k8s.daily-report"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$PROJECT_ROOT/logs/daily-report-cron.log"

write_plist() {
  mkdir -p "$HOME/Library/LaunchAgents" "$PROJECT_ROOT/logs"
  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY</string>
    <string>-m</string>
    <string>src.daily_report</string>
  </array>
  <key>WorkingDirectory</key>
  <string>$PROJECT_ROOT</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>$HOME</string>
    <key>PATH</key><string>/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <!-- 월~목(요일 2..5, Sun=0) 15:30 · 금(6) 11:30. 잠들어 있었으면 깨어난 뒤 보충 실행. -->
  <key>StartCalendarInterval</key>
  <array>
    <dict><key>Weekday</key><integer>2</integer><key>Hour</key><integer>15</integer><key>Minute</key><integer>30</integer></dict>
    <dict><key>Weekday</key><integer>3</integer><key>Hour</key><integer>15</integer><key>Minute</key><integer>30</integer></dict>
    <dict><key>Weekday</key><integer>4</integer><key>Hour</key><integer>15</integer><key>Minute</key><integer>30</integer></dict>
    <dict><key>Weekday</key><integer>5</integer><key>Hour</key><integer>15</integer><key>Minute</key><integer>30</integer></dict>
    <dict><key>Weekday</key><integer>6</integer><key>Hour</key><integer>11</integer><key>Minute</key><integer>30</integer></dict>
  </array>
  <key>StandardOutPath</key>
  <string>$LOG</string>
  <key>StandardErrorPath</key>
  <string>$LOG</string>
  <key>ProcessType</key>
  <string>Background</string>
</dict>
</plist>
PLISTEOF
}

_uid() { id -u; }

case "${1:-install}" in
  --remove)
    launchctl bootout "gui/$(_uid)/$LABEL" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"
    echo "launchd 에이전트 제거됨: $LABEL"
    ;;
  --status)
    if launchctl print "gui/$(_uid)/$LABEL" >/dev/null 2>&1; then
      echo "로드됨: $LABEL"
      launchctl print "gui/$(_uid)/$LABEL" 2>/dev/null | grep -E "state =|last exit code|runs =" | sed 's/^/  /' | head -6
    else
      echo "(로드 안 됨)"
    fi
    echo "plist: $PLIST"; echo "log:   $LOG"
    ;;
  --run)
    launchctl kickstart -k "gui/$(_uid)/$LABEL" 2>/dev/null \
      && echo "즉시 실행 트리거됨 — 로그: $LOG" \
      || { echo "먼저 설치하세요(에이전트 미로드)"; exit 1; }
    ;;
  install|*)
    write_plist
    launchctl bootout "gui/$(_uid)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(_uid)" "$PLIST"
    echo "✓ launchd 설치·로드됨 — 월~목 15:30, 금 11:30 (잠들어 있었으면 깨어난 뒤 보충 실행)"
    echo "  plist: $PLIST"
    echo "  log:   $LOG"
    echo "  상태:  scripts/install-daily-launchd.sh --status"
    echo "  테스트: scripts/install-daily-launchd.sh --run"
    ;;
esac
