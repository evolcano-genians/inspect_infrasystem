#!/usr/bin/env bash
# 아침 k8s 트리아지 → Slack DM launchd 에이전트 (macOS). 매일 07:30.
#
# Mac이 07:30에 절전이면 launchd 가 깨어난 직후(=출근 후 Mac 열 때) 놓친 실행을 보충한다.
# 트리아지는 kubeconfig(두 클러스터) + Codex 가 있는 이 Mac에서만 수행된다.
#
# 사용:
#   scripts/install-triage-launchd.sh          # 설치/갱신 + 로드
#   scripts/install-triage-launchd.sh --remove # 제거
#   scripts/install-triage-launchd.sh --status # 상태
#   scripts/install-triage-launchd.sh --run    # 즉시 실행(테스트)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$PROJECT_ROOT/.venv/bin/python"
LABEL="com.genians.inspect-k8s.morning-triage"
PLIST="$HOME/Library/LaunchAgents/$LABEL.plist"
LOG="$PROJECT_ROOT/logs/morning-triage.log"

write_plist() {
  mkdir -p "$HOME/Library/LaunchAgents" "$PROJECT_ROOT/logs"
  cat > "$PLIST" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key>
  <array>
    <string>$PY</string><string>-m</string><string>src.morning_triage</string>
  </array>
  <key>WorkingDirectory</key><string>$PROJECT_ROOT</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>HOME</key><string>$HOME</string>
    <key>PATH</key><string>/usr/local/bin:/usr/bin:/bin</string>
    <key>AGENT_ALLOW_REAL_CLUSTER</key><string>1</string>
    <key>KUBECONFIG</key><string>$HOME/.kube/config</string>
  </dict>
  <!-- 매일 07:30. 잠들어 있었으면 깨어난 뒤 보충. -->
  <key>StartCalendarInterval</key>
  <dict><key>Hour</key><integer>7</integer><key>Minute</key><integer>30</integer></dict>
  <key>StandardOutPath</key><string>$LOG</string>
  <key>StandardErrorPath</key><string>$LOG</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
PLISTEOF
}

_uid() { id -u; }

case "${1:-install}" in
  --remove)
    launchctl bootout "gui/$(_uid)/$LABEL" 2>/dev/null || launchctl unload "$PLIST" 2>/dev/null || true
    rm -f "$PLIST"; echo "트리아지 에이전트 제거됨: $LABEL" ;;
  --status)
    if launchctl print "gui/$(_uid)/$LABEL" >/dev/null 2>&1; then
      echo "로드됨: $LABEL"
      launchctl print "gui/$(_uid)/$LABEL" 2>/dev/null | grep -E "state =|last exit code|runs =" | sed 's/^/  /' | head -6
    else echo "(로드 안 됨)"; fi
    echo "plist: $PLIST"; echo "log:   $LOG" ;;
  --run)
    launchctl kickstart -k "gui/$(_uid)/$LABEL" 2>/dev/null \
      && echo "즉시 실행 트리거됨 — 로그: $LOG" || { echo "먼저 설치하세요"; exit 1; } ;;
  install|*)
    write_plist
    launchctl bootout "gui/$(_uid)/$LABEL" 2>/dev/null || true
    launchctl bootstrap "gui/$(_uid)" "$PLIST"
    echo "✓ 트리아지 launchd 설치·로드됨 — 매일 07:30 (절전 시 깨어난 뒤 보충)"
    echo "  plist: $PLIST"; echo "  log: $LOG"
    echo "  테스트: scripts/install-triage-launchd.sh --run" ;;
esac
