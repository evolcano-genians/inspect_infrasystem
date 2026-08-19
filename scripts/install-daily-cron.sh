#!/usr/bin/env bash
# 일일 대화 요약 → Confluence 비공개 게시 크론 설치/제거.
# 스케줄: 월~목 15:30, 금 11:30 (주말 없음).
#
# 사용:
#   scripts/install-daily-cron.sh          # 설치(또는 갱신)
#   scripts/install-daily-cron.sh --remove # 제거
#   scripts/install-daily-cron.sh --show   # 현재 등록 확인
#
# 요약은 Codex(gpt-5.6-sol)로 수행하고, Confluence 개인 스페이스(비공개)에 하루 1건 게시한다.
# 같은 날 재실행하면 새 문서를 만들지 않고 기존 문서를 갱신한다.
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$PROJECT_ROOT/.venv/bin/python"
LOG="$PROJECT_ROOT/logs/daily-report-cron.log"
TAG="# inspect-k8s-daily-report"
# codex OAuth·JIRA 자격증명은 .env / ~/.langchain-codex-oauth 에서 로드된다.
# 크론은 최소 PATH만 가지므로 필요한 것만 명시. MODEL_PROVIDER는 .env 기본값(codex-oauth) 사용.
# cron 요일: 1=월 … 5=금. 월~목(1-4) 15:30, 금(5) 11:30.
_CMD="cd $PROJECT_ROOT && PATH=/usr/local/bin:/usr/bin:/bin HOME=$HOME $PY -m src.daily_report >> $LOG 2>&1"
CRON_LINES=(
  "30 15 * * 1-4 $_CMD $TAG"
  "30 11 * * 5 $_CMD $TAG"
)

case "${1:-install}" in
  --show)
    crontab -l 2>/dev/null | grep -F "$TAG" || echo "(등록된 일일 크론 없음)"
    ;;
  --remove)
    current="$(crontab -l 2>/dev/null || true)"
    printf '%s\n' "$current" | grep -vF "$TAG" | grep -v '^$' | crontab - || true
    echo "일일 요약 크론 제거됨"
    ;;
  install|*)
    mkdir -p "$PROJECT_ROOT/logs"
    # 기존 항목 제거 후 재등록(중복 방지). grep 이 no-match(exit1)여도 set -e 로 중단되지 않게 분리.
    current="$(crontab -l 2>/dev/null || true)"
    kept="$(printf '%s\n' "$current" | grep -vF "$TAG" | grep -v '^$' || true)"
    { [ -n "$kept" ] && printf '%s\n' "$kept"; printf '%s\n' "${CRON_LINES[@]}"; } | crontab -
    echo "✓ 설치됨 — 월~목 15:30, 금 11:30 실행"
    echo "  로그: $LOG"
    echo "  현재 등록:"
    crontab -l 2>/dev/null | grep -F "$TAG" | sed 's/^/    /'
    ;;
esac
