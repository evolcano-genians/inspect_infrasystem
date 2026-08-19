#!/usr/bin/env bash
# nexus-lake Trino(ClusterIP)로 가는 SSH 터널 — Mac에서 Trino 분석 도구를 쓰기 위함.
#
# Trino 서비스는 ClusterIP(10.152.x.x:8080)라 Mac에서 직접 닿지 않는다. k8s 노드는 kube-proxy로
# ClusterIP를 라우팅하므로, SSH 로컬 포워딩으로 노드를 경유해 접근한다. (k8s port-forward 는
# 이 프로젝트의 read-only 원칙상 쓰지 않는다 — 순수 SSH 터널만 사용.)
#
# 사용:
#   scripts/trino-tunnel.sh azure     # Azure Trino → 127.0.0.1:18080 (azure-master 경유)
#   scripts/trino-tunnel.sh stop      # 터널 종료
#   scripts/trino-tunnel.sh status
#
# 열린 뒤: TRINO_ENDPOINT=http://127.0.0.1:18080 로 trino_* 도구가 동작한다.
set -euo pipefail

LOCAL_PORT="${TRINO_LOCAL_PORT:-18080}"
PIDFILE="/tmp/inspect-k8s-trino-tunnel.pid"

# 클러스터별 (SSH 대상, Trino ClusterIP:포트). Azure master는 인가된 SSH 키로 접근 가능.
declare_target() {
  case "$1" in
    azure)
      SSH_TARGET="azureuser@74.243.248.15"
      SSH_KEY="$HOME/.ssh/azure-master"
      TRINO_ADDR="10.152.130.71:8080"   # azure-uae-gsp nexus-shell/trino ClusterIP
      ;;
    aws)
      # AWS는 SSH 가능한 노드가 확인되면 여기 채운다(원격 PC 경유 등). 미확인.
      echo "aws 대상은 아직 SSH 노드가 설정되지 않았습니다. azure를 쓰거나 대상을 지정하세요." >&2
      exit 2
      ;;
    *) echo "알 수 없는 대상: $1 (azure|aws)" >&2; exit 2 ;;
  esac
}

case "${1:-status}" in
  stop)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      kill "$(cat "$PIDFILE")" && rm -f "$PIDFILE" && echo "터널 종료됨"
    else echo "(실행 중인 터널 없음)"; rm -f "$PIDFILE"; fi
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "터널 실행 중 (pid $(cat "$PIDFILE")) → 127.0.0.1:$LOCAL_PORT"
      echo "TRINO_ENDPOINT=http://127.0.0.1:$LOCAL_PORT"
    else echo "(터널 없음)"; fi
    ;;
  azure|aws)
    declare_target "$1"
    # 기존 터널 정리
    [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true
    ssh -i "$SSH_KEY" -o BatchMode=yes -o ExitOnForwardFailure=yes -o StrictHostKeyChecking=accept-new \
        -N -L "127.0.0.1:$LOCAL_PORT:$TRINO_ADDR" "$SSH_TARGET" &
    echo $! > "$PIDFILE"
    sleep 2
    if kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "✓ Trino 터널 열림: 127.0.0.1:$LOCAL_PORT → $1 ($TRINO_ADDR)"
      echo "  이제 설정에 TRINO_ENDPOINT=http://127.0.0.1:$LOCAL_PORT 를 넣으면 분석 도구가 동작합니다."
      echo "  종료: scripts/trino-tunnel.sh stop"
    else
      echo "터널 실패 — SSH 접근·ClusterIP를 확인하세요"; rm -f "$PIDFILE"; exit 1
    fi
    ;;
esac
