#!/usr/bin/env bash
# setup-kind.sh — 옵션 A: kind 샌드박스 생성 + 테스트 픽스처 시딩 (브리프 4.1)
#
# 원칙:
# - 이 스크립트는 자신이 생성한 샌드박스 kubeconfig(.local/kind-kubeconfig.yaml)로만 동작하며
#   사용자의 기본 kubeconfig(~/.kube 아래)는 절대 읽거나 쓰지 않는다. (kind --kubeconfig 플래그로 격리)
# - kind 기본 admin kubeconfig를 가공 없이 그대로 사용한다. RBAC·ServiceAccount·토큰을
#   생성하지 않는다 — admin 권한 아래에서도 앱 레벨 안전장치만으로 read-only가 보장되는지
#   실증하는 것이 이 샌드박스의 목적이다.
# - 픽스처 시딩은 브리프 4.1이 요구하는, 샌드박스 한정 준비 절차다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER_NAME="k8s-inspector-sandbox"
SANDBOX_KUBECONFIG="$ROOT/.local/kind-kubeconfig.yaml"
FIXTURES="$ROOT/local-verify/fixtures"

fail() { echo "setup-kind FAIL: $*" >&2; exit 1; }
kctl() { kubectl --kubeconfig "$SANDBOX_KUBECONFIG" "$@"; }

for cmd in docker kind kubectl; do
  command -v "$cmd" >/dev/null 2>&1 || fail "$cmd 가 설치되어 있지 않습니다"
done

# Docker Desktop / Colima / OrbStack 어느 런타임이든 docker info로 자동 감지
echo "[1/5] docker 데몬 확인..."
for i in $(seq 1 45); do
  if docker info >/dev/null 2>&1; then break; fi
  [ "$i" -eq 45 ] && fail "docker 데몬이 실행 중이 아닙니다 (Docker Desktop/Colima/OrbStack을 시작하세요)"
  sleep 2
done

mkdir -p "$ROOT/.local"

echo "[2/5] kind 클러스터 준비..."
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "  기존 클러스터 재사용 — kubeconfig 재발급"
  kind export kubeconfig --name "$CLUSTER_NAME" --kubeconfig "$SANDBOX_KUBECONFIG"
else
  kind create cluster \
    --name "$CLUSTER_NAME" \
    --config "$ROOT/local-verify/kind-config.yaml" \
    --kubeconfig "$SANDBOX_KUBECONFIG" \
    --wait 180s
fi

echo "[3/5] 마스터 kubeconfig 격리 검증(guard-check)..."
KUBECONFIG="$SANDBOX_KUBECONFIG" "$ROOT/local-verify/guard-check.sh"

echo "[4/5] 테스트 픽스처 시딩 (샌드박스 한정)..."
kctl apply -f "$FIXTURES/"

# 주의: metrics-server는 설치하지 않는다 — 업스트림 매니페스트에 RBAC/ServiceAccount가
# 포함되어 "RBAC은 샌드박스에조차 만들지 않는다"는 원칙과 충돌하기 때문이다.
# 리소스 사용량 시나리오는 파드 requests/limits 조회로 검증되며, `top` 테스트는
# metrics API 부재 시 skip 처리된다. (원하면 사용자가 수동으로 설치할 수는 있으나
# 이 저장소의 스크립트는 이를 자동화하지 않는다.)

echo "[5/5] 픽스처 상태 대기..."
kctl wait --for=condition=Available deployment/healthy-web -n default --timeout=240s

wait_restart() { # crashloop-demo가 최소 1회 재시작할 때까지 대기
  for i in $(seq 1 80); do
    rc="$(kctl get pod crashloop-demo -n default \
      -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo 0)"
    if [ "${rc:-0}" -ge 1 ] 2>/dev/null; then echo "  ✓ crashloop-demo restarts=$rc"; return 0; fi
    sleep 3
  done
  fail "crashloop-demo가 재시작 상태에 도달하지 않았습니다"
}

wait_imagepull() { # imagepull-demo가 ErrImagePull/ImagePullBackOff에 도달할 때까지 대기
  for i in $(seq 1 80); do
    reason="$(kctl get pod imagepull-demo -n default \
      -o jsonpath='{.status.containerStatuses[0].state.waiting.reason}' 2>/dev/null || echo '')"
    case "$reason" in
      ErrImagePull|ImagePullBackOff) echo "  ✓ imagepull-demo waiting=$reason"; return 0 ;;
    esac
    sleep 3
  done
  fail "imagepull-demo가 이미지 풀 실패 상태에 도달하지 않았습니다"
}

wait_restart
wait_imagepull
kctl wait --for=condition=Ready pod/high-resource-demo -n default --timeout=180s

echo ""
echo "setup-kind 완료. 사용법:"
echo "  KUBECONFIG=$SANDBOX_KUBECONFIG .venv/bin/pytest tests/"
echo "  KUBECONFIG=$SANDBOX_KUBECONFIG .venv/bin/python -m src.cli \"CrashLoopBackOff 파드 찾아줘\""
