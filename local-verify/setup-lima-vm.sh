#!/usr/bin/env bash
# setup-lima-vm.sh — 옵션 B: Lima VM + k3s 샌드박스 (커널 경계가 분리된 더 강한 격리)
#
# kind(컨테이너 격리)와 달리 VM 격리이므로, 구조적 안전장치 실패라는 극단적 시나리오까지
# 안전하게 관찰하고 싶을 때 사용한다. 원칙은 setup-kind.sh와 동일하다:
# k3s 기본 admin kubeconfig를 가공 없이 그대로 사용하고, RBAC을 만들지 않는다.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VM_NAME="k8s-inspector-sandbox"
SANDBOX_KUBECONFIG="$ROOT/.local/k3s-kubeconfig.yaml"
FIXTURES="$ROOT/local-verify/fixtures"

fail() { echo "setup-lima FAIL: $*" >&2; exit 1; }
kctl() { kubectl --kubeconfig "$SANDBOX_KUBECONFIG" "$@"; }

command -v limactl >/dev/null 2>&1 || fail "limactl이 없습니다 (brew install lima)"
command -v kubectl >/dev/null 2>&1 || fail "kubectl이 없습니다"

echo "[1/4] Lima VM(k3s) 준비..."
if ! limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$VM_NAME"; then
  limactl start --name="$VM_NAME" template://k3s --tty=false
fi

mkdir -p "$ROOT/.local"
limactl shell "$VM_NAME" sudo cat /etc/rancher/k3s/k3s.yaml > "$SANDBOX_KUBECONFIG"
chmod 600 "$SANDBOX_KUBECONFIG"

# 후처리: Lima는 기본적으로 VM의 6443 포트를 호스트 127.0.0.1로 포워딩하므로
# k3s.yaml의 127.0.0.1 서버 주소가 그대로 동작한다. 포워딩을 끈 커스텀 설정에서는
# LIMA_VM_IP=<vm ip> 로 서버 주소를 치환한다.
if [ -n "${LIMA_VM_IP:-}" ]; then
  sed -i.bak "s#https://127.0.0.1:6443#https://${LIMA_VM_IP}:6443#" "$SANDBOX_KUBECONFIG"
  rm -f "$SANDBOX_KUBECONFIG.bak"
fi

echo "[2/4] 마스터 kubeconfig 격리 검증(guard-check)..."
KUBECONFIG="$SANDBOX_KUBECONFIG" "$ROOT/local-verify/guard-check.sh"

echo "[3/4] 테스트 픽스처 시딩 (샌드박스 한정, RBAC 없음)..."
kctl apply -f "$FIXTURES/"

echo "[4/4] 픽스처 상태 대기..."
kctl wait --for=condition=Available deployment/healthy-web -n default --timeout=240s || true

echo ""
echo "setup-lima 완료. 사용법:"
echo "  KUBECONFIG=$SANDBOX_KUBECONFIG .venv/bin/pytest tests/"
