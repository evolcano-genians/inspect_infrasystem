#!/usr/bin/env bash
# teardown.sh — 샌드박스(클러스터/VM) 완전 삭제. setup 스크립트와 항상 쌍으로 제공 (브리프 4.2)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLUSTER_NAME="k8s-inspector-sandbox"

if command -v kind >/dev/null 2>&1 && kind get clusters 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "kind 클러스터 삭제: $CLUSTER_NAME"
  kind delete cluster --name "$CLUSTER_NAME" --kubeconfig "$ROOT/.local/kind-kubeconfig.yaml"
fi

if command -v limactl >/dev/null 2>&1 && limactl list --format '{{.Name}}' 2>/dev/null | grep -qx "$CLUSTER_NAME"; then
  echo "Lima VM 삭제: $CLUSTER_NAME"
  limactl delete "$CLUSTER_NAME" --force
fi

rm -f "$ROOT/.local/kind-kubeconfig.yaml" "$ROOT/.local/k3s-kubeconfig.yaml"
echo "teardown 완료"
