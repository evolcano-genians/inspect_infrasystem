#!/usr/bin/env bash
# guard-check.sh — 마스터 kubeconfig 격리 검증 (브리프 3절, 테스트 6-6)
#
# 현재 KUBECONFIG가:
#   1) 설정되어 있고 파일이 존재하는지
#   2) 사용자의 실제 마스터 kubeconfig(~/.kube/config) 그 자체가 아닌지
#   3) 컨텍스트 이름에 prod/production 마커가 없는지
#   4) 서버 주소·CA 지문이 마스터 kubeconfig의 어떤 클러스터와도 겹치지 않는지
# 검증하고, 하나라도 위반이면 즉시 실패(exit 1)한다.
#
# 이 스크립트가 ~/.kube/config를 참조하는 유일한 이유는 "그것을 쓰고 있지 않음"을
# 증명하기 위해서다. 자격증명으로 사용하지 않는다.
# (테스트에서는 GUARD_MASTER_KUBECONFIG로 가짜 마스터 경로를 주입한다.)
set -euo pipefail

fail() { echo "guard-check FAIL: $*" >&2; exit 1; }

command -v kubectl >/dev/null 2>&1 || fail "kubectl이 설치되어 있지 않습니다"

[ -n "${KUBECONFIG:-}" ] || fail "KUBECONFIG가 설정되지 않았습니다 — 샌드박스 kubeconfig를 명시하세요"
[ -f "$KUBECONFIG" ] || fail "KUBECONFIG 파일이 존재하지 않습니다: $KUBECONFIG"

MASTER="${GUARD_MASTER_KUBECONFIG:-$HOME/.kube/config}"

abspath() { cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd -P)" "$(basename "$1")"; }

SANDBOX_REAL="$(abspath "$KUBECONFIG")"
if [ -f "$MASTER" ]; then
  MASTER_REAL="$(abspath "$MASTER")"
  if [ "$SANDBOX_REAL" = "$MASTER_REAL" ]; then
    fail "KUBECONFIG가 마스터 kubeconfig 자체를 가리키고 있습니다: $SANDBOX_REAL"
  fi
fi

# --- 컨텍스트 이름 fail-fast ---
ALL_CTX="$(kubectl config view --kubeconfig "$KUBECONFIG" \
  -o jsonpath='{range .contexts[*]}{.name}{"\n"}{end}'; \
  kubectl config view --kubeconfig "$KUBECONFIG" -o jsonpath='{.current-context}')"
if printf '%s' "$ALL_CTX" | grep -qiE 'prod'; then
  fail "컨텍스트 이름에 prod 마커가 포함되어 있습니다: $(printf '%s' "$ALL_CTX" | tr '\n' ' ')"
fi

servers_of() {
  kubectl config view --raw --kubeconfig "$1" \
    -o jsonpath='{range .clusters[*]}{.cluster.server}{"\n"}{end}' | sed '/^$/d' | sort -u
}

ca_fingerprints_of() {
  kubectl config view --raw --kubeconfig "$1" \
    -o jsonpath='{range .clusters[*]}{.cluster.certificate-authority-data}{"\n"}{end}' \
    | sed '/^$/d' \
    | while IFS= read -r ca; do printf '%s' "$ca" | shasum -a 256 | cut -d' ' -f1; done \
    | sort -u
}

if [ -f "$MASTER" ]; then
  SERVER_OVERLAP="$(comm -12 <(servers_of "$KUBECONFIG") <(servers_of "$MASTER") || true)"
  if [ -n "$SERVER_OVERLAP" ]; then
    fail "KUBECONFIG의 서버 주소가 마스터 kubeconfig의 클러스터와 겹칩니다: $SERVER_OVERLAP"
  fi
  CA_OVERLAP="$(comm -12 <(ca_fingerprints_of "$KUBECONFIG") <(ca_fingerprints_of "$MASTER") || true)"
  if [ -n "$CA_OVERLAP" ]; then
    fail "KUBECONFIG의 CA 지문이 마스터 kubeconfig의 클러스터와 겹칩니다"
  fi
else
  echo "guard-check note: 마스터 kubeconfig($MASTER)가 없어 충돌 검사를 생략합니다"
fi

echo "guard-check OK: KUBECONFIG=$SANDBOX_REAL 는 마스터 kubeconfig와 격리되어 있습니다"
