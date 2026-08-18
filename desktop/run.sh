#!/usr/bin/env bash
# run.sh — inspect-k8s 데스크톱 앱 실행 (실 클러스터 read-only + 소스 도구).
# 필요에 맞게 환경변수를 조정하세요.
set -euo pipefail
cd "$(dirname "$0")"

[ -d node_modules/electron ] || { echo "electron 미설치 — 'npm install' 먼저 실행"; exit 1; }

export AGENT_ALLOW_REAL_CLUSTER="${AGENT_ALLOW_REAL_CLUSTER:-1}"
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
export KUBE_CONTEXT="${KUBE_CONTEXT:-aws-seoul-clouddev}"
export SOURCE_SSH_HOST="${SOURCE_SSH_HOST:-heejoon@172.29.70.161}"
export MODEL_PROVIDER="${MODEL_PROVIDER:-codex-oauth}"
# 보안 도구가 필요하면 주석 해제:
# export SANDBOX_BASH_ENABLED=1
# export STRIX_ENABLED=1

exec node_modules/.bin/electron .
