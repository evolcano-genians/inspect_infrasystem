#!/usr/bin/env bash
# push-github.sh — 릴레이 경유 GitHub 동기화 (회사 보안 정책 준수)
#
# GitHub 자격증명은 원격 개발서버(172.29.70.161)에만 있다. 이 Mac은 서버의 bare repo로
# push하고, 서버가 GitHub(evolcano-genians/inspect_infrasystem)로 push한다:
#   Mac ──push──▶ 서버 ~/git-mirrors/inspect_infrasystem.git ──push──▶ GitHub
#
# 사용법: ./scripts/push-github.sh [branch]   (기본 main)
set -euo pipefail

BRANCH="${1:-main}"
RELAY_HOST="heejoon@172.29.70.161"
RELAY_REPO="git-mirrors/inspect_infrasystem.git"

git push relay "$BRANCH"
ssh -o BatchMode=yes "$RELAY_HOST" "git --git-dir ~/$RELAY_REPO push origin '$BRANCH'"
echo "✓ GitHub 동기화 완료: $BRANCH"
