#!/bin/bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

allowed_types=("feat" "fix" "perf" "docs" "refactor" "style" "chore")
default_type="fix"
default_coauthor="Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
coauthor="${COMMIT_COAUTHOR:-$default_coauthor}"

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

contains_type() {
    local candidate="$1"
    local item
    for item in "${allowed_types[@]}"; do
        if [[ "$item" == "$candidate" ]]; then
            return 0
        fi
    done
    return 1
}

echo "=== 当前变更 ==="
git status --short
echo

if [[ -z "$(git status --short)" ]]; then
    echo "没有检测到可提交的变更。"
    exit 1
fi

echo "允许的提交类型: ${allowed_types[*]}"
read -r -p "请输入提交类型 [${default_type}]: " commit_type
commit_type="$(trim "${commit_type:-$default_type}")"
if [[ -z "$commit_type" ]]; then
    commit_type="$default_type"
fi
if ! contains_type "$commit_type"; then
    echo "错误：提交类型必须是以下之一: ${allowed_types[*]}"
    exit 1
fi

read -r -p "请输入本次更新说明: " summary
summary="$(trim "$summary")"
if [[ -z "$summary" ]]; then
    echo "错误：本次更新说明不能为空。"
    exit 1
fi

if git diff --name-only | rg -x '\.env|scripts/\.ldap_env' >/dev/null 2>&1; then
    echo "警告：检测到敏感配置文件变更，请确认是否应该提交。"
fi

commit_subject="${commit_type}: ${summary}"

echo
echo "=== 提交预览 ==="
printf '%s\n\nCo-Authored-By: %s\n' "$commit_subject" "$coauthor"
echo

read -r -p "确认执行 git add -A 并提交？[y/N]: " confirm
confirm="$(trim "$confirm")"
if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
    echo "已取消。"
    exit 0
fi

git add -A

if git diff --cached --quiet; then
    echo "暂存区没有可提交的内容。"
    exit 1
fi

git commit -m "$commit_subject" -m "Co-Authored-By: ${coauthor}"

echo
echo "=== 提交完成 ==="
git log -1 --stat
