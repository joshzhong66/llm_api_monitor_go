#!/bin/bash
# 发布 release 到 GitHub
# 使用前先确保 gh 已认证：gh auth login
set -e

cd "$(dirname "$0")"

VERSION="v0.1.0"
TARBALL="/root/llm_api_monitor_go-${VERSION}.tar.gz"

echo "=== 检查 gh 认证 ==="
if ! gh auth status 2>/dev/null; then
    echo "错误：gh 未认证，请先运行: gh auth login"
    exit 1
fi

echo "=== 创建 GitHub Release ==="
gh release create "${VERSION}" \
    --title "LLM API Monitor Go ${VERSION}" \
    --notes-file RELEASE_NOTES_v0.1.0.md \
    "${TARBALL}#llm_api_monitor_go-${VERSION}.tar.gz (源码包)"

echo "=== 完成！==="
echo "Release 地址: https://github.com/joshzhong66/llm_api_monitor_go/releases/tag/${VERSION}"
