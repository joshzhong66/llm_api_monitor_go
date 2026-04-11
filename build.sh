#!/bin/bash
# 构建 LLM API Monitor Go 版本
set -e

export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct

cd "$(dirname "$0")"

echo "=== 下载依赖 ==="
go mod tidy

echo "=== 编译 ==="
go build -o llm-api-monitor ./cmd/monitor/
ls -lh llm-api-monitor

echo "=== 完成 ==="
echo "运行方式: cd $(pwd) && ./llm-api-monitor"
echo "安装 systemd: cp systemd/llm-api-monitor-go.service /etc/systemd/system/ && systemctl daemon-reload"
