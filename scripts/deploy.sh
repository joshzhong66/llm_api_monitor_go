#!/bin/bash
# 一键编译 + 重启 LLM API Monitor (Go)
# 用法: bash scripts/deploy.sh
#
# 可选参数:
#   --merge-ip   同时合并 fixed_user_ip.csv 到 ip_user_map.json
#   --no-restart 只编译不重启

set -e

cd "$(dirname "$0")/.."
PROJECT_DIR="$(pwd)"

export PATH=$PATH:/usr/local/go/bin
export GOPROXY=https://goproxy.cn,direct

DO_RESTART=true
DO_MERGE_IP=false

for arg in "$@"; do
    case "$arg" in
        --merge-ip) DO_MERGE_IP=true ;;
        --no-restart) DO_RESTART=false ;;
    esac
done

echo "=========================================="
echo "  LLM API Monitor 部署脚本"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

# Step 1: Merge fixed IP mappings if requested
if [ "$DO_MERGE_IP" = true ]; then
    FIXED_CSV="${PROJECT_DIR}/scripts/fixed_user_ip.csv"
    JSON_FILE="${PROJECT_DIR}/scripts/ip_user_map.json"
    if [ -f "$FIXED_CSV" ] && [ -f "$JSON_FILE" ]; then
        echo ""
        echo "[1/3] 合并固定 IP-用户映射..."
        python -c "
import json, csv, sys
json_path = sys.argv[1]
csv_path  = sys.argv[2]
with open(json_path, 'r') as f:
    data = json.load(f)
before = len(data)
added = 0
with open(csv_path, 'r') as f:
    reader = csv.reader(f)
    next(reader, None)
    for row in reader:
        if len(row) < 3: continue
        username = row[0].strip()
        department = row[1].strip() if len(row) > 1 else ''
        ip = row[2].strip()
        if not ip or not username: continue
        data[ip] = {'hostname': username, 'username': username, 'department': department}
        added += 1
with open(json_path, 'w') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)
print('  合并 %d 条固定映射 (%d -> %d IPs)' % (added, before, len(data)))
" "$JSON_FILE" "$FIXED_CSV"
    else
        echo "[1/3] 跳过：缺少 fixed_user_ip.csv 或 ip_user_map.json"
    fi
else
    echo "[1/3] 跳过 IP 映射合并 (加 --merge-ip 启用)"
fi

# Step 2: Build
echo ""
echo "[2/3] 编译中..."
go build -o llm-api-monitor ./cmd/monitor/
ls -lh llm-api-monitor | awk '{print "  编译完成:", $5, $9}'

# Step 3: Restart
if [ "$DO_RESTART" = true ]; then
    echo ""
    echo "[3/3] 重启服务..."
    systemctl restart llm-api-monitor-go
    sleep 2
    STATUS=$(systemctl is-active llm-api-monitor-go 2>/dev/null)
    if [ "$STATUS" = "active" ]; then
        echo "  服务状态: 运行中 ✓"
    else
        echo "  服务状态: $STATUS ✗"
        echo "  查看日志: journalctl -u llm-api-monitor-go -n 20"
        exit 1
    fi
else
    echo ""
    echo "[3/3] 跳过重启 (加 --no-restart)"
fi

echo ""
echo "=========================================="
echo "  部署完成"
echo "=========================================="
