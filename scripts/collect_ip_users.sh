#!/bin/bash
# IP → 用户名映射采集脚本
# 从 AD 获取所有电脑主机名，通过 DNS 正向解析获取 IP，提取用户名
#
# 用法: bash scripts/collect_ip_users.sh
# 输出: scripts/ip_user_map.json (供 Go 程序读取)
#
# 依赖: ldapsearch, dig (yum install openldap-clients bind-utils)
# 环境变量:
#   LDAP_URL            ldap://10.20.3.85:389
#   LDAP_BIND_DN        ldap-ssp@xmfunny.com
#   LDAP_BIND_PASSWORD  (密码)
#   LDAP_BASE_DN        DC=xmfunny,DC=com
#   DNS_SERVER          10.20.3.11 (可选，默认从 LDAP_URL 提取)

set -e

LDAP_URL="${LDAP_URL:-ldap://10.20.3.85:389}"
LDAP_BIND_DN="${LDAP_BIND_DN:-ldap-ssp@xmfunny.com}"
LDAP_BIND_PASSWORD="${LDAP_BIND_PASSWORD}"
LDAP_BASE_DN="${LDAP_BASE_DN:-DC=xmfunny,DC=com}"
DNS_SERVER="${DNS_SERVER:-10.20.3.11}"
DOMAIN_SUFFIX="${DOMAIN_SUFFIX:-.xmfunny.com}"
OUTPUT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_FILE="${OUTPUT_DIR}/ip_user_map.json"
OUTPUT_CSV="${OUTPUT_DIR}/ip_user_map.csv"

if [ -z "$LDAP_BIND_PASSWORD" ]; then
    echo "错误: LDAP_BIND_PASSWORD 未设置"
    echo "用法: LDAP_BIND_PASSWORD='xxx' bash $0"
    exit 1
fi

echo "[$(date '+%H:%M:%S')] 从 AD 获取电脑列表..."

# Step 1: Get all computer dNSHostName + OU path from AD
HOSTS_RAW=$(ldapsearch -x -H "$LDAP_URL" \
    -D "$LDAP_BIND_DN" \
    -w "$LDAP_BIND_PASSWORD" \
    -b "$LDAP_BASE_DN" \
    -s sub '(&(objectClass=computer)(dNSHostName=*))' dNSHostName \
    -z 0 -E pr=1000/noprompt 2>/dev/null | grep "^dNSHostName:" | sed 's/dNSHostName: //')

TOTAL=$(echo "$HOSTS_RAW" | wc -l)
echo "[$(date '+%H:%M:%S')] 获取到 $TOTAL 台电脑，开始 DNS 解析..."

# Step 2: Resolve each hostname to IP and extract username from hostname
RESOLVED=0
FAILED=0

echo "ip,hostname,username,department" > "$OUTPUT_CSV"
echo "{" > "$OUTPUT_FILE"
FIRST=true

while IFS= read -r fqdn; do
    [ -z "$fqdn" ] && continue

    # DNS resolve
    ip=$(dig @"$DNS_SERVER" "$fqdn" +short +time=1 +tries=1 2>/dev/null | grep -oP '^\d+\.\d+\.\d+\.\d+' | head -1)

    if [ -z "$ip" ]; then
        FAILED=$((FAILED + 1))
        continue
    fi

    # Extract username from hostname pattern: DEPT-username.domain or username.domain
    shortname=$(echo "$fqdn" | sed "s/$DOMAIN_SUFFIX\$//" | tr '[:upper:]' '[:lower:]')

    # Try to extract username (after the department prefix)
    if echo "$shortname" | grep -q '-'; then
        dept=$(echo "$shortname" | cut -d'-' -f1 | tr '[:lower:]' '[:upper:]')
        username=$(echo "$shortname" | cut -d'-' -f2-)
    else
        dept=""
        username="$shortname"
    fi

    # Write CSV
    echo "$ip,$shortname,$username,$dept" >> "$OUTPUT_CSV"

    # Write JSON
    if [ "$FIRST" = true ]; then
        FIRST=false
    else
        echo "," >> "$OUTPUT_FILE"
    fi
    printf '  "%s": {"hostname": "%s", "username": "%s", "department": "%s"}' \
        "$ip" "$shortname" "$username" "$dept" >> "$OUTPUT_FILE"

    RESOLVED=$((RESOLVED + 1))
    if [ $((RESOLVED % 50)) -eq 0 ]; then
        echo "[$(date '+%H:%M:%S')] 已解析 $RESOLVED/$TOTAL..."
    fi
done <<< "$HOSTS_RAW"

echo "" >> "$OUTPUT_FILE"
echo "}" >> "$OUTPUT_FILE"

echo ""
echo "=========================================="
echo "  AD 采集完成"
echo "=========================================="
echo "  AD 电脑总数:   $TOTAL"
echo "  DNS 解析成功:  $RESOLVED"
echo "  DNS 解析失败:  $FAILED"
echo "  JSON 输出:     $OUTPUT_FILE"
echo "  CSV 输出:      $OUTPUT_CSV"
echo "=========================================="

# Step 3: Merge fixed IP-user mappings (manual overrides)
FIXED_CSV="${OUTPUT_DIR}/fixed_user_ip.csv"
if [ -f "$FIXED_CSV" ]; then
    echo ""
    echo "[$(date '+%H:%M:%S')] 合并固定 IP-用户映射: $FIXED_CSV"
    FIXED_COUNT=0

    # Use python to merge: read existing JSON, overlay fixed CSV entries, write back
    python -c "
import json, csv, sys

json_path = sys.argv[1]
csv_path  = sys.argv[2]

# Load existing JSON
with open(json_path, 'r') as f:
    data = json.load(f)

# Read fixed CSV (skip header, deduplicate by IP — last wins)
added = 0
with open(csv_path, 'r') as f:
    reader = csv.reader(f)
    header = next(reader, None)
    for row in reader:
        if len(row) < 3:
            continue
        username = row[0].strip()
        department = row[1].strip() if len(row) > 1 else ''
        ip = row[2].strip()
        if not ip or not username:
            continue
        # Fixed mappings override AD mappings
        data[ip] = {
            'hostname': username,
            'username': username,
            'department': department
        }
        added += 1

with open(json_path, 'w') as f:
    json.dump(data, f, ensure_ascii=False, indent=2)

print('[fixed] merged %d fixed entries (total %d IPs)' % (added, len(data)))
" "$OUTPUT_FILE" "$FIXED_CSV" 2>&1

    # Also append to CSV
    tail -n +2 "$FIXED_CSV" | while IFS=',' read -r username dept ip; do
        username=$(echo "$username" | xargs)
        dept=$(echo "$dept" | xargs)
        ip=$(echo "$ip" | xargs)
        [ -z "$ip" ] || [ -z "$username" ] && continue
        echo "$ip,$username,$username,$dept" >> "$OUTPUT_CSV"
    done

    echo "[$(date '+%H:%M:%S')] 固定映射合并完成"
else
    echo ""
    echo "[info] 未找到固定映射文件 $FIXED_CSV，跳过合并"
fi

echo ""
echo "前 10 条映射:"
head -12 "$OUTPUT_CSV"
