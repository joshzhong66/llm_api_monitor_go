#!/bin/bash
# MySQL buffer pool 在线扩展脚本
# CentOS 7 kernel 3.10 上 8G buffer pool 启动初始化极慢
# 解决方案：启动参数用 4G，启动后在线扩展到 8G
#
# 用法：
#   容器启动后执行: bash /root/llm_api_monitor/scripts/mysql_expand_buffer_pool.sh
#   或加到 crontab: @reboot sleep 120 && bash /root/llm_api_monitor/scripts/mysql_expand_buffer_pool.sh

TARGET_GB=8
TARGET_BYTES=$((TARGET_GB * 1024 * 1024 * 1024))

# 等待 MySQL 就绪
for i in $(seq 1 60); do
    if docker exec llm-monitor-mysql mysqladmin -uroot -p123456 ping 2>/dev/null | grep -q alive; then
        break
    fi
    sleep 2
done

CURRENT=$(docker exec llm-monitor-mysql mysql -uroot -p123456 -N -e "SELECT @@innodb_buffer_pool_size;" 2>/dev/null)
if [ "$CURRENT" -ge "$TARGET_BYTES" ] 2>/dev/null; then
    echo "buffer pool already ${TARGET_GB}G, skip"
    exit 0
fi

echo "expanding buffer pool to ${TARGET_GB}G..."
docker exec llm-monitor-mysql mysql -uroot -p123456 -e "SET GLOBAL innodb_buffer_pool_size = ${TARGET_BYTES};" 2>/dev/null
sleep 2
AFTER=$(docker exec llm-monitor-mysql mysql -uroot -p123456 -N -e "SELECT @@innodb_buffer_pool_size/1024/1024/1024;" 2>/dev/null)
echo "buffer pool now: ${AFTER}G"
