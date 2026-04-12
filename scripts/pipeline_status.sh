#!/bin/bash
# 解析管道进度查询脚本
# 用法: bash scripts/pipeline_status.sh

MYSQL_CMD="docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -e"
SPOOL_DIR="/data/llm_api_monitor_runtime/data/spool/results"

echo "=========================================="
echo "  LLM API Monitor 解析管道进度"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="

echo ""
echo "--- 1. 实时延迟 ---"
LATEST=$(docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -N -e "SELECT MAX(last_seen) FROM api_logs;" 2>/dev/null)
NOW=$(date '+%Y-%m-%d %H:%M:%S')
echo "  DB 最新数据:  $LATEST"
echo "  当前时间:     $NOW"
if [ -n "$LATEST" ]; then
    LAG=$(( $(date -d "$NOW" +%s 2>/dev/null || echo 0) - $(date -d "$LATEST" +%s 2>/dev/null || echo 0) ))
    if [ "$LAG" -gt 0 ] 2>/dev/null; then
        if [ "$LAG" -lt 60 ]; then
            echo "  延迟:         ${LAG}s (正常)"
        elif [ "$LAG" -lt 300 ]; then
            echo "  延迟:         $((LAG/60))m$((LAG%60))s (轻微)"
        else
            echo "  延迟:         $((LAG/3600))h$((LAG%3600/60))m (异常!)"
        fi
    fi
fi

echo ""
echo "--- 2. Go 解析管道 ---"
docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -e "
SELECT
  analysis_status AS status,
  COUNT(*) AS jobs,
  MIN(started_at) AS earliest,
  MAX(started_at) AS latest
FROM capture_jobs
GROUP BY analysis_status
ORDER BY FIELD(analysis_status,'queued','parsing','parsed_ready','merging','merged','failed');" 2>/dev/null

TOTAL=$(docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -N -e "SELECT COUNT(*) FROM capture_jobs;" 2>/dev/null)
MERGED=$(docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -N -e "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='merged';" 2>/dev/null)
QUEUED=$(docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -N -e "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='queued';" 2>/dev/null)
FAILED=$(docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -N -e "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='failed';" 2>/dev/null)
PENDING=$((TOTAL - MERGED - FAILED))
if [ "$TOTAL" -gt 0 ] 2>/dev/null; then
    PCT=$((MERGED * 100 / TOTAL))
    echo "  总进度: $MERGED/$TOTAL ($PCT%)  待处理: $PENDING  失败: $FAILED"
fi

echo ""
echo "--- 3. Python Spool 消化 ---"
SPOOL_COUNT=$(ls "$SPOOL_DIR"/*.result.json.gz 2>/dev/null | wc -l)
DRAIN_PID=$(pgrep -f drain_spool_worker.py 2>/dev/null | head -1)
echo "  待消化文件:  $SPOOL_COUNT"
if [ -n "$DRAIN_PID" ]; then
    ELAPSED=$(ps -p "$DRAIN_PID" -o etime= 2>/dev/null | tr -d ' ')
    CPU=$(ps -p "$DRAIN_PID" -o %cpu= 2>/dev/null | tr -d ' ')
    echo "  进程状态:    运行中 (PID $DRAIN_PID, ${ELAPSED}, CPU ${CPU}%)"
else
    if [ "$SPOOL_COUNT" -eq 0 ]; then
        echo "  进程状态:    已完成"
    else
        echo "  进程状态:    未运行 (用 bash scripts/spool_drain.sh start 启动)"
    fi
fi

echo ""
echo "--- 4. Go 服务 ---"
GO_PID=$(pgrep -f 'llm-api-monitor$' 2>/dev/null | head -1)
if [ -n "$GO_PID" ]; then
    CPU=$(ps -p "$GO_PID" -o %cpu= 2>/dev/null | tr -d ' ')
    MEM=$(ps -p "$GO_PID" -o rss= 2>/dev/null | awk '{printf "%.0fMB", $1/1024}')
    echo "  状态: 运行中 (PID $GO_PID, CPU ${CPU}%, MEM $MEM)"
else
    echo "  状态: 未运行"
fi

echo ""
echo "--- 5. 数据库表行数 ---"
docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor -e "
SELECT TABLE_NAME, TABLE_ROWS, ROUND(DATA_LENGTH/1024/1024) AS data_mb
FROM information_schema.TABLES
WHERE TABLE_SCHEMA='llm_api_monitor'
ORDER BY TABLE_ROWS DESC;" 2>/dev/null

echo "=========================================="
