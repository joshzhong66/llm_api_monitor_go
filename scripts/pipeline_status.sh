#!/bin/bash
# 解析管道进度查询脚本
# 用法: bash scripts/pipeline_status.sh

MYSQL_DOCKER=(docker exec llm-monitor-mysql mysql -uroot -p123456 llm_api_monitor)
SPOOL_DIR="/data/llm_api_monitor_runtime/data/spool/results"

q() {
    "${MYSQL_DOCKER[@]}" -N -e "$1" 2>/dev/null
}

HEADER_TOP='┌──────────────────────────────────────────────────────────────────────────┐'
HEADER_BOTTOM='└──────────────────────────────────────────────────────────────────────────┘'

box_line() {
    local text="$1"
    local width="${2:-72}"
    printf '│ %-*s │\n' "$width" "$text"
}

fmt_lag() {
    local lag="$1"
    if [ "$lag" -lt 60 ]; then
        printf '%ss (正常)' "$lag"
    elif [ "$lag" -lt 300 ]; then
        printf '%sm%ss (轻微)' $((lag/60)) $((lag%60))
    else
        printf '%sh%sm (异常!)' $((lag/3600)) $((lag%3600/60))
    fi
}

table_top() { echo "┌────────────────┬────────┬─────────────────────┬─────────────────────┐"; }
table_mid() { echo "├────────────────┼────────┼─────────────────────┼─────────────────────┤"; }
table_bottom() { echo "└────────────────┴────────┴─────────────────────┴─────────────────────┘"; }

stat_row() {
    printf "│ %-14s │ %6s │ %-19s │ %-19s │\n" "$1" "$2" "$3" "$4"
}

mini_top() { echo "┌──────────────────────────┬──────────────────────────────────────────────┐"; }
mini_bottom() { echo "└──────────────────────────┴──────────────────────────────────────────────┘"; }
mini_row() {
    printf "│ %-24s │ %-44s │\n" "$1" "$2"
}

NOW="$(date '+%Y-%m-%d %H:%M:%S')"
LATEST="$(q "SELECT MAX(last_seen) FROM api_logs;")"

TOTAL="$(q "SELECT COUNT(*) FROM capture_jobs;")"
MERGED="$(q "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='merged';")"
QUEUED="$(q "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='queued';")"
PARSING="$(q "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='parsing';")"
READY="$(q "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='parsed_ready';")"
MERGING="$(q "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='merging';")"
FAILED="$(q "SELECT COUNT(*) FROM capture_jobs WHERE analysis_status='failed';")"
PENDING=$((TOTAL - MERGED - FAILED))

RT_QUEUED="$(q "SELECT COUNT(*) FROM capture_jobs WHERE queue_name='realtime' AND analysis_status='queued';")"
RT_READY="$(q "SELECT COUNT(*) FROM capture_jobs WHERE queue_name='realtime' AND analysis_status='parsed_ready';")"
RT_MERGING="$(q "SELECT COUNT(*) FROM capture_jobs WHERE queue_name='realtime' AND analysis_status='merging';")"
BACKFILL_READY="$(q "SELECT COUNT(*) FROM capture_jobs WHERE queue_name='backfill' AND analysis_status='parsed_ready';")"

GO_PID="$(pgrep -f 'llm-api-monitor$' 2>/dev/null | head -1)"
if [ -n "$GO_PID" ]; then
    GO_CPU="$(ps -p "$GO_PID" -o %cpu= 2>/dev/null | tr -d ' ')"
    GO_MEM="$(ps -p "$GO_PID" -o rss= 2>/dev/null | awk '{printf "%.0fMB", $1/1024}')"
else
    GO_CPU="-"
    GO_MEM="-"
fi

DRAIN_PID="$(pgrep -f drain_spool_worker.py 2>/dev/null | head -1)"
SPOOL_COUNT=$(ls "$SPOOL_DIR"/*.result.json.gz 2>/dev/null | wc -l)
if [ -n "$DRAIN_PID" ]; then
    DRAIN_ELAPSED="$(ps -p "$DRAIN_PID" -o etime= 2>/dev/null | tr -d ' ')"
    DRAIN_CPU="$(ps -p "$DRAIN_PID" -o %cpu= 2>/dev/null | tr -d ' ')"
    DRAIN_STATUS="运行中 (PID $DRAIN_PID, ${DRAIN_ELAPSED}, CPU ${DRAIN_CPU}%)"
else
    if [ "$SPOOL_COUNT" -eq 0 ] 2>/dev/null; then
        DRAIN_STATUS="已完成"
    else
        DRAIN_STATUS="未运行"
    fi
fi

if [ -n "$LATEST" ]; then
    NOW_EPOCH=$(date -d "$NOW" +%s 2>/dev/null || echo 0)
    LATEST_EPOCH=$(date -d "$LATEST" +%s 2>/dev/null || echo 0)
    LAG=$((NOW_EPOCH - LATEST_EPOCH))
    LAG_TEXT="$(fmt_lag "$LAG")"
else
    LAG_TEXT="无数据"
fi

if [ "${READY:-0}" -gt "${PARSING:-0}" ] && [ "${MERGING:-0}" -gt 0 ]; then
    BOTTLENECK="写库/合并偏慢，parser 产出快于 writer 落库"
elif [ "${QUEUED:-0}" -gt "${READY:-0}" ]; then
    BOTTLENECK="解析偏慢，queued 高于 parsed_ready"
else
    BOTTLENECK="整体流动中，需继续观察近 5-10 分钟斜率"
fi

if [ "${RT_READY:-0}" -gt 800 ]; then
    BOTTLENECK="$BOTTLENECK；实时队列 parsed_ready 积压明显"
fi

echo "$HEADER_TOP"
box_line "LLM API Monitor Pipeline Status" 72
box_line "$NOW" 72
echo "$HEADER_BOTTOM"
echo

mini_top
mini_row "DB latest" "${LATEST:-NULL}"
mini_row "Now" "$NOW"
mini_row "Lag" "$LAG_TEXT"
mini_row "Progress" "${MERGED}/${TOTAL} ($((MERGED * 100 / TOTAL))%)"
mini_row "Pending" "$PENDING"
mini_row "Failed" "$FAILED"
mini_row "Go service" "$( [ -n "$GO_PID" ] && echo "running PID ${GO_PID}, CPU ${GO_CPU}%, MEM ${GO_MEM}" || echo "stopped" )"
mini_row "Python spool" "pending ${SPOOL_COUNT}, ${DRAIN_STATUS}"
mini_bottom
echo

table_top
stat_row "status" "jobs" "earliest" "latest"
table_mid
while IFS=$'\t' read -r status jobs earliest latest; do
    [ -z "$status" ] && continue
    stat_row "$status" "$jobs" "${earliest:-NULL}" "${latest:-NULL}"
done < <(q "SELECT analysis_status, COUNT(*), COALESCE(MIN(started_at),''), COALESCE(MAX(started_at),'') FROM capture_jobs GROUP BY analysis_status ORDER BY FIELD(analysis_status,'queued','parsing','parsed_ready','merging','merged','failed');")
table_bottom
echo

mini_top
mini_row "realtime queued" "${RT_QUEUED}"
mini_row "realtime ready" "${RT_READY}"
mini_row "realtime merging" "${RT_MERGING}"
mini_row "backfill ready" "${BACKFILL_READY}"
mini_bottom
echo

echo "Diagnosis:"
echo "  - ${BOTTLENECK}"
echo "  - key counts: ready=${READY}, merging=${MERGING}, queued=${QUEUED}, failed=${FAILED}"
echo

echo "┌────────────────┬────────────┬─────────┐"
echo "│ table          │ rows       │ data_mb │"
echo "├────────────────┼────────────┼─────────┤"
while IFS=$'\t' read -r table_name table_rows data_mb; do
    [ -z "$table_name" ] && continue
    printf "│ %-14s │ %10s │ %7s │\n" "$table_name" "$table_rows" "$data_mb"
done < <(q "SELECT TABLE_NAME, TABLE_ROWS, ROUND(DATA_LENGTH/1024/1024) FROM information_schema.TABLES WHERE TABLE_SCHEMA='llm_api_monitor' ORDER BY TABLE_ROWS DESC;")
echo "└────────────────┴────────────┴─────────┘"
