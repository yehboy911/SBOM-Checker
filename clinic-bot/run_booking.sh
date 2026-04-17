#!/bin/bash
# clinic-bot/run_booking.sh
# 由 launchd 呼叫，確保執行期間不會再次入睡
set -euo pipefail

BOT_DIR="$(cd "$(dirname "$0")" && pwd)"
PY="/Users/OwenYeh/miniconda3/bin/python3"
MODE="${1:?Usage: run_booking.sh [evening|midnight]}"
LOG="$BOT_DIR/clinic-bot.log"

echo "$(date '+%Y-%m-%d %H:%M:%S') [launchd] 啟動 mode=$MODE" >> "$LOG"

# 防止執行期間再次入睡（最多 3 分鐘）
caffeinate -i -t 180 &
CAFE_PID=$!

cd "$BOT_DIR"
"$PY" book.py --mode "$MODE" || true

kill "$CAFE_PID" 2>/dev/null || true
echo "$(date '+%Y-%m-%d %H:%M:%S') [launchd] 結束 mode=$MODE" >> "$LOG"
