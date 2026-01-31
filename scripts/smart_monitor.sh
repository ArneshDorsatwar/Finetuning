#!/bin/bash
# Smart monitoring: Hourly updates + Immediate error alerts

LOGFILE="logs/smart_monitor.log"
ALERT_FILE="logs/alerts.log"
START_TIME=$(date +%s)

mkdir -p logs

echo "=========================================" | tee -a $LOGFILE
echo "SMART MONITOR STARTED: $(date)" | tee -a $LOGFILE
echo "Mode: Hourly updates + Error alerts" | tee -a $LOGFILE
echo "=========================================" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE

# Function to check for errors
check_errors() {
    # Check all log files for errors
    errors=$(grep -i "error\|exception\|failed\|traceback" logs/*.log 2>/dev/null | grep -v "No module\|smart_monitor" | tail -5)

    if [ -n "$errors" ]; then
        echo "⚠️  ERROR DETECTED at $(date '+%H:%M:%S')" | tee -a $ALERT_FILE
        echo "$errors" | tee -a $ALERT_FILE
        echo "" | tee -a $ALERT_FILE
        return 1
    fi
    return 0
}

# Function to get detailed status
get_status() {
    local proc_count=$(ps aux | grep "generate_synthetic_data.py" | grep -v grep | wc -l)
    local file_count=$(ls data/synthetic/*.json 2>/dev/null | wc -l)
    local total_size=$(du -sh data/synthetic 2>/dev/null | awk '{print $1}')

    local total_examples=$(python3 -c "
import json, glob
total = 0
for f in glob.glob('data/synthetic/*.json'):
    try:
        with open(f) as file:
            total += len(json.load(file))
    except: pass
print(total)
" 2>/dev/null)

    echo "$proc_count|$file_count|$total_size|$total_examples"
}

# Initial status
read proc files size examples <<< $(get_status | tr '|' ' ')
initial_examples=$examples

echo "Initial Status:" | tee -a $LOGFILE
echo "  Processes: $proc" | tee -a $LOGFILE
echo "  Files: $files topics" | tee -a $LOGFILE
echo "  Size: $size" | tee -a $LOGFILE
echo "  Examples: $examples" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE

hour_count=1
check_count=0

# Monitor loop: Check every 5 minutes, report every hour
while true; do
    sleep 300  # 5 minutes
    check_count=$((check_count + 1))

    # Get current status
    read proc files size examples <<< $(get_status | tr '|' ' ')

    # Quick error check (every 5 min)
    if ! check_errors; then
        echo "🚨 ERROR ALERT - Check logs/alerts.log for details" | tee -a $LOGFILE
    fi

    # Check if generation is complete
    if grep -q "ALL GENERATION COMPLETE" logs/auto_generation_master.log 2>/dev/null; then
        echo "" | tee -a $LOGFILE
        echo "=========================================" | tee -a $LOGFILE
        echo "✅ GENERATION COMPLETE!" | tee -a $LOGFILE
        echo "Time: $(date)" | tee -a $LOGFILE
        echo "Total Examples: $examples" | tee -a $LOGFILE
        echo "Total Files: $files topics" | tee -a $LOGFILE
        echo "Total Size: $size" | tee -a $LOGFILE

        elapsed=$(($(date +%s) - START_TIME))
        hours=$((elapsed / 3600))
        mins=$(((elapsed % 3600) / 60))
        echo "Duration: ${hours}h ${mins}m" | tee -a $LOGFILE
        echo "=========================================" | tee -a $LOGFILE
        break
    fi

    # Hourly report (every 12 checks × 5min = 60min)
    if [ $((check_count % 12)) -eq 0 ]; then
        elapsed=$(($(date +%s) - START_TIME))
        hours=$((elapsed / 3600))
        mins=$(((elapsed % 3600) / 60))

        progress=$((examples - initial_examples))
        rate=$((progress / (elapsed / 60)))  # examples per minute

        echo "" | tee -a $LOGFILE
        echo "=========================================" | tee -a $LOGFILE
        echo "📊 HOURLY STATUS REPORT #$hour_count" | tee -a $LOGFILE
        echo "Time: $(date '+%H:%M:%S') | Runtime: ${hours}h ${mins}m" | tee -a $LOGFILE
        echo "=========================================" | tee -a $LOGFILE
        echo "🔄 Processes: $proc active" | tee -a $LOGFILE
        echo "📁 Files: $files topics ($size)" | tee -a $LOGFILE
        echo "📊 Examples: $examples generated (+$progress since start)" | tee -a $LOGFILE
        echo "⚡ Rate: ~$rate examples/min" | tee -a $LOGFILE
        echo "" | tee -a $LOGFILE

        # Show latest topics
        echo "📋 Latest Topics Generated:" | tee -a $LOGFILE
        ls -lt data/synthetic/*.json 2>/dev/null | head -3 | awk '{print "  " $9}' | tee -a $LOGFILE
        echo "" | tee -a $LOGFILE

        # Estimate completion
        remaining=$((8830 - examples))
        if [ $rate -gt 0 ]; then
            eta_mins=$((remaining / rate))
            eta_hours=$((eta_mins / 60))
            eta_mins=$((eta_mins % 60))
            echo "⏱️  Estimated completion: ${eta_hours}h ${eta_mins}m" | tee -a $LOGFILE
        fi

        echo "=========================================" | tee -a $LOGFILE
        echo "" | tee -a $LOGFILE

        hour_count=$((hour_count + 1))
    fi

    # Check if processes stopped unexpectedly
    if [ $proc -eq 0 ] && ! grep -q "ALL GENERATION COMPLETE" logs/auto_generation_master.log 2>/dev/null; then
        echo "⚠️  WARNING: No active processes but generation not complete!" | tee -a $ALERT_FILE
        echo "Last status: $examples examples generated" | tee -a $ALERT_FILE
    fi
done

echo "" | tee -a $LOGFILE
echo "Smart monitor exiting. Check logs/smart_monitor.log for full history." | tee -a $LOGFILE
