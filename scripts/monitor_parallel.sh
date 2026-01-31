#!/bin/bash
# Smart monitor for parallel generation
# Tracks multiple concurrent processes + provides ETA

LOGFILE="logs/parallel_monitor.log"
ALERT_FILE="logs/parallel_alerts.log"
START_TIME=$(date +%s)

mkdir -p logs

echo "=========================================" | tee $LOGFILE
echo "PARALLEL GENERATION MONITOR - STARTED" | tee -a $LOGFILE
echo "Time: $(date)" | tee -a $LOGFILE
echo "Mode: Every 5 minutes + Error alerts" | tee -a $LOGFILE
echo "=========================================" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE

# Function to check for errors
check_errors() {
    errors=$(grep -i "error\|exception\|failed\|traceback" logs/*_parallel.log 2>/dev/null | grep -v "No module\|monitor" | tail -5)
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
            data = json.load(file)
            if isinstance(data, list):
                total += len(data)
            elif 'conversations' in data:
                total += len(data['conversations'])
    except: pass
print(total)
" 2>/dev/null)

    echo "$proc_count|$file_count|$total_size|$total_examples"
}

# Initial status
read proc files size examples <<< $(get_status | tr '|' ' ')
initial_examples=$examples

echo "Initial Status:" | tee -a $LOGFILE
echo "  Parallel Processes: $proc" | tee -a $LOGFILE
echo "  Files: $files topics" | tee -a $LOGFILE
echo "  Size: $size" | tee -a $LOGFILE
echo "  Examples: $examples" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE

check_count=0

# Monitor loop: Check every 5 minutes
while true; do
    sleep 300  # 5 minutes
    check_count=$((check_count + 1))

    # Get current status
    read proc files size examples <<< $(get_status | tr '|' ' ')

    # Quick error check
    if ! check_errors; then
        echo "🚨 ERROR ALERT - Check logs/parallel_alerts.log" | tee -a $LOGFILE
    fi

    # Calculate progress
    elapsed=$(($(date +%s) - START_TIME))
    hours=$((elapsed / 3600))
    mins=$(((elapsed % 3600) / 60))

    progress=$((examples - initial_examples))
    if [ $elapsed -gt 0 ]; then
        rate=$((progress * 60 / elapsed))  # examples per minute
    else
        rate=0
    fi

    # Status update every 5 minutes
    echo "" | tee -a $LOGFILE
    echo "=========================================" | tee -a $LOGFILE
    echo "📊 STATUS UPDATE #$check_count" | tee -a $LOGFILE
    echo "Time: $(date '+%H:%M:%S') | Runtime: ${hours}h ${mins}m" | tee -a $LOGFILE
    echo "=========================================" | tee -a $LOGFILE
    echo "🔄 Parallel Processes: $proc active" | tee -a $LOGFILE
    echo "📁 Files: $files topics ($size)" | tee -a $LOGFILE
    echo "📊 Examples: $examples generated (+$progress since start)" | tee -a $LOGFILE
    echo "⚡ Rate: ~$rate examples/min" | tee -a $LOGFILE
    echo "" | tee -a $LOGFILE

    # Show currently generating topics
    echo "📋 Currently Generating:" | tee -a $LOGFILE
    ps aux | grep "generate_synthetic_data.py" | grep -v grep | awk '{for(i=11;i<=NF;i++){if($i=="--topic"){print "  - " $(i+1); break}}}' | tee -a $LOGFILE
    echo "" | tee -a $LOGFILE

    # Estimate completion
    remaining=$((8830 - examples))
    if [ $rate -gt 0 ]; then
        eta_mins=$((remaining / rate))
        eta_hours=$((eta_mins / 60))
        eta_mins=$((eta_mins % 60))
        completion_time=$(date -d "+${eta_hours} hours +${eta_mins} minutes" '+%I:%M %p')
        echo "⏱️  Remaining: $remaining examples" | tee -a $LOGFILE
        echo "⏱️  ETA: ${eta_hours}h ${eta_mins}m (~$completion_time)" | tee -a $LOGFILE
    fi

    echo "=========================================" | tee -a $LOGFILE
    echo "" | tee -a $LOGFILE

    # Check if generation is complete
    if grep -q "OPTIMIZED AUTO-GENERATION - COMPLETED" logs/auto_generation_parallel.log 2>/dev/null; then
        echo "" | tee -a $LOGFILE
        echo "==========================================" | tee -a $LOGFILE
        echo "✅ PARALLEL GENERATION COMPLETE!" | tee -a $LOGFILE
        echo "Time: $(date)" | tee -a $LOGFILE
        echo "Total Examples: $examples" | tee -a $LOGFILE
        echo "Total Files: $files topics" | tee -a $LOGFILE
        echo "Total Size: $size" | tee -a $LOGFILE
        echo "Duration: ${hours}h ${mins}m" | tee -a $LOGFILE
        echo "==========================================" | tee -a $LOGFILE
        break
    fi

    # Check if processes stopped unexpectedly
    if [ $proc -eq 0 ] && ! grep -q "OPTIMIZED AUTO-GENERATION - COMPLETED" logs/auto_generation_parallel.log 2>/dev/null; then
        echo "⚠️  WARNING: No active processes but generation not complete!" | tee -a $ALERT_FILE
        echo "Last status: $examples examples generated" | tee -a $ALERT_FILE
        sleep 60  # Wait a bit in case new batch is starting
        read proc files size examples <<< $(get_status | tr '|' ' ')
        if [ $proc -eq 0 ]; then
            echo "⚠️  CRITICAL: Generation appears stuck!" | tee -a $ALERT_FILE
            break
        fi
    fi
done

echo "" | tee -a $LOGFILE
echo "Parallel monitor exiting. Check logs/parallel_monitor.log for full history." | tee -a $LOGFILE
