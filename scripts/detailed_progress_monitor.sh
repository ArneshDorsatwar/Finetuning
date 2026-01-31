#!/bin/bash
# Detailed progress monitor - Shows current topic and batch number
# Updates every 10 seconds with granular progress

LOGFILE="logs/detailed_progress.log"
mkdir -p logs

# Colors for terminal output (optional)
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

clear
echo "=========================================" | tee $LOGFILE
echo "DETAILED PROGRESS MONITOR" | tee -a $LOGFILE
echo "Started: $(date)" | tee -a $LOGFILE
echo "Update Interval: Every 10 seconds" | tee -a $LOGFILE
echo "=========================================" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE

# Function to get topic progress from log files
get_topic_progress() {
    local topic=$1
    local log_file="logs/${topic}_anthropic_parallel.log"

    if [ ! -f "$log_file" ]; then
        log_file="logs/${topic}_openai_parallel.log"
    fi

    if [ -f "$log_file" ]; then
        # Look for batch progress indicators
        local current_batch=$(grep -o "Generating batch [0-9]*" "$log_file" 2>/dev/null | tail -1 | grep -o "[0-9]*")
        local total_batches=$(grep -o "Generating batch [0-9]*/[0-9]*" "$log_file" 2>/dev/null | tail -1 | grep -o "/[0-9]*" | tr -d '/')
        local examples_done=$(grep -o "Generated [0-9]* pairs" "$log_file" 2>/dev/null | tail -1 | grep -o "[0-9]*")

        echo "${current_batch:-0}|${total_batches:-?}|${examples_done:-0}"
    else
        echo "0|?|0"
    fi
}

# Function to get active topics
get_active_topics() {
    ps aux | grep "generate_synthetic_data.py" | grep -v grep | awk '{
        for(i=1;i<=NF;i++) {
            if($i=="--topic") {
                topic=$(i+1)
            }
            if($i=="--count") {
                count=$(i+1)
            }
            if($i=="--batch-size") {
                batch_size=$(i+1)
            }
            if($i=="--provider") {
                provider=$(i+1)
            }
        }
        if(topic) print topic"|"count"|"batch_size"|"provider
    }'
}

# Function to count total examples
count_examples() {
    python3 -c "
import json, glob
total = 0
for f in glob.glob('data/synthetic/*.json'):
    try:
        with open(f) as file:
            data = json.load(file)
            if isinstance(data, list):
                total += len(data)
    except: pass
print(total)
" 2>/dev/null
}

START_TIME=$(date +%s)
update_count=0

while true; do
    update_count=$((update_count + 1))
    clear

    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║           DETAILED GENERATION PROGRESS MONITOR                    ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🕒 Time: $(date '+%I:%M:%S %p')  |  Update #$update_count"
    echo ""

    # Get active topics
    active_topics=$(get_active_topics)

    if [ -z "$active_topics" ]; then
        echo "⏸️  No active generation processes"
        echo ""
        echo "Checking if generation is complete..."

        if grep -q "OPTIMIZED AUTO-GENERATION - COMPLETED" logs/auto_generation_parallel.log 2>/dev/null; then
            echo "✅ GENERATION COMPLETE!"
            break
        else
            echo "⚠️  Processes may have stopped. Check logs for details."
        fi
    else
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔄 ACTIVE GENERATION PROCESSES"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""

        process_num=1
        echo "$active_topics" | while IFS='|' read -r topic count batch_size provider; do
            if [ -n "$topic" ]; then
                # Get progress details
                IFS='|' read -r current_batch total_batches examples_done <<< $(get_topic_progress "$topic")

                # Calculate expected batches
                if [ "$total_batches" = "?" ]; then
                    total_batches=$(( (count + batch_size - 1) / batch_size ))
                fi

                # Calculate percentage
                if [ "$current_batch" -gt 0 ] && [ "$total_batches" -gt 0 ]; then
                    percent=$(( current_batch * 100 / total_batches ))
                else
                    percent=0
                fi

                echo "┌─ Process #$process_num ────────────────────────────────────────────────"
                echo "│"
                echo "│  📝 Topic: $topic"
                echo "│  🎯 Target: $count examples (batch size: $batch_size)"
                echo "│  🤖 Provider: $provider"
                echo "│"
                echo "│  ▶️  Current Batch: $current_batch / $total_batches"
                echo "│  📊 Progress: $examples_done / $count examples"

                # Progress bar
                bar_length=40
                filled=$(( percent * bar_length / 100 ))
                bar=$(printf "%${filled}s" | tr ' ' '█')
                empty=$(printf "%$((bar_length - filled))s" | tr ' ' '░')
                echo "│  [$bar$empty] $percent%"
                echo "│"

                process_num=$((process_num + 1))
            fi
        done

        echo "└────────────────────────────────────────────────────────────────────"
        echo ""
    fi

    # Overall statistics
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📈 OVERALL STATISTICS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    total_examples=$(count_examples)
    target_total=8830
    overall_percent=$(( total_examples * 100 / target_total ))

    elapsed=$(($(date +%s) - START_TIME))
    hours=$((elapsed / 3600))
    mins=$(((elapsed % 3600) / 60))
    secs=$((elapsed % 60))

    echo "  📊 Total Examples Generated: $total_examples / $target_total ($overall_percent%)"
    echo "  ⏱️  Runtime: ${hours}h ${mins}m ${secs}s"

    # Calculate rate and ETA
    if [ $elapsed -gt 60 ]; then
        rate=$(( (total_examples - 228) * 60 / elapsed ))  # examples per minute (subtract initial 228)
        if [ $rate -gt 0 ]; then
            remaining=$((target_total - total_examples))
            eta_mins=$(( remaining / rate ))
            eta_hours=$(( eta_mins / 60 ))
            eta_mins=$(( eta_mins % 60 ))
            completion_time=$(date -d "+${eta_hours} hours +${eta_mins} minutes" '+%I:%M %p' 2>/dev/null || echo "calculating...")
            echo "  ⚡ Generation Rate: ~$rate examples/min"
            echo "  🎯 ETA: ${eta_hours}h ${eta_mins}m (Complete by ~$completion_time)"
        fi
    fi

    # Show completed topics
    completed_files=$(ls data/synthetic/*.json 2>/dev/null | wc -l)
    echo "  ✅ Completed Topics: $completed_files files"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "💡 Tip: Press Ctrl+C to exit monitor (generation continues in background)"
    echo "📋 Logs: tail -f logs/auto_generation_parallel.log"
    echo ""

    # Log this update
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Update #$update_count | Total: $total_examples/$target_total ($overall_percent%) | Active: $(echo "$active_topics" | wc -l) processes" >> $LOGFILE

    # Check for completion
    if grep -q "OPTIMIZED AUTO-GENERATION - COMPLETED" logs/auto_generation_parallel.log 2>/dev/null; then
        echo "✅ GENERATION COMPLETE! Final count: $total_examples examples"
        echo "✅ GENERATION COMPLETE at $(date)" >> $LOGFILE
        break
    fi

    # Wait 10 seconds before next update
    sleep 10
done

echo ""
echo "Monitor stopped. Full log available at: logs/detailed_progress.log"
