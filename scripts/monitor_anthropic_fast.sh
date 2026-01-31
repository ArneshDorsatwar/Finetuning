#!/bin/bash
# Fast monitor for Anthropic-only generation
# Updates every 30 seconds

LOGFILE="logs/anthropic_fast_monitor.log"
START_TIME=$(date +%s)
INITIAL_COUNT=$(python3 -c "import json, glob; print(sum(len(json.load(open(f))) if isinstance((data:=json.load(open(f))), list) else 0 for f in glob.glob('data/synthetic/*.json')))" 2>/dev/null)

echo "=========================================" | tee $LOGFILE
echo "ANTHROPIC FAST GENERATION MONITOR" | tee -a $LOGFILE
echo "Started: $(date)" | tee -a $LOGFILE
echo "Initial examples: $INITIAL_COUNT" | tee -a $LOGFILE
echo "Target: +2,500 examples" | tee -a $LOGFILE
echo "=========================================" | tee -a $LOGFILE
echo "" | tee -a $LOGFILE

update_count=0

while true; do
    update_count=$((update_count + 1))

    # Get current status
    proc_count=$(ps aux | grep "generate_synthetic_data.py" | grep -v grep | wc -l)
    total=$(python3 -c "import json, glob; print(sum(len(json.load(open(f))) if isinstance((data:=json.load(open(f))), list) else 0 for f in glob.glob('data/synthetic/*.json')))" 2>/dev/null)
    new_examples=$((total - INITIAL_COUNT))

    # Calculate progress
    elapsed=$(($(date +%s) - START_TIME))
    hours=$((elapsed / 3600))
    mins=$(((elapsed % 3600) / 60))

    # Clear and display
    clear
    echo "╔════════════════════════════════════════════════════════════════════╗"
    echo "║        ANTHROPIC FAST GENERATION - LIVE MONITOR                   ║"
    echo "╚════════════════════════════════════════════════════════════════════╝"
    echo ""
    echo "🕒 Time: $(date '+%I:%M:%S %p')  |  Runtime: ${hours}h ${mins}m  |  Update #$update_count"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "📊 PROGRESS"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  🆕 New Examples: $new_examples / 2,500 target ($((new_examples * 100 / 2500))%)"
    echo "  📊 Total Examples: $total"
    echo "  🔄 Active Processes: $proc_count"
    echo ""

    # Progress bar
    percent=$((new_examples * 100 / 2500))
    if [ $percent -gt 100 ]; then percent=100; fi
    bar_length=50
    filled=$((percent * bar_length / 100))
    bar=$(printf "%${filled}s" | tr ' ' '█')
    empty=$(printf "%$((bar_length - filled))s" | tr ' ' '░')
    echo "  [$bar$empty] $percent%"
    echo ""

    # Show active topics
    if [ $proc_count -gt 0 ]; then
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "🔄 CURRENTLY GENERATING"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        ps aux | grep "generate_synthetic_data.py" | grep -v grep | awk '{for(i=1;i<=NF;i++) if($i=="--topic") print "  📝 " $(i+1)}'
        echo ""
    fi

    # ETA
    if [ $elapsed -gt 60 ] && [ $new_examples -gt 0 ]; then
        rate=$((new_examples * 60 / elapsed))
        if [ $rate -gt 0 ]; then
            remaining=$((2500 - new_examples))
            eta_mins=$((remaining / rate))
            eta_hours=$((eta_mins / 60))
            eta_mins=$((eta_mins % 60))
            completion=$(date -d "+${eta_hours} hours +${eta_mins} minutes" '+%I:%M %p' 2>/dev/null || echo "calculating...")

            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "⏱️  ESTIMATES"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            echo "  ⚡ Generation Rate: ~$rate examples/min"
            echo "  ⏱️  Time Remaining: ${eta_hours}h ${eta_mins}m"
            echo "  🎯 Completion: ~$completion"
            echo ""
        fi
    fi

    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "💡 Press Ctrl+C to exit (generation continues in background)"
    echo "📋 Full log: tail -f logs/anthropic_fast_generation.log"
    echo ""

    # Log update
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Update #$update_count | New: $new_examples/2500 | Total: $total | Active: $proc_count" >> $LOGFILE

    # Check if complete
    if grep -q "ANTHROPIC FAST GENERATION - COMPLETED" logs/anthropic_fast_generation.log 2>/dev/null; then
        echo "✅ GENERATION COMPLETE!"
        echo "✅ Final count: $total examples ($new_examples new)" | tee -a $LOGFILE
        break
    fi

    if [ $proc_count -eq 0 ] && [ $update_count -gt 2 ]; then
        echo "⚠️  No processes running - checking completion..."
        sleep 10
        proc_count=$(ps aux | grep "generate_synthetic_data.py" | grep -v grep | wc -l)
        if [ $proc_count -eq 0 ]; then
            echo "⚠️  Generation stopped. Check logs for details." | tee -a $LOGFILE
            break
        fi
    fi

    sleep 30
done

echo ""
echo "Monitor stopped. Full log: logs/anthropic_fast_monitor.log"
