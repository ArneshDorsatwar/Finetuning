#!/bin/bash
# Monitor current tasks and auto-start full queue when ready

echo "========================================="
echo "AUTO-GENERATION MONITOR - STARTING"
echo "========================================="
echo ""

# Wait for current generation tasks to complete
echo "⏳ Waiting for current tasks to complete..."
echo "   - fireweave-audit-logs (180 examples)"
echo "   - fireweave-system-health (150 examples)"
echo ""

# Monitor until completion
while true; do
    # Count running generation processes
    running=$(ps aux | grep "generate_synthetic_data.py" | grep -v grep | wc -l)

    if [ $running -eq 0 ]; then
        echo "✓ Current tasks completed!"
        break
    fi

    # Show progress every 30 seconds
    echo "[$(date '+%H:%M:%S')] Still running ($running processes active)..."
    sleep 30
done

echo ""
echo "========================================="
echo "STARTING FULL AUTO-GENERATION QUEUE"
echo "========================================="
echo ""

# Start the full queue
cd /home/adorsatwar/Finetuning/Finetuning
./scripts/auto_generate_all.sh

echo ""
echo "========================================="
echo "ALL GENERATION COMPLETE!"
echo "========================================="
echo ""
echo "Summary files created in data/synthetic/"
echo "Logs available in logs/"
echo ""
echo "Next: Run quality filtering and merge datasets"
