#!/bin/bash
# ANTHROPIC-ONLY FAST GENERATION
# Target: ~2,500 additional examples using Claude Sonnet 4
# Strategy: 3 parallel processes, batch-size 10, safe rate limits

source venv/bin/activate
mkdir -p data/synthetic
mkdir -p logs

MASTER_LOG="logs/anthropic_fast_generation.log"

echo "=========================================" | tee $MASTER_LOG
echo "ANTHROPIC FAST GENERATION - STARTING" | tee -a $MASTER_LOG
echo "Target: ~2,500 additional examples" | tee -a $MASTER_LOG
echo "Provider: Claude Sonnet 4.5 (Anthropic only)" | tee -a $MASTER_LOG
echo "Strategy: 3 parallel, batch-size 10" | tee -a $MASTER_LOG
echo "Rate Limit: 50 req/min (using ~15/min)" | tee -a $MASTER_LOG
echo "Estimated time: 1.5-2 hours" | tee -a $MASTER_LOG
echo "=========================================" | tee -a $MASTER_LOG
echo "" | tee -a $MASTER_LOG

# Function to generate with logging (background)
generate_topic_bg() {
    local topic=$1
    local count=$2
    local batch_size=$3

    echo "[$(date '+%H:%M:%S')] Starting: $topic ($count examples, batch $batch_size)" | tee -a $MASTER_LOG
    python3 scripts/generate_synthetic_data.py \
        --provider anthropic \
        --topic $topic \
        --count $count \
        --batch-size $batch_size \
        > logs/${topic}_anthropic_fast.log 2>&1 &

    echo $!
}

# Function to wait for background jobs
wait_for_batch() {
    local batch_name=$1
    echo "" | tee -a $MASTER_LOG
    echo "=== Waiting for $batch_name to complete ===" | tee -a $MASTER_LOG

    while [ $(jobs -r | wc -l) -gt 0 ]; do
        echo "[$(date '+%H:%M:%S')] Still running ($(jobs -r | wc -l) parallel processes)..." | tee -a $MASTER_LOG
        sleep 30
    done

    echo "✓ $batch_name completed!" | tee -a $MASTER_LOG
}

# BATCH 1: Network Security Fundamentals (3 parallel, 600 examples)
echo "=== BATCH 1: Network Security Fundamentals (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "palo-alto" 250 10
generate_topic_bg "cisco-firewall" 200 10
generate_topic_bg "network-security-fundamentals" 150 10
wait_for_batch "BATCH 1"

# BATCH 2: Advanced Networking (3 parallel, 550 examples)
echo "=== BATCH 2: Advanced Networking (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "routing-switching" 200 10
generate_topic_bg "osi-model" 150 10
generate_topic_bg "advanced-routing" 200 10
wait_for_batch "BATCH 2"

# BATCH 3: Security Operations (3 parallel, 550 examples)
echo "=== BATCH 3: Security Operations (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "soc-operations" 200 10
generate_topic_bg "incident-response" 200 10
generate_topic_bg "threat-hunting" 150 10
wait_for_batch "BATCH 3"

# BATCH 4: Infrastructure & Automation (3 parallel, 500 examples)
echo "=== BATCH 4: Infrastructure & Automation (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "datacenter-networking" 150 10
generate_topic_bg "sdn-nfv" 200 10
generate_topic_bg "network-automation" 150 10
wait_for_batch "BATCH 4"

# BATCH 5: Security Architecture (3 parallel, 400 examples)
echo "=== BATCH 5: Security Architecture (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "zero-trust-security" 150 10
generate_topic_bg "cloud-security-architecture" 150 10
generate_topic_bg "devsecops" 100 10
wait_for_batch "BATCH 5"

# Summary
echo "" | tee -a $MASTER_LOG
echo "=========================================" | tee -a $MASTER_LOG
echo "ANTHROPIC FAST GENERATION - COMPLETED" | tee -a $MASTER_LOG
echo "=========================================" | tee -a $MASTER_LOG
echo "" | tee -a $MASTER_LOG

# Count total examples
total=$(python3 -c "
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
" 2>/dev/null)

echo "Total examples generated: $total" | tee -a $MASTER_LOG
echo "Combined with existing 9,929 conversational = ~$((total + 9929)) total" | tee -a $MASTER_LOG
echo "" | tee -a $MASTER_LOG
echo "Next: Merge all datasets" | tee -a $MASTER_LOG
echo "python scripts/validate_dataset.py data/synthetic/ --merge --output data/v3/final_dataset.json --format sharegpt" | tee -a $MASTER_LOG
