#!/bin/bash
# OPTIMIZED: Parallel auto-generation with larger batches
# Speed: 4x faster (3-4 hours vs 12 hours)
# Strategy: Run 3 topics in parallel with batch-size 30-40

# Activate virtual environment
source venv/bin/activate

# Create output directory
mkdir -p data/synthetic
mkdir -p logs

MASTER_LOG="logs/auto_generation_parallel.log"

echo "=========================================" | tee $MASTER_LOG
echo "OPTIMIZED AUTO-GENERATION - STARTING" | tee -a $MASTER_LOG
echo "Strategy: Parallel (3 simultaneous) + Larger batches" | tee -a $MASTER_LOG
echo "Target: ~8,830 tool calling examples" | tee -a $MASTER_LOG
echo "Providers: Claude Sonnet 4.5 + GPT-4o-mini" | tee -a $MASTER_LOG
echo "Estimated cost: $13-15" | tee -a $MASTER_LOG
echo "Estimated time: 3-4 hours (4x faster)" | tee -a $MASTER_LOG
echo "=========================================" | tee -a $MASTER_LOG
echo "" | tee -a $MASTER_LOG

# Function to generate with logging (background)
generate_topic_bg() {
    local provider=$1
    local topic=$2
    local count=$3
    local batch_size=$4

    echo "[$(date '+%H:%M:%S')] Starting: $topic ($count examples, batch $batch_size)" | tee -a $MASTER_LOG
    python3 scripts/generate_synthetic_data.py \
        --provider $provider \
        --topic $topic \
        --count $count \
        --batch-size $batch_size \
        > logs/${topic}_${provider}_parallel.log 2>&1 &

    echo $!  # Return PID
}

# Function to wait for background jobs with status updates
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

# PARALLEL BATCH 1: Core FireWeave Features (870 examples)
# Run 3 in parallel with batch-size 10 (Claude limit fix)
echo "=== PARALLEL BATCH 1: Core FireWeave (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "anthropic" "fireweave-template-stacks" 210 10
generate_topic_bg "anthropic" "fireweave-device-group-hierarchy" 210 10
generate_topic_bg "anthropic" "fireweave-vpn-automation" 200 10
wait_for_batch "BATCH 1"

# PARALLEL BATCH 2: Advanced FireWeave (700 examples)
# Run 3 in parallel with batch-size 10 (Claude limit fix)
echo "=== PARALLEL BATCH 2: Advanced FireWeave (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "anthropic" "fireweave-object-consolidation-advanced" 250 10
generate_topic_bg "anthropic" "fireweave-topology-versioning-advanced" 200 10
generate_topic_bg "anthropic" "fireweave-jira-integration-advanced" 220 10
wait_for_batch "BATCH 2"

# PARALLEL BATCH 3: AI Workflows (1,290 examples)
# Run 3 in parallel with larger batches for GPT-4o-mini
echo "=== PARALLEL BATCH 3: AI Workflows (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "openai" "fireweave-ai-chat-workflows" 300 40
generate_topic_bg "openai" "fireweave-function-calling" 600 40
generate_topic_bg "openai" "fireweave-features" 390 40
wait_for_batch "BATCH 3"

# PARALLEL BATCH 4: Network Security Part 1 (1,040 examples)
# Run 3 in parallel
echo "=== PARALLEL BATCH 4: Network Security Part 1 (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "openai" "palo-alto-configuration" 360 40
generate_topic_bg "openai" "cisco-asa-firewall" 320 40
generate_topic_bg "anthropic" "fireweave-cloud-integration-advanced" 280 10
wait_for_batch "BATCH 4"

# PARALLEL BATCH 5: Network Security Part 2 (880 examples)
# Run 3 in parallel
echo "=== PARALLEL BATCH 5: Network Security Part 2 (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "openai" "network-troubleshooting" 240 30
generate_topic_bg "openai" "ids-ips-detection" 200 30
generate_topic_bg "anthropic" "fireweave-troubleshooting" 400 10
wait_for_batch "BATCH 5"

# PARALLEL BATCH 6: Cloud Security (860 examples)
# Run 3 in parallel
echo "=== PARALLEL BATCH 6: Cloud Security (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "openai" "aws-security" 360 40
generate_topic_bg "openai" "azure-security" 300 40
generate_topic_bg "openai" "gcp-security" 200 30
wait_for_batch "BATCH 6"

# PARALLEL BATCH 7: VPN, Compliance, Automation (820 examples)
# Run 3 in parallel
echo "=== PARALLEL BATCH 7: VPN, Compliance, Automation (3 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "openai" "vpn-configuration" 160 30
generate_topic_bg "anthropic" "compliance-frameworks" 150 10
generate_topic_bg "openai" "network-automation" 120 30
wait_for_batch "BATCH 7"

# PARALLEL BATCH 8: Final Topics (750 examples)
# Run 2 in parallel (smaller batch)
echo "=== PARALLEL BATCH 8: Final Topics (2 parallel) ===" | tee -a $MASTER_LOG
generate_topic_bg "openai" "threat-hunting" 30 10
generate_topic_bg "openai" "fireweave-api" 350 40
wait_for_batch "BATCH 8"

# Summary
echo "" | tee -a $MASTER_LOG
echo "=========================================" | tee -a $MASTER_LOG
echo "OPTIMIZED AUTO-GENERATION - COMPLETED" | tee -a $MASTER_LOG
echo "=========================================" | tee -a $MASTER_LOG
echo "" | tee -a $MASTER_LOG
echo "Generated files in data/synthetic/" | tee -a $MASTER_LOG
echo "Logs in logs/*_parallel.log" | tee -a $MASTER_LOG
echo "" | tee -a $MASTER_LOG
echo "Next: Merge and validate datasets" | tee -a $MASTER_LOG
echo "python scripts/validate_dataset.py data/synthetic/ --merge --output data/v3/final_dataset.json --format sharegpt" | tee -a $MASTER_LOG
