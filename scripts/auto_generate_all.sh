#!/bin/bash
# Auto-generate all tool calling examples for cost-effective strategy
# Total target: ~8,830 tool calling examples

# Activate virtual environment
source venv/bin/activate

# Create output directory
mkdir -p data/synthetic
mkdir -p logs

echo "========================================="
echo "AUTO-GENERATION QUEUE - STARTING"
echo "Target: ~8,830 tool calling examples"
echo "Providers: Claude Sonnet 4.5 + GPT-4o-mini"
echo "Estimated cost: $13-15"
echo "Estimated time: 4-6 hours"
echo "========================================="
echo ""

# Function to generate with logging
generate_topic() {
    local provider=$1
    local topic=$2
    local count=$3
    local batch_size=$4

    echo "[$(date '+%H:%M:%S')] Starting: $topic ($count examples)"
    python scripts/generate_synthetic_data.py \
        --provider $provider \
        --topic $topic \
        --count $count \
        --batch-size $batch_size \
        > logs/${topic}_${provider}.log 2>&1

    if [ $? -eq 0 ]; then
        echo "[$(date '+%H:%M:%S')] ✓ Completed: $topic"
    else
        echo "[$(date '+%H:%M:%S')] ✗ Failed: $topic (check logs/${topic}_${provider}.log)"
    fi
}

# BATCH 1: Core FireWeave Missing Features (Claude Sonnet - High Quality)
echo "=== BATCH 1: Core FireWeave Features ==="
generate_topic "anthropic" "fireweave-template-stacks" 210 20
generate_topic "anthropic" "fireweave-device-group-hierarchy" 210 20
generate_topic "anthropic" "fireweave-vpn-automation" 200 20
generate_topic "anthropic" "fireweave-object-consolidation-advanced" 250 20
echo ""

# BATCH 2: Advanced FireWeave Features (Claude Sonnet)
echo "=== BATCH 2: Advanced FireWeave Features ==="
generate_topic "anthropic" "fireweave-topology-versioning-advanced" 200 20
generate_topic "anthropic" "fireweave-jira-integration-advanced" 220 20
generate_topic "anthropic" "fireweave-cloud-integration-advanced" 280 20
echo ""

# BATCH 3: AI Workflows & Function Calling (GPT-4o-mini - Structured Output)
echo "=== BATCH 3: AI Workflows & Tool Calling ==="
generate_topic "openai" "fireweave-ai-chat-workflows" 300 20
generate_topic "openai" "fireweave-function-calling" 600 30
generate_topic "openai" "fireweave-features" 390 30
echo ""

# BATCH 4: Network Security Tool Examples (GPT-4o-mini)
echo "=== BATCH 4: Network Security ==="
generate_topic "openai" "palo-alto-configuration" 360 30
generate_topic "openai" "cisco-asa-firewall" 320 30
generate_topic "openai" "network-troubleshooting" 240 20
generate_topic "openai" "ids-ips-detection" 200 20
generate_topic "openai" "vpn-configuration" 160 20
echo ""

# BATCH 5: Cloud Security (GPT-4o-mini)
echo "=== BATCH 5: Cloud Security ==="
generate_topic "openai" "aws-security" 360 30
generate_topic "openai" "azure-security" 300 30
generate_topic "openai" "gcp-security" 200 20
echo ""

# BATCH 6: Compliance & Automation (Mixed)
echo "=== BATCH 6: Compliance & Automation ==="
generate_topic "anthropic" "compliance-frameworks" 150 20
generate_topic "openai" "network-automation" 120 20
generate_topic "openai" "threat-hunting" 30 10
echo ""

# BATCH 7: Additional FireWeave Expansions (to reach targets)
echo "=== BATCH 7: FireWeave Expansions ==="
generate_topic "anthropic" "fireweave-troubleshooting" 400 20
generate_topic "openai" "fireweave-api" 350 30
echo ""

# Summary
echo ""
echo "========================================="
echo "AUTO-GENERATION QUEUE - COMPLETED"
echo "========================================="
echo ""
echo "Next steps:"
echo "1. Check logs/ directory for any errors"
echo "2. Validate generated data: python scripts/validate_dataset.py data/synthetic/ --stats"
echo "3. Merge datasets: Will combine with existing 9,929 conversational examples"
echo "4. Filter for quality (threshold ≥60)"
echo "5. Create final production dataset"
echo ""
echo "Run this to merge everything:"
echo "python scripts/validate_dataset.py data/synthetic/ --merge --output data/v3/final_dataset.json --format sharegpt"
