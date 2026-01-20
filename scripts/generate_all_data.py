#!/usr/bin/env python3
"""
Batch Generation Script - Generates all training data sequentially to avoid rate limits.

This script generates ~14,000 training examples across 44 topics, running one topic at a time
to avoid OpenAI's rate limits (30,000 TPM).

Topics include:
- FireWeave platform (1,400 examples) - features, API, function calling, disambiguation
- Palo Alto Networks (1,100 examples) - includes admin roles, skills, certifications
- Core Networking (1,100 examples)
- Network Security (800 examples)
- Compliance & Policy (900 examples)
- Cloud Networking (1,100 examples)
- Threat Detection & IR (1,200 examples)
- Advanced Network Engineering (1,400 examples) - BGP, MPLS, datacenter, SDN/NFV, automation
- SecOps (1,200 examples) - SOC, threat hunting, security monitoring, vulnerability management
- Application Team Networking (1,400 examples) - API gateways, service mesh, DNS, load balancing
- InfoSec & SecOps Deep Dive (2,700 examples) - SOAR, Zero Trust, DevSecOps, EDR/XDR, scripting, forensics

Usage:
    python scripts/generate_all_data.py
    python scripts/generate_all_data.py --resume  # Resume from where it left off
"""

import subprocess
import sys
import time
import os
from pathlib import Path

# All topics with their target counts
TOPICS = [
    # Priority 0: FireWeave (1400 total)
    ("fireweave-features", 400),
    ("fireweave-troubleshooting", 200),
    ("fireweave-api", 200),
    ("fireweave-function-calling", 300),  # AI agent tool calling
    ("fireweave-disambiguation", 300),  # Explain vs execute disambiguation

    # Priority 1: Palo Alto (1100 total)
    ("palo-alto-complete", 600),
    ("palo-alto", 200),
    ("palo-alto-administration", 300),

    # Priority 2: Networking (1100 total)
    ("osi-model", 300),
    ("routing-switching", 500),
    ("network-troubleshooting", 300),

    # Priority 3: Security (800 total)
    ("network-security-fundamentals", 400),
    ("cisco-firewall", 400),

    # Priority 4: Compliance (900 total)
    ("infosec-policies", 400),
    ("cissp-domains", 500),

    # Priority 5: Cloud (1100 total)
    ("aws-networking", 400),
    ("azure-networking", 400),
    ("gcp-networking", 300),

    # Priority 6: Threat Detection (1200 total)
    ("ids-ips", 300),
    ("siem-logs", 300),
    ("aws-security", 300),
    ("azure-security", 300),
    ("incident-response", 200),

    # Priority 7: Network Engineering - Advanced (1400 total)
    ("advanced-routing", 400),
    ("datacenter-networking", 400),
    ("sdn-nfv", 300),
    ("network-automation", 300),

    # Priority 8: SecOps (1200 total)
    ("soc-operations", 300),
    ("threat-hunting", 300),
    ("security-monitoring", 300),
    ("vulnerability-management", 300),

    # Priority 9: Application Team Networking (1400 total)
    ("api-gateway", 300),
    ("service-mesh", 300),
    ("dns-fundamentals", 300),
    ("load-balancing", 300),
    ("microservices-networking", 200),

    # Priority 10: InfoSec & SecOps Deep Dive (2400 total)
    ("soar-automation", 300),
    ("zero-trust-security", 300),
    ("devsecops", 300),
    ("security-scripting", 300),
    ("edr-xdr", 300),
    ("network-traffic-analysis", 300),
    ("security-compliance-ops", 300),
    ("cloud-security-architecture", 300),
    ("malware-analysis-forensics", 300),
]

def get_output_file(topic: str) -> Path:
    """Get the output file path for a topic."""
    return Path(f"data/synthetic/{topic}_openai.json")

def topic_already_done(topic: str, target_count: int) -> bool:
    """Check if a topic has already been generated with sufficient examples."""
    output_file = get_output_file(topic)
    if not output_file.exists():
        return False

    try:
        import json
        with open(output_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
        # Consider done if we have at least 80% of target
        return len(data) >= target_count * 0.8
    except:
        return False

def run_generation(topic: str, count: int, batch_size: int = 10) -> bool:
    """Run the generation script for a single topic."""
    cmd = [
        sys.executable,
        "scripts/generate_synthetic_data.py",
        "--provider", "openai",
        "--topic", topic,
        "--count", str(count),
        "--batch-size", str(batch_size)
    ]

    print(f"\n{'='*60}")
    print(f"Generating: {topic} ({count} examples)")
    print(f"{'='*60}")

    try:
        result = subprocess.run(cmd, cwd=os.getcwd())
        return result.returncode == 0
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Generation interrupted by user")
        return False
    except Exception as e:
        print(f"[ERROR] Failed to run generation: {e}")
        return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate all training data")
    parser.add_argument("--resume", action="store_true", help="Skip already completed topics")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size per API call")
    parser.add_argument("--delay", type=int, default=5, help="Delay between topics (seconds)")
    args = parser.parse_args()

    total_target = sum(count for _, count in TOPICS)
    print(f"Training Data Generation")
    print(f"========================")
    print(f"Total topics: {len(TOPICS)}")
    print(f"Total target examples: {total_target}")
    print(f"Batch size: {args.batch_size}")
    print(f"Delay between topics: {args.delay}s")
    if args.resume:
        print(f"Mode: RESUME (skipping completed topics)")
    print()

    completed = 0
    skipped = 0
    failed = []

    for i, (topic, count) in enumerate(TOPICS, 1):
        # Check if already done (resume mode)
        if args.resume and topic_already_done(topic, count):
            print(f"[{i}/{len(TOPICS)}] SKIP: {topic} (already completed)")
            skipped += 1
            continue

        print(f"\n[{i}/{len(TOPICS)}] Starting: {topic}")

        success = run_generation(topic, count, args.batch_size)

        if success:
            completed += 1
            print(f"[OK] {topic} completed")
        else:
            failed.append(topic)
            print(f"[FAIL] {topic} failed")

        # Delay between topics to avoid rate limits
        if i < len(TOPICS):
            print(f"Waiting {args.delay} seconds before next topic...")
            time.sleep(args.delay)

    # Summary
    print(f"\n{'='*60}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"Completed: {completed}/{len(TOPICS)}")
    print(f"Skipped: {skipped}")
    print(f"Failed: {len(failed)}")

    if failed:
        print(f"\nFailed topics:")
        for topic in failed:
            print(f"  - {topic}")
        print(f"\nTo retry failed topics, run them individually:")
        for topic in failed:
            count = dict(TOPICS).get(topic, 100)
            print(f"  python scripts/generate_synthetic_data.py --provider openai --topic {topic} --count {count}")

    # List generated files
    print(f"\nGenerated files:")
    data_dir = Path("data/synthetic")
    if data_dir.exists():
        for f in sorted(data_dir.glob("*_openai.json")):
            try:
                import json
                with open(f, 'r', encoding='utf-8') as file:
                    data = json.load(file)
                print(f"  {f.name}: {len(data)} examples")
            except:
                print(f"  {f.name}: (error reading)")

    print(f"\nNext step: Validate and merge all data:")
    print(f"  python scripts/validate_dataset.py data/synthetic/ --merge --output data/processed/network_security_qa.json --format sharegpt")

if __name__ == "__main__":
    main()
