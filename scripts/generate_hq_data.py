#!/usr/bin/env python3
"""
Generate high-quality training data sequentially to avoid rate limits.
Uses the high-quality prompts for key topics.
"""

import subprocess
import sys
import time
import os
from pathlib import Path

# Topics with high-quality prompts (from high_quality_prompts.py)
# Using batch_size=15 for faster generation (15 pairs * ~200 tokens = ~3000 tokens/batch)
# With 6s delay between batches = 10 batches/min = ~30K TPM (at the limit)
HQ_TOPICS = [
    ("palo-alto-complete", 200),
    ("fireweave-features", 200),
    ("fireweave-troubleshooting", 100),
    ("fireweave-api", 100),
    ("fireweave-function-calling", 150),
    ("fireweave-disambiguation", 150),
    ("routing-switching", 200),
    ("aws-networking", 200),
    ("incident-response", 150),
    ("cissp-domains", 200),
]
# Total: 1450 examples at batch_size=15 = ~97 batches
# At 10 batches/min = ~10 minutes total generation time

def run_generation(topic: str, count: int, batch_size: int = 10) -> bool:
    """Run generation for a single topic."""
    import sys as _sys
    env = os.environ.copy()
    env['PYTHONUNBUFFERED'] = '1'

    cmd = [
        sys.executable, "-u",  # Unbuffered
        "scripts/generate_synthetic_data.py",
        "--provider", "openai",
        "--topic", topic,
        "--count", str(count),
        "--batch-size", str(batch_size)
    ]

    print(f"\n{'='*60}", flush=True)
    print(f"[HQ] Generating: {topic} ({count} examples)", flush=True)
    print(f"{'='*60}", flush=True)
    _sys.stdout.flush()

    try:
        # Stream output directly
        process = subprocess.Popen(cmd, cwd=os.getcwd(), env=env,
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   bufsize=1, universal_newlines=True)
        for line in process.stdout:
            print(line, end='', flush=True)
        process.wait()
        return process.returncode == 0
    except KeyboardInterrupt:
        print("\n[INTERRUPTED]", flush=True)
        return False
    except Exception as e:
        print(f"[ERROR] {e}", flush=True)
        return False

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate high-quality training data")
    parser.add_argument("--batch-size", type=int, default=10, help="Batch size per API call")
    parser.add_argument("--delay", type=int, default=10, help="Delay between topics (seconds)")
    parser.add_argument("--topic", type=str, help="Generate only this topic")
    args = parser.parse_args()

    topics = HQ_TOPICS
    if args.topic:
        topics = [(t, c) for t, c in HQ_TOPICS if t == args.topic]
        if not topics:
            print(f"Topic '{args.topic}' not found in HQ topics")
            return 1

    total = sum(c for _, c in topics)
    print(f"High-Quality Data Generation")
    print(f"============================")
    print(f"Topics: {len(topics)}")
    print(f"Total examples: {total}")
    print(f"Batch size: {args.batch_size}")
    print(f"Delay between topics: {args.delay}s")

    completed = 0
    failed = []

    for i, (topic, count) in enumerate(topics, 1):
        print(f"\n[{i}/{len(topics)}] Starting: {topic}")

        success = run_generation(topic, count, args.batch_size)

        if success:
            completed += 1
            print(f"[OK] {topic} completed")
        else:
            failed.append(topic)
            print(f"[FAIL] {topic} failed")

        # Delay between topics
        if i < len(topics):
            print(f"Waiting {args.delay} seconds...")
            time.sleep(args.delay)

    print(f"\n{'='*60}")
    print(f"GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"Completed: {completed}/{len(topics)}")
    print(f"Failed: {len(failed)}")

    if failed:
        print(f"\nFailed topics: {', '.join(failed)}")

    print(f"\nNext: Run quality filter:")
    print(f"  python scripts/filter_high_quality.py data/synthetic/ --output data/processed/high_quality.json")

if __name__ == "__main__":
    main()
