#!/usr/bin/env python3
"""
Dataset Validation Script for Network Security Fine-tuning

This script validates ChatML/ShareGPT formatted datasets for:
- JSON formatting correctness
- Required field presence
- Data quality metrics
- Distribution statistics
- Potential issues

Usage:
    python validate_dataset.py data/processed/network_security_qa.json
    python validate_dataset.py data/processed/network_security_qa.json --stats
    python validate_dataset.py data/processed/network_security_qa.json --sample 5
"""

import argparse
import json
import os
from typing import Dict, List
from collections import Counter


def load_dataset(file_path: str) -> List[Dict]:
    """Load JSON dataset"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except json.JSONDecodeError as e:
        print(f"❌ JSON Decode Error: {e}")
        return []
    except FileNotFoundError:
        print(f"❌ File not found: {file_path}")
        return []


def validate_structure(data: List[Dict]) -> tuple[bool, List[str]]:
    """Validate dataset structure"""
    errors = []

    if not isinstance(data, list):
        errors.append("Dataset must be a list of conversations")
        return False, errors

    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            errors.append(f"Item {idx}: Must be a dictionary")
            continue

        if "conversations" not in item:
            errors.append(f"Item {idx}: Missing 'conversations' field")
            continue

        convs = item["conversations"]
        if not isinstance(convs, list):
            errors.append(f"Item {idx}: 'conversations' must be a list")
            continue

        if len(convs) < 2:
            errors.append(f"Item {idx}: Must have at least 2 messages (human + gpt)")
            continue

        for msg_idx, msg in enumerate(convs):
            if not isinstance(msg, dict):
                errors.append(f"Item {idx}, Message {msg_idx}: Must be a dictionary")
                continue

            if "from" not in msg:
                errors.append(f"Item {idx}, Message {msg_idx}: Missing 'from' field")
            elif msg["from"] not in ["human", "gpt", "system"]:
                errors.append(f"Item {idx}, Message {msg_idx}: 'from' must be 'human', 'gpt', or 'system'")

            if "value" not in msg:
                errors.append(f"Item {idx}, Message {msg_idx}: Missing 'value' field")
            elif not msg["value"].strip():
                errors.append(f"Item {idx}, Message {msg_idx}: 'value' is empty")

    is_valid = len(errors) == 0
    return is_valid, errors


def analyze_statistics(data: List[Dict]) -> Dict:
    """Analyze dataset statistics"""
    stats = {
        "total_examples": len(data),
        "single_turn": 0,
        "multi_turn": 0,
        "avg_question_length": 0,
        "avg_answer_length": 0,
        "max_question_length": 0,
        "max_answer_length": 0,
        "min_question_length": float('inf'),
        "min_answer_length": float('inf'),
        "total_turns": 0,
        "question_lengths": [],
        "answer_lengths": []
    }

    for item in data:
        convs = item.get("conversations", [])

        # Count turns (human-gpt pairs)
        turns = len([m for m in convs if m.get("from") == "human"])
        stats["total_turns"] += turns

        if turns == 1:
            stats["single_turn"] += 1
        else:
            stats["multi_turn"] += 1

        # Analyze lengths
        for msg in convs:
            text = msg.get("value", "")
            text_len = len(text)

            if msg.get("from") == "human":
                stats["question_lengths"].append(text_len)
                stats["max_question_length"] = max(stats["max_question_length"], text_len)
                stats["min_question_length"] = min(stats["min_question_length"], text_len)
            elif msg.get("from") == "gpt":
                stats["answer_lengths"].append(text_len)
                stats["max_answer_length"] = max(stats["max_answer_length"], text_len)
                stats["min_answer_length"] = min(stats["min_answer_length"], text_len)

    # Calculate averages
    if stats["question_lengths"]:
        stats["avg_question_length"] = sum(stats["question_lengths"]) / len(stats["question_lengths"])
    if stats["answer_lengths"]:
        stats["avg_answer_length"] = sum(stats["answer_lengths"]) / len(stats["answer_lengths"])

    # Handle edge cases
    if stats["min_question_length"] == float('inf'):
        stats["min_question_length"] = 0
    if stats["min_answer_length"] == float('inf'):
        stats["min_answer_length"] = 0

    return stats


def check_quality(data: List[Dict]) -> List[str]:
    """Check for quality issues"""
    warnings = []

    for idx, item in enumerate(data):
        convs = item.get("conversations", [])

        for msg_idx, msg in enumerate(convs):
            text = msg.get("value", "")

            # Check for very short responses
            if msg.get("from") == "gpt" and len(text) < 50:
                warnings.append(f"Item {idx}, Message {msg_idx}: Very short GPT response ({len(text)} chars)")

            # Check for potential placeholder text
            placeholder_keywords = ["TODO", "FIXME", "XXX", "[placeholder]", "example.com"]
            for keyword in placeholder_keywords:
                if keyword in text:
                    warnings.append(f"Item {idx}, Message {msg_idx}: Contains placeholder '{keyword}'")

            # Check for potential PII (very basic check)
            import re
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            if re.search(email_pattern, text):
                warnings.append(f"Item {idx}, Message {msg_idx}: May contain email address")

    return warnings


def print_sample(data: List[Dict], count: int = 3):
    """Print sample conversations"""
    print(f"\n{'='*80}")
    print(f"SAMPLE CONVERSATIONS (showing {min(count, len(data))} examples)")
    print(f"{'='*80}\n")

    for idx in range(min(count, len(data))):
        item = data[idx]
        convs = item.get("conversations", [])

        print(f"Example {idx + 1}:")
        print("-" * 80)

        for msg in convs:
            role = msg.get("from", "unknown")
            text = msg.get("value", "")

            if role == "human":
                print(f"\n👤 HUMAN:\n{text[:300]}{'...' if len(text) > 300 else ''}")
            elif role == "gpt":
                print(f"\n🤖 ASSISTANT:\n{text[:500]}{'...' if len(text) > 500 else ''}")
            elif role == "system":
                print(f"\n⚙️  SYSTEM:\n{text[:200]}{'...' if len(text) > 200 else ''}")

        print("\n" + "=" * 80 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Validate network security training dataset")
    parser.add_argument("file", help="Path to dataset JSON file")
    parser.add_argument("--stats", action="store_true", help="Show detailed statistics")
    parser.add_argument("--sample", type=int, default=0, help="Show N sample conversations")
    parser.add_argument("--warnings", action="store_true", help="Show quality warnings")

    args = parser.parse_args()

    print(f"\n{'='*80}")
    print(f"DATASET VALIDATION REPORT")
    print(f"{'='*80}\n")
    print(f"File: {args.file}")

    # Check if file exists
    if not os.path.exists(args.file):
        print(f"\n❌ ERROR: File not found: {args.file}")
        return

    # Load dataset
    print(f"Loading dataset...")
    data = load_dataset(args.file)

    if not data:
        print(f"\n❌ ERROR: Could not load dataset or dataset is empty")
        return

    print(f"✓ Loaded {len(data)} examples\n")

    # Validate structure
    print(f"{'='*80}")
    print(f"STRUCTURE VALIDATION")
    print(f"{'='*80}\n")

    is_valid, errors = validate_structure(data)

    if is_valid:
        print(f"✅ Dataset structure is valid!")
    else:
        print(f"❌ Found {len(errors)} structural errors:\n")
        for error in errors[:20]:  # Show first 20 errors
            print(f"  • {error}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more errors")
        print(f"\nPlease fix these errors before using the dataset for training.")
        return

    # Show statistics
    print(f"\n{'='*80}")
    print(f"DATASET STATISTICS")
    print(f"{'='*80}\n")

    stats = analyze_statistics(data)

    print(f"Total Examples:      {stats['total_examples']}")
    print(f"Single-turn:         {stats['single_turn']} ({stats['single_turn']/stats['total_examples']*100:.1f}%)")
    print(f"Multi-turn:          {stats['multi_turn']} ({stats['multi_turn']/stats['total_examples']*100:.1f}%)")
    print(f"Total Q&A pairs:     {stats['total_turns']}")
    print(f"\nQuestion Lengths:")
    print(f"  Average:           {stats['avg_question_length']:.0f} characters")
    print(f"  Min:               {stats['min_question_length']} characters")
    print(f"  Max:               {stats['max_question_length']} characters")
    print(f"\nAnswer Lengths:")
    print(f"  Average:           {stats['avg_answer_length']:.0f} characters")
    print(f"  Min:               {stats['min_answer_length']} characters")
    print(f"  Max:               {stats['max_answer_length']} characters")

    # Estimate tokens (rough approximation: 1 token ≈ 4 characters)
    avg_total_chars = stats['avg_question_length'] + stats['avg_answer_length']
    est_tokens = avg_total_chars / 4
    print(f"\nEstimated avg tokens per example: ~{est_tokens:.0f} tokens")

    # Quality checks
    if args.warnings:
        print(f"\n{'='*80}")
        print(f"QUALITY WARNINGS")
        print(f"{'='*80}\n")

        warnings = check_quality(data)

        if warnings:
            print(f"Found {len(warnings)} potential quality issues:\n")
            for warning in warnings[:30]:  # Show first 30 warnings
                print(f"  ⚠️  {warning}")
            if len(warnings) > 30:
                print(f"  ... and {len(warnings) - 30} more warnings")
        else:
            print(f"✅ No quality issues detected!")

    # Show samples
    if args.sample > 0:
        print_sample(data, args.sample)

    # Summary
    print(f"\n{'='*80}")
    print(f"SUMMARY")
    print(f"{'='*80}\n")

    if is_valid:
        print(f"✅ Dataset is ready for training!")
        print(f"\nRecommended next steps:")
        print(f"1. Review sample conversations: --sample 5")
        print(f"2. Check for quality warnings: --warnings")
        print(f"3. Merge with other topic datasets if needed")
        print(f"4. Use for fine-tuning in your training notebook")
    else:
        print(f"❌ Please fix structural errors before training")

    print(f"\n{'='*80}\n")


if __name__ == "__main__":
    main()
