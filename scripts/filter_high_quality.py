#!/usr/bin/env python3
"""
High-Quality Data Filter - Filters training data for fine-tuning based on quality criteria.

Based on the approach from the "Fine-tuning GPT-4o-mini" paper:
1. Validate answer actually addresses the question (consistency)
2. Check for technical depth (code blocks, commands, specific details)
3. Remove duplicates and near-duplicates
4. Filter by length and formatting quality
5. Ensure diversity across topics

Usage:
    python scripts/filter_high_quality.py data/synthetic/ --output data/processed/high_quality.json
    python scripts/filter_high_quality.py data/synthetic/ --output data/processed/high_quality.json --max-examples 5000
"""

import json
import argparse
import re
from pathlib import Path
from collections import defaultdict
from difflib import SequenceMatcher
from typing import List, Dict, Tuple, Optional
import hashlib


def calculate_quality_score(example: Dict) -> Tuple[float, Dict[str, float]]:
    """
    Calculate a quality score (0-100) for a training example.
    Returns (total_score, breakdown_dict)

    BRUTAL HONESTY CRITERIA:
    - Short answers (<300 chars) are WORTHLESS for fine-tuning
    - No code/commands = weak technical depth
    - Generic responses don't teach the model anything specific
    - Duplicates waste training compute
    """
    scores = {}

    # Get question and answer
    if "conversations" in example:
        # ShareGPT format
        convs = example["conversations"]
        if not isinstance(convs, list):
            return 0, {"error": "invalid conversations format"}
        question = ""
        answer = ""
        for c in convs:
            if isinstance(c, dict):
                if c.get("from") == "human":
                    question = str(c.get("value", ""))
                elif c.get("from") == "gpt":
                    val = c.get("value", "")
                    answer = str(val) if not isinstance(val, dict) else json.dumps(val)
    else:
        question = example.get("question", "")
        answer = example.get("answer", "")

    # 1. Answer Length Score (0-20)
    # Ideal: 300-1500 chars, penalize very short or very long
    ans_len = len(answer)
    if ans_len < 100:
        scores["length"] = 0
    elif ans_len < 200:
        scores["length"] = 5
    elif ans_len < 300:
        scores["length"] = 10
    elif ans_len < 500:
        scores["length"] = 15
    elif ans_len <= 1500:
        scores["length"] = 20
    elif ans_len <= 2500:
        scores["length"] = 15
    else:
        scores["length"] = 10  # Very long answers may be bloated

    # 2. Technical Depth Score (0-30) - INCREASED from 25 for network security domain
    tech_score = 0

    # Code blocks (```code```)
    code_blocks = len(re.findall(r'```[\s\S]*?```', answer))
    tech_score += min(code_blocks * 5, 15)

    # Inline code (`code`)
    inline_code = len(re.findall(r'`[^`]+`', answer))
    tech_score += min(inline_code * 1, 5)

    # CLI commands patterns
    cli_patterns = len(re.findall(r'(?:show |config |set |get |curl |aws |az |gcloud |kubectl |docker |git )', answer, re.I))
    tech_score += min(cli_patterns * 2, 5)

    # Firewall/network specific commands
    fw_patterns = len(re.findall(r'(?:iptables|nft|firewall-cmd|ufw|palo|panorama|asa|ios|junos)', answer, re.I))
    tech_score += min(fw_patterns * 2, 5)

    scores["technical_depth"] = min(tech_score, 30)

    # 3. Formatting Quality Score (0-12) - DECREASED from 15 (less important than content)
    format_score = 0

    # Has headers (##, ###, **)
    if re.search(r'(?:^|\n)#{1,3}\s|\*\*[^*]+\*\*', answer):
        format_score += 4

    # Has bullet points or numbered lists
    if re.search(r'(?:^|\n)\s*[-*•]\s|(?:^|\n)\s*\d+[.)]\s', answer):
        format_score += 4

    # Has newlines/paragraphs (well structured)
    newlines = answer.count('\n')
    if newlines >= 3:
        format_score += 4
    elif newlines >= 1:
        format_score += 2

    scores["formatting"] = min(format_score, 12)

    # 4. Question-Answer Relevance Score (0-20)
    relevance_score = 0

    # Extract key terms from question
    q_words = set(re.findall(r'\b[a-zA-Z]{4,}\b', question.lower()))
    a_words = set(re.findall(r'\b[a-zA-Z]{4,}\b', answer.lower()))

    # Check overlap (question terms appear in answer)
    if q_words:
        overlap = len(q_words & a_words) / len(q_words)
        relevance_score = int(overlap * 20)

    scores["relevance"] = relevance_score

    # 5. Specificity Score (0-15) - INCREASED from 10 (IPs/ports/commands crucial)
    specificity_score = 0

    # Contains specific numbers, IPs, ports
    if re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', answer):  # IP addresses
        specificity_score += 4
    if re.search(r'\bport\s*\d+\b', answer, re.I):  # Port numbers
        specificity_score += 3
    if re.search(r'\b(?:192\.168|10\.|172\.(?:1[6-9]|2[0-9]|3[01]))', answer):  # Private IPs
        specificity_score += 3
    if re.search(r'\b(?:TCP|UDP|HTTP|HTTPS|SSH|SSL|TLS|ICMP)\b', answer):  # Protocols
        specificity_score += 3
    # Firewall-specific terms
    if re.search(r'\b(?:device.?group|DG-|panorama|security.?rule|NAT)\b', answer, re.I):
        specificity_score += 2

    scores["specificity"] = min(specificity_score, 15)

    # 6. No Filler/Placeholder Penalty (0-3) - DECREASED from 10 (rarely issue with GPT-4o/Claude)
    filler_score = 3

    # Check for placeholder text
    placeholders = [
        r'\[.*?\]',  # [placeholder]
        r'<.*?>',    # <placeholder>
        r'xxx+',     # xxxx
        r'your[_-]?(?:domain|ip|server|password)',
        r'example\.com',
        r'TODO',
        r'TBD',
    ]
    for pattern in placeholders:
        if re.search(pattern, answer, re.I):
            filler_score -= 1

    scores["no_filler"] = max(filler_score, 0)

    # 7. Bonus Criteria (Network Security Domain)
    bonus_score = 0

    # Security warnings and best practices (+5)
    security_patterns = [
        r'\b(?:warning|caution|security|best.?practice|recommendation|avoid|never|always)\b',
        r'(?:⚠️|🔒|🛡️|⚡)',  # Security emojis
        r'(?:CRITICAL|WARNING|NOTE|TIP):',
    ]
    for pattern in security_patterns:
        if re.search(pattern, answer, re.I):
            bonus_score += 5
            break

    # Multi-vendor support (+3)
    vendors = [r'\bpalo.?alto\b', r'\bcisco\b', r'\bfortinet\b', r'\baws\b', r'\bazure\b', r'\bgcp\b']
    vendor_count = sum(1 for v in vendors if re.search(v, answer, re.I))
    if vendor_count >= 2:
        bonus_score += 3

    # Troubleshooting steps (+5)
    troubleshooting_patterns = [
        r'\b(?:troubleshoot|debug|diagnose|fix|resolve|solution)\b',
        r'(?:^|\n)\s*\d+[.)]\s.*(?:check|verify|test|validate)',  # Numbered steps
        r'(?:if.*then|when.*use|first.*then)',  # Conditional troubleshooting
    ]
    for pattern in troubleshooting_patterns:
        if re.search(pattern, answer, re.I):
            bonus_score += 5
            break

    scores["bonus"] = bonus_score

    # Calculate total (max 113 with bonuses)
    total = sum(scores.values())

    return total, scores


def extract_qa(example: Dict) -> Tuple[str, str]:
    """Safely extract question and answer from any format."""
    if "conversations" in example:
        convs = example["conversations"]
        if not isinstance(convs, list):
            return "", ""
        question = ""
        answer = ""
        for c in convs:
            if isinstance(c, dict):
                if c.get("from") == "human":
                    question = str(c.get("value", ""))
                elif c.get("from") == "gpt":
                    val = c.get("value", "")
                    answer = str(val) if not isinstance(val, dict) else json.dumps(val)
        return question, answer
    else:
        return str(example.get("question", "")), str(example.get("answer", ""))


def is_duplicate(example: Dict, seen_hashes: set, seen_questions: List[str],
                 similarity_threshold: float = 0.85) -> bool:
    """Check if example is a duplicate or near-duplicate."""

    question, answer = extract_qa(example)

    # Exact duplicate check (hash of question + answer)
    content_hash = hashlib.md5((question + answer).encode()).hexdigest()
    if content_hash in seen_hashes:
        return True
    seen_hashes.add(content_hash)

    # Near-duplicate question check
    q_normalized = re.sub(r'\s+', ' ', question.lower().strip())
    for seen_q in seen_questions[-500:]:  # Check last 500 questions
        similarity = SequenceMatcher(None, q_normalized, seen_q).ratio()
        if similarity > similarity_threshold:
            return True

    seen_questions.append(q_normalized)
    return False


def get_topic_from_file(filepath: Path) -> str:
    """Extract topic name from filename."""
    name = filepath.stem.replace('_openai', '').replace('_anthropic', '').replace('_kimi', '')
    return name


def filter_high_quality_data(
    input_dir: Path,
    output_file: Path,
    min_score: int = 50,
    max_examples: Optional[int] = None,
    examples_per_topic: Optional[int] = None,
    format: str = "sharegpt"
) -> Dict:
    """
    Filter training data for high quality examples.

    Args:
        input_dir: Directory containing JSON/JSONL files
        output_file: Output file path
        min_score: Minimum quality score (0-100)
        max_examples: Maximum total examples to keep
        examples_per_topic: Maximum examples per topic (for balance)
        format: Output format (sharegpt or qa)

    Returns:
        Statistics dictionary
    """

    all_examples = []
    stats = {
        "files_processed": 0,
        "total_examples": 0,
        "passed_quality": 0,
        "duplicates_removed": 0,
        "by_topic": defaultdict(lambda: {"total": 0, "passed": 0}),
        "score_distribution": defaultdict(int),
    }

    seen_hashes = set()
    seen_questions = []

    # Load all examples from all files
    for filepath in sorted(input_dir.glob("*.json")):
        topic = get_topic_from_file(filepath)
        stats["files_processed"] += 1

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            continue

        if not isinstance(data, list):
            data = [data]

        for example in data:
            stats["total_examples"] += 1
            stats["by_topic"][topic]["total"] += 1

            # Calculate quality score
            score, breakdown = calculate_quality_score(example)

            # Track score distribution
            score_bucket = (score // 10) * 10
            stats["score_distribution"][score_bucket] += 1

            # Check minimum score
            if score < min_score:
                continue

            # Check for duplicates
            if is_duplicate(example, seen_hashes, seen_questions):
                stats["duplicates_removed"] += 1
                continue

            stats["passed_quality"] += 1
            stats["by_topic"][topic]["passed"] += 1

            # Add metadata
            example["_quality_score"] = score
            example["_topic"] = topic
            example["_score_breakdown"] = breakdown

            all_examples.append(example)

    # Sort by quality score (highest first)
    all_examples.sort(key=lambda x: x.get("_quality_score", 0), reverse=True)

    # Apply per-topic limit if specified
    if examples_per_topic:
        topic_counts = defaultdict(int)
        filtered = []
        for ex in all_examples:
            topic = ex.get("_topic", "unknown")
            if topic_counts[topic] < examples_per_topic:
                filtered.append(ex)
                topic_counts[topic] += 1
        all_examples = filtered

    # Apply global limit if specified
    if max_examples and len(all_examples) > max_examples:
        all_examples = all_examples[:max_examples]

    # Remove metadata before saving (optional - keep for debugging)
    final_examples = []
    for ex in all_examples:
        clean_ex = {k: v for k, v in ex.items() if not k.startswith("_")}
        final_examples.append(clean_ex)

    # Save output
    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(final_examples, f, indent=2, ensure_ascii=False)

    stats["final_count"] = len(final_examples)

    return stats


def print_stats(stats: Dict):
    """Print filtering statistics."""
    print("\n" + "=" * 60)
    print("HIGH-QUALITY DATA FILTERING RESULTS")
    print("=" * 60)

    print(f"\nFiles processed: {stats['files_processed']}")
    print(f"Total examples: {stats['total_examples']}")
    print(f"Passed quality filter: {stats['passed_quality']}")
    print(f"Duplicates removed: {stats['duplicates_removed']}")
    print(f"Final count: {stats['final_count']}")

    pass_rate = (stats['passed_quality'] / stats['total_examples'] * 100) if stats['total_examples'] > 0 else 0
    print(f"Pass rate: {pass_rate:.1f}%")

    print("\nScore Distribution:")
    for bucket in sorted(stats['score_distribution'].keys()):
        count = stats['score_distribution'][bucket]
        bar = "#" * min(count // 100, 50)
        print(f"  {bucket:2d}-{bucket+9:2d}: {count:5d} {bar}")

    print("\nBy Topic (top 10 by passed):")
    topic_stats = sorted(stats['by_topic'].items(), key=lambda x: x[1]['passed'], reverse=True)
    for topic, counts in topic_stats[:10]:
        rate = (counts['passed'] / counts['total'] * 100) if counts['total'] > 0 else 0
        print(f"  {topic}: {counts['passed']}/{counts['total']} ({rate:.0f}%)")


def main():
    parser = argparse.ArgumentParser(description="Filter high-quality training data")
    parser.add_argument("input_dir", type=Path, help="Directory with JSON files")
    parser.add_argument("--output", "-o", type=Path, default=Path("data/processed/high_quality.json"),
                        help="Output file path")
    parser.add_argument("--min-score", type=int, default=50,
                        help="Minimum quality score (0-100, default: 50)")
    parser.add_argument("--max-examples", type=int, default=None,
                        help="Maximum total examples")
    parser.add_argument("--per-topic", type=int, default=None,
                        help="Maximum examples per topic")
    parser.add_argument("--format", choices=["sharegpt", "qa"], default="sharegpt",
                        help="Output format")

    args = parser.parse_args()

    if not args.input_dir.exists():
        print(f"Error: Input directory not found: {args.input_dir}")
        return 1

    print(f"Filtering high-quality data from: {args.input_dir}")
    print(f"Minimum quality score: {args.min_score}")
    if args.max_examples:
        print(f"Maximum examples: {args.max_examples}")
    if args.per_topic:
        print(f"Maximum per topic: {args.per_topic}")

    stats = filter_high_quality_data(
        input_dir=args.input_dir,
        output_file=args.output,
        min_score=args.min_score,
        max_examples=args.max_examples,
        examples_per_topic=args.per_topic,
        format=args.format
    )

    print_stats(stats)

    print(f"\nFiltered data saved to: {args.output}")
    print(f"\nNext steps:")
    print(f"  1. Review samples: head -100 {args.output}")
    print(f"  2. Train with filtered data")

    return 0


if __name__ == "__main__":
    exit(main())
