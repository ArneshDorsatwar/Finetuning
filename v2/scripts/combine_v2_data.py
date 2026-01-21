#!/usr/bin/env python3
"""
Combine v1 training data + v2 tool calling data into final v2 dataset.

This creates a comprehensive training dataset that includes:
1. All v1 data (conceptual/theoretical + commands)
2. New v2 tool calling data in native Llama 3.1 format
3. Deduplication and quality filtering
"""

import json
import hashlib
import os
from pathlib import Path
from typing import List, Dict

def load_json(filepath: str) -> List[dict]:
    """Load JSON file."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading {filepath}: {e}")
        return []

def extract_text(value):
    """Extract text from value, handling dict/str cases."""
    if isinstance(value, str):
        return value
    elif isinstance(value, dict):
        for key in ['text', 'content', 'value', 'answer', 'response']:
            if key in value:
                return extract_text(value[key])
        return json.dumps(value, indent=2)
    elif isinstance(value, list):
        return ' '.join(str(v) for v in value)
    return str(value)

def normalize_to_sharegpt(item: dict) -> dict:
    """Normalize item to ShareGPT format."""
    if 'conversations' in item:
        # Already in ShareGPT format, just normalize
        conversations = []
        for conv in item['conversations']:
            role = conv.get('from', 'human')
            value = extract_text(conv.get('value', ''))
            conversations.append({'from': role, 'value': value})

        return {
            'conversations': conversations,
            'tools': item.get('tools', []),
            'has_tool_call': item.get('has_tool_call', False),
            'topic': item.get('topic', item.get('category', 'unknown'))
        }
    elif 'question' in item and 'answer' in item:
        # Q&A format
        return {
            'conversations': [
                {'from': 'human', 'value': extract_text(item['question'])},
                {'from': 'gpt', 'value': extract_text(item['answer'])}
            ],
            'tools': [],
            'has_tool_call': False,
            'topic': item.get('topic', 'unknown')
        }
    return None

def get_hash(item: dict) -> str:
    """Get hash for deduplication."""
    if 'conversations' in item:
        text = ''.join(c.get('value', '')[:200] for c in item['conversations'][:2])
    else:
        text = str(item)[:500]
    return hashlib.md5(text.encode()).hexdigest()

def score_quality(item: dict) -> int:
    """Score item quality (0-100)."""
    score = 0

    if 'conversations' not in item:
        return 0

    convs = item['conversations']
    if len(convs) < 2:
        return 0

    # Get answer content
    answer = ''
    for conv in convs:
        if conv.get('from') == 'gpt':
            answer += conv.get('value', '')

    # Length scoring
    if len(answer) > 100:
        score += 10
    if len(answer) > 300:
        score += 15
    if len(answer) > 500:
        score += 10
    if len(answer) > 1000:
        score += 5

    # Tool calling bonus
    if item.get('has_tool_call') or '<|python_tag|>' in answer:
        score += 20

    # Has tool response
    for conv in convs:
        if conv.get('from') == 'tool':
            score += 10
            break

    # Technical content
    if '```' in answer:
        score += 10
    if any(term in answer.lower() for term in ['pci', 'soc2', 'nist', 'hipaa', 'compliance']):
        score += 10
    if any(term in answer.lower() for term in ['fireweave', 'panorama', 'firewall']):
        score += 5

    # Multi-turn bonus
    if len(convs) > 2:
        score += 5
    if len(convs) > 4:
        score += 5

    return min(score, 100)

def main():
    print("=" * 60)
    print("COMBINING V2 TRAINING DATA")
    print("=" * 60)

    # Paths
    v1_data_path = Path("data/processed/all_training_data.json")
    v2_synthetic_dir = Path("v2/data/synthetic")
    output_path = Path("v2/data/processed/all_training_data_v2.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    all_examples = []
    seen_hashes = set()

    # Load v1 data
    print("\n[1] Loading v1 training data...")
    if v1_data_path.exists():
        v1_data = load_json(str(v1_data_path))
        print(f"  Loaded {len(v1_data)} v1 examples")

        for item in v1_data:
            normalized = normalize_to_sharegpt(item)
            if normalized:
                h = get_hash(normalized)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    all_examples.append(normalized)

        print(f"  After dedup: {len(all_examples)} unique examples")

    # Load v2 tool calling data
    print("\n[2] Loading v2 tool calling data...")
    v2_files = list(v2_synthetic_dir.glob("*.json"))

    for filepath in v2_files:
        data = load_json(str(filepath))
        added = 0

        for item in data:
            normalized = normalize_to_sharegpt(item)
            if normalized:
                h = get_hash(normalized)
                if h not in seen_hashes:
                    seen_hashes.add(h)
                    all_examples.append(normalized)
                    added += 1

        print(f"  {filepath.name}: +{added} new examples")

    print(f"\n[3] Total combined: {len(all_examples)} examples")

    # Quality scoring
    print("\n[4] Quality scoring...")
    high_quality = []
    medium_quality = []
    low_quality = []

    for ex in all_examples:
        score = score_quality(ex)
        ex['quality_score'] = score

        if score >= 50:
            high_quality.append(ex)
        elif score >= 30:
            medium_quality.append(ex)
        else:
            low_quality.append(ex)

    print(f"  High quality (50+): {len(high_quality)}")
    print(f"  Medium quality (30-49): {len(medium_quality)}")
    print(f"  Low quality (<30): {len(low_quality)}")

    # Combine (prioritize high quality, include medium)
    final_data = high_quality + medium_quality

    # Stats
    tool_call_count = sum(1 for ex in final_data if ex.get('has_tool_call'))
    multi_turn_count = sum(1 for ex in final_data if len(ex.get('conversations', [])) > 2)

    print(f"\n[5] Final dataset stats:")
    print(f"  Total examples: {len(final_data)}")
    print(f"  With tool calls: {tool_call_count} ({100*tool_call_count/len(final_data):.1f}%)")
    print(f"  Multi-turn: {multi_turn_count} ({100*multi_turn_count/len(final_data):.1f}%)")

    # Topic distribution
    topics = {}
    for ex in final_data:
        topic = ex.get('topic', 'unknown')
        topics[topic] = topics.get(topic, 0) + 1

    print(f"\n  Top topics:")
    for topic, count in sorted(topics.items(), key=lambda x: -x[1])[:15]:
        print(f"    {topic}: {count}")

    # Save
    print(f"\n[6] Saving to {output_path}...")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(final_data, f, indent=2, ensure_ascii=False)

    size_mb = output_path.stat().st_size / (1024 * 1024)
    print(f"  File size: {size_mb:.1f} MB")

    print("\n" + "=" * 60)
    print("COMPLETE!")
    print("=" * 60)
    print(f"\nFinal v2 dataset: {output_path}")
    print(f"Examples: {len(final_data)}")
    print(f"Tool calling examples: {tool_call_count}")

    return final_data

if __name__ == "__main__":
    main()
