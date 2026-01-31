#!/usr/bin/env python3
"""
Prepare final training data by combining, deduplicating, and validating all sources.

Combines:
- V1 converted data (from convert_to_native_format.py)
- V2 native tool calling data
- External datasets (glaive, xlam)

Usage:
    python v2/scripts/prepare_training_data.py
    python v2/scripts/prepare_training_data.py --validate
    python v2/scripts/prepare_training_data.py --balance 0.8  # 80% tool calling
"""

import json
import argparse
import hashlib
import random
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import Counter
import re

# Default data sources
DATA_SOURCES = {
    # V1/V2 FireWeave data
    'v1_converted': 'v2/data/converted/v1_converted.json',
    'v2_native': 'v2/data/synthetic/tool_calling_native.json',
    'v2_hq': 'v2/data/synthetic/hq_tool_calling.json',
    'v2_combined': 'v2/data/synthetic/all_tool_calling_combined.json',
    # Tool calling datasets
    'glaive': 'v2/data/external/glaive_filtered.json',
    'xlam': 'v2/data/external/xlam_filtered.json',
    # Security knowledge datasets
    'trendyol_cyber': 'v2/data/external/trendyol_cyber_filtered.json',
    'fenrir': 'v2/data/external/fenrir_filtered.json',
    'ir_playbooks': 'v2/data/external/ir_playbooks.json',
}

# FireWeave tool definitions
FIREWEAVE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "check_traffic_flow",
            "description": "Check if traffic is allowed between source and destination IP addresses through the firewall",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string", "description": "Source IP address or CIDR"},
                    "destination_ip": {"type": "string", "description": "Destination IP address or CIDR"},
                    "port": {"type": "integer", "description": "Destination port number"},
                    "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp"]}
                },
                "required": ["source_ip", "destination_ip", "port"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_compliance_scan",
            "description": "Run compliance scan against specified framework",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {"type": "string", "enum": ["pci-dss", "soc2", "nist", "hipaa", "iso27001", "cis"]},
                    "scope": {"type": "string", "description": "Device groups or 'all'"},
                    "include_evidence": {"type": "boolean"}
                },
                "required": ["framework"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_attack_path",
            "description": "Analyze potential attack paths from source to target",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Starting point (IP, zone, or 'internet')"},
                    "target": {"type": "string", "description": "Target asset or zone"},
                    "include_cloud": {"type": "boolean"},
                    "max_hops": {"type": "integer"}
                },
                "required": ["source", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_shadowed_rules",
            "description": "Find rules that are shadowed by more specific rules",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_group": {"type": "string"},
                    "include_recommendations": {"type": "boolean"}
                },
                "required": ["device_group"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_firewall_rule",
            "description": "Generate firewall rule configuration",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "source_zone": {"type": "string"},
                    "destination_zone": {"type": "string"},
                    "source_address": {"type": "string"},
                    "destination_address": {"type": "string"},
                    "service": {"type": "string"},
                    "action": {"type": "string", "enum": ["allow", "deny"]},
                    "logging": {"type": "boolean"}
                },
                "required": ["name", "source_zone", "destination_zone", "action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_rule_hit_count",
            "description": "Get hit count statistics for firewall rules",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_group": {"type": "string"},
                    "rule_name": {"type": "string"},
                    "days": {"type": "integer"}
                },
                "required": ["device_group"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_blast_radius",
            "description": "Calculate blast radius if an asset is compromised",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset": {"type": "string"},
                    "include_lateral": {"type": "boolean"}
                },
                "required": ["asset"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "fetch_jira_issues",
            "description": "Fetch firewall change requests from Jira",
            "parameters": {
                "type": "object",
                "properties": {
                    "project": {"type": "string"},
                    "status": {"type": "string"},
                    "max_results": {"type": "integer"}
                },
                "required": ["project"]
            }
        }
    }
]


def compute_hash(example: dict) -> str:
    """Compute hash for deduplication based on first message."""
    convs = example.get('conversations', [])
    if not convs:
        return hashlib.md5(json.dumps(example).encode()).hexdigest()

    # Hash first 200 chars of first human message
    first_human = next((c['value'] for c in convs if c.get('from') == 'human'), '')
    return hashlib.md5(first_human[:200].encode()).hexdigest()


def validate_json_in_tool_calls(example: dict) -> bool:
    """Validate that all tool calls contain valid JSON."""
    for conv in example.get('conversations', []):
        value = conv.get('value', '')
        if '<|python_tag|>' in value:
            # Extract JSON after tag
            try:
                json_str = value.split('<|python_tag|>')[1].strip()
                # Handle cases where there's text after the JSON
                # Find the JSON object/array
                if json_str.startswith('['):
                    end = json_str.rfind(']') + 1
                elif json_str.startswith('{'):
                    end = json_str.rfind('}') + 1
                else:
                    return False
                json_str = json_str[:end]
                json.loads(json_str)
            except (json.JSONDecodeError, IndexError):
                return False
    return True


def validate_conversation_structure(example: dict) -> bool:
    """Validate conversation has proper structure."""
    convs = example.get('conversations', [])
    if len(convs) < 2:
        return False

    # First message should be human
    if convs[0].get('from') != 'human':
        return False

    # Check alternating pattern (allowing tool responses)
    valid_after_human = {'gpt'}
    valid_after_gpt = {'human', 'tool'}
    valid_after_tool = {'gpt'}

    prev_role = None
    for conv in convs:
        role = conv.get('from')
        if not role or not conv.get('value'):
            return False

        if prev_role == 'human' and role not in valid_after_human:
            return False
        if prev_role == 'gpt' and role not in valid_after_gpt:
            return False
        if prev_role == 'tool' and role not in valid_after_tool:
            return False

        prev_role = role

    return True


def has_tool_call(example: dict) -> bool:
    """Check if example contains tool calls."""
    for conv in example.get('conversations', []):
        if '<|python_tag|>' in conv.get('value', ''):
            return True
    return example.get('has_tool_call', False)


def ensure_tools_field(example: dict) -> dict:
    """Ensure example has tools field if it has tool calls."""
    if has_tool_call(example) and not example.get('tools'):
        example['tools'] = FIREWEAVE_TOOLS
    return example


def load_data_source(path: Path, source_name: str) -> List[dict]:
    """Load data from a JSON file."""
    if not path.exists():
        print(f"  Warning: {source_name} not found at {path}")
        return []

    try:
        with open(path, 'r') as f:
            data = json.load(f)

        if isinstance(data, dict):
            data = [data]

        # Add source tag
        for item in data:
            if 'source' not in item:
                item['source'] = source_name

        print(f"  Loaded {len(data)} examples from {source_name}")
        return data
    except Exception as e:
        print(f"  Error loading {source_name}: {e}")
        return []


def deduplicate(examples: List[dict]) -> List[dict]:
    """Remove duplicate examples based on first message hash."""
    seen = set()
    unique = []

    for ex in examples:
        h = compute_hash(ex)
        if h not in seen:
            seen.add(h)
            unique.append(ex)

    return unique


def balance_dataset(examples: List[dict], tool_ratio: float = 0.65) -> List[dict]:
    """Balance dataset to achieve target tool calling ratio (default: 65% tools, 35% conversational)."""
    with_tools = [x for x in examples if has_tool_call(x)]
    without_tools = [x for x in examples if not has_tool_call(x)]

    print(f"\nBefore balancing:")
    print(f"  With tools: {len(with_tools)}")
    print(f"  Without tools: {len(without_tools)}")

    # Calculate target counts
    total_target = len(with_tools) + len(without_tools)

    # If we have more tool examples than needed, keep all; otherwise use what we have
    tool_target = int(total_target * tool_ratio)
    non_tool_target = total_target - tool_target

    # Sample to balance
    if len(with_tools) > tool_target:
        with_tools = random.sample(with_tools, tool_target)
    if len(without_tools) > non_tool_target:
        without_tools = random.sample(without_tools, non_tool_target)

    balanced = with_tools + without_tools
    random.shuffle(balanced)

    actual_ratio = len([x for x in balanced if has_tool_call(x)]) / len(balanced) if balanced else 0

    print(f"\nAfter balancing:")
    print(f"  Total: {len(balanced)}")
    print(f"  Tool ratio: {actual_ratio:.1%}")

    return balanced


def validate_dataset(examples: List[dict], strict: bool = False) -> List[dict]:
    """Validate all examples and filter out invalid ones."""
    valid = []
    invalid_json = 0
    invalid_structure = 0

    for ex in examples:
        # Check JSON validity
        if has_tool_call(ex) and not validate_json_in_tool_calls(ex):
            invalid_json += 1
            if strict:
                continue

        # Check conversation structure
        if not validate_conversation_structure(ex):
            invalid_structure += 1
            if strict:
                continue

        # Ensure tools field
        ex = ensure_tools_field(ex)
        valid.append(ex)

    print(f"\nValidation results:")
    print(f"  Invalid JSON in tool calls: {invalid_json}")
    print(f"  Invalid conversation structure: {invalid_structure}")
    print(f"  Valid examples: {len(valid)}")

    return valid


def compute_stats(examples: List[dict]) -> Dict[str, Any]:
    """Compute dataset statistics."""
    stats = {
        'total': len(examples),
        'with_tools': 0,
        'without_tools': 0,
        'sources': Counter(),
        'avg_turns': 0,
        'multi_turn': 0,  # >2 turns
    }

    total_turns = 0
    for ex in examples:
        if has_tool_call(ex):
            stats['with_tools'] += 1
        else:
            stats['without_tools'] += 1

        source = ex.get('source', 'unknown')
        stats['sources'][source] += 1

        turns = len(ex.get('conversations', []))
        total_turns += turns
        if turns > 2:
            stats['multi_turn'] += 1

    stats['avg_turns'] = total_turns / len(examples) if examples else 0
    stats['tool_ratio'] = stats['with_tools'] / stats['total'] if stats['total'] else 0

    return stats


def main():
    parser = argparse.ArgumentParser(description='Prepare final training data')
    parser.add_argument('--output', type=str, default='v2/data/processed/training_data_final.json',
                       help='Output file path')
    parser.add_argument('--balance', type=float, default=0.65,
                       help='Target ratio of tool calling examples (default: 0.65 = 65%% tools, 35%% conversational)')
    parser.add_argument('--validate', action='store_true',
                       help='Run validation only, don\'t create output')
    parser.add_argument('--strict', action='store_true',
                       help='Use strict validation (remove invalid examples)')
    parser.add_argument('--no-balance', action='store_true',
                       help='Skip balancing, use all data')
    parser.add_argument('--seed', type=int, default=42,
                       help='Random seed for reproducibility')

    args = parser.parse_args()
    random.seed(args.seed)

    print(f"{'='*60}")
    print("Preparing Training Data")
    print(f"{'='*60}")

    # Load all data sources
    all_data = []

    print("\nLoading data sources...")
    for name, path in DATA_SOURCES.items():
        data = load_data_source(Path(path), name)
        all_data.extend(data)

    print(f"\nTotal loaded: {len(all_data)} examples")

    # Deduplicate
    print("\nDeduplicating...")
    unique_data = deduplicate(all_data)
    print(f"After deduplication: {len(unique_data)} examples")
    print(f"Removed {len(all_data) - len(unique_data)} duplicates")

    # Validate
    print("\nValidating...")
    valid_data = validate_dataset(unique_data, strict=args.strict)

    if args.validate:
        # Just show stats and exit
        stats = compute_stats(valid_data)
        print(f"\n{'='*60}")
        print("Dataset Statistics")
        print(f"{'='*60}")
        print(f"Total examples: {stats['total']}")
        print(f"With tool calls: {stats['with_tools']} ({stats['tool_ratio']:.1%})")
        print(f"Without tool calls: {stats['without_tools']}")
        print(f"Multi-turn (>2 turns): {stats['multi_turn']}")
        print(f"Average turns: {stats['avg_turns']:.1f}")
        print(f"\nBy source:")
        for source, count in stats['sources'].most_common():
            print(f"  {source}: {count}")
        return

    # Balance
    if not args.no_balance:
        print(f"\nBalancing dataset (target: {args.balance:.0%} tool calling)...")
        final_data = balance_dataset(valid_data, args.balance)
    else:
        final_data = valid_data

    # Final stats
    stats = compute_stats(final_data)
    print(f"\n{'='*60}")
    print("Final Dataset Statistics")
    print(f"{'='*60}")
    print(f"Total examples: {stats['total']}")
    print(f"With tool calls: {stats['with_tools']} ({stats['tool_ratio']:.1%})")
    print(f"Without tool calls: {stats['without_tools']}")
    print(f"Multi-turn (>2 turns): {stats['multi_turn']}")
    print(f"Average turns: {stats['avg_turns']:.1f}")
    print(f"\nBy source:")
    for source, count in stats['sources'].most_common():
        print(f"  {source}: {count}")

    # Save output
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w') as f:
        json.dump(final_data, f, indent=2)

    print(f"\nSaved to {output_path}")
    print(f"File size: {output_path.stat().st_size / (1024*1024):.1f} MB")

    # Also save a small sample for inspection
    sample_path = output_path.parent / 'training_sample.json'
    sample = random.sample(final_data, min(10, len(final_data)))
    with open(sample_path, 'w') as f:
        json.dump(sample, f, indent=2)
    print(f"Sample saved to {sample_path}")


if __name__ == '__main__':
    main()
