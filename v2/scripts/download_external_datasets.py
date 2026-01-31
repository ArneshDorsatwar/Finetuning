#!/usr/bin/env python3
"""
Download and filter external datasets for training.

Downloads:
- glaive-function-calling-v2-sharegpt (~113K examples) -> ~10K filtered
- Salesforce/xlam-function-calling-60k (~60K examples) -> ~3K filtered
- Trendyol-Cybersecurity (~53K examples) -> ~10K filtered
- Fenrir-v2.0 Cybersecurity (~84K examples) -> ~10K filtered
- Incident Response Playbooks (~175 examples) -> all

Usage:
    python v2/scripts/download_external_datasets.py
    python v2/scripts/download_external_datasets.py --all
    python v2/scripts/download_external_datasets.py --only-security  # Skip tool calling datasets
"""

import json
import argparse
import hashlib
import re
from pathlib import Path
from typing import Optional
from collections import Counter

try:
    from datasets import load_dataset
except ImportError:
    print("Please install datasets: pip install datasets")
    exit(1)

# Security/infrastructure keywords for filtering xlam
SECURITY_KEYWORDS = [
    # Network security
    'firewall', 'network', 'security', 'traffic', 'ip', 'port', 'rule',
    'vpn', 'dns', 'routing', 'subnet', 'cidr', 'tcp', 'udp', 'icmp',
    # Cloud
    'aws', 'azure', 'gcp', 'cloud', 'ec2', 'vpc', 's3', 'iam',
    # Security operations
    'scan', 'vulnerability', 'threat', 'attack', 'compliance', 'audit',
    'encrypt', 'certificate', 'ssl', 'tls', 'authentication', 'authorization',
    # Infrastructure
    'server', 'database', 'api', 'endpoint', 'service', 'container', 'docker',
    'kubernetes', 'load balancer', 'proxy', 'gateway'
]


def is_valid_json(s: str) -> bool:
    """Check if string is valid JSON."""
    try:
        json.loads(s)
        return True
    except (json.JSONDecodeError, TypeError):
        return False


def extract_function_call(text: str) -> Optional[dict]:
    """Extract function call from assistant response."""
    # Try to find JSON in the text
    try:
        # Look for JSON object pattern
        match = re.search(r'\{[^{}]*"name"[^{}]*\}', text, re.DOTALL)
        if match:
            return json.loads(match.group())
    except:
        pass

    # Try parsing the whole text as JSON
    try:
        data = json.loads(text)
        if isinstance(data, dict) and 'name' in data:
            return data
    except:
        pass

    return None


def has_security_relevance(example: dict) -> bool:
    """Check if example is related to security/infrastructure topics."""
    text = json.dumps(example).lower()
    return any(keyword in text for keyword in SECURITY_KEYWORDS)


def convert_glaive_to_native(example: dict) -> Optional[dict]:
    """Convert glaive ShareGPT format to native Llama 3.1 format."""
    conversations = example.get('conversations', [])
    if len(conversations) < 2:
        return None

    converted = []
    tools = []
    has_tool_call = False

    for turn in conversations:
        role = turn.get('from', '')
        value = turn.get('value', '')

        if role == 'system':
            # Extract tool definitions from system prompt if present
            if 'function' in value.lower() or 'tool' in value.lower():
                # Try to extract function definitions
                try:
                    # Look for JSON array of functions
                    match = re.search(r'\[[\s\S]*?\{[\s\S]*?"name"[\s\S]*?\}[\s\S]*?\]', value)
                    if match:
                        tools = json.loads(match.group())
                except:
                    pass
            continue  # Skip system turns in conversations

        elif role == 'human':
            converted.append({'from': 'human', 'value': value})

        elif role == 'gpt':
            # Check if this is a function call
            func_call = extract_function_call(value)
            if func_call:
                # Convert to native format
                converted.append({
                    'from': 'gpt',
                    'value': f'<|python_tag|>{json.dumps(func_call)}'
                })
                has_tool_call = True
            else:
                converted.append({'from': 'gpt', 'value': value})

        elif role == 'function_call':
            # This is a function call turn
            func_call = extract_function_call(value)
            if func_call:
                converted.append({
                    'from': 'gpt',
                    'value': f'<|python_tag|>{json.dumps(func_call)}'
                })
                has_tool_call = True

        elif role == 'observation' or role == 'tool':
            # Tool response
            converted.append({'from': 'tool', 'value': value})

    if not converted or not has_tool_call:
        return None

    # Validate conversation structure
    if len(converted) < 2:
        return None

    return {
        'conversations': converted,
        'tools': tools,
        'has_tool_call': has_tool_call,
        'source': 'glaive'
    }


def convert_xlam_to_native(example: dict) -> Optional[dict]:
    """Convert xLAM format to native Llama 3.1 format."""
    query = example.get('query', '')
    tools = example.get('tools', '[]')
    answers = example.get('answers', '[]')

    if not query or not answers:
        return None

    # Parse tools
    try:
        if isinstance(tools, str):
            tools = json.loads(tools)
    except:
        tools = []

    # Parse answers
    try:
        if isinstance(answers, str):
            answers = json.loads(answers)
    except:
        return None

    if not answers:
        return None

    conversations = [{'from': 'human', 'value': query}]

    # Convert answer to tool call format
    for answer in answers:
        if isinstance(answer, dict):
            func_name = answer.get('name', '')
            func_args = answer.get('arguments', {})

            if func_name:
                tool_call = {
                    'name': func_name,
                    'parameters': func_args if isinstance(func_args, dict) else {}
                }
                conversations.append({
                    'from': 'gpt',
                    'value': f'<|python_tag|>{json.dumps(tool_call)}'
                })

    if len(conversations) < 2:
        return None

    # Convert tools to standard format
    formatted_tools = []
    for tool in tools:
        if isinstance(tool, dict):
            formatted_tools.append({
                'type': 'function',
                'function': tool
            })

    return {
        'conversations': conversations,
        'tools': formatted_tools,
        'has_tool_call': True,
        'source': 'xlam'
    }


def deduplicate(examples: list) -> list:
    """Remove duplicates based on first message hash."""
    seen = set()
    unique = []

    for ex in examples:
        # Create hash from first human message
        convs = ex.get('conversations', [])
        if not convs:
            continue

        first_msg = convs[0].get('value', '')[:200]
        msg_hash = hashlib.md5(first_msg.encode()).hexdigest()

        if msg_hash not in seen:
            seen.add(msg_hash)
            unique.append(ex)

    return unique


def download_glaive(output_dir: Path, limit: int = 10000) -> Path:
    """Download and process glaive-function-calling-v2-sharegpt dataset."""
    print(f"\n{'='*60}")
    print("Downloading glaive-function-calling-v2-sharegpt...")
    print(f"{'='*60}")

    output_file = output_dir / 'glaive_filtered.json'

    try:
        # Load dataset
        ds = load_dataset('hiyouga/glaive-function-calling-v2-sharegpt', split='train')
        print(f"Loaded {len(ds)} examples from glaive dataset")

        # Convert and filter
        converted = []
        failed = 0

        for i, example in enumerate(ds):
            if i % 10000 == 0:
                print(f"Processing {i}/{len(ds)}...")

            result = convert_glaive_to_native(example)
            if result:
                converted.append(result)
            else:
                failed += 1

            # Stop if we have enough
            if len(converted) >= limit * 1.5:  # Get extra for dedup
                break

        print(f"Converted {len(converted)} examples, {failed} failed")

        # Deduplicate
        unique = deduplicate(converted)
        print(f"After deduplication: {len(unique)} examples")

        # Take limit
        final = unique[:limit]
        print(f"Final count: {len(final)} examples")

        # Save
        with open(output_file, 'w') as f:
            json.dump(final, f, indent=2)

        print(f"Saved to {output_file}")
        return output_file

    except Exception as e:
        print(f"Error downloading glaive: {e}")
        return None


def download_xlam(output_dir: Path, limit: int = 3000) -> Path:
    """Download and process Salesforce/xlam-function-calling-60k dataset."""
    print(f"\n{'='*60}")
    print("Downloading Salesforce/xlam-function-calling-60k...")
    print(f"{'='*60}")

    output_file = output_dir / 'xlam_filtered.json'

    try:
        # Load dataset
        ds = load_dataset('Salesforce/xlam-function-calling-60k', split='train')
        print(f"Loaded {len(ds)} examples from xlam dataset")

        # Convert and filter for security relevance
        converted = []
        security_filtered = []
        failed = 0

        for i, example in enumerate(ds):
            if i % 10000 == 0:
                print(f"Processing {i}/{len(ds)}...")

            result = convert_xlam_to_native(example)
            if result:
                converted.append(result)

                # Check for security relevance
                if has_security_relevance(result):
                    security_filtered.append(result)
            else:
                failed += 1

        print(f"Converted {len(converted)} examples, {failed} failed")
        print(f"Security-relevant: {len(security_filtered)} examples")

        # Use security-filtered if we have enough, otherwise use all
        to_use = security_filtered if len(security_filtered) >= limit else converted

        # Deduplicate
        unique = deduplicate(to_use)
        print(f"After deduplication: {len(unique)} examples")

        # Take limit
        final = unique[:limit]
        print(f"Final count: {len(final)} examples")

        # Save
        with open(output_file, 'w') as f:
            json.dump(final, f, indent=2)

        print(f"Saved to {output_file}")
        return output_file

    except Exception as e:
        print(f"Error downloading xlam: {e}")
        return None


def convert_instruction_to_sharegpt(example: dict) -> Optional[dict]:
    """Convert instruction-tuning format to ShareGPT format."""
    # Handle different field names (various dataset formats)
    # Format 1: instruction/response
    # Format 2: user/assistant (Trendyol, Fenrir)
    # Format 3: prompt/output
    # Format 4: input/answer

    instruction = (
        example.get('user') or  # Trendyol, Fenrir format
        example.get('instruction') or
        example.get('prompt') or
        example.get('input') or
        example.get('question', '')
    )

    response = (
        example.get('assistant') or  # Trendyol, Fenrir format
        example.get('response') or
        example.get('output') or
        example.get('answer', '')
    )

    if not instruction or not response:
        return None

    # Skip very short responses
    if len(response) < 100:
        return None

    conversations = [
        {'from': 'human', 'value': instruction},
        {'from': 'gpt', 'value': response}
    ]

    return {
        'conversations': conversations,
        'has_tool_call': False,
        'source': 'security_knowledge'
    }


def download_trendyol_cyber(output_dir: Path, limit: int = 10000) -> Path:
    """Download Trendyol Cybersecurity Instruction Tuning dataset."""
    print(f"\n{'='*60}")
    print("Downloading Trendyol-Cybersecurity-Instruction-Tuning-Dataset...")
    print(f"{'='*60}")

    output_file = output_dir / 'trendyol_cyber_filtered.json'

    try:
        ds = load_dataset('Trendyol/Trendyol-Cybersecurity-Instruction-Tuning-Dataset', split='train')
        print(f"Loaded {len(ds)} examples from Trendyol cybersecurity dataset")

        converted = []
        for i, example in enumerate(ds):
            if i % 10000 == 0:
                print(f"Processing {i}/{len(ds)}...")

            result = convert_instruction_to_sharegpt(example)
            if result:
                result['source'] = 'trendyol_cyber'
                converted.append(result)

            if len(converted) >= limit * 1.2:
                break

        print(f"Converted {len(converted)} examples")

        unique = deduplicate(converted)
        print(f"After deduplication: {len(unique)} examples")

        final = unique[:limit]
        print(f"Final count: {len(final)} examples")

        with open(output_file, 'w') as f:
            json.dump(final, f, indent=2)

        print(f"Saved to {output_file}")
        return output_file

    except Exception as e:
        print(f"Error downloading Trendyol: {e}")
        return None


def download_fenrir(output_dir: Path, limit: int = 10000) -> Path:
    """Download Fenrir-v2.0 Cybersecurity dataset."""
    print(f"\n{'='*60}")
    print("Downloading Cybersecurity-Dataset-Fenrir-v2.0...")
    print(f"{'='*60}")

    output_file = output_dir / 'fenrir_filtered.json'

    try:
        ds = load_dataset('AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.0', split='train')
        print(f"Loaded {len(ds)} examples from Fenrir dataset")

        converted = []
        for i, example in enumerate(ds):
            if i % 10000 == 0:
                print(f"Processing {i}/{len(ds)}...")

            result = convert_instruction_to_sharegpt(example)
            if result:
                result['source'] = 'fenrir'
                converted.append(result)

            if len(converted) >= limit * 1.2:
                break

        print(f"Converted {len(converted)} examples")

        unique = deduplicate(converted)
        print(f"After deduplication: {len(unique)} examples")

        final = unique[:limit]
        print(f"Final count: {len(final)} examples")

        with open(output_file, 'w') as f:
            json.dump(final, f, indent=2)

        print(f"Saved to {output_file}")
        return output_file

    except Exception as e:
        print(f"Error downloading Fenrir: {e}")
        return None


def download_ir_playbooks(output_dir: Path) -> Path:
    """Download Incident Response Playbook dataset."""
    print(f"\n{'='*60}")
    print("Downloading Incident Response Playbook Dataset...")
    print(f"{'='*60}")

    output_file = output_dir / 'ir_playbooks.json'

    try:
        ds = load_dataset('darkknight25/Incident_Response_Playbook_Dataset', split='train')
        print(f"Loaded {len(ds)} examples from IR Playbook dataset")

        converted = []
        for example in ds:
            # Convert playbook to Q&A format
            playbook = example.get('playbook', {})
            if isinstance(playbook, str):
                try:
                    playbook = json.loads(playbook)
                except:
                    continue

            name = playbook.get('name', 'Incident Response')
            description = playbook.get('description', '')
            steps = playbook.get('steps', [])

            if not steps:
                continue

            # Create Q&A from playbook
            question = f"What is the incident response procedure for: {name}?"
            answer = f"**{name}**\n\n{description}\n\n**Steps:**\n"
            for i, step in enumerate(steps, 1):
                if isinstance(step, dict):
                    step_name = step.get('name', f'Step {i}')
                    step_desc = step.get('description', '')
                    answer += f"\n{i}. **{step_name}**: {step_desc}"
                else:
                    answer += f"\n{i}. {step}"

            converted.append({
                'conversations': [
                    {'from': 'human', 'value': question},
                    {'from': 'gpt', 'value': answer}
                ],
                'has_tool_call': False,
                'source': 'ir_playbooks'
            })

        print(f"Converted {len(converted)} playbooks")

        with open(output_file, 'w') as f:
            json.dump(converted, f, indent=2)

        print(f"Saved to {output_file}")
        return output_file

    except Exception as e:
        print(f"Error downloading IR Playbooks: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description='Download external datasets for training')
    parser.add_argument('--output-dir', type=str, default='v2/data/external',
                       help='Output directory for downloaded data')

    # Limits
    parser.add_argument('--glaive-limit', type=int, default=10000,
                       help='Maximum examples from glaive dataset')
    parser.add_argument('--xlam-limit', type=int, default=3000,
                       help='Maximum examples from xlam dataset')
    parser.add_argument('--trendyol-limit', type=int, default=10000,
                       help='Maximum examples from Trendyol cybersecurity dataset')
    parser.add_argument('--fenrir-limit', type=int, default=10000,
                       help='Maximum examples from Fenrir cybersecurity dataset')

    # Flags
    parser.add_argument('--all', action='store_true',
                       help='Download all datasets')
    parser.add_argument('--only-security', action='store_true',
                       help='Only download security knowledge datasets (skip tool calling)')
    parser.add_argument('--only-tools', action='store_true',
                       help='Only download tool calling datasets (skip security knowledge)')
    parser.add_argument('--skip-glaive', action='store_true',
                       help='Skip glaive dataset download')
    parser.add_argument('--skip-xlam', action='store_true',
                       help='Skip xlam dataset download')
    parser.add_argument('--skip-trendyol', action='store_true',
                       help='Skip Trendyol cybersecurity dataset')
    parser.add_argument('--skip-fenrir', action='store_true',
                       help='Skip Fenrir cybersecurity dataset')
    parser.add_argument('--skip-ir-playbooks', action='store_true',
                       help='Skip IR Playbooks dataset')

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = {}

    # Determine what to download
    download_tools = not args.only_security
    download_security = not args.only_tools

    # Tool calling datasets
    if download_tools:
        if not args.skip_glaive:
            glaive_file = download_glaive(output_dir, args.glaive_limit)
            if glaive_file:
                results['glaive'] = glaive_file

        if not args.skip_xlam:
            xlam_file = download_xlam(output_dir, args.xlam_limit)
            if xlam_file:
                results['xlam'] = xlam_file

    # Security knowledge datasets
    if download_security:
        if not args.skip_trendyol:
            trendyol_file = download_trendyol_cyber(output_dir, args.trendyol_limit)
            if trendyol_file:
                results['trendyol_cyber'] = trendyol_file

        if not args.skip_fenrir:
            fenrir_file = download_fenrir(output_dir, args.fenrir_limit)
            if fenrir_file:
                results['fenrir'] = fenrir_file

        if not args.skip_ir_playbooks:
            ir_file = download_ir_playbooks(output_dir)
            if ir_file:
                results['ir_playbooks'] = ir_file

    # Summary
    print(f"\n{'='*60}")
    print("Download Summary")
    print(f"{'='*60}")

    total = 0
    tool_count = 0
    security_count = 0

    for name, path in results.items():
        if path and path.exists():
            with open(path) as f:
                data = json.load(f)
            count = len(data)
            total += count

            if name in ['glaive', 'xlam']:
                tool_count += count
            else:
                security_count += count

            print(f"{name}: {count} examples -> {path}")

    print(f"\nTool calling examples: {tool_count}")
    print(f"Security knowledge examples: {security_count}")
    print(f"Total external examples: {total}")
    print(f"\nNext step: Run prepare_training_data.py to combine with FireWeave data")


if __name__ == '__main__':
    main()
