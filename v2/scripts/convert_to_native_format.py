#!/usr/bin/env python3
"""
Convert existing training data to Llama 3.1 native tool calling format.

Converts:
- V1 XML-style tool calls (<invoke> tags) to <|python_tag|> JSON format
- V1 ShareGPT data to include proper tool definitions
- Validates all JSON in tool calls

Usage:
    python v2/scripts/convert_to_native_format.py
    python v2/scripts/convert_to_native_format.py --input data/synthetic/ --output v2/data/converted/
"""

import json
import re
import argparse
from pathlib import Path
from typing import Optional, List, Dict, Any
import hashlib

# FireWeave tool definitions for tool-bearing examples
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
                    "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp"], "description": "Protocol"}
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
                    "include_evidence": {"type": "boolean", "description": "Generate evidence artifacts"}
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
                    "include_cloud": {"type": "boolean", "description": "Include cloud infrastructure"},
                    "max_hops": {"type": "integer", "description": "Maximum path length"}
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
                    "device_group": {"type": "string", "description": "Device group to analyze"},
                    "include_recommendations": {"type": "boolean", "description": "Include cleanup recommendations"}
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
                    "name": {"type": "string", "description": "Rule name"},
                    "source_zone": {"type": "string", "description": "Source security zone"},
                    "destination_zone": {"type": "string", "description": "Destination security zone"},
                    "source_address": {"type": "string", "description": "Source IP/object"},
                    "destination_address": {"type": "string", "description": "Destination IP/object"},
                    "service": {"type": "string", "description": "Service/port"},
                    "action": {"type": "string", "enum": ["allow", "deny"]},
                    "logging": {"type": "boolean", "description": "Enable logging"}
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
                    "device_group": {"type": "string", "description": "Device group to query"},
                    "rule_name": {"type": "string", "description": "Specific rule name (optional)"},
                    "days": {"type": "integer", "description": "Number of days to analyze"}
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
                    "asset": {"type": "string", "description": "Asset identifier (IP, hostname, or zone)"},
                    "include_lateral": {"type": "boolean", "description": "Include lateral movement paths"}
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
                    "project": {"type": "string", "description": "Jira project key"},
                    "status": {"type": "string", "description": "Issue status filter"},
                    "max_results": {"type": "integer", "description": "Maximum results to return"}
                },
                "required": ["project"]
            }
        }
    }
]


def extract_xml_tool_call(text: str) -> Optional[Dict[str, Any]]:
    """Extract tool call from XML-style <invoke> tags."""
    # Pattern for <invoke name="tool_name"><parameter name="x">value</parameter></invoke>
    invoke_pattern = r'<invoke\s+name=["\']([^"\']+)["\']>(.*?)</invoke>'
    param_pattern = r'<parameter\s+name=["\']([^"\']+)["\']>([^<]*)</parameter>'

    match = re.search(invoke_pattern, text, re.DOTALL)
    if not match:
        return None

    tool_name = match.group(1)
    params_text = match.group(2)

    # Extract parameters
    params = {}
    for param_match in re.finditer(param_pattern, params_text):
        param_name = param_match.group(1)
        param_value = param_match.group(2).strip()

        # Try to convert to appropriate type
        if param_value.lower() in ('true', 'false'):
            params[param_name] = param_value.lower() == 'true'
        elif param_value.isdigit():
            params[param_name] = int(param_value)
        else:
            try:
                params[param_name] = float(param_value)
            except ValueError:
                params[param_name] = param_value

    return {
        'name': tool_name,
        'parameters': params
    }


def extract_function_calls_tag(text: str) -> List[Dict[str, Any]]:
    """Extract tool calls from <function_calls> block."""
    # Pattern for <function_calls>...</function_calls>
    func_calls_pattern = r'<function_calls>(.*?)</function_calls>'
    match = re.search(func_calls_pattern, text, re.DOTALL)

    if not match:
        return []

    content = match.group(1)
    tool_calls = []

    # Find all <invoke> tags within
    invoke_pattern = r'<invoke\s+name=["\']([^"\']+)["\']>(.*?)</invoke>'
    param_pattern = r'<parameter\s+name=["\']([^"\']+)["\']>([^<]*)</parameter>'

    for invoke_match in re.finditer(invoke_pattern, content, re.DOTALL):
        tool_name = invoke_match.group(1)
        params_text = invoke_match.group(2)

        params = {}
        for param_match in re.finditer(param_pattern, params_text):
            param_name = param_match.group(1)
            param_value = param_match.group(2).strip()

            if param_value.lower() in ('true', 'false'):
                params[param_name] = param_value.lower() == 'true'
            elif param_value.isdigit():
                params[param_name] = int(param_value)
            else:
                try:
                    params[param_name] = float(param_value)
                except ValueError:
                    params[param_name] = param_value

        tool_calls.append({
            'name': tool_name,
            'parameters': params
        })

    return tool_calls


def has_tool_call(text: str) -> bool:
    """Check if text contains a tool call (XML or native format)."""
    return (
        '<invoke' in text or
        '<function_calls>' in text or
        '<|python_tag|>' in text
    )


def convert_to_native_format(value: str) -> str:
    """Convert XML tool calls in text to native Llama 3.1 format."""
    # Check for <function_calls> block first
    tool_calls = extract_function_calls_tag(value)
    if tool_calls:
        # Remove the <function_calls> block from text
        cleaned = re.sub(r'<function_calls>.*?</function_calls>', '', value, flags=re.DOTALL)
        cleaned = cleaned.strip()

        # Create native format
        if len(tool_calls) == 1:
            tool_json = json.dumps(tool_calls[0])
        else:
            tool_json = json.dumps(tool_calls)

        # Combine explanation with tool call
        if cleaned:
            return f"{cleaned}\n\n<|python_tag|>{tool_json}"
        else:
            return f"<|python_tag|>{tool_json}"

    # Check for single <invoke> tag
    tool_call = extract_xml_tool_call(value)
    if tool_call:
        # Remove the <invoke> block from text
        cleaned = re.sub(r'<invoke\s+name=["\'][^"\']+["\']>.*?</invoke>', '', value, flags=re.DOTALL)
        cleaned = cleaned.strip()

        tool_json = json.dumps(tool_call)

        if cleaned:
            return f"{cleaned}\n\n<|python_tag|>{tool_json}"
        else:
            return f"<|python_tag|>{tool_json}"

    return value


def convert_example(example: dict) -> Optional[dict]:
    """Convert a single example to native tool calling format."""
    conversations = example.get('conversations', [])
    if not conversations:
        return None

    converted_convs = []
    has_tool = False

    for turn in conversations:
        role = turn.get('from', '')
        value = turn.get('value', '')

        if role == 'human':
            converted_convs.append({'from': 'human', 'value': value})

        elif role == 'gpt':
            # Check if contains tool call
            if has_tool_call(value):
                has_tool = True
                if '<|python_tag|>' in value:
                    # Already native format
                    converted_convs.append({'from': 'gpt', 'value': value})
                else:
                    # Convert XML to native
                    native_value = convert_to_native_format(value)
                    converted_convs.append({'from': 'gpt', 'value': native_value})
            else:
                converted_convs.append({'from': 'gpt', 'value': value})

        elif role == 'tool' or role == 'observation':
            converted_convs.append({'from': 'tool', 'value': value})

        elif role == 'function_call':
            # Convert function_call role to gpt with native format
            has_tool = True
            try:
                func_data = json.loads(value) if isinstance(value, str) else value
                native_value = f"<|python_tag|>{json.dumps(func_data)}"
                converted_convs.append({'from': 'gpt', 'value': native_value})
            except:
                converted_convs.append({'from': 'gpt', 'value': value})

    if not converted_convs:
        return None

    result = {
        'conversations': converted_convs,
        'has_tool_call': has_tool,
        'source': example.get('source', 'v1')
    }

    # Add tools if this has tool calls
    if has_tool:
        result['tools'] = FIREWEAVE_TOOLS

    return result


def process_file(input_path: Path) -> List[dict]:
    """Process a single JSON file and convert to native format."""
    print(f"Processing {input_path.name}...")

    try:
        with open(input_path, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  Error parsing JSON: {e}")
        return []

    # Handle both list and single object formats
    if isinstance(data, dict):
        data = [data]

    converted = []
    tool_count = 0

    for example in data:
        result = convert_example(example)
        if result:
            converted.append(result)
            if result.get('has_tool_call'):
                tool_count += 1

    print(f"  Converted {len(converted)} examples ({tool_count} with tool calls)")
    return converted


def main():
    parser = argparse.ArgumentParser(description='Convert training data to native Llama 3.1 format')
    parser.add_argument('--input', type=str, default='data/synthetic',
                       help='Input directory with JSON files')
    parser.add_argument('--output', type=str, default='v2/data/converted',
                       help='Output directory for converted data')
    parser.add_argument('--v2-input', type=str, default='v2/data/synthetic',
                       help='V2 input directory (already native format)')
    parser.add_argument('--include-v2', action='store_true',
                       help='Also include V2 data in output')

    args = parser.parse_args()

    input_dir = Path(args.input)
    output_dir = Path(args.output)
    v2_input_dir = Path(args.v2_input)

    output_dir.mkdir(parents=True, exist_ok=True)

    all_converted = []

    # Process V1 data
    if input_dir.exists():
        print(f"\n{'='*60}")
        print(f"Converting V1 data from {input_dir}")
        print(f"{'='*60}")

        for json_file in sorted(input_dir.glob('*.json')):
            converted = process_file(json_file)
            all_converted.extend(converted)

    # Include V2 data if requested
    if args.include_v2 and v2_input_dir.exists():
        print(f"\n{'='*60}")
        print(f"Including V2 data from {v2_input_dir}")
        print(f"{'='*60}")

        for json_file in sorted(v2_input_dir.glob('*.json')):
            converted = process_file(json_file)
            all_converted.extend(converted)

    # Summary
    print(f"\n{'='*60}")
    print("Conversion Summary")
    print(f"{'='*60}")

    total = len(all_converted)
    with_tools = sum(1 for x in all_converted if x.get('has_tool_call'))
    without_tools = total - with_tools

    print(f"Total examples: {total}")
    print(f"  With tool calls: {with_tools} ({100*with_tools/total:.1f}%)")
    print(f"  Without tool calls: {without_tools} ({100*without_tools/total:.1f}%)")

    # Save combined output
    output_file = output_dir / 'v1_converted.json'
    with open(output_file, 'w') as f:
        json.dump(all_converted, f, indent=2)

    print(f"\nSaved to {output_file}")

    # Also save tool-only subset
    tool_only = [x for x in all_converted if x.get('has_tool_call')]
    tool_file = output_dir / 'v1_tool_calls_only.json'
    with open(tool_file, 'w') as f:
        json.dump(tool_only, f, indent=2)

    print(f"Tool-only subset saved to {tool_file} ({len(tool_only)} examples)")


if __name__ == '__main__':
    main()
