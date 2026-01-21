#!/usr/bin/env python3
"""
Generate High-Quality Tool Calling Training Data using Claude (Anthropic API)

OPTIMIZED VERSION - Faster generation with adaptive rate limiting

Usage:
    python generate_tool_data_claude.py --count 200
    python generate_tool_data_claude.py --category traffic_analysis --count 50
    python generate_tool_data_claude.py --all --count 300
    python generate_tool_data_claude.py --fast --count 200  # Faster, larger batches

Environment:
    ANTHROPIC_API_KEY: Your Anthropic API key
"""

import os
import json
import argparse
import hashlib
import time
import sys
from typing import List, Dict, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

try:
    import anthropic
except ImportError:
    print("Install anthropic: pip install anthropic")
    exit(1)

# =============================================================================
# FIREWEAVE TOOL DEFINITIONS
# =============================================================================

FIREWEAVE_TOOLS = {
    "check_traffic_flow": {
        "description": "Check if network traffic is allowed between source and destination through firewalls",
        "parameters": {
            "source_ip": "Source IP address or CIDR (e.g., '10.0.0.1', '10.0.0.0/24')",
            "destination_ip": "Destination IP address or CIDR",
            "port": "Destination port number (e.g., 443, 22, 3306)",
            "protocol": "Protocol: tcp, udp, or icmp (default: tcp)"
        },
        "required": ["source_ip", "destination_ip", "port"]
    },
    "analyze_attack_path": {
        "description": "Analyze potential attack paths from source to target for security assessment",
        "parameters": {
            "source": "Attack origin: 'internet', IP address, hostname, or zone name",
            "target": "Target asset: IP, hostname, zone, or asset group",
            "include_cloud": "Include AWS/Azure/GCP paths (default: true)"
        },
        "required": ["source", "target"]
    },
    "run_compliance_scan": {
        "description": "Run compliance scan against security frameworks (PCI-DSS, SOC2, NIST, HIPAA, ISO27001)",
        "parameters": {
            "framework": "Framework: pci-dss, soc2, nist-800-53, hipaa, iso27001, cis",
            "scope": "Scope: device group names (comma-separated) or 'all'",
            "include_evidence": "Generate evidence artifacts for auditors (default: false)"
        },
        "required": ["framework", "scope"]
    },
    "find_shadowed_rules": {
        "description": "Find firewall rules shadowed by more specific rules above them",
        "parameters": {
            "device_group": "Panorama device group to analyze",
            "include_recommendations": "Include safe removal recommendations (default: true)"
        },
        "required": ["device_group"]
    },
    "create_firewall_rule": {
        "description": "Generate a firewall rule configuration for deployment",
        "parameters": {
            "name": "Descriptive rule name",
            "source_zone": "Source security zone",
            "destination_zone": "Destination security zone",
            "source_address": "Source IP, CIDR, or address object",
            "destination_address": "Destination IP, CIDR, or address object",
            "service": "Service: 'tcp/443', 'application-default', 'any'",
            "action": "Action: allow, deny, or drop",
            "logging": "Enable logging (default: true)"
        },
        "required": ["name", "source_zone", "destination_zone", "source_address", "destination_address", "service", "action"]
    },
    "submit_change_request": {
        "description": "Create ServiceNow change request for firewall changes",
        "parameters": {
            "description": "Change description",
            "justification": "Business justification",
            "rules": "Array of rule configurations",
            "schedule": "Schedule: 'immediate', 'next-maintenance-window', or datetime"
        },
        "required": ["description", "justification", "rules"]
    },
    "calculate_blast_radius": {
        "description": "Calculate assets reachable if an asset is compromised",
        "parameters": {
            "asset": "Potentially compromised asset (IP, hostname, or zone)",
            "include_lateral": "Include lateral movement paths (default: true)"
        },
        "required": ["asset"]
    },
    "get_topology": {
        "description": "Query network topology across platforms",
        "parameters": {
            "platform": "Platform: aws, azure, gcp, panorama, or all",
            "region": "Optional region filter for cloud platforms"
        },
        "required": ["platform"]
    }
}

# =============================================================================
# SCENARIO CATEGORIES
# =============================================================================

SCENARIO_CATEGORIES = {
    "traffic_analysis": {
        "description": "Traffic flow verification and troubleshooting scenarios",
        "examples": [
            "Check if web servers can reach the database",
            "Verify API gateway connectivity to microservices",
            "Test if monitoring can reach all production hosts",
            "Check DMZ to internal network access",
            "Verify backup server connectivity"
        ]
    },
    "compliance": {
        "description": "Compliance scanning and audit preparation",
        "examples": [
            "Run PCI-DSS scan before quarterly audit",
            "Check SOC2 compliance for customer data zones",
            "HIPAA compliance verification for healthcare systems",
            "NIST 800-53 assessment for federal contract",
            "ISO 27001 evidence collection"
        ]
    },
    "attack_surface": {
        "description": "Attack path analysis and blast radius calculations",
        "examples": [
            "What can an attacker reach from the internet?",
            "Calculate blast radius if web server is compromised",
            "Analyze lateral movement from DMZ",
            "Find attack paths to database servers",
            "Assess risk if VPN endpoint is breached"
        ]
    },
    "rule_optimization": {
        "description": "Policy cleanup and optimization",
        "examples": [
            "Find shadowed rules in production firewall",
            "Identify unused rules for cleanup",
            "Find overly permissive any-any rules",
            "Detect rules without logging enabled",
            "Find duplicate address objects"
        ]
    },
    "change_management": {
        "description": "Rule creation and ServiceNow integration",
        "examples": [
            "Create rule for new application deployment",
            "Submit change request for database migration",
            "Add temporary rule for vendor access",
            "Create rules for cloud workload connectivity",
            "Emergency rule for incident response"
        ]
    },
    "multi_cloud": {
        "description": "Multi-cloud topology and security",
        "examples": [
            "Get AWS VPC topology for security review",
            "Check Azure to on-prem connectivity",
            "Verify GCP firewall rules match policy",
            "Cross-cloud traffic flow verification",
            "Cloud security posture assessment"
        ]
    }
}

# =============================================================================
# GENERATION PROMPTS
# =============================================================================

SYSTEM_PROMPT = """You are an expert at generating realistic training data for an AI assistant that helps with enterprise firewall management.

The assistant has access to these FireWeave platform tools:
{tools_description}

Generate realistic user queries and the appropriate tool calls the assistant should make.

IMPORTANT FORMATTING RULES:
1. User queries should be natural language, like a network engineer would ask
2. Tool calls must be valid JSON with "name" and "parameters" fields
3. Tool responses should be realistic data that FireWeave would return
4. The assistant's final response should interpret the results helpfully
5. Include chain-of-thought reasoning when appropriate

Output Format (JSON):
{{
    "conversations": [
        {{"from": "human", "value": "<user question>"}},
        {{"from": "gpt", "value": "<|python_tag|>{{\\"name\\": \\"tool_name\\", \\"parameters\\": {{...}}}}"}},
        {{"from": "tool", "value": "<tool response JSON>"}},
        {{"from": "gpt", "value": "<final response interpreting results>"}}
    ],
    "category": "<category_name>",
    "tools_used": ["tool1", "tool2"]
}}"""

CATEGORY_PROMPT = """Generate {count} unique, high-quality training examples for the "{category}" category.

Category Description: {description}

Example scenarios to inspire you (but create different ones):
{examples}

Requirements:
1. Each example must be UNIQUE - different IPs, ports, scenarios
2. Use realistic enterprise network scenarios
3. Include technical details (specific IPs, ports, zones)
4. Vary complexity: some simple queries, some multi-step
5. Include relevant compliance/security context where appropriate
6. Tool parameters must match the schema exactly

Generate {count} examples as a JSON array. Each example should follow this structure:
{{
    "conversations": [...],
    "category": "{category}",
    "tools_used": [...]
}}

Return ONLY valid JSON array, no other text."""

MULTI_STEP_PROMPT = """Generate {count} MULTI-STEP workflow examples where the user's request requires calling multiple tools in sequence.

Example multi-step scenarios:
1. "Check if traffic is allowed, and if not, create a rule and submit change request"
2. "Run compliance scan, then analyze attack paths for any failing controls"
3. "Find shadowed rules, calculate their blast radius, then create cleanup request"
4. "Verify connectivity, analyze security implications, submit change for approval"

Requirements:
1. Must use 2-4 different tools in sequence
2. Each tool call should depend on or relate to previous results
3. Include realistic reasoning between tool calls
4. Final response should summarize the entire workflow
5. Use realistic enterprise scenarios

Format each example as:
{{
    "conversations": [
        {{"from": "human", "value": "<complex request>"}},
        {{"from": "gpt", "value": "Let me help with that. First, I'll check... <|python_tag|>{{...}}"}},
        {{"from": "tool", "value": "<result 1>"}},
        {{"from": "gpt", "value": "Based on those results, now I'll... <|python_tag|>{{...}}"}},
        {{"from": "tool", "value": "<result 2>"}},
        {{"from": "gpt", "value": "<final comprehensive response>"}}
    ],
    "category": "workflow",
    "tools_used": ["tool1", "tool2", ...]
}}

Generate {count} unique multi-step examples as a JSON array."""


class ClaudeToolDataGenerator:
    """Generate tool calling training data using Claude - OPTIMIZED."""

    def __init__(self, api_key: str = None, fast_mode: bool = False):
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable required")

        self.client = anthropic.Anthropic(api_key=self.api_key)
        self.seen_hashes = set()
        self.fast_mode = fast_mode

        # Adaptive rate limiting
        self.min_delay = 0.3 if fast_mode else 0.5  # Minimum delay between calls
        self.current_delay = self.min_delay
        self.max_delay = 10.0
        self.consecutive_successes = 0
        self.batch_size = 10 if fast_mode else 5  # Larger batches = fewer API calls

    def _get_tools_description(self) -> str:
        """Format tools for the system prompt."""
        lines = []
        for name, spec in FIREWEAVE_TOOLS.items():
            lines.append(f"\n{name}: {spec['description']}")
            lines.append("  Parameters:")
            for param, desc in spec['parameters'].items():
                required = "(required)" if param in spec['required'] else "(optional)"
                lines.append(f"    - {param} {required}: {desc}")
        return "\n".join(lines)

    def _hash_example(self, example: Dict) -> str:
        """Generate hash for deduplication."""
        content = json.dumps(example.get("conversations", []), sort_keys=True)
        return hashlib.md5(content.encode()).hexdigest()[:12]

    def _is_duplicate(self, example: Dict) -> bool:
        """Check if example is duplicate."""
        h = self._hash_example(example)
        if h in self.seen_hashes:
            return True
        self.seen_hashes.add(h)
        return False

    def _adaptive_delay(self, success: bool):
        """Adjust delay based on success/failure."""
        if success:
            self.consecutive_successes += 1
            # Speed up after 3 consecutive successes
            if self.consecutive_successes >= 3:
                self.current_delay = max(self.min_delay, self.current_delay * 0.8)
        else:
            self.consecutive_successes = 0
            # Back off on failure
            self.current_delay = min(self.max_delay, self.current_delay * 2)

        time.sleep(self.current_delay)

    def _call_claude(self, prompt: str, max_tokens: int = 8192) -> str:
        """Call Claude API with retry logic."""
        system = SYSTEM_PROMPT.format(tools_description=self._get_tools_description())

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=max_tokens,
                    system=system,
                    messages=[{"role": "user", "content": prompt}]
                )
                self._adaptive_delay(True)
                return response.content[0].text
            except anthropic.RateLimitError:
                self._adaptive_delay(False)
                if attempt < max_retries - 1:
                    print(f"  Rate limited, waiting {self.current_delay:.1f}s...")
                    continue
                raise
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                raise

        return ""

    def _parse_response(self, response: str) -> List[Dict]:
        """Parse Claude's response into examples with robust error recovery."""
        response = response.strip()

        # Handle markdown code blocks
        if "```json" in response:
            start = response.find("```json") + 7
            end = response.find("```", start)
            if end != -1:
                response = response[start:end].strip()
            else:
                response = response[start:].strip()
        elif "```" in response:
            start = response.find("```") + 3
            end = response.find("```", start)
            if end != -1:
                response = response[start:end].strip()
            else:
                response = response[start:].strip()

        # Try to find JSON array
        if not response.startswith("["):
            idx = response.find("[")
            if idx != -1:
                response = response[idx:]

        # First attempt: direct parse
        try:
            examples = json.loads(response)
            if isinstance(examples, dict):
                examples = [examples]
            return examples
        except json.JSONDecodeError:
            pass

        # Second attempt: find proper array end
        if not response.endswith("]"):
            idx = response.rfind("]")
            if idx != -1:
                try:
                    examples = json.loads(response[:idx+1])
                    if isinstance(examples, dict):
                        examples = [examples]
                    return examples
                except json.JSONDecodeError:
                    pass

        # Third attempt: extract individual objects from truncated array
        examples = self._extract_objects_from_truncated(response)
        if examples:
            return examples

        # Fourth attempt: fix common JSON issues
        fixed = self._fix_common_json_issues(response)
        try:
            examples = json.loads(fixed)
            if isinstance(examples, dict):
                examples = [examples]
            return examples
        except json.JSONDecodeError as e:
            print(f"  JSON parse error: {e}")
            return []

    def _extract_objects_from_truncated(self, response: str) -> List[Dict]:
        """Extract complete JSON objects from a potentially truncated array."""
        examples = []

        # Find all complete objects by tracking brace depth
        depth = 0
        start = -1
        in_string = False
        escape_next = False

        for i, char in enumerate(response):
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not escape_next:
                in_string = not in_string
                continue
            if in_string:
                continue

            if char == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif char == '}':
                depth -= 1
                if depth == 0 and start != -1:
                    obj_str = response[start:i+1]
                    try:
                        obj = json.loads(obj_str)
                        if isinstance(obj, dict) and "conversations" in obj:
                            examples.append(obj)
                    except json.JSONDecodeError:
                        pass
                    start = -1

        return examples

    def _fix_common_json_issues(self, response: str) -> str:
        """Fix common JSON formatting issues."""
        import re

        # Remove trailing commas before ] or }
        response = re.sub(r',\s*([}\]])', r'\1', response)

        # Ensure array is properly closed
        open_brackets = response.count('[') - response.count(']')
        open_braces = response.count('{') - response.count('}')

        # Close any open braces first, then brackets
        response = response.rstrip()
        if response.endswith(','):
            response = response[:-1]

        response += '}' * max(0, open_braces)
        response += ']' * max(0, open_brackets)

        return response

    def generate_category_examples(self, category: str, count: int = 20) -> List[Dict]:
        """Generate examples for a specific category - OPTIMIZED."""
        if category not in SCENARIO_CATEGORIES:
            raise ValueError(f"Unknown category: {category}")

        cat_info = SCENARIO_CATEGORIES[category]
        examples = []

        print(f"\n[{category.upper()}] Generating {count} examples...", flush=True)

        batch_num = 0
        while len(examples) < count:
            remaining = min(self.batch_size, count - len(examples))
            if remaining <= 0:
                break

            prompt = CATEGORY_PROMPT.format(
                count=remaining,
                category=category,
                description=cat_info["description"],
                examples="\n".join(f"- {ex}" for ex in cat_info["examples"])
            )

            try:
                response = self._call_claude(prompt, max_tokens=12000)
                batch_examples = self._parse_response(response)

                added = 0
                for ex in batch_examples:
                    if not self._is_duplicate(ex):
                        ex["category"] = category
                        examples.append(ex)
                        added += 1

                batch_num += 1
                print(f"  Batch {batch_num}: +{added} examples (total: {len(examples)})", flush=True)

            except anthropic.RateLimitError as e:
                print(f"  Rate limited, backing off...", flush=True)
                time.sleep(self.current_delay)
            except Exception as e:
                print(f"  Error: {str(e)[:50]}", flush=True)
                time.sleep(2)

        return examples[:count]

    def generate_multi_step_workflows(self, count: int = 30) -> List[Dict]:
        """Generate multi-step workflow examples - OPTIMIZED."""
        examples = []
        workflow_batch_size = 6 if self.fast_mode else 4

        print(f"\n[MULTI-STEP WORKFLOWS] Generating {count} examples...", flush=True)

        batch_num = 0
        while len(examples) < count:
            remaining = min(workflow_batch_size, count - len(examples))
            if remaining <= 0:
                break

            prompt = MULTI_STEP_PROMPT.format(count=remaining)

            try:
                response = self._call_claude(prompt, max_tokens=12000)
                batch_examples = self._parse_response(response)

                added = 0
                for ex in batch_examples:
                    if not self._is_duplicate(ex):
                        ex["category"] = "workflow"
                        examples.append(ex)
                        added += 1

                batch_num += 1
                print(f"  Batch {batch_num}: +{added} workflows (total: {len(examples)})", flush=True)

            except anthropic.RateLimitError:
                print(f"  Rate limited, backing off...", flush=True)
                time.sleep(self.current_delay)
            except Exception as e:
                print(f"  Error: {str(e)[:50]}", flush=True)
                time.sleep(2)

        return examples[:count]

    def generate_all(self, total_count: int = 200, output_path: str = None) -> List[Dict]:
        """Generate examples across all categories - OPTIMIZED with incremental saving."""
        all_examples = []

        # Distribute count across categories
        categories = list(SCENARIO_CATEGORIES.keys())
        per_category = total_count // (len(categories) + 1)  # +1 for workflows
        workflow_count = total_count - (per_category * len(categories))

        print(f"Generating {per_category} examples per category + {workflow_count} workflows")
        print(f"Batch size: {self.batch_size}, Fast mode: {self.fast_mode}\n")

        # Generate category examples
        for category in categories:
            examples = self.generate_category_examples(category, per_category)
            all_examples.extend(examples)
            print(f"  -> {category}: {len(examples)} examples", flush=True)

            # Incremental save after each category
            if output_path and all_examples:
                self._save_incremental(all_examples, output_path)

        # Generate multi-step workflows
        workflows = self.generate_multi_step_workflows(workflow_count)
        all_examples.extend(workflows)

        # Final incremental save
        if output_path and all_examples:
            self._save_incremental(all_examples, output_path)

        return all_examples

    def _save_incremental(self, examples: List[Dict], output_path: str):
        """Save examples incrementally to avoid data loss."""
        try:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(examples, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"  Warning: Could not save incremental: {e}", flush=True)


def main():
    parser = argparse.ArgumentParser(description="Generate tool calling data with Claude")
    parser.add_argument("--count", type=int, default=200, help="Total examples to generate")
    parser.add_argument("--category", type=str, help="Specific category to generate")
    parser.add_argument("--all", action="store_true", help="Generate across all categories")
    parser.add_argument("--output", type=str, default="v2/data/synthetic/hq_tool_calling_claude.json")
    parser.add_argument("--workflows-only", action="store_true", help="Generate only multi-step workflows")
    parser.add_argument("--fast", action="store_true", help="Fast mode: larger batches, shorter delays")
    args = parser.parse_args()

    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("HIGH-QUALITY TOOL CALLING DATA GENERATION (Claude)")
    print("=" * 60)
    sys.stdout.flush()

    generator = ClaudeToolDataGenerator(fast_mode=args.fast)
    examples = []

    start_time = time.time()

    if args.workflows_only:
        examples = generator.generate_multi_step_workflows(args.count)
    elif args.category:
        examples = generator.generate_category_examples(args.category, args.count)
    else:
        examples = generator.generate_all(args.count, output_path=str(output_path))

    elapsed = time.time() - start_time

    # Save results
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(examples, f, indent=2, ensure_ascii=False)

    print("\n" + "=" * 60)
    print(f"COMPLETE: {len(examples)} high-quality examples")
    print(f"Saved to: {output_path}")
    print(f"Time: {elapsed:.1f}s ({len(examples)/max(elapsed,1)*60:.1f} examples/min)")
    print("=" * 60)

    # Statistics
    categories = {}
    workflow_count = 0
    for ex in examples:
        cat = ex.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
        if cat == "workflow":
            workflow_count += 1

    print("\nBy category:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")

    print(f"\nMulti-step workflows: {workflow_count}")
    sys.stdout.flush()


if __name__ == "__main__":
    main()
