#!/usr/bin/env python3
"""
High-Quality Tool Calling Data Generator for v2

Generates premium quality training data using GPT-4o with:
- Realistic enterprise scenarios
- Detailed reasoning before tool calls
- Proper tool response handling
- Multi-step workflows
"""

import os
import sys
import json
import time
import random
from pathlib import Path
from typing import List, Dict
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# FIREWEAVE TOOLS DEFINITION
# =============================================================================

FIREWEAVE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "check_traffic_flow",
            "description": "Check if traffic is allowed between source and destination IP addresses through the firewall",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {"type": "string", "description": "Source IP or CIDR"},
                    "destination_ip": {"type": "string", "description": "Destination IP or CIDR"},
                    "port": {"type": "integer", "description": "Destination port"},
                    "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp"]}
                },
                "required": ["source_ip", "destination_ip", "port"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_attack_path",
            "description": "Analyze potential attack paths from source to target asset",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {"type": "string", "description": "Starting point (IP, zone, or 'internet')"},
                    "target": {"type": "string", "description": "Target asset or zone"},
                    "include_cloud": {"type": "boolean", "description": "Include cloud infrastructure"}
                },
                "required": ["source", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_compliance_scan",
            "description": "Run compliance scan against a security framework",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {"type": "string", "enum": ["pci-dss", "soc2", "nist-800-53", "hipaa", "iso27001", "cis"]},
                    "scope": {"type": "string", "description": "Device groups to scan or 'all'"},
                    "include_evidence": {"type": "boolean", "description": "Generate audit evidence"}
                },
                "required": ["framework", "scope"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_shadowed_rules",
            "description": "Find firewall rules shadowed by more specific rules above them",
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
            "description": "Generate firewall rule configuration for deployment",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "source_zone": {"type": "string"},
                    "destination_zone": {"type": "string"},
                    "source_address": {"type": "string"},
                    "destination_address": {"type": "string"},
                    "service": {"type": "string"},
                    "action": {"type": "string", "enum": ["allow", "deny", "drop"]},
                    "logging": {"type": "boolean"}
                },
                "required": ["name", "source_zone", "destination_zone", "source_address", "destination_address", "service", "action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_change_request",
            "description": "Create ServiceNow change request for firewall changes",
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {"type": "string"},
                    "justification": {"type": "string"},
                    "rules": {"type": "array", "items": {"type": "object"}},
                    "schedule": {"type": "string"}
                },
                "required": ["description", "justification", "rules"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_blast_radius",
            "description": "Calculate what assets an attacker could reach if asset is compromised",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset": {"type": "string", "description": "Asset to analyze"},
                    "include_lateral": {"type": "boolean", "description": "Include lateral movement"}
                },
                "required": ["asset"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_topology",
            "description": "Query network topology across platforms",
            "parameters": {
                "type": "object",
                "properties": {
                    "platform": {"type": "string", "enum": ["aws", "azure", "gcp", "panorama", "all"]},
                    "region": {"type": "string"}
                },
                "required": ["platform"]
            }
        }
    }
]

# =============================================================================
# HIGH-QUALITY SCENARIO CATEGORIES
# =============================================================================

HQ_SCENARIOS = {
    "traffic_analysis": [
        "A security engineer needs to verify if the new application server can reach the production database",
        "The SOC team detected suspicious traffic and wants to verify if it should be allowed",
        "During a PCI audit, the auditor asks to demonstrate traffic segmentation between CDE and corporate network",
        "A developer reports their microservice can't reach an external API and needs help troubleshooting",
        "The network team wants to verify if the backup server can reach the DR site over the VPN",
        "After a firewall migration, verify critical business flows are still working",
        "Check if the new IoT devices on the OT network can reach the cloud management platform",
        "Verify that the guest WiFi network is properly isolated from internal resources",
    ],
    "compliance": [
        "Prepare for the upcoming PCI-DSS audit by scanning all cardholder data environment rules",
        "The CISO wants a SOC2 compliance report for the board meeting",
        "Healthcare organization needs to verify HIPAA compliance for their patient data systems",
        "Government contractor needs NIST 800-53 compliance verification for FedRAMP",
        "Run CIS benchmark scan before the quarterly security review",
        "Generate compliance evidence for the ISO 27001 recertification audit",
        "Check if recent firewall changes impacted our PCI compliance status",
        "Verify compliance across all cloud environments before the external audit",
    ],
    "attack_surface": [
        "Analyze what an attacker could reach if they compromised our public-facing web server",
        "The red team found a vulnerability - calculate the blast radius before patching",
        "Map all attack paths from the internet to our database tier",
        "After a phishing incident, analyze what the attacker could have accessed from the compromised workstation",
        "Identify attack paths that cross multiple cloud environments",
        "Calculate blast radius for our most critical asset before implementing micro-segmentation",
        "Analyze lateral movement possibilities from the DMZ to internal networks",
        "Map attack paths that could lead to our Active Directory servers",
    ],
    "rule_optimization": [
        "The firewall is slow - find and remove shadowed rules to improve performance",
        "Before the audit, clean up unused rules in the production device group",
        "Identify rules that can be consolidated to reduce policy complexity",
        "Find rules that haven't been hit in 90 days and may be candidates for removal",
        "Analyze the legacy rules from the acquired company's firewall for optimization",
        "Check for overly permissive rules that violate least privilege",
        "Find duplicate address objects that can be consolidated",
        "Identify rules with 'any' in source or destination that should be tightened",
    ],
    "change_management": [
        "Create a change request for the new application deployment requiring database access",
        "Submit an emergency change for the security patch deployment",
        "Generate a change request for the network segmentation project",
        "Create a scheduled change for the weekend maintenance window",
        "Submit a change request for decommissioning legacy application firewall rules",
        "Create a change for the new VPN tunnel to the partner network",
        "Submit a standard change for adding a new web server to the load balancer pool",
        "Generate a change request for the cloud migration firewall rules",
    ],
    "multi_cloud": [
        "Show me the complete network topology across AWS, Azure, and our on-prem Panorama",
        "Verify security group configurations in our AWS production VPCs",
        "Check Azure NSG rules for the new Kubernetes cluster",
        "Map the connectivity between our GCP project and on-prem data center",
        "Analyze cross-cloud traffic flows for the hybrid application",
        "Verify Transit Gateway routing is correct after the AWS infrastructure changes",
        "Check if the Azure ExpressRoute has proper firewall rules configured",
        "Review the security posture across all three cloud providers",
    ]
}

# =============================================================================
# GPT-4O GENERATION
# =============================================================================

def generate_hq_examples(count_per_category: int = 30) -> List[dict]:
    """Generate high-quality examples using GPT-4o."""

    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    all_examples = []

    for category, scenarios in HQ_SCENARIOS.items():
        print(f"\n[{category.upper()}] Generating {count_per_category} examples...")

        for i in range(0, count_per_category, 5):
            batch_size = min(5, count_per_category - i)
            selected_scenarios = random.sample(scenarios, min(batch_size, len(scenarios)))

            prompt = f"""Generate {batch_size} HIGH-QUALITY training examples for an AI assistant that helps with network security using FireWeave platform.

Category: {category}
Scenarios to cover:
{chr(10).join(f"- {s}" for s in selected_scenarios)}

Available FireWeave tools:
{json.dumps([t["function"]["name"] + ": " + t["function"]["description"] for t in FIREWEAVE_TOOLS], indent=2)}

REQUIREMENTS FOR HIGH QUALITY:
1. User questions should be realistic - what a senior security engineer at a Fortune 500 would ask
2. Before calling a tool, the assistant should briefly explain WHY it's using that tool
3. After receiving tool results, provide DETAILED analysis and recommendations
4. Reference compliance frameworks (PCI-DSS, SOC2, NIST) where relevant
5. Include security best practices and risk considerations
6. For complex requests, use multiple tool calls in sequence
7. Answers should be 200-500 words with proper formatting (markdown)

Output as JSON array with this EXACT format:
[
  {{
    "conversations": [
      {{"from": "human", "value": "User's realistic question"}},
      {{"from": "gpt", "value": "<|python_tag|>{{\\\"name\\\": \\\"tool_name\\\", \\\"parameters\\\": {{...}}}}"}},
      {{"from": "tool", "value": "{{\\\"result\\\": ...}}"}},
      {{"from": "gpt", "value": "Detailed response explaining results with recommendations"}}
    ],
    "tools": ["tool_name"],
    "category": "{category}"
  }}
]

IMPORTANT:
- The tool call MUST start with <|python_tag|>
- Tool response must be valid JSON
- Final response should be detailed and actionable
- Include compliance/security context"""

            try:
                response = client.chat.completions.create(
                    model="gpt-4o",
                    messages=[
                        {"role": "system", "content": "You are an expert at creating high-quality training data for AI assistants. Generate realistic, detailed examples."},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.8,
                    max_tokens=8000
                )

                content = response.choices[0].message.content

                # Parse JSON
                start_idx = content.find('[')
                end_idx = content.rfind(']') + 1

                if start_idx != -1 and end_idx > 0:
                    examples = json.loads(content[start_idx:end_idx])

                    # Validate and fix format
                    for ex in examples:
                        ex['has_tool_call'] = True
                        ex['category'] = category

                        # Ensure tools list exists
                        if 'tools' not in ex:
                            ex['tools'] = []
                            for conv in ex.get('conversations', []):
                                if conv.get('from') == 'gpt' and '<|python_tag|>' in conv.get('value', ''):
                                    try:
                                        tool_json = conv['value'].replace('<|python_tag|>', '')
                                        tool_data = json.loads(tool_json)
                                        if tool_data.get('name'):
                                            ex['tools'].append(tool_data['name'])
                                    except:
                                        pass

                        all_examples.append(ex)

                    print(f"  Batch {i//5 + 1}: +{len(examples)} examples")

            except Exception as e:
                print(f"  Error in batch: {e}")

            # Rate limit
            time.sleep(3)

    return all_examples


def generate_multi_step_workflows(count: int = 50) -> List[dict]:
    """Generate complex multi-step workflow examples."""

    from openai import OpenAI
    client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

    workflows = [
        "User wants to add a new application that needs database access - check current access, create rule, submit change request",
        "Investigate a security alert - check if traffic should be allowed, analyze blast radius if compromised, recommend actions",
        "Prepare for PCI audit - run compliance scan, identify issues, check attack paths to CDE, generate remediation plan",
        "Onboard new cloud environment - get topology, check compliance, identify attack paths, recommend security improvements",
        "Respond to vulnerability disclosure - calculate blast radius, check traffic flows, create emergency change request",
        "Optimize firewall performance - find shadowed rules, identify unused rules, create cleanup change request",
        "Implement network segmentation - analyze current attack paths, create new rules, verify compliance improvement",
        "Decommission legacy application - find all related rules, verify no active traffic, submit removal change request",
    ]

    all_examples = []

    print(f"\n[MULTI-STEP WORKFLOWS] Generating {count} examples...")

    for i in range(0, count, 4):
        batch_size = min(4, count - i)
        selected = random.sample(workflows, min(batch_size, len(workflows)))

        prompt = f"""Generate {batch_size} MULTI-STEP workflow examples where the AI assistant uses multiple FireWeave tools in sequence to complete a complex task.

Workflows to implement:
{chr(10).join(f"- {w}" for w in selected)}

Available tools: check_traffic_flow, analyze_attack_path, run_compliance_scan, find_shadowed_rules, create_firewall_rule, submit_change_request, calculate_blast_radius, get_topology

REQUIREMENTS:
1. Each workflow should use 2-4 different tools
2. The assistant should explain reasoning between each tool call
3. Build on previous tool results to inform next steps
4. Provide comprehensive final summary with all findings
5. Include compliance and security context throughout

Output as JSON array:
[
  {{
    "conversations": [
      {{"from": "human", "value": "Complex user request"}},
      {{"from": "gpt", "value": "Let me help with that. First, I'll check... <|python_tag|>{{...}}"}},
      {{"from": "tool", "value": "{{...}}"}},
      {{"from": "gpt", "value": "Based on those results, now I'll... <|python_tag|>{{...}}"}},
      {{"from": "tool", "value": "{{...}}"}},
      {{"from": "gpt", "value": "Comprehensive summary and recommendations..."}}
    ],
    "tools": ["tool1", "tool2", "tool3"],
    "workflow": "description",
    "multi_step": true
  }}
]"""

        try:
            response = client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an expert at creating training data for AI assistants. Generate complex, realistic multi-step workflows."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.8,
                max_tokens=10000
            )

            content = response.choices[0].message.content
            start_idx = content.find('[')
            end_idx = content.rfind(']') + 1

            if start_idx != -1 and end_idx > 0:
                examples = json.loads(content[start_idx:end_idx])
                for ex in examples:
                    ex['has_tool_call'] = True
                    ex['multi_step'] = True
                    all_examples.append(ex)
                print(f"  Batch {i//4 + 1}: +{len(examples)} workflows")

        except Exception as e:
            print(f"  Error: {e}")

        time.sleep(3)

    return all_examples


def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--examples-per-category", type=int, default=30)
    parser.add_argument("--multi-step-count", type=int, default=50)
    parser.add_argument("--output", type=str, default="v2/data/synthetic/hq_tool_calling.json")
    args = parser.parse_args()

    print("="*60)
    print("HIGH-QUALITY TOOL CALLING DATA GENERATION")
    print("="*60)

    # Generate category-based examples
    category_examples = generate_hq_examples(args.examples_per_category)
    print(f"\nGenerated {len(category_examples)} category examples")

    # Generate multi-step workflows
    workflow_examples = generate_multi_step_workflows(args.multi_step_count)
    print(f"Generated {len(workflow_examples)} workflow examples")

    # Combine
    all_examples = category_examples + workflow_examples

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(all_examples, f, indent=2, ensure_ascii=False)

    print(f"\n{'='*60}")
    print(f"COMPLETE: {len(all_examples)} high-quality examples")
    print(f"Saved to: {output_path}")
    print(f"{'='*60}")

    # Stats
    categories = {}
    multi_step = 0
    for ex in all_examples:
        cat = ex.get('category', 'workflow')
        categories[cat] = categories.get(cat, 0) + 1
        if ex.get('multi_step'):
            multi_step += 1

    print("\nBy category:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count}")
    print(f"\nMulti-step workflows: {multi_step}")


if __name__ == "__main__":
    main()
