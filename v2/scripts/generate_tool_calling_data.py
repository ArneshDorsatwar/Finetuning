#!/usr/bin/env python3
"""
Network Security Expert v2 - Tool Calling Training Data Generator

Generates training data in Llama 3.1's NATIVE tool calling format:
- <|python_tag|> for function calls
- Tool response handling
- Multi-turn tool conversations

This enables the fine-tuned model to retain native tool calling capabilities.
"""

import os
import sys
import json
import argparse
import time
import random
from pathlib import Path
from typing import Dict, List, Optional, Any
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# FIREWEAVE TOOL DEFINITIONS (Llama 3.1 Format)
# =============================================================================

FIREWEAVE_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "check_traffic_flow",
            "description": "Check if traffic is allowed between source and destination IP addresses through the firewall. Returns whether traffic is allowed or blocked and which rule matches.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "description": "Source IP address or CIDR (e.g., '10.0.0.1' or '10.0.0.0/24')"
                    },
                    "destination_ip": {
                        "type": "string",
                        "description": "Destination IP address or CIDR"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Destination port number"
                    },
                    "protocol": {
                        "type": "string",
                        "enum": ["tcp", "udp", "icmp"],
                        "description": "Protocol (default: tcp)"
                    }
                },
                "required": ["source_ip", "destination_ip", "port"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_attack_path",
            "description": "Analyze potential attack paths from a source to a target asset. Returns attack paths with risk scores and recommended mitigations.",
            "parameters": {
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Starting point - can be 'internet', an IP, or zone name"
                    },
                    "target": {
                        "type": "string",
                        "description": "Target asset - IP address, hostname, or zone"
                    },
                    "include_cloud": {
                        "type": "boolean",
                        "description": "Include AWS/Azure/GCP paths in analysis"
                    }
                },
                "required": ["source", "target"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_compliance_scan",
            "description": "Run a compliance scan against a security framework. Returns findings, violations, and remediation guidance.",
            "parameters": {
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "enum": ["pci-dss", "soc2", "nist-800-53", "hipaa", "iso27001", "cis"],
                        "description": "Compliance framework to scan against"
                    },
                    "scope": {
                        "type": "string",
                        "description": "Device groups to scan (comma-separated) or 'all'"
                    },
                    "include_evidence": {
                        "type": "boolean",
                        "description": "Generate evidence artifacts for audit"
                    }
                },
                "required": ["framework", "scope"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "find_shadowed_rules",
            "description": "Find firewall rules that are shadowed (never matched) by more specific rules above them.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_group": {
                        "type": "string",
                        "description": "Device group to analyze"
                    },
                    "include_recommendations": {
                        "type": "boolean",
                        "description": "Include cleanup recommendations"
                    }
                },
                "required": ["device_group"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_firewall_rule",
            "description": "Generate a firewall rule configuration for deployment.",
            "parameters": {
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Rule name"
                    },
                    "source_zone": {
                        "type": "string",
                        "description": "Source security zone"
                    },
                    "destination_zone": {
                        "type": "string",
                        "description": "Destination security zone"
                    },
                    "source_address": {
                        "type": "string",
                        "description": "Source IP, CIDR, or address object"
                    },
                    "destination_address": {
                        "type": "string",
                        "description": "Destination IP, CIDR, or address object"
                    },
                    "service": {
                        "type": "string",
                        "description": "Service (e.g., 'tcp/443', 'http', 'any')"
                    },
                    "action": {
                        "type": "string",
                        "enum": ["allow", "deny", "drop"],
                        "description": "Rule action"
                    },
                    "logging": {
                        "type": "boolean",
                        "description": "Enable logging"
                    }
                },
                "required": ["name", "source_zone", "destination_zone", "source_address", "destination_address", "service", "action"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "submit_change_request",
            "description": "Create a ServiceNow change request for firewall changes.",
            "parameters": {
                "type": "object",
                "properties": {
                    "description": {
                        "type": "string",
                        "description": "Change description"
                    },
                    "justification": {
                        "type": "string",
                        "description": "Business justification"
                    },
                    "rules": {
                        "type": "array",
                        "items": {"type": "object"},
                        "description": "Rules to create/modify"
                    },
                    "schedule": {
                        "type": "string",
                        "description": "Deployment window (e.g., 'immediate', '2024-01-20 02:00')"
                    }
                },
                "required": ["description", "justification", "rules"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_topology",
            "description": "Query network topology across all connected platforms.",
            "parameters": {
                "type": "object",
                "properties": {
                    "platform": {
                        "type": "string",
                        "enum": ["aws", "azure", "gcp", "panorama", "all"],
                        "description": "Platform to query"
                    },
                    "region": {
                        "type": "string",
                        "description": "Optional region filter"
                    }
                },
                "required": ["platform"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "calculate_blast_radius",
            "description": "Calculate what assets an attacker could reach if a specific asset is compromised.",
            "parameters": {
                "type": "object",
                "properties": {
                    "asset": {
                        "type": "string",
                        "description": "Compromised asset (IP, hostname, or zone)"
                    },
                    "include_lateral": {
                        "type": "boolean",
                        "description": "Include lateral movement paths"
                    }
                },
                "required": ["asset"]
            }
        }
    }
]

# =============================================================================
# SAMPLE TOOL RESPONSES (For Training Data)
# =============================================================================

SAMPLE_TOOL_RESPONSES = {
    "check_traffic_flow": [
        {
            "allowed": True,
            "rule_name": "allow-web-traffic",
            "device_group": "Production",
            "action": "allow",
            "logging": True
        },
        {
            "allowed": False,
            "rule_name": "implicit-deny",
            "device_group": "Production",
            "reason": "No matching allow rule found"
        },
        {
            "allowed": True,
            "rule_name": "allow-app-to-db",
            "device_group": "Database-Access",
            "action": "allow",
            "logging": True,
            "nat": {"type": "source-nat", "translated_ip": "10.100.1.1"}
        }
    ],
    "analyze_attack_path": [
        {
            "paths_found": 3,
            "critical_paths": 1,
            "paths": [
                {
                    "risk_score": 9.2,
                    "hops": ["internet", "dmz-web", "app-tier", "database"],
                    "vulnerabilities": ["exposed-ssh", "weak-segmentation"]
                }
            ],
            "recommendations": ["Implement micro-segmentation", "Remove SSH exposure"]
        },
        {
            "paths_found": 0,
            "message": "No attack paths found to target",
            "segmentation_score": "excellent"
        }
    ],
    "run_compliance_scan": [
        {
            "framework": "pci-dss",
            "total_controls": 45,
            "passed": 42,
            "failed": 3,
            "findings": [
                {"control": "1.2.1", "severity": "high", "description": "Unrestricted outbound traffic detected"},
                {"control": "1.3.4", "severity": "medium", "description": "Missing anti-spoofing rules"}
            ]
        },
        {
            "framework": "soc2",
            "total_controls": 38,
            "passed": 38,
            "failed": 0,
            "compliance_score": 100,
            "evidence_generated": True
        }
    ],
    "find_shadowed_rules": [
        {
            "shadowed_rules": 12,
            "rules": [
                {"name": "old-web-rule", "shadowed_by": "new-web-rule", "safe_to_remove": True},
                {"name": "legacy-ssh", "shadowed_by": "deny-all-ssh", "safe_to_remove": True}
            ],
            "potential_savings": "12 rules can be safely removed"
        },
        {
            "shadowed_rules": 0,
            "message": "No shadowed rules found",
            "rule_base_health": "good"
        }
    ],
    "create_firewall_rule": [
        {
            "status": "created",
            "rule_id": "rule-2024-0120-001",
            "configuration": {
                "name": "allow-web-to-api",
                "source_zone": "web-tier",
                "destination_zone": "api-tier",
                "service": "tcp/443",
                "action": "allow"
            },
            "pending_approval": True
        }
    ],
    "submit_change_request": [
        {
            "ticket_number": "CHG0012345",
            "status": "pending_approval",
            "approvers": ["network-team", "security-team"],
            "scheduled_deployment": "2024-01-20 02:00 UTC",
            "estimated_duration": "35 seconds"
        }
    ],
    "get_topology": [
        {
            "platform": "aws",
            "vpcs": 5,
            "subnets": 23,
            "security_groups": 45,
            "regions": ["us-east-1", "us-west-2"],
            "connectivity": ["transit-gateway", "vpc-peering"]
        }
    ],
    "calculate_blast_radius": [
        {
            "compromised_asset": "web-server-01",
            "reachable_assets": 15,
            "critical_assets_at_risk": 3,
            "assets": [
                {"name": "app-server-01", "risk": "high"},
                {"name": "database-01", "risk": "critical"}
            ],
            "recommendations": ["Implement micro-segmentation", "Enable MFA"]
        }
    ]
}

# =============================================================================
# TRAINING SCENARIOS
# =============================================================================

TOOL_CALLING_SCENARIOS = [
    # Traffic Flow Checks
    {
        "user_query": "Is traffic allowed from 10.1.1.100 to 192.168.50.10 on port 5432?",
        "tool_name": "check_traffic_flow",
        "tool_params": {"source_ip": "10.1.1.100", "destination_ip": "192.168.50.10", "port": 5432, "protocol": "tcp"},
        "followup": "The traffic path is configured correctly for PostgreSQL database access."
    },
    {
        "user_query": "Can our web servers reach the payment API at 203.0.113.50 on HTTPS?",
        "tool_name": "check_traffic_flow",
        "tool_params": {"source_ip": "10.1.0.0/24", "destination_ip": "203.0.113.50", "port": 443, "protocol": "tcp"},
        "followup": "This is important for PCI-DSS compliance - ensure logging is enabled for all payment-related traffic."
    },
    {
        "user_query": "Check if SSH is allowed from the internet to our DMZ servers",
        "tool_name": "check_traffic_flow",
        "tool_params": {"source_ip": "0.0.0.0/0", "destination_ip": "10.0.1.0/24", "port": 22, "protocol": "tcp"},
        "followup": "SSH from internet should generally be blocked. Consider using a bastion host or VPN instead."
    },

    # Attack Path Analysis
    {
        "user_query": "What attack paths exist from the internet to our database tier?",
        "tool_name": "analyze_attack_path",
        "tool_params": {"source": "internet", "target": "database-tier", "include_cloud": True},
        "followup": "Based on the analysis, I recommend implementing the suggested mitigations to reduce your attack surface."
    },
    {
        "user_query": "Analyze the blast radius if our web server gets compromised",
        "tool_name": "calculate_blast_radius",
        "tool_params": {"asset": "web-server-01", "include_lateral": True},
        "followup": "To reduce blast radius, implement micro-segmentation and limit lateral movement capabilities."
    },

    # Compliance Scans
    {
        "user_query": "Run a PCI-DSS compliance scan on our production environment",
        "tool_name": "run_compliance_scan",
        "tool_params": {"framework": "pci-dss", "scope": "Production", "include_evidence": True},
        "followup": "I'll help you remediate the findings. Let's start with the high-severity issues first."
    },
    {
        "user_query": "Check our SOC2 compliance status",
        "tool_name": "run_compliance_scan",
        "tool_params": {"framework": "soc2", "scope": "all", "include_evidence": True},
        "followup": "Your SOC2 compliance posture looks good. The evidence has been generated for your auditor."
    },
    {
        "user_query": "Are we compliant with NIST 800-53 for our AWS environment?",
        "tool_name": "run_compliance_scan",
        "tool_params": {"framework": "nist-800-53", "scope": "AWS-Production", "include_evidence": False},
        "followup": "NIST 800-53 has specific requirements for boundary protection (SC-7) that we should review."
    },

    # Rule Optimization
    {
        "user_query": "Find shadowed rules in our Production device group",
        "tool_name": "find_shadowed_rules",
        "tool_params": {"device_group": "Production", "include_recommendations": True},
        "followup": "Cleaning up these shadowed rules will improve policy performance and reduce audit complexity."
    },

    # Rule Creation
    {
        "user_query": "Create a rule to allow our app servers to access the new API on port 8443",
        "tool_name": "create_firewall_rule",
        "tool_params": {
            "name": "allow-app-to-api",
            "source_zone": "app-tier",
            "destination_zone": "api-tier",
            "source_address": "app-servers",
            "destination_address": "api-gateway",
            "service": "tcp/8443",
            "action": "allow",
            "logging": True
        },
        "followup": "The rule has been created and is pending approval. Would you like me to submit a change request?"
    },

    # ServiceNow Integration
    {
        "user_query": "Submit a change request for the new database access rule",
        "tool_name": "submit_change_request",
        "tool_params": {
            "description": "Add database access for new application servers",
            "justification": "Required for Q1 application deployment",
            "rules": [{"name": "allow-app-to-db", "action": "allow"}],
            "schedule": "2024-01-20 02:00"
        },
        "followup": "The change request has been submitted. You'll receive approval notifications from the CAB."
    },

    # Topology Queries
    {
        "user_query": "Show me our AWS network topology",
        "tool_name": "get_topology",
        "tool_params": {"platform": "aws", "region": "us-east-1"},
        "followup": "Your AWS environment has good VPC segmentation. Consider reviewing the security group rules for tighter controls."
    }
]

# =============================================================================
# LLAMA 3.1 NATIVE FORMAT GENERATOR
# =============================================================================

class NativeToolCallingGenerator:
    """Generates training data in Llama 3.1's native tool calling format."""

    def __init__(self, provider: str = "openai"):
        self.provider = provider
        self.client = None
        self._setup_client()

    def _setup_client(self):
        if self.provider == "openai":
            from openai import OpenAI
            api_key = os.getenv("OPENAI_API_KEY")
            if not api_key:
                raise ValueError("OPENAI_API_KEY not found")
            self.client = OpenAI(api_key=api_key)
        elif self.provider == "mock":
            self.client = None

    def generate_tool_conversation(self, scenario: dict) -> dict:
        """Generate a single tool calling conversation in native format."""

        tool_name = scenario["tool_name"]
        tool_params = scenario["tool_params"]

        # Get a random tool response
        responses = SAMPLE_TOOL_RESPONSES.get(tool_name, [{"status": "success"}])
        tool_response = random.choice(responses)

        # Build conversation in Llama 3.1 native format
        conversations = [
            {
                "from": "human",
                "value": scenario["user_query"]
            },
            {
                "from": "gpt",
                "value": f"<|python_tag|>{json.dumps({'name': tool_name, 'parameters': tool_params})}"
            },
            {
                "from": "tool",
                "value": json.dumps(tool_response)
            },
            {
                "from": "gpt",
                "value": self._generate_followup(scenario, tool_response)
            }
        ]

        return {
            "conversations": conversations,
            "tools": [t for t in FIREWEAVE_TOOLS if t["function"]["name"] == tool_name],
            "has_tool_call": True,
            "tool_name": tool_name
        }

    def _generate_followup(self, scenario: dict, tool_response: dict) -> str:
        """Generate a contextual followup based on tool response."""

        base_followup = scenario.get("followup", "")
        tool_name = scenario["tool_name"]

        # Add context based on tool response
        if tool_name == "check_traffic_flow":
            if tool_response.get("allowed"):
                return f"**Traffic is ALLOWED**\n\nThe traffic matches rule '{tool_response.get('rule_name', 'unknown')}' in Device Group: {tool_response.get('device_group', 'unknown')}.\n\n{base_followup}"
            else:
                return f"**Traffic is BLOCKED**\n\nNo matching allow rule was found. The traffic is denied by '{tool_response.get('rule_name', 'implicit-deny')}'.\n\n{base_followup}\n\nWould you like me to create a rule to allow this traffic?"

        elif tool_name == "analyze_attack_path":
            paths = tool_response.get("paths_found", 0)
            if paths > 0:
                return f"**{paths} Attack Path(s) Detected**\n\nRisk Score: {tool_response.get('paths', [{}])[0].get('risk_score', 'N/A')}/10\n\nRecommendations:\n" + "\n".join(f"- {r}" for r in tool_response.get("recommendations", [])) + f"\n\n{base_followup}"
            else:
                return f"**No Attack Paths Found**\n\nYour segmentation is {tool_response.get('segmentation_score', 'good')}. {base_followup}"

        elif tool_name == "run_compliance_scan":
            passed = tool_response.get("passed", 0)
            failed = tool_response.get("failed", 0)
            total = tool_response.get("total_controls", 0)
            framework = tool_response.get("framework", "").upper()

            if failed == 0:
                return f"**{framework} Compliance: PASSED**\n\nAll {passed}/{total} controls passed.\n\n{base_followup}"
            else:
                findings = "\n".join(f"- [{f['severity'].upper()}] {f['control']}: {f['description']}" for f in tool_response.get("findings", []))
                return f"**{framework} Compliance: {passed}/{total} Controls Passed**\n\n**Findings ({failed}):**\n{findings}\n\n{base_followup}"

        elif tool_name == "find_shadowed_rules":
            count = tool_response.get("shadowed_rules", 0)
            if count > 0:
                rules = "\n".join(f"- '{r['name']}' shadowed by '{r['shadowed_by']}'" for r in tool_response.get("rules", [])[:5])
                return f"**Found {count} Shadowed Rules**\n\n{rules}\n\n{tool_response.get('potential_savings', '')}\n\n{base_followup}"
            else:
                return f"**No Shadowed Rules Found**\n\nYour rule base is clean. {base_followup}"

        elif tool_name == "create_firewall_rule":
            return f"**Rule Created Successfully**\n\nRule ID: {tool_response.get('rule_id', 'N/A')}\nStatus: {'Pending Approval' if tool_response.get('pending_approval') else 'Active'}\n\n{base_followup}"

        elif tool_name == "submit_change_request":
            return f"**Change Request Submitted**\n\nTicket: {tool_response.get('ticket_number', 'N/A')}\nStatus: {tool_response.get('status', 'pending')}\nScheduled: {tool_response.get('scheduled_deployment', 'TBD')}\n\n{base_followup}"

        elif tool_name == "calculate_blast_radius":
            reachable = tool_response.get("reachable_assets", 0)
            critical = tool_response.get("critical_assets_at_risk", 0)
            return f"**Blast Radius Analysis**\n\nIf '{tool_response.get('compromised_asset', 'asset')}' is compromised:\n- Reachable assets: {reachable}\n- Critical assets at risk: {critical}\n\n{base_followup}"

        return base_followup

    def generate_multi_turn_tool_conversation(self) -> dict:
        """Generate a multi-turn conversation with multiple tool calls."""

        # Pick 2-3 related scenarios
        scenarios = random.sample(TOOL_CALLING_SCENARIOS, min(3, len(TOOL_CALLING_SCENARIOS)))

        conversations = []
        tools_used = []

        for i, scenario in enumerate(scenarios):
            tool_name = scenario["tool_name"]
            tool_params = scenario["tool_params"]
            responses = SAMPLE_TOOL_RESPONSES.get(tool_name, [{"status": "success"}])
            tool_response = random.choice(responses)

            # Add user query
            if i == 0:
                conversations.append({"from": "human", "value": scenario["user_query"]})
            else:
                conversations.append({"from": "human", "value": f"Also, {scenario['user_query'].lower()}"})

            # Add tool call
            conversations.append({
                "from": "gpt",
                "value": f"<|python_tag|>{json.dumps({'name': tool_name, 'parameters': tool_params})}"
            })

            # Add tool response
            conversations.append({
                "from": "tool",
                "value": json.dumps(tool_response)
            })

            # Add assistant followup
            conversations.append({
                "from": "gpt",
                "value": self._generate_followup(scenario, tool_response)
            })

            tools_used.append(tool_name)

        return {
            "conversations": conversations,
            "tools": FIREWEAVE_TOOLS,
            "has_tool_call": True,
            "tools_used": tools_used,
            "multi_turn": True
        }

    def generate_batch(self, count: int = 50, multi_turn_ratio: float = 0.3) -> List[dict]:
        """Generate a batch of tool calling training examples."""

        examples = []
        multi_turn_count = int(count * multi_turn_ratio)
        single_turn_count = count - multi_turn_count

        # Generate single-turn examples
        for _ in range(single_turn_count):
            scenario = random.choice(TOOL_CALLING_SCENARIOS)
            example = self.generate_tool_conversation(scenario)
            examples.append(example)

        # Generate multi-turn examples
        for _ in range(multi_turn_count):
            example = self.generate_multi_turn_tool_conversation()
            examples.append(example)

        return examples

    def generate_with_gpt(self, count: int = 20) -> List[dict]:
        """Use GPT-4o to generate more diverse tool calling scenarios."""

        if self.provider == "mock":
            return self.generate_batch(count)

        prompt = f"""Generate {count} diverse tool calling scenarios for a network security AI assistant.

The AI has access to these FireWeave tools:
{json.dumps([t["function"]["name"] + ": " + t["function"]["description"] for t in FIREWEAVE_TOOLS], indent=2)}

For each scenario, provide:
1. A realistic user query (what a security engineer would ask)
2. Which tool to call and with what parameters
3. A realistic tool response
4. The assistant's explanation of the results

Output as JSON array:
[
  {{
    "user_query": "Check if our web servers can reach the payment gateway",
    "tool_name": "check_traffic_flow",
    "tool_params": {{"source_ip": "10.1.0.0/24", "destination_ip": "payment.example.com", "port": 443}},
    "tool_response": {{"allowed": true, "rule_name": "allow-payment", "device_group": "Production"}},
    "assistant_response": "Traffic is ALLOWED via rule 'allow-payment'. This is correct for PCI-DSS compliance."
  }}
]

Make scenarios realistic for enterprise environments (Fortune 500, healthcare, financial services).
Cover all tools, not just check_traffic_flow.
"""

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": "You are an expert at generating training data for AI assistants."},
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
                scenarios = json.loads(content[start_idx:end_idx])

                # Convert to native format
                examples = []
                for s in scenarios:
                    example = {
                        "conversations": [
                            {"from": "human", "value": s["user_query"]},
                            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': s['tool_name'], 'parameters': s['tool_params']})}"},
                            {"from": "tool", "value": json.dumps(s["tool_response"])},
                            {"from": "gpt", "value": s["assistant_response"]}
                        ],
                        "tools": [t for t in FIREWEAVE_TOOLS if t["function"]["name"] == s["tool_name"]],
                        "has_tool_call": True,
                        "tool_name": s["tool_name"]
                    }
                    examples.append(example)

                return examples

        except Exception as e:
            print(f"Error generating with GPT: {e}")

        return self.generate_batch(count)


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(description="Generate native tool calling training data")
    parser.add_argument("--provider", choices=["openai", "mock"], default="mock")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--output", type=str, default="v2/data/synthetic/tool_calling_native.json")
    parser.add_argument("--use-gpt", action="store_true", help="Use GPT-4o for more diverse scenarios")

    args = parser.parse_args()

    print(f"Generating {args.count} native tool calling examples...")

    generator = NativeToolCallingGenerator(provider=args.provider)

    if args.use_gpt and args.provider == "openai":
        # Generate half with GPT, half from templates
        gpt_examples = generator.generate_with_gpt(args.count // 2)
        template_examples = generator.generate_batch(args.count - len(gpt_examples))
        examples = gpt_examples + template_examples
    else:
        examples = generator.generate_batch(args.count)

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(examples, f, indent=2, ensure_ascii=False)

    print(f"Generated {len(examples)} examples")
    print(f"Saved to: {output_path}")

    # Stats
    tool_counts = {}
    multi_turn = 0
    for ex in examples:
        if ex.get("multi_turn"):
            multi_turn += 1
        tool = ex.get("tool_name") or "multi"
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    print(f"\nTool distribution:")
    for tool, count in sorted(tool_counts.items(), key=lambda x: -x[1]):
        print(f"  {tool}: {count}")
    print(f"\nMulti-turn conversations: {multi_turn}")


if __name__ == "__main__":
    main()
