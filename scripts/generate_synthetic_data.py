#!/usr/bin/env python3
"""
Synthetic Data Generation Script for Network Security Fine-tuning

This script generates synthetic Q&A pairs for network security training using
OpenAI GPT-4 or Anthropic Claude. It covers three main domains:
1. Firewall & Network Device Configuration
2. Cloud Security (AWS/Azure/GCP)
3. Threat Detection & Incident Response

Usage:
    python generate_synthetic_data.py --provider openai --topic cisco-firewall --count 50
    python generate_synthetic_data.py --provider anthropic --topic aws-security --count 100
"""

import argparse
import json
import os
import time
from typing import List, Dict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Topic templates for different network security domains
TOPICS = {
    "cisco-firewall": {
        "description": "Cisco firewall and router configuration, ACLs, NAT, VPN",
        "prompt_template": """Generate {count} realistic network security Q&A pairs about Cisco firewall and router configuration.

Topics to cover:
- Cisco ASA firewall configuration
- Access Control Lists (ACLs)
- NAT and PAT configuration
- Site-to-site and remote access VPN (IPSec, SSL)
- Zone-based firewalls
- Routing protocol security (BGP, OSPF)

Requirements:
- Include accurate Cisco IOS/ASA commands
- Provide detailed explanations, not just commands
- Add security warnings and best practices
- Vary difficulty from beginner to advanced
- Use realistic scenarios network engineers face
- Include troubleshooting scenarios

Format each Q&A as a JSON object with "question" and "answer" fields."""
    },

    "palo-alto": {
        "description": "Palo Alto firewall configuration and management",
        "prompt_template": """Generate {count} realistic network security Q&A pairs about Palo Alto Networks firewall configuration.

Topics to cover:
- PAN-OS security policies
- Application-based firewall rules
- User-ID and device mapping
- Threat prevention profiles
- Security zones and interfaces
- VPN configuration
- High availability and failover

Requirements:
- Include accurate PAN-OS CLI and WebUI procedures
- Provide context and explanations
- Add security best practices
- Mix beginner to advanced topics
- Use realistic enterprise scenarios

Format each Q&A as a JSON object with "question" and "answer" fields."""
    },

    "aws-security": {
        "description": "AWS cloud security, VPC, Security Groups, IAM",
        "prompt_template": """Generate {count} realistic cloud security Q&A pairs about AWS security.

Topics to cover:
- VPC design and subnet architecture
- Security Groups vs Network ACLs
- IAM policies and roles
- CloudTrail and logging
- AWS GuardDuty and Security Hub
- S3 bucket security
- EC2 instance security hardening
- Compliance and auditing

Requirements:
- Include accurate AWS CLI commands and configurations
- Provide detailed explanations with examples
- Add security warnings and compliance considerations
- Vary difficulty levels
- Include troubleshooting scenarios
- Reference AWS best practices

Format each Q&A as a JSON object with "question" and "answer" fields."""
    },

    "azure-security": {
        "description": "Azure cloud security, networking, and identity",
        "prompt_template": """Generate {count} realistic cloud security Q&A pairs about Microsoft Azure security.

Topics to cover:
- Virtual Networks and NSGs
- Azure Firewall configuration
- Azure AD and identity management
- Security Center and Sentinel
- Storage account security
- Key Vault and secrets management
- Network peering and VPN gateways

Requirements:
- Include accurate Azure CLI and PowerShell commands
- Provide detailed explanations
- Add security best practices
- Mix beginner to advanced topics
- Use realistic enterprise scenarios

Format each Q&A as a JSON object with "question" and "answer" fields."""
    },

    "ids-ips": {
        "description": "IDS/IPS systems - Snort, Suricata rule creation",
        "prompt_template": """Generate {count} realistic network security Q&A pairs about IDS/IPS systems.

Topics to cover:
- Snort rule creation and syntax
- Suricata rule writing
- Signature-based vs anomaly-based detection
- IDS/IPS deployment strategies
- Tuning and false positive reduction
- Common attack signatures
- Log analysis and alert investigation

Requirements:
- Include accurate Snort/Suricata rule syntax
- Provide explanations of detection logic
- Add best practices for rule deployment
- Mix beginner to advanced topics
- Include real-world attack scenarios

Format each Q&A as a JSON object with "question" and "answer" fields."""
    },

    "siem-logs": {
        "description": "SIEM, log analysis, and security event correlation",
        "prompt_template": """Generate {count} realistic network security Q&A pairs about SIEM and log analysis.

Topics to cover:
- SIEM query syntax (Splunk, ELK, Sentinel)
- Log correlation and pattern detection
- Security event investigation workflows
- Common attack indicators in logs
- Threat hunting techniques
- Alerting and incident response
- Log retention and compliance

Requirements:
- Include accurate query syntax for major SIEM platforms
- Provide detailed investigation procedures
- Add context about attack patterns
- Mix beginner to advanced topics
- Use realistic security incidents

Format each Q&A as a JSON object with "question" and "answer" fields."""
    },

    "network-troubleshooting": {
        "description": "Network troubleshooting and connectivity issues",
        "prompt_template": """Generate {count} realistic network security Q&A pairs about network troubleshooting.

Topics to cover:
- Connectivity troubleshooting methodologies
- Packet capture analysis
- Firewall rule debugging
- VPN connectivity issues
- Routing problems
- DNS and DHCP issues
- Performance troubleshooting

Requirements:
- Include systematic troubleshooting steps
- Provide diagnostic commands for multiple platforms
- Add common mistakes and solutions
- Mix simple to complex scenarios
- Use realistic enterprise problems

Format each Q&A as a JSON object with "question" and "answer" fields."""
    }
}


def generate_with_openai(prompt: str, count: int) -> List[Dict[str, str]]:
    """Generate synthetic data using OpenAI GPT-4"""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        response = client.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are a network security expert who creates high-quality training data for AI models. Generate accurate, detailed, and practical Q&A pairs."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.8,
            max_tokens=4000
        )

        content = response.choices[0].message.content

        # Try to parse JSON from the response
        qa_pairs = []
        # Look for JSON objects in the response
        lines = content.split('\n')
        current_json = ""
        for line in lines:
            current_json += line
            if line.strip().endswith('}') or line.strip().endswith('},'):
                try:
                    # Remove trailing comma if present
                    json_str = current_json.strip().rstrip(',')
                    qa_pair = json.loads(json_str)
                    if "question" in qa_pair and "answer" in qa_pair:
                        qa_pairs.append(qa_pair)
                    current_json = ""
                except json.JSONDecodeError:
                    continue

        return qa_pairs

    except Exception as e:
        print(f"Error generating with OpenAI: {e}")
        return []


def generate_with_anthropic(prompt: str, count: int) -> List[Dict[str, str]]:
    """Generate synthetic data using Anthropic Claude"""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4000,
            temperature=0.8,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        content = message.content[0].text

        # Try to parse JSON from the response
        qa_pairs = []
        lines = content.split('\n')
        current_json = ""
        for line in lines:
            current_json += line
            if line.strip().endswith('}') or line.strip().endswith('},'):
                try:
                    json_str = current_json.strip().rstrip(',')
                    qa_pair = json.loads(json_str)
                    if "question" in qa_pair and "answer" in qa_pair:
                        qa_pairs.append(qa_pair)
                    current_json = ""
                except json.JSONDecodeError:
                    continue

        return qa_pairs

    except Exception as e:
        print(f"Error generating with Anthropic: {e}")
        return []


def convert_to_chatml_format(qa_pairs: List[Dict[str, str]]) -> List[Dict]:
    """Convert Q&A pairs to ChatML/ShareGPT format"""
    formatted_data = []
    for qa in qa_pairs:
        formatted_data.append({
            "conversations": [
                {
                    "from": "human",
                    "value": qa["question"]
                },
                {
                    "from": "gpt",
                    "value": qa["answer"]
                }
            ]
        })
    return formatted_data


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic network security training data")
    parser.add_argument("--provider", choices=["openai", "anthropic"], required=True,
                       help="AI provider to use for generation")
    parser.add_argument("--topic", choices=list(TOPICS.keys()), required=True,
                       help="Topic to generate data for")
    parser.add_argument("--count", type=int, default=50,
                       help="Number of Q&A pairs to generate (default: 50)")
    parser.add_argument("--output", type=str,
                       help="Output file path (default: data/synthetic/<topic>_<provider>.json)")
    parser.add_argument("--batch-size", type=int, default=10,
                       help="Generate in batches to avoid token limits (default: 10)")

    args = parser.parse_args()

    # Check API keys
    if args.provider == "openai" and not os.getenv("OPENAI_API_KEY"):
        print("Error: OPENAI_API_KEY not found in environment variables")
        print("Please create a .env file with: OPENAI_API_KEY=your-key-here")
        return

    if args.provider == "anthropic" and not os.getenv("ANTHROPIC_API_KEY"):
        print("Error: ANTHROPIC_API_KEY not found in environment variables")
        print("Please create a .env file with: ANTHROPIC_API_KEY=your-key-here")
        return

    # Set output path
    if args.output:
        output_path = args.output
    else:
        output_path = f"data/synthetic/{args.topic}_{args.provider}.json"

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    topic_info = TOPICS[args.topic]
    print(f"Generating {args.count} Q&A pairs about: {topic_info['description']}")
    print(f"Using provider: {args.provider}")
    print(f"Output file: {output_path}")
    print("-" * 80)

    all_qa_pairs = []
    batches = (args.count + args.batch_size - 1) // args.batch_size

    for batch in range(batches):
        batch_count = min(args.batch_size, args.count - len(all_qa_pairs))
        print(f"\nGenerating batch {batch + 1}/{batches} ({batch_count} pairs)...")

        prompt = topic_info["prompt_template"].format(count=batch_count)

        if args.provider == "openai":
            qa_pairs = generate_with_openai(prompt, batch_count)
        else:
            qa_pairs = generate_with_anthropic(prompt, batch_count)

        if qa_pairs:
            all_qa_pairs.extend(qa_pairs)
            print(f"✓ Generated {len(qa_pairs)} pairs (Total: {len(all_qa_pairs)})")
        else:
            print(f"✗ Failed to generate batch {batch + 1}")

        # Rate limiting
        if batch < batches - 1:
            print("Waiting 2 seconds before next batch...")
            time.sleep(2)

    if not all_qa_pairs:
        print("\n❌ No data generated. Please check your API key and try again.")
        return

    # Convert to ChatML format
    print(f"\nConverting {len(all_qa_pairs)} Q&A pairs to ChatML format...")
    formatted_data = convert_to_chatml_format(all_qa_pairs)

    # Save to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(formatted_data, f, indent=2, ensure_ascii=False)

    print(f"\n✅ Successfully generated {len(formatted_data)} training examples!")
    print(f"📁 Saved to: {output_path}")
    print(f"\nSample question: {all_qa_pairs[0]['question'][:100]}...")
    print(f"\nNext steps:")
    print(f"1. Review the generated data for quality and accuracy")
    print(f"2. Run validation: python scripts/validate_dataset.py {output_path}")
    print(f"3. Generate more topics and merge datasets")
    print(f"4. Use the combined dataset for fine-tuning")


if __name__ == "__main__":
    main()
