#!/usr/bin/env python3
"""
High-Quality Prompt Templates for Training Data Generation

These prompts are designed to produce HIGH-QUALITY training examples with:
- Minimum 500-character answers
- Multiple code blocks with actual commands
- Step-by-step procedures
- Verification commands
- Security considerations

Based on the paper: "Fine-tuning GPT-4o-mini" - quality over quantity approach
"""

# Quality enforcement instructions that get prepended to all prompts
# NOTE: Uses %d instead of {count} to avoid format string issues with JSON examples
QUALITY_ENFORCEMENT = """
CRITICAL QUALITY REQUIREMENTS - FOLLOW EXACTLY:

1. ANSWER LENGTH: Each answer MUST be at least 500 characters. Short answers are WORTHLESS for training.

2. CODE BLOCKS: Every answer MUST include at least ONE code block with actual commands. Use triple backticks with language.

3. STRUCTURE: Each answer MUST have:
   - Brief context (1-2 sentences)
   - Step-by-step procedure with numbered steps
   - Actual CLI commands or code in code blocks
   - Verification command to confirm success
   - At least one security consideration or best practice

4. SPECIFICITY: Use realistic values:
   - Real IP ranges (10.x.x.x, 192.168.x.x, 172.16.x.x)
   - Real port numbers (443, 8443, 3389, 22)
   - Real interface names (eth0, Gi0/0, ethernet1/1)
   - Real zone names (trust, untrust, dmz)

5. NO LAZY ANSWERS: Avoid generic text like "Navigate to the menu and configure it".
   ALWAYS provide the exact commands, exact paths, exact syntax.

6. VARY DIFFICULTY: Mix of basic concepts, intermediate configs, advanced troubleshooting.

NOW, generate %d Q&A pairs following these EXACT quality standards:
"""


HIGH_QUALITY_TOPICS = {
    "palo-alto-complete": {
        "description": "Complete Palo Alto Networks coverage with detailed CLI commands and procedures",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about Palo Alto Networks firewall configuration and management.

REQUIRED TOPICS (cover all):
1. Security Policy Configuration - Rules, zones, applications, services
2. NAT Policies - Source NAT, destination NAT, bidirectional
3. Decryption - SSL Forward Proxy, certificate management
4. GlobalProtect VPN - Portal, gateway, agent configuration
5. Panorama - Device groups, templates, commit/push workflows
6. Threat Prevention - Antivirus, anti-spyware, vulnerability profiles
7. User-ID - AD integration, group mapping, captive portal
8. Troubleshooting - Debug commands, packet capture, session analysis

FOR EACH ANSWER:
- Start with what the feature does and when to use it
- Provide BOTH CLI commands AND WebUI paths
- Include actual configuration examples with realistic values
- Add verification commands to confirm success
- Include at least one security warning or best practice

Format as JSON array with "question" and "answer" fields."""
    },

    "fireweave-features": {
        "description": "FireWeave platform features with detailed usage procedures",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about FireWeave, an enterprise Panorama firewall management platform.

REQUIRED TOPICS (cover all with detailed procedures):

1. Traffic Flow Analysis: How to check if traffic is allowed between two IPs
2. NAT Check: Testing NAT policy matches using zone_from, zone_to parameters
3. Rule Analysis: Shadowed rules, unused rules, mergeable rules, any-service rules
4. Object Deduplication: Finding duplicate address objects (95%% similarity threshold)
5. Compliance Scanning: PCI-DSS, SOC2, NIST, CIS, HIPAA frameworks
6. Bulk Import: Importing rules from Excel, CSV, ServiceNow FCR
7. Batch Deploy: Creating multiple rules via API with placement options
8. Mass Edit: Filter types and action types for bulk rule modifications
9. Topology Collection: Triggering and understanding collection process
10. ServiceNow/Jira Integration: Webhook and API configuration

FOR EACH ANSWER - Include:
- Exact UI navigation path (e.g., "Analysis > Traffic Flow > Check Traffic")
- Step-by-step procedure
- Error handling and common issues
- At least 500 characters with code blocks

Format as JSON array with "question" and "answer" fields."""
    },

    "fireweave-troubleshooting": {
        "description": "FireWeave troubleshooting with specific diagnostic steps",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about troubleshooting FireWeave issues.

REQUIRED TROUBLESHOOTING SCENARIOS (with detailed resolution steps):

1. Topology Collection stuck at 0%%: Check Panorama connectivity, API key, CORS
2. Topology Collection stuck at 50%%: Memory issues, increase TOPOLOGY_TIMEOUT
3. Topology Collection fails completely: curl test, Celery worker status
4. Stale Topology Data: Identifying stale data, triggering fresh collection
5. Traffic Analysis Returns No Results: Zone configuration, device group rules
6. Batch Deploy Failures: Object not found, name conflict, validation error
7. Integration Failures: ServiceNow webhook, Jira API token, cloud connectors
8. Performance Issues: Slow analysis, database bottleneck, memory issues
9. API Errors: AUTH.001, VALIDATION.001, PANORAMA.001, OBJECTS.001
10. Job Queue Issues: Flower dashboard, Redis memory, worker crashes

FOR EACH ANSWER - Include:
- Exact error message or symptom
- Step-by-step diagnostic procedure
- Specific commands to run
- Environment variables to check
- Resolution steps with verification

Format as JSON array with "question" and "answer" fields."""
    },

    "fireweave-api": {
        "description": "FireWeave REST API with complete curl examples",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about FireWeave's REST API.

REQUIRED API ENDPOINTS (describe each with usage):

1. Authentication: POST /api/v1/auth/login - returns JWT token
2. Traffic Analysis: POST /api/v1/traffic-analysis/check - source_ip, dest_ip, port, protocol
3. NAT Check: POST /api/v1/nat/check - zone_from, zone_to parameters
4. Rule Creation: POST /api/v1/rules/create - rule configuration
5. Batch Deploy: POST /api/v1/batch-deploy - multiple rules with placement
6. Compliance Scan: POST /api/v1/compliance/scan - framework selection
7. Object Lookup: POST /api/v1/objects/lookup - IP/subnet search
8. Topology Collection: POST /api/v1/panorama/topology/collect
9. Job Status: GET /api/v1/jobs/id - check async task progress
10. Health Check: GET /api/v1/health/detailed - system status

ERROR CODES to include:
- AUTH.001, AUTH.002: Authentication errors
- VALIDATION.001-010: Input validation errors
- PANORAMA.001-005: Panorama connectivity errors
- OBJECTS.001-003: Object not found errors
- POLICY.001-005: Policy validation errors

For each answer, provide curl examples with realistic parameters.
Format as JSON array with "question" and "answer" fields."""
    },

    "fireweave-function-calling": {
        "description": "FireWeave AI function calling for intent disambiguation",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about how FireWeave's AI agent uses function calling to disambiguate user intent.

CONTEXT:
FireWeave has an AI Chat interface that must determine whether users want to:
1. EXPLAIN - Get information about a topic (educational)
2. EXECUTE - Actually perform an action (operational)

AVAILABLE FUNCTIONS:
1. check_traffic_flow(source_ip, dest_ip, port, protocol) - Check if traffic is allowed
2. check_nat_policy(source_ip, dest_ip, zone_from, zone_to) - Test NAT translation
3. analyze_rules(device_group, analysis_type) - Find shadowed/unused/mergeable rules
4. lookup_object(query, object_type) - Find address/service objects
5. scan_compliance(framework, device_groups) - Run compliance scan
6. create_rule(rule_config) - Create a new security rule
7. collect_topology() - Trigger topology refresh
8. get_rule_hitcount(rule_name, device_group) - Get rule usage stats

TOPICS TO COVER:
1. Intent classification heuristics (keywords like "check", "run", "execute" vs "explain", "how", "what is")
2. Handling ambiguous queries with clarification
3. Parameter extraction from natural language
4. Error handling when parameters are missing
5. Multi-step workflows (e.g., "find shadowed rules and delete them")
6. Confirmation before destructive actions
7. Response formatting after function execution

For each answer, show the classification logic and example function calls.
Format as JSON array with "question" and "answer" fields."""
    },

    "fireweave-disambiguation": {
        "description": "Explain vs Execute disambiguation training data",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs for training an AI to distinguish between "explain" and "execute" intents.

SCENARIO: FireWeave AI Chat receives user messages. It must correctly classify:
- EXPLAIN: User wants to learn/understand something
- EXECUTE: User wants to perform an action

CLASSIFICATION RULES:

EXPLAIN signals:
- Questions starting with "How", "What", "Why", "When", "Where"
- Words like "explain", "describe", "tell me about", "understand"
- Asking about concepts, best practices, theory
- No specific IPs, objects, or target systems mentioned

EXECUTE signals:
- Imperative verbs: "check", "run", "create", "delete", "find", "scan"
- Specific technical parameters: IP addresses, port numbers, rule names
- Phrases like "for me", "right now", "on the firewall"
- Requesting actual results or actions

AMBIGUOUS cases (need clarification):
- Could be either - ask for clarification
- Example: "Traffic from 10.1.1.1 to 192.168.1.1" - info about it or check it?

FOR EACH Q&A:
- Provide the user query
- Classify as EXPLAIN, EXECUTE, or AMBIGUOUS
- If EXECUTE: show the function call with parameters
- If AMBIGUOUS: show the clarification question to ask
- If EXPLAIN: provide a detailed educational response

Format as JSON array with "question" and "answer" fields."""
    },

    "routing-switching": {
        "description": "Routing and switching with actual CLI commands",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about routing and switching concepts with actual configuration commands.

REQUIRED TOPICS:

1. BGP Configuration (Cisco IOS): router bgp, neighbor, network commands
2. OSPF Configuration: router ospf, router-id, network, area commands
3. VLAN and Trunking: vlan, switchport trunk, allowed vlan
4. Spanning Tree: spanning-tree mode, priority, portfast, bpduguard
5. Inter-VLAN Routing: Router-on-a-stick and SVI configuration
6. HSRP/VRRP Configuration: standby commands, priority, preempt
7. Link Aggregation (LACP): channel-group, port-channel interface
8. Route Redistribution: redistribute command between protocols

FOR EACH ANSWER:
- Explain the concept first (2-3 sentences)
- Provide complete CLI configuration with realistic values
- Include verification commands (show commands)
- Add troubleshooting tips
- Security considerations

Format as JSON array with "question" and "answer" fields."""
    },

    "aws-networking": {
        "description": "AWS networking with Terraform and CLI examples",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about AWS networking with actual CLI and Terraform examples.

REQUIRED TOPICS:

1. VPC Architecture: aws ec2 create-vpc, subnets, CIDR blocks
2. Security Groups vs NACLs: When to use each, stateful vs stateless
3. Transit Gateway: create-transit-gateway, VPC attachments
4. Direct Connect and VPN: Hybrid connectivity options
5. Route 53 DNS: Hosted zones, record sets, routing policies
6. VPC Endpoints: Gateway and interface endpoints for AWS services
7. Network Load Balancer: Target groups, listeners, health checks
8. VPC Flow Logs: Enabling and analyzing network traffic logs

FOR EACH ANSWER:
- Explain the AWS service/concept
- Provide AWS CLI commands with realistic parameters
- Include Terraform example where applicable
- Add IAM permissions required
- Include cost considerations

Format as JSON array with "question" and "answer" fields."""
    },

    "incident-response": {
        "description": "Incident response procedures with specific commands",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about incident response with specific tools and commands.

REQUIRED TOPICS:

1. Initial Detection and Triage: ps aux, netstat, last commands for suspicious activity
2. Containment Procedures: iptables rules, user lockout commands
3. Evidence Collection: Memory dumps (avml), disk imaging (dd), volatile data
4. Log Analysis: grep commands for auth failures, web attacks
5. Malware Analysis (Basic): file, strings, sha256sum, VirusTotal checks
6. Ransomware Response: Isolation, backup verification, negotiation guidance
7. Timeline Reconstruction: find -mtime, log parsing
8. Post-Incident: Root cause analysis, lessons learned, detection rule updates

FOR EACH ANSWER:
- Explain the IR phase/concept
- Provide specific commands to run (bash/Linux)
- Include tool recommendations
- Add chain of custody considerations
- Legal/compliance notes where relevant

Format as JSON array with "question" and "answer" fields."""
    },

    "cissp-domains": {
        "description": "CISSP 8 domains with practical examples",
        "prompt_template": QUALITY_ENFORCEMENT + """
Generate Q&A pairs about the 8 CISSP domains with practical examples.

REQUIRED DOMAINS:

1. Security and Risk Management (15%%): Risk assessment, ALE calculation, governance frameworks
2. Asset Security (10%%): Data classification, retention, secure destruction
3. Security Architecture and Engineering (13%%): Security models, cryptography, PKI
4. Communication and Network Security (13%%): OSI security, attacks, firewalls, VPNs
5. Identity and Access Management (13%%): Authentication factors, SSO, access models
6. Security Assessment and Testing (12%%): Vuln scanning vs pentesting, OWASP Top 10
7. Security Operations (13%%): Incident response, forensics, SIEM, patch management
8. Software Development Security (11%%): SDLC security, secure coding, DevSecOps

FOR EACH ANSWER:
- Explain the concept clearly
- Provide real-world example
- Include relevant formulas/calculations where applicable
- Mention related standards/frameworks (NIST, ISO 27001)
- Add exam tips

Format as JSON array with "question" and "answer" fields."""
    }
}


def get_high_quality_prompt(topic: str, count: int) -> str:
    """Get a high-quality prompt for a topic using %d formatting."""
    if topic not in HIGH_QUALITY_TOPICS:
        raise ValueError(f"Topic '{topic}' not found")

    template = HIGH_QUALITY_TOPICS[topic]["prompt_template"]
    # Use % formatting instead of .format() to avoid issues with JSON braces
    return template % count


if __name__ == "__main__":
    # Print available topics
    print("High-Quality Topics Available:")
    print("=" * 60)
    for topic, info in HIGH_QUALITY_TOPICS.items():
        print(f"  {topic}: {info['description']}")
