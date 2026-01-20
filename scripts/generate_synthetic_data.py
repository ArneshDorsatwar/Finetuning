#!/usr/bin/env python3
"""
Synthetic Data Generation Script for Network Security Fine-tuning

This script generates synthetic Q&A pairs for network security training using
OpenAI GPT-4, Anthropic Claude, or Kimi (Moonshot AI). It covers three main domains:
1. Firewall & Network Device Configuration
2. Cloud Security (AWS/Azure/GCP)
3. Threat Detection & Incident Response

Usage:
    python generate_synthetic_data.py --provider openai --topic cisco-firewall --count 50
    python generate_synthetic_data.py --provider anthropic --topic aws-security --count 100
    python generate_synthetic_data.py --provider kimi --topic ids-ips --count 50
"""

import argparse
import json
import os
import time
from typing import List, Dict
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

import re

# Import high-quality prompts (these override default prompts for key topics)
try:
    from high_quality_prompts import HIGH_QUALITY_TOPICS
    HQ_PROMPTS_AVAILABLE = True
    print("[INFO] High-quality prompts loaded successfully")
except ImportError:
    HQ_PROMPTS_AVAILABLE = False
    HIGH_QUALITY_TOPICS = {}


def parse_qa_response(content: str) -> List[Dict[str, str]]:
    """Parse Q&A pairs from various JSON response formats"""
    qa_pairs = []

    # First, try to parse as a complete JSON object or array
    try:
        # Try parsing entire content as JSON
        data = json.loads(content)

        # If it's a list of Q&A pairs
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and "question" in item and "answer" in item:
                    qa_pairs.append({"question": item["question"], "answer": item["answer"]})
            if qa_pairs:
                return qa_pairs

        # If it's a numbered dict like {"1": {...}, "2": {...}}
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and "question" in value and "answer" in value:
                    qa_pairs.append({"question": value["question"], "answer": value["answer"]})
            if qa_pairs:
                return qa_pairs
    except json.JSONDecodeError:
        pass

    # Try to extract JSON from markdown code blocks
    code_block_pattern = r'```(?:json)?\s*([\s\S]*?)```'
    code_blocks = re.findall(code_block_pattern, content)

    for block in code_blocks:
        try:
            data = json.loads(block.strip())
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and "question" in item and "answer" in item:
                        qa_pairs.append({"question": item["question"], "answer": item["answer"]})
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict) and "question" in value and "answer" in value:
                        qa_pairs.append({"question": value["question"], "answer": value["answer"]})
        except json.JSONDecodeError:
            continue

    if qa_pairs:
        return qa_pairs

    # Try to find individual JSON objects line by line
    lines = content.split('\n')
    current_json = ""
    brace_count = 0

    for line in lines:
        current_json += line + "\n"
        brace_count += line.count('{') - line.count('}')

        if brace_count == 0 and current_json.strip():
            try:
                # Try to parse accumulated JSON
                json_str = current_json.strip().rstrip(',')
                obj = json.loads(json_str)

                if isinstance(obj, dict):
                    if "question" in obj and "answer" in obj:
                        qa_pairs.append({"question": obj["question"], "answer": obj["answer"]})
                    else:
                        # Check if it's a numbered format
                        for key, value in obj.items():
                            if isinstance(value, dict) and "question" in value and "answer" in value:
                                qa_pairs.append({"question": value["question"], "answer": value["answer"]})

                current_json = ""
            except json.JSONDecodeError:
                # Keep accumulating if parse fails
                if brace_count == 0:
                    current_json = ""

    return qa_pairs

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
    },

    # ==================== FIREWEAVE TOPICS (Priority 0) ====================

    "fireweave-features": {
        "description": "FireWeave platform features and usage",
        "prompt_template": """Generate {count} Q&A pairs about FireWeave, an enterprise Panorama firewall management platform.

FireWeave Features to cover:
- Traffic Flow Analysis: Check if traffic between IPs is allowed (source IP, dest IP, port, protocol). Navigate to Analysis > Traffic Flow, enter IPs and port, view matching rules and zones.
- NAT Check: Test NAT policy matches using Panorama's test nat-policy-match API. Check source/destination NAT translations.
- Rule Analysis: Shadowed rules (rules that never match because earlier rules catch all traffic), unused rules (zero hit count), mergeable rules (can be consolidated), any-service rules (security risk), no-logging rules (compliance risk).
- Object Deduplication: Find and consolidate duplicate address/service objects using 95% similarity matching. Reduces policy complexity.
- Object Consolidation: Promote local device group objects to Shared device group for reuse across all device groups.
- Compliance Scanning: PCI-DSS, SOC2, NIST, CIS, HIPAA framework checks. Automated scanning with severity levels and remediation guidance.
- Bulk Import: Import rules from Excel, CSV, DOCX, or ServiceNow FCR attachments. Validates objects exist before import.
- Batch Deploy: Deploy multiple rules with smart profile selection (security, logging, threat prevention). Placement options: top, bottom, before/after rule.
- Mass Edit: Modify multiple rules using filters (15+ types like zone, address, application) and actions (25+ types like add tag, change logging, modify profile).
- ServiceNow Integration: Webhook receives FCR submissions, Table API fetches attachments, auto-parses rule requests.
- Jira Integration: JQL-based issue fetching, parses rule requests from issue descriptions and attachments.
- Topology Collection: Single API call to fetch entire Panorama config including device groups, templates, zones, interfaces (~55 seconds for large deployments).
- Topology Versioning: Immutable snapshots with SHA256 checksums. Compare versions to see changes over time.
- Device Group Hierarchy: Visualize inheritance (Shared > Region > Site). See which objects/rules are inherited vs local.
- Template Stack Hierarchy: Override detection shows which settings are overridden at each level.
- Cloud Integration: AWS (VPCs, Security Groups, Transit Gateway), Azure (VNets, NSGs, ExpressRoute), GCP (VPC, Firewall Rules) topology discovery.
- AI Chat: Natural language interface for policy queries. Ask questions like "show me all rules allowing SSH from internet".

Include specific UI navigation paths (e.g., "Analysis > Traffic Flow") and explain the workflow for each feature.
Format as JSON with "question" and "answer" fields."""
    },

    "fireweave-troubleshooting": {
        "description": "FireWeave troubleshooting and common issues",
        "prompt_template": """Generate {count} Q&A pairs about troubleshooting FireWeave issues.

Common issues to cover:
- Topology collection stuck/timeout: Check Panorama connectivity (curl test), verify API key validity, check TOPOLOGY_TIMEOUT environment variable (default 120s), increase for large deployments.
- Topology collection fails: Test with curl -k https://panorama-ip/api/?type=keygen, check Celery workers running, verify Redis connection, check memory (large configs need 4GB+ RAM).
- Stale topology data: Trigger new collection via Topology > Collect Now, check scheduled task status in admin panel, verify last_collected timestamp.
- Traffic analysis returns no results: Verify zones are correct (check Topology > Zones), ensure device group has security rules, check if pre-computed analysis is enabled.
- Batch deploy fails: Common errors - "Object not found" (object doesn't exist in device group), "Name conflict" (rule name already exists), "Validation error" (invalid IP/port format), "Commit conflict" (another commit in progress).
- ServiceNow webhook not working: Verify webhook secret matches SERVICENOW_WEBHOOK_SECRET env var, check firewall allows inbound from ServiceNow IPs, verify SSL certificate is valid, check webhook logs.
- Slow analysis performance: Enable pre-computed analysis in settings (ENABLE_PRECOMPUTED_ANALYSIS=true), check PostgreSQL query performance, consider adding indexes, verify Redis caching is working.
- Mass edit approval stuck: Check approval workflow settings, verify approver has correct permissions, check if approval notification was sent (email/Slack).
- Cloud connector errors: AWS - verify AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, check IAM permissions. Azure - verify AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET. GCP - verify GCP_SERVICE_ACCOUNT_KEY JSON file exists and has permissions.
- Job queue backlog: Check Celery workers with 'celery inspect active', verify Redis memory (redis-cli INFO memory), access Flower dashboard at port 5555 for queue visualization.
- API authentication errors: JWT token expired (default 24h), refresh token, verify user has API access permission in FireWeave admin.
- Database connection issues: Check DATABASE_URL environment variable, verify PostgreSQL is running, check connection pool settings (max 20 default).

Include diagnostic commands, environment variables to check, and step-by-step resolution procedures.
Format as JSON with "question" and "answer" fields."""
    },

    "fireweave-function-calling": {
        "description": "FireWeave tool/function calling training for AI agent integration",
        "prompt_template": """Generate {count} examples of user requests and corresponding FireWeave tool calls for AI agent integration.

FireWeave is a Panorama firewall management platform. The AI should understand user requests and output structured tool calls.

AVAILABLE TOOLS:

1. traffic_flow_analysis - Check if traffic is allowed
   Parameters: source_ip, destination_ip, port, protocol, device_group (optional)

2. nat_check - Test NAT translations
   Parameters: source_ip, destination_ip, port, zone_from, zone_to

3. rule_search - Search security rules
   Parameters: query, device_group, rule_type (security/nat/decryption), filters (source_zone, destination_zone, application, action)

4. compliance_scan - Run compliance checks
   Parameters: framework (PCI-DSS/SOC2/NIST/CIS/HIPAA/ISO27001), device_groups (array), severity_filter

5. shadowed_rules_check - Find shadowed rules
   Parameters: device_group, rulebase (pre-rulebase/post-rulebase)

6. unused_rules_check - Find unused rules
   Parameters: device_group, days_threshold

7. object_lookup - Search address/service objects
   Parameters: query, object_type (address/address-group/service/service-group), device_group

8. deduplication_scan - Find duplicate objects
   Parameters: device_group, object_type, similarity_threshold

9. create_rule - Create new security rule
   Parameters: name, device_group, rulebase, source_zone, destination_zone, source_address, destination_address, application, service, action, log_start, log_end, profile_setting, description, tags

10. batch_deploy - Deploy multiple rules
    Parameters: device_group, rulebase, placement (top/bottom/before/after), reference_rule, rules, auto_commit

11. mass_edit - Modify multiple rules
    Parameters: device_group, filters, actions, preview_only

12. topology_collect - Refresh Panorama data
    Parameters: panorama_id, full_collection

13. export_rules - Export rules to file
    Parameters: device_group, rulebase, format (excel/csv/json)

14. get_hit_count - Get rule hit statistics
    Parameters: device_group, rule_names, time_range

For each example, provide a JSON object with:
- "question": Natural language user request (what a network admin would actually ask)
- "answer": Response that includes:
  1. Brief acknowledgment of the request
  2. The tool call in JSON format within a code block
  3. Explanation of what the tool will do
  4. Any relevant security/best practice notes

EXAMPLE FORMAT:
{{
  "question": "Check if the web server at 10.1.1.50 can reach the database at 172.16.5.100 on port 5432",
  "answer": "I'll check if PostgreSQL traffic is allowed between these servers.\\n\\n**Executing:**\\n```json\\n{{\\n  \\"tool\\": \\"traffic_flow_analysis\\",\\n  \\"parameters\\": {{\\n    \\"source_ip\\": \\"10.1.1.50\\",\\n    \\"destination_ip\\": \\"172.16.5.100\\",\\n    \\"port\\": 5432,\\n    \\"protocol\\": \\"tcp\\"\\n  }}\\n}}\\n```\\n\\nThis will analyze the security policies to determine if PostgreSQL (port 5432/TCP) traffic is permitted between your web server and database server, showing which rule would match."
}}

Generate varied scenarios including:
- Traffic flow checks (HTTP, HTTPS, SSH, RDP, database ports, custom apps)
- NAT verification (source NAT, destination NAT)
- Compliance audits (PCI-DSS, SOC2, HIPAA pre-audit checks)
- Rule cleanup (unused rules, shadowed rules, duplicates)
- Incident response (blocking IPs, investigating access)
- Policy creation (new application access, server migrations)
- Mass operations (enable logging, add tags, update profiles)
- Multi-step workflows (check then create, audit then remediate)

Make requests realistic - use typical enterprise IPs, common applications, real compliance frameworks.
Format as JSON array."""
    },

    "fireweave-api": {
        "description": "FireWeave REST API usage",
        "prompt_template": """Generate {count} Q&A pairs about FireWeave's REST API.

API Topics to cover:
- Authentication: POST /api/v1/auth/login with {{"username": "user", "password": "pass"}} returns JWT token. Use in subsequent requests: Authorization: Bearer <token>. Token expires in 24 hours by default.
- Traffic Analysis: POST /api/v1/traffic-analysis/check with {{"source_ip": "10.1.1.100", "destination_ip": "192.168.1.50", "port": 443, "protocol": "tcp"}}. Returns matching rules, zones, and allow/deny result.
- NAT Check: POST /api/v1/nat/check with {{"source_ip": "10.1.1.100", "destination_ip": "8.8.8.8", "port": 53, "zone_from": "trust", "zone_to": "untrust"}}. Returns NAT policy matches and translations.
- Rule Creation: POST /api/v1/rules/create with full rule specification including name, zones, addresses, applications, services, action, logging, and security profiles.
- Batch Deploy: POST /api/v1/batch-deploy with {{"device_group": "DG-Site1", "rulebase": "pre-rulebase", "placement": "top", "rules": [...]}}. Returns job_id for async tracking.
- Compliance Scan: POST /api/v1/compliance/scan with {{"framework": "PCI-DSS", "device_groups": ["DG-Site1", "DG-Site2"]}}. Returns violations with severity and remediation.
- Object Lookup: POST /api/v1/objects/lookup with {{"query": "10.1.1.0/24", "type": "address"}}. Searches across all device groups.
- Deduplication Scan: POST /api/v1/deduplication/scan with {{"device_group": "Shared", "object_type": "address", "similarity_threshold": 0.95}}.
- Topology Collection: POST /api/v1/panorama/topology/collect triggers full collection. Returns job_id. Check progress with GET /api/v1/jobs/{{job_id}}.
- Job Status: GET /api/v1/jobs/{{id}} returns {{"status": "pending|running|completed|failed", "progress": 75, "result": {{...}}}}.
- Health Check: GET /api/v1/health/detailed returns system status including database, Redis, Celery workers, Panorama connectivity.
- Bulk Import: POST /api/v1/import/rules with multipart form data containing Excel/CSV file.
- Rule Search: GET /api/v1/rules/search?q=ssh&device_group=DG-Site1 for full-text rule search.

Error Codes and handling:
- AUTH.INVALID_CREDENTIALS (401): Wrong username/password
- AUTH.TOKEN_EXPIRED (401): Refresh token needed
- VALIDATION.INVALID_IP (400): IP format incorrect
- VALIDATION.MISSING_FIELD (400): Required field not provided
- PANORAMA.CONNECTION_FAILED (503): Can't reach Panorama
- PANORAMA.API_ERROR (502): Panorama returned error
- OBJECTS.NOT_FOUND (404): Referenced object doesn't exist
- POLICY.COMMIT_CONFLICT (409): Another commit in progress

Include curl examples and Python requests code samples. Show request and response JSON formats.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== PALO ALTO TOPICS (Priority 1) ====================

    "palo-alto-complete": {
        "description": "Complete Palo Alto Networks coverage including Panorama, GlobalProtect, Prisma",
        "prompt_template": """Generate {count} Q&A pairs about Palo Alto Networks products and technologies.

Topics to cover comprehensively:
- PAN-OS Firewall Configuration: Security policies, NAT policies, routing, zones, interfaces, virtual routers, VSYS.
- Panorama Centralized Management: Device groups (hierarchy and inheritance), template stacks, log collectors, managed firewalls, commit and push workflows, role-based access control.
- GlobalProtect VPN: Portal and gateway configuration, agent settings, HIP checks, split tunneling, always-on VPN, MFA integration, clientless VPN.
- Prisma Access: Cloud-delivered security, mobile users, remote networks, service connections, traffic steering, ZTNA 2.0.
- WildFire Malware Analysis: Sandbox analysis, verdict lookup, file blocking, WildFire API integration, custom analysis profiles.
- App-ID Technology: Application identification, custom App-IDs, application dependencies, application groups, app-override policies.
- Content-ID: Vulnerability protection, anti-spyware, URL filtering, file blocking, data filtering profiles.
- User-ID: AD integration, Terminal Services agent, Captive Portal, Group Mapping, user-based policies.
- Decryption: SSL Forward Proxy, Inbound Inspection, SSH Proxy, decryption profiles, certificate management, decryption exclusions.
- High Availability: Active/Passive and Active/Active modes, HA link monitoring, preemption, session synchronization.
- Logging and Monitoring: Log forwarding, syslog, SNMP, email alerts, custom reports, log types (traffic, threat, URL, etc.).
- Troubleshooting: Debug commands, packet capture, ACC, flow basic, session info, routing table verification.
- Automation: XML API, REST API, pan-python, Ansible modules, Terraform provider.

Include both CLI commands (configure mode and operational mode) and WebUI navigation steps.
Provide best practices for enterprise deployments.
Format as JSON with "question" and "answer" fields."""
    },

    "palo-alto-administration": {
        "description": "Palo Alto Network Security Engineer roles, skills, certifications, and rule management",
        "prompt_template": """Generate {count} Q&A pairs about Palo Alto Networks administration roles and responsibilities.

Roles and Responsibilities:
- Network Security Engineers/Administrators: Primary roles for daily firewall operations, policy creation, troubleshooting, and maintenance
- Security Analysts: Focus on policy review, log analysis, threat monitoring, and security assessments
- Security Architects: Design large-scale network security strategies, define standards, plan Panorama hierarchies
- SOC Analysts: Monitor alerts, investigate incidents, use ACC and logs for threat detection
- Network Engineers: Integrate firewalls with routing, switching, VPN, and cloud infrastructure

Technical Skills Required:
- PAN-OS Expertise: In-depth knowledge of Palo Alto's operating system versions, upgrade paths, feature sets
- Panorama Management: Centralized management, device groups, template stacks, log collectors, Strata Cloud Manager
- Security Policy Configuration: App-ID rules, User-ID integration, zone-based policies, rule ordering, shadowed rule detection
- NAT Configuration: Source NAT, destination NAT, bidirectional NAT, NAT policy ordering
- Threat Prevention: Antivirus, anti-spyware, vulnerability protection profiles, WildFire integration
- URL Filtering: Category-based filtering, custom URL categories, credential phishing prevention
- DNS Security: DNS sinkholing, malicious domain blocking, DNS tunneling detection
- VPN Configuration: GlobalProtect portal/gateway, site-to-site IPSec, IKE configuration
- Core Networking: TCP/IP deep understanding, routing protocols, subnetting, network segmentation
- Automation Skills: pan-python, Ansible pan-os collection, Terraform provider, XML/REST API scripting

Soft Skills:
- Problem-Solving: Methodical troubleshooting of complex connectivity and security issues
- Communication: Explaining technical policies to business stakeholders, writing change requests
- Documentation: Maintaining runbooks, architecture diagrams, policy documentation
- Project Management: Planning migrations, upgrades, and large-scale deployments
- Change Management: Following CAB processes, testing changes, rollback planning

Certifications:
- PCNSA (Palo Alto Networks Certified Network Security Administrator): Entry-level, covers firewall basics
- PCNSE (Palo Alto Networks Certified Network Security Engineer): Advanced, covers complex deployments
- PCCSE (Palo Alto Networks Certified Cloud Security Engineer): Prisma Cloud focus
- PSE (Palo Alto Networks Systems Engineer): Pre-sales technical certification
- Other relevant: CCNA/CCNP Security, CompTIA Security+, CISSP

What Security Rules Do:
- Traffic Control: Allow/deny based on App-ID (application), User-ID (user/group), zone, IP, port
- Next-Generation Capabilities: Move beyond port/protocol to application-aware, user-aware policies
- Threat Prevention: Block malware, ransomware, exploits, C2 traffic using threat profiles
- Network Segmentation: Isolate critical assets, implement zero trust microsegmentation
- Compliance Enforcement: Apply URL filtering, file blocking, data loss prevention
- Service Application: Implement DNS security, SSL decryption, QoS policies

Rule Management Best Practices:
- Rule naming conventions and documentation
- Regular rule review and cleanup (unused, shadowed, overly permissive)
- Testing policies before production deployment
- Using rule tags for organization and reporting
- Implementing least privilege access principles
- Separating administrative access from user traffic policies

Career Path and Growth:
- Entry level: Junior Network Security Admin, SOC Analyst
- Mid level: Network Security Engineer, Firewall Administrator
- Senior level: Senior Security Engineer, Security Architect
- Leadership: Security Manager, Director of Network Security, CISO path

Include real-world scenarios, interview questions, and practical examples.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== NETWORKING TOPICS (Priority 2) ====================

    "osi-model": {
        "description": "OSI 7-layer model and network protocols",
        "prompt_template": """Generate {count} Q&A pairs about the OSI model and network protocols.

Topics to cover in depth:
- Layer 1 (Physical): Cables (Cat5e, Cat6, fiber), connectors (RJ45, SFP, QSFP), signaling, hubs, repeaters, physical topologies, bit transmission.
- Layer 2 (Data Link): MAC addresses, Ethernet frames, switches, VLANs, STP/RSTP/MSTP, ARP, broadcast domains, MAC address tables, port security.
- Layer 3 (Network): IP addressing (IPv4 and IPv6), subnetting, CIDR, routing, ICMP, routers, routing tables, packet forwarding, TTL, fragmentation.
- Layer 4 (Transport): TCP (three-way handshake, flow control, congestion control, reliability), UDP, ports, sockets, segments, NAT/PAT.
- Layer 5 (Session): Session establishment, maintenance, termination, NetBIOS, RPC, session multiplexing.
- Layer 6 (Presentation): Data formatting, encryption/decryption, compression, character encoding (ASCII, UTF-8), TLS/SSL handshake.
- Layer 7 (Application): HTTP/HTTPS, DNS, SMTP, FTP, SSH, DHCP, SNMP, application protocols, APIs.

Additional concepts:
- Protocol Data Units (PDUs) at each layer: bits, frames, packets, segments, data
- Encapsulation and de-encapsulation process
- Troubleshooting by layer (physical connectivity, L2 switching issues, L3 routing, L4 firewall rules, application issues)
- How protocols map to OSI layers
- TCP/IP model comparison (4 layers vs 7 layers)
- Common network tools for each layer (cable testers, Wireshark, traceroute, netstat, curl)

Provide practical examples and real troubleshooting scenarios.
Format as JSON with "question" and "answer" fields."""
    },

    "routing-switching": {
        "description": "Routing protocols and switching concepts",
        "prompt_template": """Generate {count} Q&A pairs about routing and switching.

Routing Topics:
- Static Routing: Configuration, floating static routes, default routes, next-hop vs exit interface.
- OSPF: Areas, LSA types, DR/BDR election, cost calculation, route summarization, stub areas, NSSA, virtual links, authentication.
- BGP: eBGP vs iBGP, AS numbers, path attributes (AS_PATH, LOCAL_PREF, MED, NEXT_HOP), route filtering, prefix lists, route maps, communities, confederation, route reflectors.
- EIGRP: Metric calculation (bandwidth, delay, reliability, load), feasible successor, successor, stuck-in-active, named mode configuration.
- RIP: RIPv1 vs RIPv2, hop count, split horizon, route poisoning (legacy protocol).
- IS-IS: Area types, NET addressing, DIS election, level 1/2 routing.
- Route Redistribution: Between protocols, metric assignment, preventing routing loops, distribute lists.
- VRF: Virtual Routing and Forwarding, VRF-Lite, route leaking between VRFs.
- Policy-Based Routing: Route maps, match conditions, set actions, local policy routing.

Switching Topics:
- VLANs: VLAN creation, access ports, trunk ports (802.1Q), native VLAN, voice VLAN, private VLANs.
- STP/RSTP/MSTP: Root bridge election, port states, port roles, PortFast, BPDU Guard, Root Guard, Loop Guard, STP timers.
- EtherChannel/Port-Channel: LACP vs PAgP, load balancing methods, configuration.
- Inter-VLAN Routing: Router-on-a-stick, Layer 3 switches, SVI configuration.
- Layer 2 Security: Port security, DHCP snooping, Dynamic ARP Inspection, IP Source Guard, storm control.
- First Hop Redundancy: HSRP, VRRP, GLBP configuration, preemption, tracking.

Include vendor-neutral concepts and Cisco-specific CLI examples.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== SECURITY TOPICS (Priority 3) ====================

    "network-security-fundamentals": {
        "description": "Network security concepts and practices",
        "prompt_template": """Generate {count} Q&A pairs about network security fundamentals.

Topics to cover:
- Firewall Types and Architectures: Packet filtering, stateful inspection, application layer (proxy), next-generation firewalls (NGFW), cloud firewalls, WAF.
- VPN Technologies: IPSec (IKE phases, ESP, AH, tunnel vs transport mode), SSL/TLS VPN, WireGuard, site-to-site vs remote access, split tunneling.
- Network Segmentation: VLANs, subnets, micro-segmentation, DMZ design, internal segmentation firewalls.
- Zero Trust Architecture: Principles (never trust, always verify), identity-centric security, least privilege, continuous verification, microsegmentation, ZTNA.
- Network Access Control (NAC): 802.1X authentication, RADIUS, TACACS+, posture assessment, guest access, quarantine VLANs.
- Encryption: Symmetric vs asymmetric, TLS 1.2/1.3, certificate management, PKI, key exchange algorithms, cipher suites.
- DDoS Protection: Attack types (volumetric, protocol, application), mitigation strategies, rate limiting, blackholing, scrubbing centers.
- Network Security Monitoring: NetFlow/IPFIX, packet capture, IDS/IPS placement, network taps, SPAN ports.
- Security Zones: Trust levels, zone-based policies, inter-zone traffic control, zone design best practices.
- Defense in Depth: Layered security approach, security controls at each layer, redundancy in security measures.
- Wireless Security: WPA3, 802.1X for wireless, rogue AP detection, wireless IDS, secure guest networks.
- Email Security: SPF, DKIM, DMARC, email gateways, anti-phishing controls.

Include implementation examples and security best practices.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== COMPLIANCE TOPICS (Priority 4) ====================

    "infosec-policies": {
        "description": "Information security policies and governance",
        "prompt_template": """Generate {count} Q&A pairs about InfoSec policies and governance.

Topics to cover:
- Security Policy Development: Policy hierarchy (policies, standards, procedures, guidelines), policy lifecycle, stakeholder involvement, policy exceptions.
- Acceptable Use Policy (AUP): Scope, acceptable behavior, prohibited activities, monitoring disclosure, consequences of violation.
- Data Classification: Classification levels (public, internal, confidential, restricted), handling requirements, labeling, data lifecycle.
- Access Control Policy: Least privilege, need-to-know, role-based access, account management, privileged access management, access reviews.
- Incident Response Policy: IR team structure, incident classification, escalation procedures, communication plans, post-incident review.
- Business Continuity and Disaster Recovery: BIA (Business Impact Analysis), RTO/RPO, DR site types (hot/warm/cold), testing requirements.
- Compliance Frameworks:
  - PCI-DSS: 12 requirements, SAQ types, scope reduction, compensating controls, annual assessment.
  - HIPAA: Privacy Rule, Security Rule, administrative/physical/technical safeguards, BAA requirements.
  - GDPR: Lawful basis, data subject rights, DPO requirements, breach notification, international transfers.
  - SOX: IT controls, segregation of duties, change management, access controls for financial systems.
  - SOC 2: Trust Service Criteria (security, availability, processing integrity, confidentiality, privacy), Type I vs Type II.
  - NIST Cybersecurity Framework: Identify, Protect, Detect, Respond, Recover functions.
- Risk Assessment: Risk identification, qualitative vs quantitative analysis, risk treatment options (accept, mitigate, transfer, avoid), risk register.
- Security Awareness Training: Training topics, frequency, phishing simulations, measuring effectiveness.
- Vendor Risk Management: Due diligence, security questionnaires, contract requirements, ongoing monitoring.
- Change Management: Change types, CAB reviews, emergency changes, rollback procedures.
- Asset Management: Hardware/software inventory, CMDB, asset lifecycle, disposal procedures.

Include real-world examples and compliance audit considerations.
Format as JSON with "question" and "answer" fields."""
    },

    "cissp-domains": {
        "description": "CISSP 8 domains knowledge",
        "prompt_template": """Generate {count} Q&A pairs covering the 8 CISSP domains.

Domain 1 - Security and Risk Management (15%):
- Security governance principles, compliance, legal/regulatory issues
- Professional ethics, security policies, risk management concepts
- Threat modeling, supply chain risk, security awareness training
- Business continuity planning

Domain 2 - Asset Security (10%):
- Information and asset classification, ownership
- Data privacy, retention, handling requirements
- Data security controls, data remanence

Domain 3 - Security Architecture and Engineering (13%):
- Security models (Bell-LaPadula, Biba, Clark-Wilson)
- Security architecture frameworks, cryptography
- Site and facility security, secure design principles
- Vulnerabilities in systems (hardware, firmware, software)

Domain 4 - Communication and Network Security (13%):
- Network architecture, protocols, components
- Secure network design, network attacks
- Securing network components, wireless security

Domain 5 - Identity and Access Management (13%):
- Physical and logical access control
- Identification, authentication, authorization
- Identity as a Service, federated identity
- Access control attacks and countermeasures

Domain 6 - Security Assessment and Testing (12%):
- Vulnerability assessment, penetration testing
- Security audits, log reviews
- Synthetic transactions, code review
- KPIs and metrics

Domain 7 - Security Operations (13%):
- Investigations, logging and monitoring
- Incident management, disaster recovery
- Resource protection, change management
- Patch and vulnerability management

Domain 8 - Software Development Security (11%):
- Security in SDLC, development methodologies
- Secure coding practices, code review
- Software security testing, APIs security
- DevSecOps concepts

Include exam-style questions and practical applications of each concept.
Reference relevant standards: NIST, ISO 27001/27002, COBIT, ITIL.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== CLOUD TOPICS (Priority 5) ====================

    "aws-networking": {
        "description": "AWS networking services and architecture",
        "prompt_template": """Generate {count} Q&A pairs about AWS networking.

Topics to cover:
- VPC Architecture: VPC design, CIDR planning, subnets (public, private, isolated), availability zones, VPC sizing best practices.
- Internet Connectivity: Internet Gateway, NAT Gateway vs NAT Instance, Egress-only Internet Gateway (IPv6).
- VPC Connectivity: VPC Peering (limitations, non-transitive), Transit Gateway (attachments, route tables, inter-region peering), PrivateLink.
- Hybrid Connectivity: AWS Direct Connect (dedicated vs hosted, LAG, virtual interfaces), Site-to-Site VPN (route-based vs policy-based, VPN CloudHub), Client VPN.
- Route 53: DNS management, routing policies (simple, weighted, latency, failover, geolocation, geoproximity, multivalue), health checks, private hosted zones.
- Load Balancing: Application Load Balancer (path-based, host-based routing, authentication), Network Load Balancer (static IP, preserve source IP), Gateway Load Balancer (inline appliances).
- VPC Security: Security Groups (stateful, rules evaluation), Network ACLs (stateless, numbered rules), security group referencing.
- VPC Endpoints: Gateway endpoints (S3, DynamoDB), Interface endpoints (PrivateLink), endpoint policies.
- AWS Network Firewall: Stateful and stateless rules, rule groups, domain filtering, IPS capabilities.
- CloudFront: CDN distribution, origins, cache behaviors, edge locations, signed URLs, WAF integration.
- Global Accelerator: Anycast IPs, endpoint groups, health checks, traffic dials.
- Network Monitoring: VPC Flow Logs (format, analysis), Traffic Mirroring, Reachability Analyzer, Network Access Analyzer.

Include AWS CLI commands and CloudFormation/Terraform examples.
Format as JSON with "question" and "answer" fields."""
    },

    "azure-networking": {
        "description": "Azure networking services and architecture",
        "prompt_template": """Generate {count} Q&A pairs about Azure networking.

Topics to cover:
- Virtual Networks (VNet): VNet design, address spaces, subnets, VNet integration, service endpoints, private endpoints.
- Connectivity: VNet Peering (global peering, gateway transit), Virtual WAN, hub-and-spoke topology.
- Hybrid Connectivity: ExpressRoute (private peering, Microsoft peering, Global Reach, FastPath), VPN Gateway (site-to-site, point-to-site, VNet-to-VNet), Azure Virtual WAN.
- Load Balancing: Azure Load Balancer (Standard vs Basic, internal vs public, HA ports), Application Gateway (WAF, URL-based routing, SSL termination, autoscaling), Azure Front Door (global load balancing, CDN, WAF).
- Traffic Manager: DNS-based load balancing, routing methods (priority, weighted, performance, geographic, multivalue, subnet).
- Azure DNS: Public and private DNS zones, alias records, zone delegation.
- Network Security: Network Security Groups (rules, application security groups, service tags), Azure Firewall (FQDN filtering, threat intelligence, TLS inspection), Azure DDoS Protection.
- Azure Bastion: Secure RDP/SSH access, bastion hosts, native client support.
- Private Link: Private endpoints, private link service, DNS integration.
- Network Monitoring: Network Watcher (IP flow verify, next hop, NSG diagnostics, packet capture, connection troubleshoot), Azure Monitor network insights.
- Azure Route Server: BGP peering with NVAs, route exchange.

Include Azure CLI, PowerShell, and ARM template examples.
Format as JSON with "question" and "answer" fields."""
    },

    "gcp-networking": {
        "description": "Google Cloud Platform networking",
        "prompt_template": """Generate {count} Q&A pairs about GCP networking.

Topics to cover:
- VPC Networks: VPC types (auto mode vs custom mode), subnets, regional resources, VPC sharing (Shared VPC, VPC peering).
- IP Addressing: Internal IP (primary, alias), external IP (ephemeral, static), Private Google Access, Private Service Connect.
- Firewall Rules: VPC firewall rules (ingress, egress), firewall policies (hierarchical, network), firewall rule logging, priority ordering.
- Cloud NAT: NAT gateway, static IP for NAT, port allocation, logging.
- Cloud Router: BGP configuration, custom route advertisements, route priority.
- Hybrid Connectivity: Cloud Interconnect (Dedicated, Partner), Cloud VPN (HA VPN, Classic VPN), Network Connectivity Center.
- Load Balancing: Global vs regional, external vs internal, HTTP(S) Load Balancer, TCP/SSL Proxy, Network Load Balancer, Internal TCP/UDP Load Balancer.
- Cloud CDN: Caching, cache modes, signed URLs, cache invalidation.
- Cloud DNS: Public and private zones, DNS policies, DNS forwarding, DNSSEC.
- Cloud Armor: DDoS protection, WAF rules, security policies, rate limiting.
- Network Intelligence Center: Network Topology, Connectivity Tests, Performance Dashboard, Firewall Insights.
- Service Directory: Service registration, service resolution, DNS integration.
- Traffic Director: Service mesh, Envoy proxy, advanced traffic management.

Include gcloud CLI commands and Terraform examples.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== THREAT DETECTION TOPICS (Priority 6) ====================

    "incident-response": {
        "description": "Incident response procedures and forensics",
        "prompt_template": """Generate {count} Q&A pairs about incident response.

Topics to cover:
- IR Phases (NIST SP 800-61):
  1. Preparation: IR team formation, playbooks, tools, training, communication plans, legal considerations.
  2. Detection & Analysis: Indicators of compromise, alert triage, severity classification, initial scoping.
  3. Containment: Short-term (isolate affected systems), long-term (patch, harden), evidence preservation during containment.
  4. Eradication: Malware removal, backdoor identification, root cause analysis, vulnerability remediation.
  5. Recovery: System restoration, service restoration, monitoring for re-infection, phased recovery.
  6. Post-Incident: Lessons learned, documentation, report writing, process improvements.

- Containment Strategies: Network isolation (VLAN changes, firewall rules), credential rotation, DNS sinkholing, account disabling.
- Evidence Preservation: Chain of custody, forensic imaging, memory acquisition, log preservation, legal hold procedures.
- Log Analysis: Timeline reconstruction, log correlation, key log sources (auth logs, firewall, proxy, DNS, endpoint).
- Malware Analysis Basics: Static analysis (strings, PE analysis), dynamic analysis (sandbox), behavioral indicators.
- Specific Incident Types:
  - Ransomware: Isolation, backup verification, decryption options, payment considerations, reporting.
  - Business Email Compromise: Account recovery, financial controls, user notification.
  - Data Breach: Scope determination, notification requirements, regulatory reporting timelines.
  - Insider Threat: Evidence collection, HR coordination, legal considerations.
- Communication: Internal stakeholders, executive briefings, external parties (customers, regulators, law enforcement).
- IR Metrics: MTTD (Mean Time to Detect), MTTR (Mean Time to Respond), dwell time, incident volume.
- Tools: SIEM, EDR, memory forensics (Volatility), disk forensics (Autopsy, FTK), network forensics (Wireshark, Zeek).
- Playbook Development: Playbook components, testing and exercises, automation opportunities.

Include practical procedures and tool-specific examples.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== NETWORK ENGINEERING TOPICS ====================

    "advanced-routing": {
        "description": "Advanced routing concepts for network engineers (BGP edge cases, MPLS, segment routing)",
        "prompt_template": """Generate {count} Q&A pairs about advanced routing for network engineers.

Topics to cover:
- Advanced BGP:
  - BGP path selection algorithm (all 13+ attributes in order)
  - BGP communities (standard, extended, large), community strings, regex filtering
  - BGP route filtering: prefix-lists, AS-path access-lists, route-maps, ORF
  - BGP convergence optimization: BFD, fast-failover, add-path, best-external
  - BGP security: RPKI/ROV, BGPsec, prefix filtering, max-prefix limits, GTSM
  - BGP troubleshooting: stuck in Active/Connect, attribute errors, route dampening
  - Internet peering: IXP connections, route servers, PNI, peering policies
  - BGP in datacenter: eBGP-only designs, RFC 7938, unnumbered BGP

- MPLS:
  - Label switching architecture: LSR, LER, LSP, label stack
  - LDP: label distribution, targeted LDP, LDP-IGP sync
  - MPLS Traffic Engineering: RSVP-TE, explicit paths, FRR, bandwidth constraints
  - MPLS VPN: L3VPN (VRF, RD, RT), L2VPN (VPLS, EVPN)
  - Segment Routing: SR-MPLS, prefix SIDs, adjacency SIDs, TI-LFA
  - SR-TE: explicit segment lists, on-demand nexthop, PCE integration

- Advanced OSPF/IS-IS:
  - Multi-area design: stub areas, NSSA, totally stubby, area summarization
  - OSPF database optimization: stub routers, max-metric, prefix suppression
  - IS-IS: level 1/2 routing, route leaking, overload bit
  - Fast convergence: SPF tuning, LSA throttling, incremental SPF

- Advanced Routing Concepts:
  - Policy-based routing: match conditions, set actions, local policy routing
  - VRF-Lite and VRF route leaking between instances
  - BFD: single-hop, multi-hop, micro-BFD for LAG
  - GRE/IPsec tunnels: recursive routing issues, tunnel keepalives

Include CLI examples for Cisco IOS-XE, IOS-XR, and Junos where applicable.
Format as JSON with "question" and "answer" fields."""
    },

    "datacenter-networking": {
        "description": "Datacenter networking (spine-leaf, VXLAN, EVPN, fabric automation)",
        "prompt_template": """Generate {count} Q&A pairs about datacenter networking.

Topics to cover:
- Datacenter Architectures:
  - Traditional 3-tier: access, aggregation, core (and why it's being replaced)
  - Spine-leaf (Clos) topology: design principles, oversubscription ratios, scaling
  - Fat-tree networks: pod design, bisectional bandwidth
  - Multi-tier Clos: super-spines, datacenter interconnect (DCI)

- VXLAN:
  - VXLAN fundamentals: VNI, VTEP, encapsulation format, UDP port 4789
  - Flood-and-learn VXLAN: multicast groups, ingress replication
  - VXLAN with MP-BGP EVPN: type-2 (MAC/IP), type-5 (IP prefix) routes
  - Symmetric vs asymmetric IRB: distributed anycast gateway
  - VXLAN troubleshooting: show nve peers, show l2route evpn, show bgp l2vpn evpn

- EVPN:
  - EVPN route types (1-5): auto-discovery, MAC/IP, multicast, ES, IP prefix
  - Multi-homing: ESI, designated forwarder election, all-active vs single-active
  - EVPN-VXLAN fabric design: border leafs, external connectivity
  - EVPN for DCI: stretched VLANs, type-5 routes, RT/RD considerations

- Datacenter Switching:
  - High-density switching: merchant silicon (Memory, Memory, Memory, Memory, Memory)
  - Buffer sizing: shallow vs deep buffers, microburst handling
  - ECMP in datacenters: 5-tuple hashing, polarization, resilient hashing
  - QoS in DC: DSCP marking, ECN for RDMA, PFC for lossless Ethernet

- Datacenter Interconnect (DCI):
  - OTV: overlay transport virtualization for L2 extension
  - VXLAN over DCI: multi-site EVPN, anycast RP for BUM traffic
  - Dark fiber, DWDM, and metro Ethernet for DCI links

- Automation and Orchestration:
  - Network automation tools: Ansible, Terraform, Nornir, NAPALM
  - Intent-based networking: Cisco ACI, VMware NSX, Arista CloudVision
  - API-driven configuration: RESTCONF, NETCONF, gNMI/gRPC
  - Infrastructure as Code: GitOps for network, CI/CD pipelines

Include real datacenter design scenarios and configuration examples.
Format as JSON with "question" and "answer" fields."""
    },

    "sdn-nfv": {
        "description": "Software-Defined Networking and Network Functions Virtualization",
        "prompt_template": """Generate {count} Q&A pairs about SDN and NFV.

Topics to cover:
- SDN Fundamentals:
  - SDN architecture: control plane, data plane, management plane separation
  - OpenFlow: flow tables, match fields, actions, pipeline processing
  - SDN controllers: OpenDaylight, ONOS, Ryu, Floodlight
  - Northbound and southbound APIs: REST APIs, OpenFlow, NETCONF
  - SDN use cases: traffic engineering, network slicing, micro-segmentation

- NFV Architecture:
  - NFV framework: NFVI, VNF, MANO (Management and Orchestration)
  - VNF types: virtual routers, firewalls, load balancers, WAN optimizers
  - NFVI infrastructure: compute, storage, networking for VNFs
  - Service chaining: SFC, NSH (Network Service Header), traffic steering
  - VNF lifecycle management: instantiation, scaling, healing, termination

- SDN/NFV Platforms:
  - VMware NSX-T: segments, T0/T1 gateways, distributed firewall, micro-segmentation
  - Cisco ACI: EPG, contracts, bridge domains, fabric discovery
  - OpenStack Networking (Neutron): networks, subnets, routers, security groups
  - Kubernetes networking: CNI, Calico, Cilium, service mesh integration

- SD-WAN:
  - SD-WAN architecture: overlay, underlay, controller, edge devices
  - SD-WAN vendors: Cisco Viptela, VMware VeloCloud, Fortinet, Palo Alto Prisma SD-WAN
  - Transport independence: MPLS, broadband, LTE/5G, satellite
  - Application-aware routing: DPI, SLA measurement, path selection
  - SD-WAN security: integration with SASE, cloud security services

- Network Programmability:
  - Python for networking: netmiko, napalm, ncclient, pyATS/Genie
  - Ansible network modules: ios_config, nxos_config, junos_config
  - YANG data models: device models, service models, deviation handling
  - RESTCONF/NETCONF: GET, PATCH, PUT operations, RPC calls
  - Streaming telemetry: gNMI, model-driven telemetry, dial-in vs dial-out

- Modern Network Paradigms:
  - Intent-Based Networking (IBN): business intent translation, closed-loop automation
  - Network as a Service (NaaS): consumption models, API-first design
  - GitOps for networking: version control, pull requests, automated testing
  - Infrastructure as Code: Terraform providers, Pulumi, Crossplane

Include practical examples with code snippets and CLI configurations.
Format as JSON with "question" and "answer" fields."""
    },

    "network-automation": {
        "description": "Network automation with Python, Ansible, and modern tooling",
        "prompt_template": """Generate {count} Q&A pairs about network automation.

Topics to cover:
- Python for Network Automation:
  - Netmiko: SSH connections, send_command, send_config_set, handling prompts
  - NAPALM: get_facts, get_interfaces, get_bgp_neighbors, configuration replace/merge
  - Nornir: inventory management, task execution, threading, filtering hosts
  - pyATS/Genie: testbed, device connections, parsers, Dq queries
  - Paramiko: low-level SSH, SFTP file transfers
  - Requests: REST API calls, authentication, JSON handling

- Ansible for Networking:
  - Network modules: ios_command, nxos_config, junos_config, eos_config
  - Ansible inventory: hosts, groups, host_vars, group_vars
  - Playbook structure: tasks, handlers, roles, includes
  - Network resource modules: interfaces, l3_interfaces, bgp_global, acls
  - Ansible Tower/AWX: job templates, surveys, credentials, RBAC
  - Error handling: ignore_errors, block/rescue, failed_when

- Configuration Management:
  - Jinja2 templating: variables, loops, conditionals, filters, macros
  - Template inheritance: base templates, child templates, blocks
  - Configuration validation: pre/post checks, compliance verification
  - Config diff and rollback: generating diffs, rollback procedures

- Data Formats and Parsing:
  - TextFSM: parsing unstructured CLI output, NTC-templates
  - TTP: Template Text Parser, more Python-like syntax
  - Regular expressions: pattern matching for network data
  - YAML/JSON: structured data for automation, schema validation

- Source Control and CI/CD:
  - Git for network configs: branching strategies, merge requests
  - Pre-commit hooks: linting, syntax checking, secret scanning
  - CI/CD pipelines: GitLab CI, GitHub Actions, Jenkins for network
  - Testing: Batfish for config validation, robot framework, pytest

- API Automation:
  - REST APIs: GET, POST, PUT, DELETE, PATCH operations
  - NETCONF: edit-config, get-config, RPC calls, capabilities
  - gNMI/gRPC: streaming telemetry, configuration management
  - GraphQL: flexible queries, mutations, subscriptions

- Automation Best Practices:
  - Idempotency: ensuring consistent results on repeated runs
  - Error handling: graceful failures, logging, notifications
  - Secrets management: Ansible Vault, HashiCorp Vault, environment variables
  - Documentation: auto-generating docs, inline comments, README files

Include working code examples with explanations.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== SECOPS TOPICS ====================

    "soc-operations": {
        "description": "Security Operations Center (SOC) operations and procedures",
        "prompt_template": """Generate {count} Q&A pairs about SOC operations.

Topics to cover:
- SOC Structure and Roles:
  - SOC tiers: Tier 1 (alert triage), Tier 2 (investigation), Tier 3 (threat hunting/engineering)
  - SOC roles: analysts, engineers, threat hunters, incident responders, SOC manager
  - 24/7 operations: shift handoff, escalation procedures, on-call rotations
  - SOC metrics: MTTD, MTTR, alert volume, false positive rate, SLA adherence

- Alert Triage and Investigation:
  - Alert prioritization: severity scoring, asset criticality, threat intelligence enrichment
  - Initial triage: true positive vs false positive determination, context gathering
  - Investigation workflow: hypothesis formation, evidence collection, timeline building
  - Escalation criteria: when to escalate, who to notify, documentation requirements

- SIEM Operations:
  - SIEM platforms: Splunk, Microsoft Sentinel, Elastic SIEM, QRadar, Chronicle
  - Log sources: firewall, proxy, EDR, authentication, cloud, network flow
  - Use case development: detection rules, correlation rules, behavioral analytics
  - Alert tuning: reducing false positives, threshold adjustment, whitelist management
  - Dashboard creation: executive dashboards, operational dashboards, KPI tracking

- Security Monitoring:
  - Network monitoring: IDS/IPS alerts, NetFlow analysis, packet capture
  - Endpoint monitoring: EDR alerts, process execution, file integrity monitoring
  - Identity monitoring: failed logins, privilege escalation, account anomalies
  - Cloud monitoring: CloudTrail, Azure Activity Logs, GCP Audit Logs
  - Email security: phishing detection, malware attachments, BEC indicators

- SOC Tooling:
  - SOAR platforms: Splunk SOAR, Palo Alto XSOAR, IBM Resilient, Swimlane
  - Threat intelligence platforms: MISP, ThreatConnect, Anomali, Recorded Future
  - Ticketing systems: ServiceNow, Jira, TheHive for case management
  - Communication: Slack/Teams integration, PagerDuty, on-call management

- SOC Processes:
  - Runbooks and playbooks: standard operating procedures, decision trees
  - Knowledge management: wiki, case documentation, lessons learned
  - Continuous improvement: after-action reviews, process optimization
  - Training: tabletop exercises, purple team exercises, certification paths

Include practical examples of SOC workflows and decision-making.
Format as JSON with "question" and "answer" fields."""
    },

    "threat-hunting": {
        "description": "Proactive threat hunting techniques and methodologies",
        "prompt_template": """Generate {count} Q&A pairs about threat hunting.

Topics to cover:
- Threat Hunting Fundamentals:
  - Definition: proactive search for threats that evade automated detection
  - Hunt types: hypothesis-driven, IOC-based, machine learning-assisted
  - Hunting vs detection: proactive vs reactive, human-led vs automated
  - MITRE ATT&CK: tactics, techniques, procedures (TTPs) for hunt hypotheses

- Hunt Methodologies:
  - Hypothesis-driven hunting: developing hypotheses from threat intel, TTPs
  - Intel-driven hunting: using IOCs, threat reports, vulnerability disclosures
  - Situational awareness hunting: baseline anomalies, environmental changes
  - Hunt cycle: hypothesis, data collection, analysis, findings, improvement

- Data Sources for Hunting:
  - Endpoint data: process execution, file creation, registry changes, network connections
  - Network data: DNS queries, HTTP/S traffic, lateral movement indicators
  - Authentication data: logon events, Kerberos tickets, service accounts
  - Cloud data: API calls, resource creation, permission changes

- Hunting Techniques by ATT&CK Tactic:
  - Initial Access: phishing indicators, web shells, exploit attempts
  - Execution: PowerShell, WMI, scheduled tasks, script interpreters
  - Persistence: registry run keys, services, startup folders, DLL hijacking
  - Privilege Escalation: token manipulation, UAC bypass, exploits
  - Defense Evasion: process injection, timestomping, log clearing
  - Credential Access: Mimikatz patterns, LSASS access, credential dumping
  - Discovery: network scanning, account enumeration, system info gathering
  - Lateral Movement: PsExec, WMI, RDP, SSH, pass-the-hash/ticket
  - Collection: data staging, clipboard data, screen capture
  - Exfiltration: large data transfers, DNS tunneling, cloud storage
  - Command and Control: beaconing patterns, unusual ports, domain fronting

- Hunt Tools:
  - Endpoint: Velociraptor, OSQuery, Carbon Black, CrowdStrike
  - Network: Zeek, Rita, NetworkMiner, Arkime (Moloch)
  - SIEM queries: Splunk SPL, KQL for Sentinel, Elastic EQL
  - Memory analysis: Volatility, Rekall, memory acquisition tools

- Threat Hunting in Practice:
  - Documentation: hunt hypotheses, methodology, findings, recommendations
  - Turning hunts into detections: creating rules from hunt findings
  - Metrics: hunts conducted, findings per hunt, detections created
  - Knowledge sharing: threat intel sharing, community collaboration

Include specific hunt queries and detection patterns.
Format as JSON with "question" and "answer" fields."""
    },

    "security-monitoring": {
        "description": "Security monitoring, log analysis, and detection engineering",
        "prompt_template": """Generate {count} Q&A pairs about security monitoring and detection engineering.

Topics to cover:
- Log Collection and Management:
  - Log sources: Windows Event Logs, syslog, application logs, cloud logs
  - Log forwarding: syslog-ng, rsyslog, NXLog, Beats, Fluentd
  - Log aggregation: centralized logging, log retention, storage considerations
  - Log normalization: field mapping, timestamp standardization, enrichment

- Windows Event Logging:
  - Key event IDs: 4624/4625 (logon), 4688 (process), 4672 (privileges), 4720 (account created)
  - Security log: authentication, authorization, policy changes
  - Sysmon: process creation, network connections, file creation, registry
  - PowerShell logging: script block, module, transcription logging
  - Advanced audit policies: enabling detailed logging, GPO configuration

- Linux/Unix Logging:
  - Auth logs: /var/log/auth.log, /var/log/secure
  - Syslog: facility, severity, message format
  - Auditd: syscall monitoring, file access, user actions
  - Journal: systemd journal, journalctl queries

- Network Security Monitoring:
  - Zeek (Bro): connection logs, DNS logs, HTTP logs, SSL logs, notices
  - NetFlow/IPFIX: traffic metadata, flow analysis, anomaly detection
  - Packet capture: full PCAP, triggered capture, retention policies
  - DNS monitoring: query logs, DGA detection, tunneling detection

- Detection Engineering:
  - Detection types: signature, behavioral, anomaly, heuristic
  - Sigma rules: vendor-agnostic detection format, rule structure, conversion
  - YARA rules: malware detection, file scanning, memory scanning
  - Detection-as-Code: version control, testing, CI/CD for detections

- SIEM Query Languages:
  - Splunk SPL: search, stats, eval, rex, lookup, subsearch
  - Microsoft KQL: where, project, summarize, join, let
  - Elastic EQL: event queries, sequences, pipes
  - Chronicle YARA-L: rule structure, functions, variables

- Alert Management:
  - Alert fatigue: causes, impacts, mitigation strategies
  - Alert prioritization: severity, confidence, asset criticality
  - Tuning detections: reducing false positives, adding context
  - Alert lifecycle: creation, triage, investigation, closure

- Detection Metrics:
  - Coverage: MITRE ATT&CK coverage mapping
  - Quality: true positive rate, false positive rate
  - Timeliness: detection latency, MTTD
  - Maintenance: rule review cadence, deprecation process

Include specific detection rules and query examples.
Format as JSON with "question" and "answer" fields."""
    },

    "vulnerability-management": {
        "description": "Vulnerability scanning, assessment, and remediation",
        "prompt_template": """Generate {count} Q&A pairs about vulnerability management.

Topics to cover:
- Vulnerability Management Program:
  - VM lifecycle: discover, prioritize, remediate, verify, report
  - Asset inventory: CMDB integration, asset discovery, criticality classification
  - Scanning cadence: frequency, authenticated vs unauthenticated, agent vs agentless
  - Risk-based prioritization: CVSS, EPSS, asset criticality, threat intelligence

- Vulnerability Scanning:
  - Scanner types: network scanners, web application scanners, container scanners
  - Commercial tools: Nessus, Qualys, Rapid7 InsightVM, Tenable.io
  - Open source: OpenVAS, Nuclei, Nikto, OWASP ZAP
  - Cloud-native: AWS Inspector, Azure Defender, GCP Security Command Center
  - Credential management: scan accounts, least privilege, secure storage

- Vulnerability Prioritization:
  - CVSS scoring: base, temporal, environmental scores, CVSS v3.1 vectors
  - EPSS: Exploit Prediction Scoring System, probability-based prioritization
  - CISA KEV: Known Exploited Vulnerabilities catalog, BOD 22-01
  - Threat intelligence: active exploitation, weaponization, attacker interest
  - Business context: asset criticality, data sensitivity, exposure

- Remediation Strategies:
  - Patching: regular patch cycles, emergency patches, testing requirements
  - Compensating controls: network segmentation, WAF rules, access restrictions
  - Virtual patching: IPS signatures, WAF rules for unpatched systems
  - Risk acceptance: documentation, approval process, expiration dates
  - SLA management: remediation timelines by severity

- Web Application Vulnerabilities:
  - OWASP Top 10: injection, broken auth, XSS, insecure design, misconfig
  - DAST vs SAST: dynamic vs static analysis, when to use each
  - API security: OWASP API Top 10, authentication, rate limiting
  - Bug bounty: scope, rules, payouts, platform selection

- Container and Cloud Vulnerabilities:
  - Container scanning: image scanning, registry integration, admission control
  - Infrastructure as Code scanning: Terraform, CloudFormation security checks
  - CSPM: cloud security posture management, misconfiguration detection
  - CWPP: cloud workload protection, runtime security

- Vulnerability Reporting:
  - Metrics: vulnerability count, MTTR, SLA compliance, risk reduction
  - Executive reporting: risk trends, remediation progress, exceptions
  - Technical reporting: detailed findings, remediation guidance, evidence
  - Compliance reporting: audit requirements, control mapping

Include practical examples of vulnerability assessment and remediation.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== APPLICATION TEAM TOPICS ====================

    "api-gateway": {
        "description": "API gateway configuration, security, and management",
        "prompt_template": """Generate {count} Q&A pairs about API gateways.

Topics to cover:
- API Gateway Fundamentals:
  - Purpose: single entry point, request routing, cross-cutting concerns
  - Architecture patterns: gateway per team, BFF (Backend for Frontend), shared gateway
  - API gateway vs load balancer vs reverse proxy: when to use each
  - Common platforms: Kong, AWS API Gateway, Azure API Management, Apigee, Nginx

- Traffic Management:
  - Request routing: path-based, header-based, query parameter routing
  - Load balancing: round-robin, least connections, weighted, consistent hashing
  - Rate limiting: per-client, per-API, sliding window, token bucket
  - Request/response transformation: header manipulation, body transformation
  - Caching: response caching, cache invalidation, cache-control headers

- API Security:
  - Authentication: API keys, OAuth 2.0/OIDC, JWT validation, mTLS
  - Authorization: scope validation, RBAC, ABAC, policy enforcement
  - Input validation: schema validation, request size limits, content type restrictions
  - Threat protection: SQL injection, XSS, command injection blocking
  - Bot protection: bot detection, CAPTCHA, behavioral analysis

- API Gateway Platforms:
  - Kong: plugins (rate-limiting, auth, logging), declarative config, DB-less mode
  - AWS API Gateway: REST vs HTTP APIs, Lambda integration, usage plans
  - Azure API Management: policies, products, subscriptions, developer portal
  - Nginx/NGINX Plus: location blocks, upstream configuration, lua scripting
  - Envoy: xDS APIs, filters, observability features

- Observability:
  - Logging: access logs, error logs, structured logging, log aggregation
  - Metrics: latency, throughput, error rates, upstream health
  - Tracing: distributed tracing, trace context propagation, correlation IDs
  - Dashboards: Grafana, Kibana, CloudWatch, custom dashboards

- API Lifecycle Management:
  - Versioning: URL versioning, header versioning, deprecation strategies
  - Documentation: OpenAPI/Swagger, API catalogs, developer experience
  - Testing: contract testing, mocking, load testing
  - Deployment: blue-green, canary, feature flags for APIs

- API Gateway Operations:
  - High availability: clustering, failover, multi-region deployment
  - Configuration management: GitOps, declarative configuration, secrets
  - Performance tuning: connection pooling, keep-alive, buffer sizes
  - Troubleshooting: debugging requests, latency analysis, error investigation

Include configuration examples for popular API gateway platforms.
Format as JSON with "question" and "answer" fields."""
    },

    "service-mesh": {
        "description": "Service mesh architecture (Istio, Envoy, Linkerd)",
        "prompt_template": """Generate {count} Q&A pairs about service mesh.

Topics to cover:
- Service Mesh Fundamentals:
  - What is a service mesh: sidecar proxy pattern, control plane vs data plane
  - Why use a service mesh: observability, security, traffic management at scale
  - Service mesh vs API gateway: complementary roles, when to use each
  - Architecture: sidecar injection, control plane components, data plane proxies

- Istio:
  - Architecture: istiod (control plane), Envoy sidecars, ingress/egress gateways
  - Installation: istioctl, Helm, operator-based installation
  - Traffic management: VirtualService, DestinationRule, Gateway, ServiceEntry
  - Security: mTLS (STRICT, PERMISSIVE), AuthorizationPolicy, PeerAuthentication
  - Observability: Kiali, Jaeger, Prometheus metrics, access logging
  - Troubleshooting: istioctl analyze, proxy-status, proxy-config

- Envoy Proxy:
  - Architecture: listeners, filter chains, clusters, routes
  - Configuration: static config, dynamic (xDS), ADS, gRPC-based config
  - Filters: HTTP connection manager, router, rate limit, fault injection
  - Load balancing: round-robin, least request, ring hash, maglev
  - Health checking: active, passive, outlier detection, ejection

- Linkerd:
  - Architecture: control plane (destination, identity, proxy-injector), data plane
  - Installation: linkerd CLI, Helm, GitOps-friendly
  - Traffic management: ServiceProfile, TrafficSplit, HTTPRoute
  - Security: automatic mTLS, identity-based authorization
  - Observability: Linkerd Viz, built-in Prometheus, Grafana dashboards

- Traffic Management:
  - Routing: header-based, path-based, weight-based traffic splitting
  - Resilience: retries, timeouts, circuit breaking, outlier detection
  - Canary deployments: gradual traffic shifting, automated rollback
  - A/B testing: user-based routing, header-based splitting
  - Fault injection: delay injection, abort injection for chaos testing

- Service Mesh Security:
  - mTLS: certificate management, trust domains, certificate rotation
  - Authorization: deny-by-default, allow lists, RBAC policies
  - External authorization: OPA integration, custom auth services
  - Egress control: controlling outbound traffic, external service access

- Service Mesh Operations:
  - Sidecar resource management: CPU/memory limits, proxy tuning
  - Upgrade strategies: canary upgrades, revision-based upgrades
  - Multi-cluster mesh: primary-remote, multi-primary configurations
  - Debugging: proxy logs, envoy admin interface, tcpdump in sidecar

Include YAML configuration examples and troubleshooting procedures.
Format as JSON with "question" and "answer" fields."""
    },

    "dns-fundamentals": {
        "description": "DNS architecture, troubleshooting, and security for application teams",
        "prompt_template": """Generate {count} Q&A pairs about DNS for application teams.

Topics to cover:
- DNS Fundamentals:
  - DNS hierarchy: root, TLD, authoritative, recursive resolvers
  - Record types: A, AAAA, CNAME, MX, TXT, SRV, NS, SOA, PTR
  - TTL: caching behavior, propagation delays, TTL best practices
  - DNS resolution process: iterative vs recursive queries, caching layers

- DNS for Applications:
  - Service discovery: internal DNS, Kubernetes DNS, Consul DNS
  - Load balancing via DNS: round-robin, weighted, GeoDNS
  - CDN integration: CNAME to CDN, Anycast DNS
  - Multi-region routing: GeoDNS, latency-based routing, failover

- Kubernetes DNS:
  - CoreDNS: configuration, plugins, performance tuning
  - Service DNS: service-name.namespace.svc.cluster.local
  - Pod DNS: pod-ip.namespace.pod.cluster.local
  - External DNS: ExternalDNS controller, cloud provider integration
  - Headless services: direct pod IP resolution, StatefulSet DNS

- Cloud DNS Services:
  - AWS Route 53: hosted zones, routing policies, health checks, alias records
  - Azure DNS: public/private zones, alias records, Traffic Manager integration
  - GCP Cloud DNS: managed zones, DNS policies, DNSSEC
  - Cloudflare DNS: proxy mode, page rules, Workers integration

- DNS Security:
  - DNSSEC: signing, validation, key management, DS records
  - DNS over HTTPS (DoH) / DNS over TLS (DoT): privacy, implementation
  - DNS filtering: category-based blocking, threat intelligence feeds
  - DNS-based threats: DNS hijacking, cache poisoning, tunneling detection
  - CAA records: certificate authority authorization, issuance control

- DNS Troubleshooting:
  - Diagnostic tools: dig, nslookup, host, drill
  - Common issues: NXDOMAIN, SERVFAIL, resolution timeouts
  - Propagation checking: TTL expiry, checking multiple resolvers
  - Split-horizon DNS: internal vs external resolution issues
  - DNS debugging in containers: resolv.conf, ndots setting, search domains

- DNS Best Practices:
  - Record management: IaC for DNS, change management, audit logging
  - TTL strategy: low TTL for failover, higher for stable records
  - Redundancy: multiple NS records, anycast, multi-provider DNS
  - Performance: resolver selection, caching, prefetching
  - Migration: planned migrations, TTL reduction, rollback procedures

Include command-line examples and cloud console instructions.
Format as JSON with "question" and "answer" fields."""
    },

    "load-balancing": {
        "description": "Load balancer configuration and application delivery",
        "prompt_template": """Generate {count} Q&A pairs about load balancing for application teams.

Topics to cover:
- Load Balancing Fundamentals:
  - Purpose: high availability, scalability, traffic distribution
  - L4 vs L7 load balancing: TCP/UDP vs HTTP/HTTPS, use cases
  - Load balancing algorithms: round-robin, least connections, weighted, IP hash
  - Health checks: TCP, HTTP, custom health endpoints, check intervals

- Load Balancer Types:
  - Hardware load balancers: F5 BIG-IP, Citrix ADC (NetScaler), A10
  - Software load balancers: HAProxy, Nginx, Envoy, Traefik
  - Cloud load balancers: AWS ALB/NLB/GLB, Azure LB/AppGW, GCP LB
  - Container-native: Kubernetes Service, Ingress controllers, service mesh

- HTTP/HTTPS Load Balancing:
  - Virtual hosts: host-based routing, SNI for TLS
  - Path-based routing: URL path routing, rewrite rules
  - Header-based routing: custom headers, cookies, user-agent
  - SSL/TLS termination: certificate management, cipher suites, HSTS
  - HTTP/2 and HTTP/3: protocol support, multiplexing, QUIC

- Session Persistence:
  - Sticky sessions: cookie-based, source IP, session affinity
  - Session replication: shared session stores, JWT tokens
  - Persistence challenges: scaling, failover, cache invalidation
  - When to avoid persistence: stateless design, API backends

- Advanced Features:
  - Connection draining: graceful shutdown, deployment support
  - Rate limiting: per-client limits, DDoS protection
  - Request/response transformation: header manipulation, compression
  - Content-based routing: JSON body inspection, gRPC routing
  - WebSocket support: upgrade handling, connection persistence

- Cloud Load Balancing:
  - AWS: ALB (L7), NLB (L4), CLB (classic), GLB (gateway)
  - Azure: Load Balancer (L4), Application Gateway (L7), Front Door (global)
  - GCP: HTTP(S) LB, TCP/UDP LB, Internal LB, Traffic Director
  - Cross-region load balancing: global server load balancing, failover

- Kubernetes Ingress:
  - Ingress controllers: Nginx, Traefik, HAProxy, AWS ALB controller
  - Ingress resources: rules, TLS, annotations, path types
  - IngressClass: controller selection, default class
  - Gateway API: new standard, HTTPRoute, TCPRoute, TLSRoute

- Troubleshooting:
  - Health check failures: application issues, network problems
  - Connection errors: timeouts, 502/503/504 errors
  - Performance issues: latency, throughput, connection limits
  - SSL/TLS issues: certificate chain, cipher mismatches, OCSP

Include configuration examples for popular load balancers.
Format as JSON with "question" and "answer" fields."""
    },

    "microservices-networking": {
        "description": "Networking for microservices and distributed applications",
        "prompt_template": """Generate {count} Q&A pairs about microservices networking.

Topics to cover:
- Microservices Communication:
  - Synchronous: REST, gRPC, GraphQL
  - Asynchronous: message queues (Kafka, RabbitMQ, SQS), event streaming
  - Service-to-service: direct calls, service mesh, API gateway
  - Protocol selection: JSON/HTTP vs Protobuf/gRPC, when to use each

- Service Discovery:
  - Client-side discovery: service registry lookup, load balancing in client
  - Server-side discovery: load balancer in front of instances
  - Service registries: Consul, etcd, ZooKeeper, Eureka
  - Kubernetes service discovery: DNS, environment variables, API

- gRPC:
  - Protocol: HTTP/2, Protobuf serialization, streaming
  - Service definition: .proto files, message types, service definitions
  - Load balancing: client-side, proxy-based (Envoy), service mesh
  - gRPC-Web: browser support, proxying requirements
  - Health checking: gRPC health checking protocol, Kubernetes integration

- Message Queues and Event Streaming:
  - Kafka: topics, partitions, consumer groups, offset management
  - RabbitMQ: exchanges, queues, bindings, acknowledgments
  - AWS SQS/SNS: standard vs FIFO, fan-out patterns
  - Event-driven patterns: event sourcing, CQRS, saga pattern

- API Design:
  - REST best practices: resource naming, HTTP methods, status codes
  - API versioning: URL, header, query parameter versioning
  - Pagination: cursor-based, offset-based, keyset pagination
  - Error handling: error codes, problem details (RFC 7807)
  - Rate limiting: client communication, retry-after headers

- Resilience Patterns:
  - Circuit breaker: states, thresholds, fallbacks
  - Retry with backoff: exponential backoff, jitter, max retries
  - Timeout configuration: connection timeout, read timeout, overall timeout
  - Bulkhead pattern: isolation, resource limits, queue depth
  - Fallback strategies: cached data, default values, degraded functionality

- Observability in Microservices:
  - Distributed tracing: OpenTelemetry, Jaeger, Zipkin, context propagation
  - Correlation IDs: request tracing across services
  - Metrics: RED method (Rate, Errors, Duration), USE method
  - Logging: structured logging, log correlation, centralized logging

- Network Security:
  - mTLS between services: certificate management, rotation
  - Network policies: Kubernetes NetworkPolicy, Calico/Cilium
  - Zero trust: identity-based access, micro-segmentation
  - Secrets management: Vault, Kubernetes secrets, cloud secrets managers

Include code examples and architecture diagrams descriptions.
Format as JSON with "question" and "answer" fields."""
    },

    # ==================== INFOSEC & SECOPS DEEP DIVE ====================

    "soar-automation": {
        "description": "SOAR platforms, security automation, and playbook development",
        "prompt_template": """Generate {count} Q&A pairs about SOAR and security automation.

Topics to cover:
- SOAR Fundamentals:
  - What is SOAR: Security Orchestration, Automation, and Response
  - SOAR vs SIEM: complementary roles, when to use each
  - Key capabilities: orchestration, automation, case management, threat intelligence
  - ROI of SOAR: time savings, consistency, analyst efficiency

- SOAR Platforms:
  - Palo Alto Cortex XSOAR: playbooks, integrations, War Room, indicators
  - Splunk SOAR (Phantom): playbooks, apps, containers, custom functions
  - IBM Resilient: workflows, action modules, incident types
  - Microsoft Sentinel automation: Logic Apps, playbooks, automation rules
  - Swimlane, Tines, Torq: low-code automation platforms

- Playbook Development:
  - Playbook design principles: modularity, error handling, documentation
  - Common playbook types: phishing response, malware analysis, user investigation
  - Trigger types: incident-based, scheduled, manual, indicator-based
  - Decision trees and conditional logic in playbooks
  - Testing and validation: sandbox environments, test cases

- Integration Development:
  - API integrations: REST, GraphQL, webhooks
  - Common integrations: SIEM, EDR, ticketing, threat intel, email
  - Authentication: API keys, OAuth, certificates
  - Error handling and retry logic
  - Rate limiting and API quotas

- Automation Use Cases:
  - Phishing triage: email analysis, URL detonation, user notification
  - Indicator enrichment: VirusTotal, Shodan, threat intel lookups
  - User investigation: AD lookups, recent activity, access review
  - Endpoint isolation: EDR integration, network quarantine
  - Ticket creation: ServiceNow, Jira, PagerDuty integration
  - Threat intelligence: IOC ingestion, blocklist updates

- SOAR Operations:
  - Metrics: automation rate, MTTR improvement, playbook execution
  - Continuous improvement: playbook optimization, new use case identification
  - Change management: playbook versioning, testing, deployment
  - Training: analyst onboarding, playbook documentation

- Python in SOAR:
  - Custom script development for SOAR platforms
  - API client development
  - Data parsing and transformation
  - Integration with security tools

Include specific playbook examples and automation code.
Format as JSON with "question" and "answer" fields."""
    },

    "zero-trust-security": {
        "description": "Zero Trust Architecture implementation and principles",
        "prompt_template": """Generate {count} Q&A pairs about Zero Trust security.

Topics to cover:
- Zero Trust Principles:
  - "Never trust, always verify" philosophy
  - Assume breach mentality
  - Least privilege access
  - Continuous verification
  - Micro-segmentation

- Zero Trust Architecture Components:
  - Identity: strong authentication, MFA, SSO, identity providers
  - Devices: device health, MDM/UEM, endpoint security posture
  - Network: micro-segmentation, software-defined perimeter, ZTNA
  - Applications: application-aware access, API security
  - Data: data classification, DLP, encryption
  - Visibility: logging, monitoring, analytics

- Identity and Access Management for Zero Trust:
  - Identity providers: Okta, Azure AD, Ping Identity
  - MFA: TOTP, FIDO2, push notifications, hardware tokens
  - Conditional access: risk-based, location-based, device-based
  - Just-in-time access: PAM, temporary privilege elevation
  - Service accounts: managed identities, secrets management

- Network Zero Trust:
  - Micro-segmentation: network policies, Kubernetes NetworkPolicy, VMware NSX
  - Software-Defined Perimeter (SDP): dark cloud, single-packet authorization
  - ZTNA (Zero Trust Network Access): replacing VPN, application-specific access
  - East-west traffic inspection: internal firewalls, service mesh

- Zero Trust Vendors and Solutions:
  - Zscaler ZPA: ZTNA, cloud security
  - Cloudflare Access: identity-aware proxy
  - Palo Alto Prisma Access: SASE, ZTNA
  - Microsoft Entra (Azure AD): conditional access, identity governance
  - Google BeyondCorp: context-aware access

- Zero Trust Implementation:
  - Maturity model: crawl, walk, run phases
  - Assessment: current state, gap analysis, roadmap
  - Quick wins: MFA everywhere, network segmentation, logging
  - Metrics: coverage, adoption, security incidents

- Zero Trust Frameworks:
  - NIST SP 800-207: Zero Trust Architecture
  - CISA Zero Trust Maturity Model
  - Forrester ZTX framework
  - DoD Zero Trust Reference Architecture

Include real implementation examples and architecture patterns.
Format as JSON with "question" and "answer" fields."""
    },

    "devsecops": {
        "description": "DevSecOps practices, pipeline security, and shift-left security",
        "prompt_template": """Generate {count} Q&A pairs about DevSecOps.

Topics to cover:
- DevSecOps Fundamentals:
  - Shift-left security: finding vulnerabilities early
  - Security as code: policies, controls, tests as code
  - Collaboration: security, development, operations teams
  - Automation: security in CI/CD pipelines
  - Continuous security: ongoing assessment, not point-in-time

- Secure Development Lifecycle:
  - Threat modeling: STRIDE, attack trees, data flow diagrams
  - Secure coding: OWASP guidelines, input validation, output encoding
  - Code review: security-focused review, automated tools
  - Security testing: SAST, DAST, IAST, SCA
  - Security training: developer security awareness

- CI/CD Pipeline Security:
  - Pipeline stages: commit, build, test, deploy, monitor
  - Security gates: blocking vs warning, threshold configuration
  - Secret management: vault integration, environment variables, secret scanning
  - Artifact security: signing, verification, SBOM generation
  - Container security: image scanning, base image management

- Security Testing Tools:
  - SAST (Static Analysis): SonarQube, Checkmarx, Semgrep, CodeQL
  - DAST (Dynamic Analysis): OWASP ZAP, Burp Suite, Nuclei
  - SCA (Software Composition Analysis): Snyk, Dependabot, WhiteSource
  - Container scanning: Trivy, Clair, Anchore, Aqua
  - IaC scanning: Checkov, tfsec, Terrascan, KICS
  - Secret scanning: GitLeaks, TruffleHog, detect-secrets

- Infrastructure as Code Security:
  - Terraform security: secure module development, state file protection
  - CloudFormation/ARM security: template validation, drift detection
  - Kubernetes manifests: pod security, RBAC, network policies
  - Policy as code: OPA/Gatekeeper, Kyverno, Sentinel

- Container and Kubernetes Security:
  - Container hardening: minimal images, non-root, read-only filesystem
  - Registry security: private registries, image signing, admission control
  - Kubernetes security: RBAC, network policies, pod security standards
  - Runtime security: Falco, Sysdig, eBPF-based monitoring
  - Service mesh security: mTLS, authorization policies

- DevSecOps Metrics:
  - Vulnerability metrics: count, severity, MTTR
  - Pipeline metrics: security gate pass rate, false positive rate
  - Coverage metrics: % of apps scanned, policy compliance
  - Developer metrics: security training completion, secure coding adoption

Include pipeline configuration examples and tool integrations.
Format as JSON with "question" and "answer" fields."""
    },

    "security-scripting": {
        "description": "Python and PowerShell scripting for security operations",
        "prompt_template": """Generate {count} Q&A pairs about security scripting and automation.

Topics to cover:
- Python for Security:
  - Security libraries: requests, scapy, pycryptodome, paramiko, impacket
  - API automation: REST API clients for security tools
  - Log parsing: regex, json, csv modules for log analysis
  - Network tools: socket programming, port scanning, packet manipulation
  - File analysis: hashing, YARA integration, PE file parsing

- PowerShell for Security:
  - Active Directory: Get-ADUser, Get-ADGroup, security auditing
  - Event log analysis: Get-WinEvent, filtering, correlation
  - Remote execution: Invoke-Command, PSRemoting, JEA
  - Windows security: firewall rules, audit policies, registry
  - Incident response: collecting artifacts, live response

- Common Security Scripts:
  - IOC scanners: hash lookup, IP/domain reputation
  - Log analyzers: parsing, pattern matching, alerting
  - Vulnerability scanners: port scanning, service detection
  - User activity monitors: login tracking, privilege changes
  - Configuration auditors: compliance checking, hardening validation

- API Integration Scripts:
  - SIEM integration: Splunk SDK, Elastic, Sentinel
  - Threat intelligence: VirusTotal, Shodan, OTX APIs
  - EDR integration: CrowdStrike, Carbon Black, Defender APIs
  - Ticketing: ServiceNow, Jira automation
  - Cloud APIs: AWS boto3, Azure SDK, GCP client libraries

- Security Tool Development:
  - CLI tools: argparse, click for command-line interfaces
  - Web scrapers: BeautifulSoup, Selenium for OSINT
  - Network analyzers: scapy for packet analysis
  - Password tools: secure generation, hashing, cracking (authorized testing)
  - Encryption utilities: AES, RSA implementation

- Best Practices:
  - Secure coding: input validation, secrets handling
  - Error handling: logging, graceful failures
  - Code organization: modules, packages, documentation
  - Testing: unit tests, integration tests for security tools
  - Version control: Git, code review, CI/CD

- Practical Examples:
  - Automated phishing analysis script
  - Log correlation and alerting tool
  - User access review automation
  - Vulnerability report generator
  - Threat intel feed aggregator

Include complete working code examples with explanations.
Format as JSON with "question" and "answer" fields."""
    },

    "edr-xdr": {
        "description": "Endpoint Detection and Response (EDR) and Extended Detection and Response (XDR)",
        "prompt_template": """Generate {count} Q&A pairs about EDR and XDR.

Topics to cover:
- EDR Fundamentals:
  - What is EDR: endpoint visibility, detection, investigation, response
  - EDR vs antivirus: behavioral vs signature, response capabilities
  - Key capabilities: process monitoring, file activity, network connections, registry
  - Deployment models: agent-based, cloud-managed, on-premises

- EDR Platforms:
  - CrowdStrike Falcon: sensor, cloud, threat graph, Falcon Fusion
  - Microsoft Defender for Endpoint: MDE, advanced hunting, live response
  - Carbon Black (VMware): CB Response, CB Defense, Workload
  - SentinelOne: Singularity, Storyline, Ranger
  - Palo Alto Cortex XDR: agent, analytics, response
  - Trend Micro Vision One: XDR platform, endpoints, network, cloud

- EDR Detection Capabilities:
  - Behavioral detection: process trees, parent-child relationships
  - MITRE ATT&CK mapping: technique detection, coverage analysis
  - Custom detection rules: IOC-based, behavioral indicators
  - Machine learning: anomaly detection, threat scoring
  - Threat intelligence: IOC matching, threat actor tracking

- EDR Investigation:
  - Alert triage: severity, confidence, context gathering
  - Timeline analysis: process execution, file activity, network connections
  - Threat hunting: proactive searches, hypothesis-driven investigation
  - Forensic artifacts: memory, disk, network forensics
  - Root cause analysis: patient zero, lateral movement tracking

- EDR Response Actions:
  - Isolation: network quarantine, process blocking
  - Remediation: file quarantine, registry cleanup, process termination
  - Collection: memory dumps, file retrieval, log collection
  - Live response: remote shell, script execution, evidence collection
  - Automated response: playbooks, SOAR integration

- XDR (Extended Detection and Response):
  - XDR vs EDR vs SIEM: scope, correlation, response
  - Data sources: endpoint, network, cloud, email, identity
  - Cross-domain correlation: unified threat detection
  - XDR platforms: native vs open XDR approaches
  - Benefits: reduced alert fatigue, faster investigation

- EDR/XDR Operations:
  - Tuning: reducing false positives, custom exclusions
  - Metrics: detection rate, MTTR, coverage
  - Integration: SIEM, SOAR, ticketing systems
  - Reporting: executive dashboards, incident reports

Include detection rule examples and investigation workflows.
Format as JSON with "question" and "answer" fields."""
    },

    "network-traffic-analysis": {
        "description": "Network traffic analysis, packet capture, and deep packet inspection",
        "prompt_template": """Generate {count} Q&A pairs about network traffic analysis.

Topics to cover:
- Network Traffic Analysis Fundamentals:
  - Traffic types: north-south, east-west, encrypted vs cleartext
  - Analysis approaches: signature, behavioral, statistical, ML-based
  - Data sources: packet capture, flow data, proxy logs, DNS logs
  - Legal considerations: lawful intercept, privacy, data retention

- Packet Capture and Analysis:
  - Capture tools: tcpdump, Wireshark, tshark, NetworkMiner
  - Capture points: TAP, SPAN port, inline, agent-based
  - Capture filters: BPF syntax, reducing capture volume
  - Analysis techniques: follow stream, protocol decode, expert info
  - Performance: ring buffers, capture file rotation, high-speed capture

- Wireshark Deep Dive:
  - Display filters: syntax, operators, field references
  - Protocol analysis: HTTP, DNS, TLS, SMB, Kerberos
  - Statistics: conversations, endpoints, protocol hierarchy
  - Expert analysis: errors, warnings, notes
  - Scripting: tshark, pyshark for automation
  - Custom dissectors: Lua scripting for proprietary protocols

- Flow Analysis:
  - NetFlow/IPFIX: flow records, templates, collectors
  - sFlow: sampling, packet headers, counters
  - Flow analysis tools: ntopng, Elastic, Splunk Stream
  - Baseline analysis: normal traffic patterns, anomaly detection
  - Threat indicators: beaconing, data exfiltration, lateral movement

- Protocol Analysis for Security:
  - DNS: tunneling detection, DGA, malicious domains
  - HTTP/HTTPS: malware C2, data exfiltration, web attacks
  - TLS: certificate analysis, JA3/JA3S fingerprinting, downgrade attacks
  - SMB: lateral movement, PsExec, Eternal Blue patterns
  - Kerberos: Golden Ticket, Pass-the-Ticket, Kerberoasting
  - LDAP: enumeration, credential harvesting

- Network Forensics:
  - Evidence collection: chain of custody, hash verification
  - Timeline reconstruction: connection timing, session analysis
  - Malware traffic analysis: C2 patterns, payload extraction
  - Data exfiltration detection: large transfers, unusual protocols
  - Lateral movement tracking: RDP, SSH, WMI, PsExec

- Network Detection Tools:
  - Zeek (Bro): log types, scripts, notice framework
  - Suricata: rule-based detection, EVE JSON, file extraction
  - Arkime (Moloch): full packet capture, indexing, search
  - RITA: beacon detection, DNS analysis, threat hunting

Include filter examples, detection queries, and analysis procedures.
Format as JSON with "question" and "answer" fields."""
    },

    "security-compliance-ops": {
        "description": "Security compliance operations, auditing, and continuous compliance",
        "prompt_template": """Generate {count} Q&A pairs about security compliance operations.

Topics to cover:
- Compliance Frameworks Deep Dive:
  - PCI-DSS v4.0: 12 requirements, scope, SAQ types, compensating controls
  - SOC 2 Type II: Trust Service Criteria, controls, evidence collection
  - ISO 27001/27002: ISMS, Annex A controls, certification process
  - NIST 800-53: control families, baselines, overlays
  - HIPAA: Privacy Rule, Security Rule, administrative/physical/technical safeguards
  - GDPR: lawful basis, data subject rights, breach notification, DPIAs

- Compliance Operations:
  - Control implementation: technical, administrative, physical controls
  - Evidence collection: automated, manual, continuous
  - Control testing: effectiveness, design vs operating effectiveness
  - Gap assessment: current state, target state, remediation planning
  - Exception management: risk acceptance, compensating controls, timelines

- Audit Preparation:
  - Audit types: internal, external, regulatory, customer
  - Evidence organization: control mapping, documentation, walkthroughs
  - Audit communication: opening meetings, status updates, findings discussion
  - Remediation tracking: findings, action plans, verification
  - Audit fatigue reduction: unified control framework, automation

- Continuous Compliance:
  - Compliance automation: policy as code, automated evidence
  - Monitoring: configuration drift, policy violations, access reviews
  - GRC platforms: ServiceNow GRC, RSA Archer, OneTrust, Drata
  - Cloud compliance: AWS Config, Azure Policy, GCP Organization Policy
  - Reporting: dashboards, executive summaries, trend analysis

- Security Assessments:
  - Risk assessments: qualitative vs quantitative, risk registers
  - Vulnerability assessments: scanning, prioritization, remediation
  - Penetration testing: scope, rules of engagement, reporting
  - Third-party risk: vendor questionnaires, due diligence, ongoing monitoring
  - Control assessments: design, implementation, operating effectiveness

- Compliance for Cloud:
  - Shared responsibility model: provider vs customer responsibilities
  - Cloud compliance certifications: SOC 2, ISO 27001, FedRAMP
  - Cloud security posture management (CSPM): misconfigurations, compliance
  - Data residency: regional requirements, data sovereignty
  - Multi-cloud compliance: unified policies, centralized monitoring

- Compliance Metrics:
  - Control effectiveness: pass/fail rates, coverage
  - Remediation metrics: time to remediate, overdue findings
  - Audit metrics: findings trends, repeat findings
  - Risk metrics: risk score, risk reduction over time

Include practical examples of control implementation and evidence collection.
Format as JSON with "question" and "answer" fields."""
    },

    "cloud-security-architecture": {
        "description": "Cloud security architecture across AWS, Azure, and GCP",
        "prompt_template": """Generate {count} Q&A pairs about cloud security architecture.

Topics to cover:
- Cloud Security Fundamentals:
  - Shared responsibility model: IaaS, PaaS, SaaS differences
  - Cloud security pillars: identity, network, data, application, monitoring
  - Multi-cloud security: unified policies, central visibility
  - Cloud-native vs lift-and-shift security considerations

- Identity and Access Management:
  - AWS IAM: users, roles, policies, permission boundaries, SCP
  - Azure AD/Entra: users, groups, service principals, managed identities
  - GCP IAM: members, roles, service accounts, resource hierarchy
  - Cross-cloud identity: federation, SSO, identity providers
  - Privileged access: JIT access, PIM, break-glass procedures

- Network Security:
  - VPC/VNet security: subnets, security groups, NACLs/NSGs
  - Cloud firewalls: AWS Network Firewall, Azure Firewall, GCP Cloud Armor
  - Private connectivity: PrivateLink, Private Endpoint, Private Service Connect
  - DDoS protection: Shield, DDoS Protection, Cloud Armor
  - WAF: AWS WAF, Azure Front Door, Cloud Armor rules

- Data Security:
  - Encryption at rest: KMS, Key Vault, Cloud KMS
  - Encryption in transit: TLS, certificate management
  - Data classification: tagging, automated discovery
  - Data loss prevention: Macie, Purview, Cloud DLP
  - Secrets management: Secrets Manager, Key Vault, Secret Manager

- Workload Security:
  - Compute security: EC2/VM hardening, security groups, instance metadata
  - Container security: ECR/ACR/GCR scanning, runtime protection
  - Serverless security: Lambda/Functions security, least privilege
  - Kubernetes security: EKS/AKS/GKE hardening, RBAC, network policies

- Monitoring and Detection:
  - Cloud logging: CloudTrail, Activity Logs, Audit Logs
  - Security services: GuardDuty, Defender for Cloud, Security Command Center
  - SIEM integration: log forwarding, cloud connectors
  - Threat detection: anomaly detection, threat intelligence

- Compliance and Governance:
  - Policy enforcement: AWS Config, Azure Policy, Organization Policy
  - Compliance frameworks: built-in compliance assessments
  - Landing zones: Control Tower, Azure Landing Zone, blueprints
  - Cloud security posture management: native and third-party CSPM

- Incident Response in Cloud:
  - Cloud forensics: evidence collection, snapshot analysis
  - Isolation: security group changes, network ACLs
  - Investigation: CloudTrail analysis, log correlation
  - Automation: Lambda/Functions for response, SOAR integration

Include architecture diagrams descriptions and security configurations.
Format as JSON with "question" and "answer" fields."""
    },

    "malware-analysis-forensics": {
        "description": "Malware analysis, reverse engineering, and digital forensics",
        "prompt_template": """Generate {count} Q&A pairs about malware analysis and forensics.

Topics to cover:
- Malware Analysis Fundamentals:
  - Analysis types: static, dynamic, behavioral, code analysis
  - Malware categories: ransomware, trojans, worms, rootkits, RATs, cryptominers
  - Analysis environment: isolated labs, virtual machines, sandboxes
  - Safety precautions: network isolation, snapshots, disposable VMs

- Static Analysis:
  - File identification: file types, magic bytes, hashing (MD5, SHA256)
  - PE file analysis: headers, sections, imports, exports, resources
  - String analysis: extracting strings, encoded strings, obfuscation
  - Packer detection: UPX, Themida, custom packers, entropy analysis
  - Tools: PE-bear, pestudio, Detect It Easy, YARA

- Dynamic Analysis:
  - Sandbox analysis: automated sandboxes (Any.Run, Joe Sandbox, Cuckoo)
  - Process monitoring: Process Monitor, Process Hacker, API Monitor
  - Network monitoring: Wireshark, Fiddler, FakeNet-NG
  - File system monitoring: changes, dropped files, persistence
  - Registry monitoring: changes, autorun entries

- Behavioral Analysis:
  - Execution patterns: process trees, child processes, injection
  - Network behavior: C2 communication, beaconing, data exfiltration
  - Persistence mechanisms: registry, scheduled tasks, services, WMI
  - Evasion techniques: anti-VM, anti-debug, sleep, sandbox detection
  - Indicators of Compromise: file, network, host-based IOCs

- Reverse Engineering Basics:
  - Disassembly: IDA Free, Ghidra, x64dbg
  - Assembly basics: x86/x64, common patterns, function calls
  - Debugging: breakpoints, stepping, memory analysis
  - Code analysis: control flow, data flow, function identification
  - Decompilation: pseudo-code generation, code understanding

- Digital Forensics:
  - Evidence acquisition: disk imaging, memory acquisition, live response
  - Chain of custody: documentation, hashing, integrity verification
  - Disk forensics: Autopsy, FTK, EnCase, Sleuth Kit
  - Memory forensics: Volatility, Rekall, process analysis, malware detection
  - Timeline analysis: MFT, event logs, browser history, prefetch

- Forensic Artifacts:
  - Windows: registry, event logs, prefetch, SRUM, amcache, shimcache
  - Linux: auth logs, bash history, cron, systemd
  - Network: packet captures, flow data, DNS logs
  - Browser: history, cookies, cache, downloads
  - Cloud: CloudTrail, activity logs, API audit logs

- Incident Forensics Workflow:
  - Scoping: initial assessment, affected systems identification
  - Collection: evidence preservation, imaging, log collection
  - Analysis: timeline, IOCs, attack reconstruction
  - Reporting: findings, timeline, recommendations
  - Lessons learned: detection improvements, prevention measures

Include tool usage examples and analysis procedures.
Format as JSON with "question" and "answer" fields."""
    },

    "fireweave-disambiguation": {
        "description": "Training data to disambiguate when to explain features vs execute tool calls",
        "prompt_template": """Generate {count} training examples for a FireWeave AI assistant that teach the model WHEN to explain features vs WHEN to execute tool calls.

FireWeave is a Panorama firewall management platform with AI chat. The model must learn to:
1. EXPLAIN features when users ask "what is", "how does", "tell me about", "explain"
2. OUTPUT TOOL CALLS when users want actions: "check if", "find", "create", "run", "scan"
3. SHOW CODE EXAMPLES when users ask "how do I call the API", "show me the code"

CATEGORIES TO COVER:

1. EXPLAIN_FEATURE (No tool call - just explanation):
   - "What is traffic flow analysis?"
   - "How does compliance scanning work?"
   - "Tell me about batch deploy"
   - "Explain object deduplication"

2. EXECUTE_ACTION (Output tool call JSON):
   - "Check if 10.1.1.50 can reach 192.168.1.100 on port 443"
   - "Run a PCI-DSS compliance scan on DG-Production"
   - "Find all rules tagged 'legacy'"
   - "Create a rule to allow SSH from the bastion host"

3. SHOW_CODE (Show API code examples, no execution):
   - "How do I call the traffic flow API?"
   - "Show me Python code for compliance scanning"
   - "What's the curl command for creating a rule?"

4. CLARIFICATION_NEEDED (Ask for more details):
   - "Check the compliance" (which framework? which device group?)
   - "Create a rule" (for what traffic?)

5. EDGE CASES:
   - "Can you search by tag?" = EXPLAIN capability
   - "Can you search for rules tagged 'legacy'?" = EXECUTE (specific request)
   - "Tell me about traffic from 10.1.1.1 to 10.2.2.2" = Could be either, lean explain
   - "10.1.1.50 to 192.168.1.100 port 443" = EXECUTE (implicit traffic check)
   - "Don't run anything, just explain..." = Explicit explanation request
   - "I'm not sure if..." = Check for them (execute)

TOOL CALL FORMAT (when executing):
The response should include an "Executing Tool Call:" section with JSON:
```json
[
  {{
    "name": "tool_name",
    "arguments": {{ ... }}
  }}
]
```

AVAILABLE TOOLS:
- traffic_flow_analysis: source_ip, destination_ip, port, protocol
- nat_check: source_ip, destination_ip, port, zone_from, zone_to
- rule_search: query, device_group, rule_type, filters
- compliance_scan: framework, device_groups, severity_filter
- shadowed_rules_check: device_group, rulebase
- unused_rules_check: device_group, days_threshold
- object_lookup: query, object_type, device_group
- deduplication_scan: device_group, object_type, similarity_threshold
- create_rule: name, device_group, source_zone, destination_zone, source_address, destination_address, application, service, action, log_end, description, tags
- mass_edit: device_group, filters, actions, preview_only
- topology_collect: panorama_id, full_collection
- get_device_groups: include_hierarchy
- get_zones: device_group
- export_rules: device_group, rulebase, format

Generate diverse examples across all categories.
Format as JSON array with "question" and "answer" fields."""
    }
}


def generate_with_openai(prompt: str, count: int) -> List[Dict[str, str]]:
    """Generate synthetic data using OpenAI GPT-4"""
    try:
        from openai import OpenAI

        api_key = os.getenv("OPENAI_API_KEY")
        model = "gpt-4o"  # Best model for generating high-quality training data

        # Debug logging
        print(f"  [DEBUG] OpenAI API Configuration:")
        print(f"  [DEBUG]   Model: {model}")
        print(f"  [DEBUG]   API Key: {api_key[:20]}...{api_key[-10:] if api_key and len(api_key) > 30 else 'KEY TOO SHORT OR MISSING'}")
        print(f"  [DEBUG]   API Key Length: {len(api_key) if api_key else 0}")

        if not api_key:
            print("  [ERROR] OPENAI_API_KEY is empty or not set!")
            return []

        client = OpenAI(api_key=api_key)

        print(f"  [DEBUG] Sending request to OpenAI API...")
        print(f"  [DEBUG]   Prompt length: {len(prompt)} characters")

        # Use higher max_tokens for detailed answers (high-quality prompts need more space)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a network security expert who creates high-quality training data for AI models. Generate accurate, detailed, and practical Q&A pairs. CRITICAL: Each answer MUST be at least 500 characters with code blocks and step-by-step instructions. Short generic answers are worthless."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.7,  # Slightly lower for more consistent quality
            max_tokens=8000   # Increased for detailed answers
        )

        print(f"  [DEBUG] Response received successfully!")
        print(f"  [DEBUG]   Response ID: {response.id if hasattr(response, 'id') else 'N/A'}")
        print(f"  [DEBUG]   Model used: {response.model if hasattr(response, 'model') else 'N/A'}")
        print(f"  [DEBUG]   Usage: {response.usage if hasattr(response, 'usage') else 'N/A'}")

        content = response.choices[0].message.content
        print(f"  [DEBUG]   Response content length: {len(content)} characters")
        print(f"  [DEBUG]   Response preview: {content[:200]}...")

        # Try to parse JSON from the response
        qa_pairs = parse_qa_response(content)

        print(f"  [DEBUG] Parsed {len(qa_pairs)} Q&A pairs from response")

        return qa_pairs

    except Exception as e:
        import traceback
        print(f"  [ERROR] Error generating with OpenAI:")
        print(f"  [ERROR]   Exception type: {type(e).__name__}")
        print(f"  [ERROR]   Exception message: {e}")
        print(f"  [ERROR]   Full traceback:")
        traceback.print_exc()
        return []


def generate_with_anthropic(prompt: str, count: int) -> List[Dict[str, str]]:
    """Generate synthetic data using Anthropic Claude"""
    try:
        import anthropic

        api_key = os.getenv("ANTHROPIC_API_KEY")
        model = "claude-sonnet-4-20250514"

        # Debug logging
        print(f"  [DEBUG] Anthropic API Configuration:")
        print(f"  [DEBUG]   Model: {model}")
        print(f"  [DEBUG]   API Key: {api_key[:20]}...{api_key[-10:] if api_key and len(api_key) > 30 else 'KEY TOO SHORT OR MISSING'}")
        print(f"  [DEBUG]   API Key Length: {len(api_key) if api_key else 0}")

        if not api_key:
            print("  [ERROR] ANTHROPIC_API_KEY is empty or not set!")
            return []

        client = anthropic.Anthropic(api_key=api_key)

        print(f"  [DEBUG] Sending request to Anthropic API...")
        print(f"  [DEBUG]   Prompt length: {len(prompt)} characters")

        message = client.messages.create(
            model=model,
            max_tokens=4000,
            temperature=0.8,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        print(f"  [DEBUG] Response received successfully!")
        print(f"  [DEBUG]   Response ID: {message.id if hasattr(message, 'id') else 'N/A'}")
        print(f"  [DEBUG]   Model used: {message.model if hasattr(message, 'model') else 'N/A'}")
        print(f"  [DEBUG]   Usage: input={message.usage.input_tokens}, output={message.usage.output_tokens}" if hasattr(message, 'usage') else "  [DEBUG]   Usage: N/A")
        print(f"  [DEBUG]   Stop reason: {message.stop_reason if hasattr(message, 'stop_reason') else 'N/A'}")

        content = message.content[0].text
        print(f"  [DEBUG]   Response content length: {len(content)} characters")
        print(f"  [DEBUG]   Response preview: {content[:200]}...")

        # Try to parse JSON from the response
        qa_pairs = parse_qa_response(content)

        print(f"  [DEBUG] Parsed {len(qa_pairs)} Q&A pairs from response")

        return qa_pairs

    except Exception as e:
        import traceback
        print(f"  [ERROR] Error generating with Anthropic:")
        print(f"  [ERROR]   Exception type: {type(e).__name__}")
        print(f"  [ERROR]   Exception message: {e}")
        print(f"  [ERROR]   Full traceback:")
        traceback.print_exc()
        return []


def generate_with_kimi(prompt: str, count: int) -> List[Dict[str, str]]:
    """Generate synthetic data using Kimi (Moonshot AI)"""
    try:
        from openai import OpenAI

        api_key = os.getenv("KIMI_API_KEY")
        base_url = "https://api.moonshot.ai/v1"
        model = "moonshot-v1-8k"

        # Debug logging
        print(f"  [DEBUG] Kimi API Configuration:")
        print(f"  [DEBUG]   Base URL: {base_url}")
        print(f"  [DEBUG]   Model: {model}")
        print(f"  [DEBUG]   API Key: {api_key[:20]}...{api_key[-10:] if api_key and len(api_key) > 30 else 'KEY TOO SHORT OR MISSING'}")
        print(f"  [DEBUG]   API Key Length: {len(api_key) if api_key else 0}")

        if not api_key:
            print("  [ERROR] KIMI_API_KEY is empty or not set!")
            return []

        # Kimi uses OpenAI-compatible API
        client = OpenAI(
            api_key=api_key,
            base_url=base_url
        )

        print(f"  [DEBUG] Sending request to Kimi API...")
        print(f"  [DEBUG]   Prompt length: {len(prompt)} characters")

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a network security expert who creates high-quality training data for AI models. Generate accurate, detailed, and practical Q&A pairs."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=4000
        )

        print(f"  [DEBUG] Response received successfully!")
        print(f"  [DEBUG]   Response ID: {response.id if hasattr(response, 'id') else 'N/A'}")
        print(f"  [DEBUG]   Model used: {response.model if hasattr(response, 'model') else 'N/A'}")
        print(f"  [DEBUG]   Usage: {response.usage if hasattr(response, 'usage') else 'N/A'}")

        content = response.choices[0].message.content
        print(f"  [DEBUG]   Response content length: {len(content)} characters")
        print(f"  [DEBUG]   Response preview: {content[:200]}...")

        # Try to parse JSON from the response
        qa_pairs = parse_qa_response(content)

        print(f"  [DEBUG] Parsed {len(qa_pairs)} Q&A pairs from response")

        return qa_pairs

    except Exception as e:
        import traceback
        print(f"  [ERROR] Error generating with Kimi:")
        print(f"  [ERROR]   Exception type: {type(e).__name__}")
        print(f"  [ERROR]   Exception message: {e}")
        print(f"  [ERROR]   Full traceback:")
        traceback.print_exc()
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
    parser.add_argument("--provider", choices=["openai", "anthropic", "kimi"], required=True,
                       help="AI provider to use for generation (openai, anthropic, or kimi)")
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

    if args.provider == "kimi" and not os.getenv("KIMI_API_KEY"):
        print("Error: KIMI_API_KEY not found in environment variables")
        print("Please create a .env file with: KIMI_API_KEY=your-key-here")
        print("Get your API key from: https://platform.moonshot.cn/")
        return

    # Set output path
    if args.output:
        output_path = args.output
    else:
        output_path = f"data/synthetic/{args.topic}_{args.provider}.json"

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Check if high-quality prompt is available for this topic
    using_hq_prompt = False
    if HQ_PROMPTS_AVAILABLE and args.topic in HIGH_QUALITY_TOPICS:
        topic_info = HIGH_QUALITY_TOPICS[args.topic]
        using_hq_prompt = True
        print(f"[HQ] Using HIGH-QUALITY prompt for: {args.topic}")
    else:
        topic_info = TOPICS[args.topic]

    print(f"Generating {args.count} Q&A pairs about: {topic_info['description']}")
    print(f"Using provider: {args.provider}")
    print(f"Output file: {output_path}")
    if using_hq_prompt:
        print(f"[HQ] Quality enforcement: ENABLED (min 500 chars, code blocks required)")
    print("-" * 80)

    all_qa_pairs = []
    batches = (args.count + args.batch_size - 1) // args.batch_size

    for batch in range(batches):
        batch_count = min(args.batch_size, args.count - len(all_qa_pairs))
        print(f"\nGenerating batch {batch + 1}/{batches} ({batch_count} pairs)...")

        # Use % formatting for high-quality prompts (avoids JSON brace issues)
        # Use .format() for regular prompts
        if using_hq_prompt:
            prompt = topic_info["prompt_template"] % batch_count
        else:
            prompt = topic_info["prompt_template"].format(count=batch_count)

        if args.provider == "openai":
            qa_pairs = generate_with_openai(prompt, batch_count)
        elif args.provider == "anthropic":
            qa_pairs = generate_with_anthropic(prompt, batch_count)
        else:  # kimi
            qa_pairs = generate_with_kimi(prompt, batch_count)

        if qa_pairs:
            all_qa_pairs.extend(qa_pairs)
            print(f"[OK] Generated {len(qa_pairs)} pairs (Total: {len(all_qa_pairs)})")
        else:
            print(f"[FAIL] Failed to generate batch {batch + 1}")

        # Rate limiting - wait longer to stay under 30K TPM limit
        # Each batch uses ~2500-3000 tokens, so 10 batches/min = 25-30K tokens
        # With batch_size=10, we need ~6 seconds between batches to stay safe
        if batch < batches - 1:
            delay = 6  # 6 seconds = 10 batches/min = ~25K TPM
            print(f"Waiting {delay} seconds (rate limit: 30K TPM)...")
            time.sleep(delay)

    if not all_qa_pairs:
        print("\n[ERROR] No data generated. Please check your API key and try again.")
        return

    # Convert to ChatML format
    print(f"\nConverting {len(all_qa_pairs)} Q&A pairs to ChatML format...")
    formatted_data = convert_to_chatml_format(all_qa_pairs)

    # Save to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(formatted_data, f, indent=2, ensure_ascii=False)

    print(f"\n[SUCCESS] Successfully generated {len(formatted_data)} training examples!")
    print(f"[FILE] Saved to: {output_path}")
    print(f"\nSample question: {all_qa_pairs[0]['question'][:100]}...")
    print(f"\nNext steps:")
    print(f"1. Review the generated data for quality and accuracy")
    print(f"2. Run validation: python scripts/validate_dataset.py {output_path}")
    print(f"3. Generate more topics and merge datasets")
    print(f"4. Use the combined dataset for fine-tuning")


if __name__ == "__main__":
    main()
