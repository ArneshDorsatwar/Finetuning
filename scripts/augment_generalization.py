#!/usr/bin/env python3
"""
Augment training data for tool calling generalization.

Two techniques from research (Hammer ICLR 2025, ToolACE, ToolAlpaca):

1. FUNCTION MASKING (~40% of tool calling examples):
   Replace tool names with random strings in both system message schemas
   AND tool call JSON. Forces model to read descriptions instead of
   memorizing "search_objects" → always call it.

2. DIVERSE GENERIC TOOL EXAMPLES (~500 examples):
   Generate examples with completely novel tools (not FireWeave) using
   the same Llama 3.1 protocol. Teaches the model the PATTERN of
   "read schema → call tool" not "memorize 22 tool names."

Usage:
    python scripts/augment_generalization.py
    python scripts/augment_generalization.py --dry-run
    python scripts/augment_generalization.py --mask-pct 0.40 --diverse-count 500
"""

import json
import random
import string
import hashlib
import argparse
import sys
import copy
import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Function masking utilities
# ---------------------------------------------------------------------------

def generate_masked_name(rng: random.Random) -> str:
    """Generate a random function name like fn_8x2k or tool_m3p9."""
    prefix = rng.choice(["fn", "tool", "op", "func", "api", "action"])
    suffix = "".join(rng.choices(string.ascii_lowercase + string.digits, k=4))
    return f"{prefix}_{suffix}"


def mask_tool_names_in_example(example: dict, rng: random.Random) -> dict:
    """Replace real tool names with random strings in an example.

    Replaces names in:
    - System message (schema JSON)
    - gpt turns (tool call JSON after <|python_tag|>)
    - Does NOT change: descriptions, parameter names, ipython results, human queries
    """
    example = copy.deepcopy(example)
    convs = example["conversations"]

    # Find all tool names used in this example
    real_names = set()

    # From system message schemas
    sys_val = convs[0]["value"] if convs[0]["from"] == "system" else ""
    for match in re.finditer(r'"name":\s*"([^"]+)"', sys_val):
        real_names.add(match.group(1))

    # From tool calls in gpt turns
    for c in convs:
        if c["from"] == "gpt" and "<|python_tag|>" in c.get("value", ""):
            json_str = c["value"].split("<|python_tag|>", 1)[1]
            try:
                tc = json.loads(json_str)
                if isinstance(tc, dict) and "name" in tc:
                    real_names.add(tc["name"])
            except (json.JSONDecodeError, ValueError):
                pass

    if not real_names:
        return example  # Nothing to mask

    # Create mapping: real_name → masked_name
    name_map = {}
    for name in real_names:
        name_map[name] = generate_masked_name(rng)

    # Apply masking to system message
    if convs[0]["from"] == "system":
        val = convs[0]["value"]
        for real, masked in name_map.items():
            # Replace in schema JSON: "name": "real_name" → "name": "masked_name"
            val = val.replace(f'"name": "{real}"', f'"name": "{masked}"')
            val = val.replace(f'"name":"{real}"', f'"name":"{masked}"')
        convs[0]["value"] = val

    # Apply masking to gpt tool calls
    for c in convs:
        if c["from"] == "gpt" and "<|python_tag|>" in c.get("value", ""):
            parts = c["value"].split("<|python_tag|>", 1)
            json_str = parts[1]
            try:
                tc = json.loads(json_str)
                if isinstance(tc, dict) and "name" in tc and tc["name"] in name_map:
                    tc["name"] = name_map[tc["name"]]
                    c["value"] = "<|python_tag|>" + json.dumps(tc, ensure_ascii=False)
            except (json.JSONDecodeError, ValueError):
                pass

    return example


# ---------------------------------------------------------------------------
# Diverse generic tool definitions (NOT FireWeave)
# ---------------------------------------------------------------------------

GENERIC_TOOLS = [
    {
        "name": "lookup_cve",
        "description": "Look up CVE vulnerability details by CVE ID",
        "parameters": {
            "type": "object",
            "properties": {
                "cve_id": {"type": "string", "description": "CVE identifier (e.g. CVE-2024-1234)"},
            },
            "required": ["cve_id"],
        },
        "examples": [
            {
                "query": "look up CVE-2024-3094",
                "call": {"name": "lookup_cve", "parameters": {"cve_id": "CVE-2024-3094"}},
                "result": {"status": "success", "cve_id": "CVE-2024-3094", "severity": "critical", "cvss": 10.0, "description": "XZ Utils backdoor allowing unauthorized SSH access", "affected": "xz-utils 5.6.0-5.6.1", "published": "2024-03-29"},
                "response": "**CVE-2024-3094** — Critical (CVSS 10.0)\n\n| Field | Value |\n|-------|-------|\n| Severity | Critical |\n| CVSS | 10.0 |\n| Affected | xz-utils 5.6.0-5.6.1 |\n| Published | 2024-03-29 |\n\nXZ Utils backdoor allowing unauthorized SSH access. Patch immediately.",
            },
            {
                "query": "what's CVE-2023-44487",
                "call": {"name": "lookup_cve", "parameters": {"cve_id": "CVE-2023-44487"}},
                "result": {"status": "success", "cve_id": "CVE-2023-44487", "severity": "high", "cvss": 7.5, "description": "HTTP/2 Rapid Reset attack enabling DDoS", "affected": "Multiple HTTP/2 implementations", "published": "2023-10-10"},
                "response": "**CVE-2023-44487** — High (CVSS 7.5)\n\nHTTP/2 Rapid Reset attack enabling DDoS. Affects multiple HTTP/2 implementations. Published 2023-10-10.\n\nEnsure your web servers and load balancers are patched against this.",
            },
        ],
    },
    {
        "name": "query_dns",
        "description": "Perform DNS lookup for a domain name",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "Domain name to resolve"},
                "record_type": {"type": "string", "description": "DNS record type: A, AAAA, MX, CNAME, TXT, NS"},
            },
            "required": ["domain"],
        },
        "examples": [
            {
                "query": "resolve api.example.com",
                "call": {"name": "query_dns", "parameters": {"domain": "api.example.com"}},
                "result": {"status": "success", "domain": "api.example.com", "records": [{"type": "A", "value": "203.0.113.50", "ttl": 300}, {"type": "A", "value": "203.0.113.51", "ttl": 300}]},
                "response": "**api.example.com** resolves to:\n\n| Type | Value | TTL |\n|------|-------|-----|\n| A | 203.0.113.50 | 300s |\n| A | 203.0.113.51 | 300s |\n\nTwo A records — likely behind a round-robin load balancer.",
            },
            {
                "query": "MX records for contoso.com",
                "call": {"name": "query_dns", "parameters": {"domain": "contoso.com", "record_type": "MX"}},
                "result": {"status": "success", "domain": "contoso.com", "records": [{"type": "MX", "value": "mail1.contoso.com", "priority": 10, "ttl": 3600}, {"type": "MX", "value": "mail2.contoso.com", "priority": 20, "ttl": 3600}]},
                "response": "**contoso.com** MX records:\n\n| Priority | Mail Server | TTL |\n|----------|-------------|-----|\n| 10 | mail1.contoso.com | 3600s |\n| 20 | mail2.contoso.com | 3600s |\n\nPrimary mail server is mail1.contoso.com.",
            },
        ],
    },
    {
        "name": "scan_ports",
        "description": "Scan open ports on a target host",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP address or hostname"},
                "port_range": {"type": "string", "description": "Port range (e.g. 1-1024, 80,443,8080)"},
            },
            "required": ["target"],
        },
        "examples": [
            {
                "query": "scan ports on 10.5.20.100",
                "call": {"name": "scan_ports", "parameters": {"target": "10.5.20.100"}},
                "result": {"status": "success", "target": "10.5.20.100", "open_ports": [{"port": 22, "service": "ssh", "version": "OpenSSH 8.9"}, {"port": 443, "service": "https", "version": "nginx/1.24"}, {"port": 3306, "service": "mysql", "version": "MySQL 8.0"}]},
                "response": "**10.5.20.100** — 3 open ports:\n\n| Port | Service | Version |\n|------|---------|--------|\n| 22 | SSH | OpenSSH 8.9 |\n| 443 | HTTPS | nginx/1.24 |\n| 3306 | MySQL | MySQL 8.0 |\n\nMySQL (3306) exposed is a concern — ensure it's not reachable from untrusted networks.",
            },
        ],
    },
    {
        "name": "whois_lookup",
        "description": "Get WHOIS registration details for a domain or IP",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Domain name or IP address"},
            },
            "required": ["query"],
        },
        "examples": [
            {
                "query": "whois for suspicious-domain.xyz",
                "call": {"name": "whois_lookup", "parameters": {"query": "suspicious-domain.xyz"}},
                "result": {"status": "success", "domain": "suspicious-domain.xyz", "registrar": "NameCheap Inc", "created": "2024-11-15", "expires": "2025-11-15", "registrant_country": "RU", "nameservers": ["ns1.shady-hosting.net", "ns2.shady-hosting.net"]},
                "response": "**suspicious-domain.xyz** WHOIS:\n\n| Field | Value |\n|-------|-------|\n| Registrar | NameCheap Inc |\n| Created | 2024-11-15 |\n| Expires | 2025-11-15 |\n| Country | RU |\n| Nameservers | ns1.shady-hosting.net, ns2.shady-hosting.net |\n\nRecently registered (3 months ago) with a 1-year expiry and Russian registrant — flags for potential malicious use.",
            },
        ],
    },
    {
        "name": "check_ssl_cert",
        "description": "Check SSL/TLS certificate details for a host",
        "parameters": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "description": "Hostname to check"},
                "port": {"type": "integer", "description": "Port number (default 443)"},
            },
            "required": ["host"],
        },
        "examples": [
            {
                "query": "check the SSL cert on portal.corp.local",
                "call": {"name": "check_ssl_cert", "parameters": {"host": "portal.corp.local"}},
                "result": {"status": "success", "host": "portal.corp.local", "issuer": "DigiCert SHA2 Extended Validation", "subject": "portal.corp.local", "valid_from": "2024-06-01", "valid_to": "2025-06-01", "days_remaining": 120, "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384"},
                "response": "**portal.corp.local** SSL certificate:\n\n| Field | Value |\n|-------|-------|\n| Issuer | DigiCert SHA2 EV |\n| Valid until | 2025-06-01 (120 days) |\n| Protocol | TLSv1.3 |\n| Cipher | TLS_AES_256_GCM_SHA384 |\n\nCert is valid with 120 days remaining. TLSv1.3 with strong cipher — looks good.",
            },
            {
                "query": "ssl check on expired.example.com",
                "call": {"name": "check_ssl_cert", "parameters": {"host": "expired.example.com"}},
                "result": {"status": "success", "host": "expired.example.com", "issuer": "Let's Encrypt", "subject": "expired.example.com", "valid_from": "2024-01-15", "valid_to": "2024-04-15", "days_remaining": -300, "protocol": "TLSv1.2", "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
                "response": "**expired.example.com** — Certificate EXPIRED.\n\n| Field | Value |\n|-------|-------|\n| Issuer | Let's Encrypt |\n| Expired | 2024-04-15 (300 days ago) |\n| Protocol | TLSv1.2 |\n\nThis cert expired 300 days ago. Renew immediately — browsers will show security warnings.",
            },
        ],
    },
    {
        "name": "get_threat_intel",
        "description": "Get threat intelligence for an IP address or domain",
        "parameters": {
            "type": "object",
            "properties": {
                "indicator": {"type": "string", "description": "IP address, domain, or hash"},
                "indicator_type": {"type": "string", "description": "ip, domain, hash, or url"},
            },
            "required": ["indicator"],
        },
        "examples": [
            {
                "query": "threat intel on 185.220.101.42",
                "call": {"name": "get_threat_intel", "parameters": {"indicator": "185.220.101.42"}},
                "result": {"status": "success", "indicator": "185.220.101.42", "reputation": "malicious", "threat_score": 95, "categories": ["tor-exit-node", "brute-force", "scanner"], "first_seen": "2023-08-15", "last_seen": "2026-02-08", "reports": 847, "country": "DE"},
                "response": "**185.220.101.42** — Malicious (Score: 95/100)\n\n| Field | Value |\n|-------|-------|\n| Reputation | Malicious |\n| Categories | Tor exit node, brute-force, scanner |\n| Reports | 847 |\n| Country | DE |\n| Active | 2023-08-15 to 2026-02-08 |\n\nKnown Tor exit node with extensive brute-force activity. Block at the perimeter.",
            },
        ],
    },
    {
        "name": "list_firewall_zones",
        "description": "List all configured security zones on a firewall",
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device name or IP"},
            },
            "required": ["device"],
        },
        "examples": [
            {
                "query": "list zones on fw-east-01",
                "call": {"name": "list_firewall_zones", "parameters": {"device": "fw-east-01"}},
                "result": {"status": "success", "device": "fw-east-01", "zones": [{"name": "trust", "interfaces": ["ethernet1/1", "ethernet1/2"], "type": "layer3"}, {"name": "untrust", "interfaces": ["ethernet1/3"], "type": "layer3"}, {"name": "dmz", "interfaces": ["ethernet1/4"], "type": "layer3"}]},
                "response": "**fw-east-01** zones:\n\n| Zone | Type | Interfaces |\n|------|------|------------|\n| trust | L3 | ethernet1/1, ethernet1/2 |\n| untrust | L3 | ethernet1/3 |\n| dmz | L3 | ethernet1/4 |\n\n3 zones configured.",
            },
        ],
    },
    {
        "name": "get_bgp_neighbors",
        "description": "Get BGP neighbor status and details",
        "parameters": {
            "type": "object",
            "properties": {
                "router": {"type": "string", "description": "Router hostname or IP"},
                "vrf": {"type": "string", "description": "VRF name (optional)"},
            },
            "required": ["router"],
        },
        "examples": [
            {
                "query": "BGP neighbors on core-rtr-01",
                "call": {"name": "get_bgp_neighbors", "parameters": {"router": "core-rtr-01"}},
                "result": {"status": "success", "router": "core-rtr-01", "neighbors": [{"peer": "10.0.0.2", "asn": 65002, "state": "Established", "uptime": "45d 12h", "prefixes_received": 1250}, {"peer": "10.0.0.6", "asn": 65003, "state": "Idle", "uptime": "0", "prefixes_received": 0}]},
                "response": "**core-rtr-01** BGP neighbors:\n\n| Peer | ASN | State | Uptime | Prefixes |\n|------|-----|-------|--------|----------|\n| 10.0.0.2 | 65002 | Established | 45d 12h | 1,250 |\n| 10.0.0.6 | 65003 | **Idle** | — | 0 |\n\n10.0.0.6 (AS65003) is down — check physical connectivity and BGP configuration.",
            },
        ],
    },
    {
        "name": "get_interface_stats",
        "description": "Get network interface statistics and errors",
        "parameters": {
            "type": "object",
            "properties": {
                "device": {"type": "string", "description": "Device hostname"},
                "interface": {"type": "string", "description": "Interface name (e.g. eth0, GigabitEthernet0/1)"},
            },
            "required": ["device", "interface"],
        },
        "examples": [
            {
                "query": "interface stats for eth1/3 on fw-west-02",
                "call": {"name": "get_interface_stats", "parameters": {"device": "fw-west-02", "interface": "eth1/3"}},
                "result": {"status": "success", "device": "fw-west-02", "interface": "eth1/3", "status": "up", "speed": "10Gbps", "in_bytes": 892345678901, "out_bytes": 456789012345, "in_errors": 0, "out_errors": 0, "crc_errors": 0, "drops": 12},
                "response": "**fw-west-02 eth1/3** — Up at 10Gbps\n\n| Metric | Value |\n|--------|-------|\n| In | 892.3 GB |\n| Out | 456.8 GB |\n| Errors | 0 |\n| Drops | 12 |\n\n12 drops recorded but zero errors — likely brief congestion, not a hardware issue.",
            },
        ],
    },
    {
        "name": "check_ip_reputation",
        "description": "Check the reputation score of an IP address",
        "parameters": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "IP address to check"},
            },
            "required": ["ip"],
        },
        "examples": [
            {
                "query": "reputation check on 45.33.32.156",
                "call": {"name": "check_ip_reputation", "parameters": {"ip": "45.33.32.156"}},
                "result": {"status": "success", "ip": "45.33.32.156", "score": 15, "category": "scanner", "owner": "Linode LLC", "country": "US", "blacklisted": False},
                "response": "**45.33.32.156** — Low risk (Score: 15/100)\n\n| Field | Value |\n|-------|-------|\n| Score | 15/100 |\n| Category | Scanner |\n| Owner | Linode LLC |\n| Country | US |\n| Blacklisted | No |\n\nKnown scanner (likely Shodan/Censys). Low threat — standard internet noise.",
            },
        ],
    },
    {
        "name": "get_siem_alerts",
        "description": "Retrieve recent SIEM alerts by severity or type",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "description": "critical, high, medium, low"},
                "time_range": {"type": "string", "description": "1h, 6h, 24h, 7d"},
                "source": {"type": "string", "description": "Alert source (e.g. firewall, ids, edr)"},
            },
            "required": ["severity"],
        },
        "examples": [
            {
                "query": "show critical SIEM alerts from last 24h",
                "call": {"name": "get_siem_alerts", "parameters": {"severity": "critical", "time_range": "24h"}},
                "result": {"status": "success", "count": 3, "alerts": [{"id": "ALT-2891", "rule": "Lateral Movement Detected", "source_ip": "10.1.5.22", "target": "10.1.5.50", "time": "2026-02-08T14:22:00Z"}, {"id": "ALT-2893", "rule": "Data Exfiltration Attempt", "source_ip": "10.1.5.22", "target": "185.100.86.1", "time": "2026-02-08T14:35:00Z"}, {"id": "ALT-2895", "rule": "C2 Beacon Detected", "source_ip": "10.1.5.22", "target": "185.100.86.1", "time": "2026-02-08T15:01:00Z"}]},
                "response": "**3 critical alerts** in the last 24h — all from **10.1.5.22**:\n\n| Alert | Rule | Target | Time |\n|-------|------|--------|------|\n| ALT-2891 | Lateral Movement | 10.1.5.50 | 14:22 UTC |\n| ALT-2893 | Data Exfiltration | 185.100.86.1 | 14:35 UTC |\n| ALT-2895 | C2 Beacon | 185.100.86.1 | 15:01 UTC |\n\nThis looks like an active compromise — 10.1.5.22 moved laterally then began exfiltrating to 185.100.86.1. Isolate 10.1.5.22 immediately.",
            },
        ],
    },
    {
        "name": "get_endpoint_status",
        "description": "Get endpoint security agent status",
        "parameters": {
            "type": "object",
            "properties": {
                "hostname": {"type": "string", "description": "Endpoint hostname"},
            },
            "required": ["hostname"],
        },
        "examples": [
            {
                "query": "endpoint status for DESKTOP-JM4522",
                "call": {"name": "get_endpoint_status", "parameters": {"hostname": "DESKTOP-JM4522"}},
                "result": {"status": "success", "hostname": "DESKTOP-JM4522", "agent": "CrowdStrike Falcon", "agent_version": "7.10.18607", "last_checkin": "2026-02-08T16:00:00Z", "os": "Windows 11 23H2", "policy": "Standard-Workstation", "isolation": False},
                "response": "**DESKTOP-JM4522**:\n\n| Field | Value |\n|-------|-------|\n| Agent | CrowdStrike Falcon 7.10 |\n| Last check-in | 2026-02-08 16:00 UTC |\n| OS | Windows 11 23H2 |\n| Policy | Standard-Workstation |\n| Isolated | No |\n\nAgent is current and checking in normally.",
            },
        ],
    },
    {
        "name": "run_vulnerability_scan",
        "description": "Run or retrieve vulnerability scan results for a target",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, hostname, or subnet"},
                "scan_type": {"type": "string", "description": "quick, full, or compliance"},
            },
            "required": ["target"],
        },
        "examples": [
            {
                "query": "vulnerability scan on 10.2.0.0/24",
                "call": {"name": "run_vulnerability_scan", "parameters": {"target": "10.2.0.0/24", "scan_type": "quick"}},
                "result": {"status": "success", "target": "10.2.0.0/24", "hosts_scanned": 45, "vulnerabilities": {"critical": 2, "high": 8, "medium": 23, "low": 41}, "top_findings": [{"host": "10.2.0.15", "vuln": "CVE-2024-6387 OpenSSH regreSSHion", "severity": "critical"}, {"host": "10.2.0.22", "vuln": "CVE-2024-3094 XZ Utils backdoor", "severity": "critical"}]},
                "response": "**10.2.0.0/24** scan — 45 hosts, 74 vulnerabilities:\n\n| Severity | Count |\n|----------|-------|\n| Critical | 2 |\n| High | 8 |\n| Medium | 23 |\n| Low | 41 |\n\n**Critical findings:**\n- 10.2.0.15 — CVE-2024-6387 (OpenSSH regreSSHion)\n- 10.2.0.22 — CVE-2024-3094 (XZ Utils backdoor)\n\nPatch these two hosts immediately.",
            },
        ],
    },
    {
        "name": "get_cloud_inventory",
        "description": "List cloud resources by type and region",
        "parameters": {
            "type": "object",
            "properties": {
                "provider": {"type": "string", "description": "aws, azure, or gcp"},
                "resource_type": {"type": "string", "description": "vm, sg, vpc, subnet, lb"},
                "region": {"type": "string", "description": "Cloud region (e.g. us-east-1)"},
            },
            "required": ["provider"],
        },
        "examples": [
            {
                "query": "list AWS security groups in us-east-1",
                "call": {"name": "get_cloud_inventory", "parameters": {"provider": "aws", "resource_type": "sg", "region": "us-east-1"}},
                "result": {"status": "success", "provider": "aws", "region": "us-east-1", "count": 3, "resources": [{"id": "sg-0abc123", "name": "web-tier-sg", "vpc": "vpc-prod-01", "rules_count": 8}, {"id": "sg-0def456", "name": "db-tier-sg", "vpc": "vpc-prod-01", "rules_count": 3}, {"id": "sg-0ghi789", "name": "default", "vpc": "vpc-prod-01", "rules_count": 2}]},
                "response": "**AWS us-east-1** security groups:\n\n| SG ID | Name | VPC | Rules |\n|-------|------|-----|-------|\n| sg-0abc123 | web-tier-sg | vpc-prod-01 | 8 |\n| sg-0def456 | db-tier-sg | vpc-prod-01 | 3 |\n| sg-0ghi789 | default | vpc-prod-01 | 2 |\n\nThe `default` SG should be reviewed — it's best practice to not use the default security group.",
            },
        ],
    },
    {
        "name": "check_password_policy",
        "description": "Check password policy compliance for a domain or system",
        "parameters": {
            "type": "object",
            "properties": {
                "domain": {"type": "string", "description": "AD domain or system name"},
            },
            "required": ["domain"],
        },
        "examples": [
            {
                "query": "check password policy for corp.local",
                "call": {"name": "check_password_policy", "parameters": {"domain": "corp.local"}},
                "result": {"status": "success", "domain": "corp.local", "min_length": 8, "complexity": True, "max_age_days": 90, "lockout_threshold": 5, "lockout_duration_min": 30, "history_count": 12, "compliant": False, "issues": ["min_length should be 14+", "max_age should be 365 or never"]},
                "response": "**corp.local** password policy:\n\n| Setting | Current | Recommended |\n|---------|---------|-------------|\n| Min length | 8 | 14+ |\n| Complexity | Yes | Yes |\n| Max age | 90 days | 365 days or disable |\n| Lockout | 5 attempts / 30 min | OK |\n| History | 12 | OK |\n\n**Non-compliant**: NIST 800-63B recommends minimum 14 characters and eliminating forced rotation. Update your GPO.",
            },
        ],
    },
]

# Additional error scenarios for diverse tools
GENERIC_ERROR_EXAMPLES = [
    {
        "tool": "lookup_cve",
        "query": "look up CVE-9999-0000",
        "call": {"name": "lookup_cve", "parameters": {"cve_id": "CVE-9999-0000"}},
        "result": {"status": "error", "error": "CVE not found in database"},
        "response": "CVE-9999-0000 was not found in the vulnerability database. Verify the CVE ID is correct.",
    },
    {
        "tool": "scan_ports",
        "query": "scan 10.99.99.99",
        "call": {"name": "scan_ports", "parameters": {"target": "10.99.99.99"}},
        "result": {"status": "error", "error": "Host unreachable - connection timed out"},
        "response": "10.99.99.99 is unreachable — connection timed out. Verify the host is online and not blocked by a firewall.",
    },
    {
        "tool": "get_bgp_neighbors",
        "query": "BGP status on offline-rtr",
        "call": {"name": "get_bgp_neighbors", "parameters": {"router": "offline-rtr"}},
        "result": {"status": "error", "error": "Device not reachable via SSH"},
        "response": "Cannot reach offline-rtr via SSH. The device may be down or SSH access is blocked.",
    },
    {
        "tool": "check_ssl_cert",
        "query": "check ssl on internal-app.local",
        "call": {"name": "check_ssl_cert", "parameters": {"host": "internal-app.local"}},
        "result": {"status": "error", "error": "SSL handshake failed - self-signed certificate"},
        "response": "SSL handshake failed for internal-app.local — self-signed certificate detected. This host is using an untrusted cert.",
    },
]


SYSTEM_PROMPTS = [
    (
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- For optional parameters like device_group, leave them null unless the user specified one.\n"
        "- After a tool returns data, present findings concisely using markdown tables.\n"
        "- Don't narrate your process. Present results directly."
    ),
    (
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- For optional parameters like device_group, leave them null unless the user specified one.\n"
        "- After a tool returns data, present findings concisely using markdown tables."
    ),
    (
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- Don't narrate your process. Present results directly."
    ),
]


def build_schema_json(tool_def: dict) -> str:
    """Build compact schema JSON string from a tool definition."""
    schema = {
        "name": tool_def["name"],
        "description": tool_def["description"],
        "parameters": tool_def["parameters"],
    }
    return json.dumps(schema, ensure_ascii=False)


def build_diverse_example(tool_def: dict, example: dict, rng: random.Random,
                          extra_tools: list = None) -> dict:
    """Build a single diverse tool calling training example."""
    system_prompt = rng.choice(SYSTEM_PROMPTS)

    # Build tool schemas for system message (1-3 tools including the target)
    schemas = [build_schema_json(tool_def)]
    if extra_tools:
        for et in extra_tools:
            schemas.append(build_schema_json(et))

    system_value = f"{system_prompt}\n\nEnvironment: ipython\n\n" + "\n".join(schemas)

    convs = [
        {"from": "system", "value": system_value},
        {"from": "human", "value": example["query"]},
        {"from": "gpt", "value": "<|python_tag|>" + json.dumps(example["call"], ensure_ascii=False)},
        {"from": "ipython", "value": json.dumps(example["result"], ensure_ascii=False)},
        {"from": "gpt", "value": example["response"]},
    ]

    return {"conversations": convs}


def _rand_ip(rng: random.Random) -> str:
    return f"{rng.randint(10,192)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"


def _rand_hostname(rng: random.Random) -> str:
    prefixes = ["fw", "rtr", "sw", "srv", "web", "db", "app", "core", "edge", "vpn", "lb", "proxy", "waf", "ids"]
    locations = ["east", "west", "north", "south", "central", "dc1", "dc2", "prod", "stg", "dev", "dmz", "corp"]
    return f"{rng.choice(prefixes)}-{rng.choice(locations)}-{rng.randint(1,99):02d}"


def _rand_domain(rng: random.Random) -> str:
    names = ["acme", "contoso", "globex", "initech", "umbrella", "waystar", "delos", "soylent", "cyberdyne", "oscorp"]
    tlds = ["com", "net", "org", "io", "xyz", "co", "tech", "cloud"]
    subs = ["", "api.", "portal.", "mail.", "vpn.", "admin.", "app.", "dev.", "staging.", "internal."]
    return f"{rng.choice(subs)}{rng.choice(names)}.{rng.choice(tlds)}"


def _rand_cve(rng: random.Random) -> str:
    return f"CVE-{rng.randint(2020,2026)}-{rng.randint(1000,99999)}"


def _rand_port(rng: random.Random) -> tuple:
    ports = [(22, "ssh", "OpenSSH 8.9"), (80, "http", "Apache 2.4"), (443, "https", "nginx/1.24"),
             (3306, "mysql", "MySQL 8.0"), (5432, "postgresql", "PostgreSQL 15"), (6379, "redis", "Redis 7.2"),
             (8080, "http-alt", "Tomcat 10"), (8443, "https-alt", "WildFly 30"), (27017, "mongodb", "MongoDB 7.0"),
             (9200, "elasticsearch", "ES 8.12"), (3389, "rdp", "Microsoft RDP"), (25, "smtp", "Postfix 3.8")]
    return rng.choice(ports)


# Parametric generators: each returns (query, call, result, response) tuple
def _gen_lookup_cve(rng):
    cve = _rand_cve(rng)
    severity = rng.choice(["critical", "high", "medium"])
    cvss = round(rng.uniform(4.0, 10.0), 1)
    descs = [
        "Remote code execution in web framework",
        "Authentication bypass in API gateway",
        "SQL injection in admin panel",
        "Buffer overflow in network daemon",
        "Privilege escalation via kernel vulnerability",
        "Cross-site scripting in dashboard component",
        "Insecure deserialization in message queue",
        "Path traversal in file upload handler",
    ]
    desc = rng.choice(descs)
    queries = [f"look up {cve}", f"details on {cve}", f"what is {cve}", f"CVE info for {cve}", f"check {cve}"]
    return (
        rng.choice(queries),
        {"name": "lookup_cve", "parameters": {"cve_id": cve}},
        {"status": "success", "cve_id": cve, "severity": severity, "cvss": cvss, "description": desc},
        f"**{cve}** — {severity.title()} (CVSS {cvss})\n\n{desc}. Review affected systems and patch accordingly.",
    )


def _gen_query_dns(rng):
    domain = _rand_domain(rng)
    rec_type = rng.choice(["A", "MX", "CNAME", "TXT", "NS"])
    ip = _rand_ip(rng)
    queries = [f"resolve {domain}", f"DNS lookup for {domain}", f"{rec_type} records for {domain}",
               f"what does {domain} resolve to"]
    call_params = {"domain": domain}
    if rec_type != "A":
        call_params["record_type"] = rec_type
    return (
        rng.choice(queries),
        {"name": "query_dns", "parameters": call_params},
        {"status": "success", "domain": domain, "records": [{"type": rec_type, "value": ip, "ttl": rng.choice([60, 300, 600, 3600])}]},
        f"**{domain}** resolves to:\n\n| Type | Value | TTL |\n|------|-------|-----|\n| {rec_type} | {ip} | {rng.choice([60,300,600,3600])}s |",
    )


def _gen_scan_ports(rng):
    target = _rand_ip(rng)
    n_ports = rng.randint(1, 4)
    open_ports = [_rand_port(rng) for _ in range(n_ports)]
    queries = [f"scan ports on {target}", f"port scan {target}", f"what ports are open on {target}",
               f"nmap {target}", f"check open ports {target}"]
    return (
        rng.choice(queries),
        {"name": "scan_ports", "parameters": {"target": target}},
        {"status": "success", "target": target, "open_ports": [{"port": p, "service": s, "version": v} for p, s, v in open_ports]},
        f"**{target}** — {n_ports} open port{'s' if n_ports > 1 else ''}:\n\n| Port | Service |\n|------|---------|\n" +
        "\n".join(f"| {p} | {s} |" for p, s, _ in open_ports),
    )


def _gen_whois(rng):
    domain = _rand_domain(rng)
    registrars = ["NameCheap Inc", "GoDaddy LLC", "Cloudflare Inc", "Google Domains", "Namecheap Inc"]
    countries = ["US", "RU", "CN", "DE", "NL", "RO", "UA", "GB", "CA"]
    queries = [f"whois for {domain}", f"whois {domain}", f"who owns {domain}", f"registration info for {domain}"]
    country = rng.choice(countries)
    return (
        rng.choice(queries),
        {"name": "whois_lookup", "parameters": {"query": domain}},
        {"status": "success", "domain": domain, "registrar": rng.choice(registrars), "created": f"20{rng.randint(20,25)}-{rng.randint(1,12):02d}-{rng.randint(1,28):02d}", "registrant_country": country},
        f"**{domain}** registered with {rng.choice(registrars)}, country: {country}.",
    )


def _gen_ssl_cert(rng):
    host = _rand_domain(rng)
    days = rng.randint(-200, 400)
    expired = days < 0
    issuers = ["DigiCert SHA2 EV", "Let's Encrypt", "Comodo RSA", "GlobalSign", "Sectigo"]
    protocols = ["TLSv1.2", "TLSv1.3"]
    queries = [f"check the SSL cert on {host}", f"ssl check {host}", f"certificate status for {host}",
               f"is {host} cert valid", f"TLS check on {host}"]
    return (
        rng.choice(queries),
        {"name": "check_ssl_cert", "parameters": {"host": host}},
        {"status": "success", "host": host, "issuer": rng.choice(issuers), "days_remaining": days, "protocol": rng.choice(protocols)},
        f"**{host}** — {'EXPIRED' if expired else 'Valid'} ({abs(days)} days {'ago' if expired else 'remaining'}). {rng.choice(protocols)}." +
        (" Renew immediately." if expired else ""),
    )


def _gen_threat_intel(rng):
    ip = _rand_ip(rng)
    score = rng.randint(5, 100)
    cats_pool = ["tor-exit-node", "brute-force", "scanner", "botnet", "phishing", "spam", "malware-host", "c2-server"]
    cats = rng.sample(cats_pool, rng.randint(1, 3))
    countries = ["US", "RU", "CN", "DE", "NL", "RO", "UA", "IR", "KP", "BR"]
    queries = [f"threat intel on {ip}", f"is {ip} malicious", f"reputation for {ip}",
               f"check {ip} against threat feeds", f"threat report for {ip}"]
    rep = "malicious" if score > 70 else "suspicious" if score > 40 else "clean"
    return (
        rng.choice(queries),
        {"name": "get_threat_intel", "parameters": {"indicator": ip}},
        {"status": "success", "indicator": ip, "reputation": rep, "threat_score": score, "categories": cats, "country": rng.choice(countries)},
        f"**{ip}** — {rep.title()} (Score: {score}/100). Categories: {', '.join(cats)}." +
        (" Block at the perimeter." if score > 70 else ""),
    )


def _gen_zones(rng):
    device = _rand_hostname(rng)
    zone_names = ["trust", "untrust", "dmz", "management", "guest", "iot", "servers", "vpn-zone", "lab"]
    n_zones = rng.randint(2, 5)
    zones = rng.sample(zone_names, n_zones)
    queries = [f"list zones on {device}", f"show zones for {device}", f"what zones are on {device}",
               f"security zones on {device}"]
    return (
        rng.choice(queries),
        {"name": "list_firewall_zones", "parameters": {"device": device}},
        {"status": "success", "device": device, "zones": [{"name": z, "type": "layer3"} for z in zones]},
        f"**{device}** — {n_zones} zones: {', '.join(zones)}.",
    )


def _gen_bgp(rng):
    router = _rand_hostname(rng)
    n_peers = rng.randint(1, 4)
    peers = []
    for _ in range(n_peers):
        state = rng.choice(["Established", "Established", "Established", "Idle", "Active", "OpenSent"])
        peers.append({"peer": _rand_ip(rng), "asn": rng.randint(64512, 65534), "state": state, "prefixes": rng.randint(0, 5000) if state == "Established" else 0})
    queries = [f"BGP neighbors on {router}", f"show bgp summary for {router}", f"BGP status on {router}",
               f"check BGP peering on {router}"]
    down = [p for p in peers if p["state"] != "Established"]
    return (
        rng.choice(queries),
        {"name": "get_bgp_neighbors", "parameters": {"router": router}},
        {"status": "success", "router": router, "neighbors": peers},
        f"**{router}** — {n_peers} BGP peers, {len(down)} down." +
        (" Check connectivity to down peers." if down else " All peers healthy."),
    )


def _gen_interface(rng):
    device = _rand_hostname(rng)
    ifaces = ["eth1/1", "eth1/2", "eth1/3", "GigabitEthernet0/0", "GigabitEthernet0/1", "ae0", "bond0", "Ethernet1"]
    iface = rng.choice(ifaces)
    errors = rng.randint(0, 50)
    drops = rng.randint(0, 200)
    queries = [f"interface stats for {iface} on {device}", f"show {iface} counters on {device}",
               f"errors on {device} {iface}", f"check {iface} on {device}"]
    speed = rng.choice(["1Gbps", "10Gbps", "25Gbps", "100Gbps"])
    return (
        rng.choice(queries),
        {"name": "get_interface_stats", "parameters": {"device": device, "interface": iface}},
        {"status": "success", "device": device, "interface": iface, "status": "up", "speed": speed, "in_errors": errors, "drops": drops},
        f"**{device} {iface}** — Up at {speed}. {errors} errors, {drops} drops." +
        (" Investigate error source." if errors > 10 else ""),
    )


def _gen_ip_rep(rng):
    ip = _rand_ip(rng)
    score = rng.randint(0, 100)
    cats = ["scanner", "proxy", "vpn", "tor", "hosting", "isp", "education", "government"]
    queries = [f"reputation check on {ip}", f"is {ip} safe", f"IP reputation {ip}",
               f"check {ip} reputation", f"blacklist check {ip}"]
    return (
        rng.choice(queries),
        {"name": "check_ip_reputation", "parameters": {"ip": ip}},
        {"status": "success", "ip": ip, "score": score, "category": rng.choice(cats), "blacklisted": score > 80},
        f"**{ip}** — Score: {score}/100. {'Blacklisted — block this IP.' if score > 80 else 'No immediate threat.'}",
    )


def _gen_siem(rng):
    severities = ["critical", "high", "medium"]
    severity = rng.choice(severities)
    time_ranges = ["1h", "6h", "24h", "7d"]
    time_range = rng.choice(time_ranges)
    rules = ["Lateral Movement Detected", "Data Exfiltration Attempt", "C2 Beacon Detected",
             "Brute Force Attack", "Privilege Escalation", "Anomalous DNS Query", "Port Scan Detected",
             "Malware Download", "Unauthorized Access Attempt", "Policy Violation"]
    n_alerts = rng.randint(0, 8)
    queries = [f"show {severity} SIEM alerts from last {time_range}", f"{severity} alerts in the past {time_range}",
               f"any {severity} security alerts recently", f"SIEM {severity} events last {time_range}"]
    return (
        rng.choice(queries),
        {"name": "get_siem_alerts", "parameters": {"severity": severity, "time_range": time_range}},
        {"status": "success", "count": n_alerts, "alerts": [{"rule": rng.choice(rules), "source_ip": _rand_ip(rng)} for _ in range(n_alerts)]},
        f"**{n_alerts} {severity} alerts** in the last {time_range}." +
        (" Investigate immediately." if n_alerts > 3 and severity == "critical" else " Situation looks manageable." if n_alerts <= 2 else ""),
    )


def _gen_endpoint(rng):
    hostname = f"DESKTOP-{rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ')}{rng.randint(1000,9999)}"
    agents = ["CrowdStrike Falcon", "SentinelOne", "Microsoft Defender", "Carbon Black", "Sophos Endpoint"]
    oses = ["Windows 11 23H2", "Windows 10 22H2", "macOS 14.3", "Ubuntu 24.04", "RHEL 9.3"]
    queries = [f"endpoint status for {hostname}", f"check {hostname} agent", f"is {hostname} protected",
               f"EDR status on {hostname}"]
    return (
        rng.choice(queries),
        {"name": "get_endpoint_status", "parameters": {"hostname": hostname}},
        {"status": "success", "hostname": hostname, "agent": rng.choice(agents), "os": rng.choice(oses), "isolation": False},
        f"**{hostname}** — {rng.choice(agents)} installed, {rng.choice(oses)}. Agent active and reporting.",
    )


def _gen_vuln_scan(rng):
    target = f"{rng.randint(10,172)}.{rng.randint(0,255)}.{rng.randint(0,255)}.0/24"
    hosts = rng.randint(5, 100)
    crit = rng.randint(0, 5)
    high = rng.randint(0, 15)
    med = rng.randint(5, 40)
    queries = [f"vulnerability scan on {target}", f"scan {target} for vulnerabilities",
               f"vuln assessment for {target}", f"security scan {target}"]
    return (
        rng.choice(queries),
        {"name": "run_vulnerability_scan", "parameters": {"target": target}},
        {"status": "success", "target": target, "hosts_scanned": hosts, "vulnerabilities": {"critical": crit, "high": high, "medium": med}},
        f"**{target}** — {hosts} hosts scanned. {crit} critical, {high} high, {med} medium vulnerabilities." +
        (" Patch critical findings immediately." if crit > 0 else " No critical issues."),
    )


def _gen_cloud_inv(rng):
    providers = ["aws", "azure", "gcp"]
    provider = rng.choice(providers)
    resource_types = ["sg", "vm", "vpc", "subnet", "lb"]
    res_type = rng.choice(resource_types)
    regions = {"aws": ["us-east-1", "us-west-2", "eu-west-1"], "azure": ["eastus", "westeurope", "southeastasia"], "gcp": ["us-central1", "europe-west1", "asia-east1"]}
    region = rng.choice(regions[provider])
    n_resources = rng.randint(1, 8)
    queries = [f"list {provider.upper()} {res_type}s in {region}", f"{provider} {res_type} inventory for {region}",
               f"show {provider} resources in {region}"]
    return (
        rng.choice(queries),
        {"name": "get_cloud_inventory", "parameters": {"provider": provider, "resource_type": res_type, "region": region}},
        {"status": "success", "provider": provider, "region": region, "count": n_resources},
        f"**{provider.upper()} {region}** — {n_resources} {res_type} resource{'s' if n_resources > 1 else ''} found.",
    )


def _gen_password_policy(rng):
    domains = ["corp.local", "internal.acme.com", "ad.contoso.net", "hq.globex.org", "prod.initech.io"]
    domain = rng.choice(domains)
    min_len = rng.choice([6, 8, 10, 12, 14, 16])
    max_age = rng.choice([30, 60, 90, 180, 365, 0])
    compliant = min_len >= 14 and (max_age == 0 or max_age >= 365)
    queries = [f"check password policy for {domain}", f"password requirements on {domain}",
               f"AD password policy {domain}", f"is {domain} password policy compliant"]
    return (
        rng.choice(queries),
        {"name": "check_password_policy", "parameters": {"domain": domain}},
        {"status": "success", "domain": domain, "min_length": min_len, "max_age_days": max_age, "compliant": compliant},
        f"**{domain}** — Min length: {min_len}, Max age: {max_age if max_age else 'never'}. " +
        ("Compliant." if compliant else "Non-compliant — update GPO per NIST 800-63B."),
    )


# Map generator functions to tool definitions
PARAMETRIC_GENERATORS = [
    _gen_lookup_cve,
    _gen_query_dns,
    _gen_scan_ports,
    _gen_whois,
    _gen_ssl_cert,
    _gen_threat_intel,
    _gen_zones,
    _gen_bgp,
    _gen_interface,
    _gen_ip_rep,
    _gen_siem,
    _gen_endpoint,
    _gen_vuln_scan,
    _gen_cloud_inv,
    _gen_password_policy,
]

# Map generator to tool def for schema lookup
GENERATOR_TOOL_MAP = {
    _gen_lookup_cve: "lookup_cve",
    _gen_query_dns: "query_dns",
    _gen_scan_ports: "scan_ports",
    _gen_whois: "whois_lookup",
    _gen_ssl_cert: "check_ssl_cert",
    _gen_threat_intel: "get_threat_intel",
    _gen_zones: "list_firewall_zones",
    _gen_bgp: "get_bgp_neighbors",
    _gen_interface: "get_interface_stats",
    _gen_ip_rep: "check_ip_reputation",
    _gen_siem: "get_siem_alerts",
    _gen_endpoint: "get_endpoint_status",
    _gen_vuln_scan: "run_vulnerability_scan",
    _gen_cloud_inv: "get_cloud_inventory",
    _gen_password_policy: "check_password_policy",
}


def generate_diverse_examples(count: int, rng: random.Random) -> list:
    """Generate diverse generic tool calling examples with parametric variation."""
    tool_by_name = {t["name"]: t for t in GENERIC_TOOLS}
    examples = []
    seen_queries = set()

    attempts = 0
    while len(examples) < count and attempts < count * 3:
        attempts += 1

        # Pick a random generator
        gen_fn = rng.choice(PARAMETRIC_GENERATORS)
        query, call, result, response = gen_fn(rng)

        # Skip if we've seen this exact query
        q_hash = hashlib.md5(query.strip().lower().encode()).hexdigest()
        if q_hash in seen_queries:
            continue
        seen_queries.add(q_hash)

        # Build the example
        tool_name = GENERATOR_TOOL_MAP[gen_fn]
        tool_def = tool_by_name[tool_name]

        # Pick 0-2 extra tools for system message
        other_tools = [t for t in GENERIC_TOOLS if t["name"] != tool_name]
        extra_count = rng.choice([0, 0, 1, 1, 2])
        extra_tools = rng.sample(other_tools, min(extra_count, len(other_tools)))

        system_prompt = rng.choice(SYSTEM_PROMPTS)
        schemas = [build_schema_json(tool_def)]
        for et in extra_tools:
            schemas.append(build_schema_json(et))
        system_value = f"{system_prompt}\n\nEnvironment: ipython\n\n" + "\n".join(schemas)

        convs = [
            {"from": "system", "value": system_value},
            {"from": "human", "value": query},
            {"from": "gpt", "value": "<|python_tag|>" + json.dumps(call, ensure_ascii=False)},
            {"from": "ipython", "value": json.dumps(result, ensure_ascii=False)},
            {"from": "gpt", "value": response},
        ]

        examples.append({"conversations": convs})

    rng.shuffle(examples)
    return examples


def main():
    parser = argparse.ArgumentParser(description="Augment dataset for tool calling generalization")
    parser.add_argument("--input", default="data/processed/combined_train.json",
                        help="Input combined dataset")
    parser.add_argument("--output", default="data/processed/combined_train.json",
                        help="Output path (overwrites input by default)")
    parser.add_argument("--mask-pct", type=float, default=0.40,
                        help="Fraction of tool calling examples to apply function masking (default 0.40)")
    parser.add_argument("--diverse-count", type=int, default=500,
                        help="Number of diverse generic tool examples to add (default 500)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # -------------------------------------------------------------------------
    # Step 1: Load existing dataset
    # -------------------------------------------------------------------------
    print("=" * 60)
    print("STEP 1: Load existing combined dataset")
    print("=" * 60)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input not found: {input_path}")
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))
    print(f"  Loaded: {len(data)} examples")

    # Separate tool calling from knowledge
    tc_examples = []
    kn_examples = []
    for ex in data:
        convs = ex.get("conversations", [])
        has_tool_call = any(
            "<|python_tag|>" in c.get("value", "")
            for c in convs if c["from"] == "gpt" and isinstance(c.get("value"), str)
        )
        has_ipython = any(c["from"] == "ipython" for c in convs)
        if has_tool_call or has_ipython:
            tc_examples.append(ex)
        else:
            kn_examples.append(ex)

    print(f"  Tool calling: {len(tc_examples)}")
    print(f"  Knowledge: {len(kn_examples)}")

    # -------------------------------------------------------------------------
    # Step 2: Apply function masking
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 2: Apply function masking (Hammer technique)")
    print("=" * 60)

    mask_count = int(len(tc_examples) * args.mask_pct)
    indices = list(range(len(tc_examples)))
    rng.shuffle(indices)
    mask_indices = set(indices[:mask_count])

    masked_count = 0
    for i in mask_indices:
        original = tc_examples[i]
        masked = mask_tool_names_in_example(original, rng)
        tc_examples[i] = masked
        masked_count += 1

    print(f"  Masked {masked_count}/{len(tc_examples)} tool calling examples ({args.mask_pct*100:.0f}%)")

    # Verify a sample
    sample_idx = list(mask_indices)[:3]
    for idx in sample_idx:
        ex = tc_examples[idx]
        sys_val = ex["conversations"][0]["value"]
        # Find tool names in system message
        names_in_sys = re.findall(r'"name":\s*"([^"]+)"', sys_val)
        gpt_calls = [c for c in ex["conversations"] if c["from"] == "gpt" and "<|python_tag|>" in c.get("value", "")]
        if gpt_calls:
            try:
                tc_json = json.loads(gpt_calls[0]["value"].split("<|python_tag|>")[1])
                call_name = tc_json.get("name", "?")
            except Exception:
                call_name = "?"
        else:
            call_name = "(no call)"
        print(f"  Sample: schema names={names_in_sys[:3]}, call name={call_name}")

    # -------------------------------------------------------------------------
    # Step 3: Generate diverse generic tool examples
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 3: Generate diverse generic tool examples")
    print("=" * 60)

    diverse = generate_diverse_examples(args.diverse_count, rng)
    print(f"  Generated: {len(diverse)} diverse examples")
    print(f"  Unique tools used: {len(GENERIC_TOOLS)}")

    # Count by tool
    tool_counts = {}
    for ex in diverse:
        for c in ex["conversations"]:
            if c["from"] == "gpt" and "<|python_tag|>" in c.get("value", ""):
                try:
                    tc = json.loads(c["value"].split("<|python_tag|>")[1])
                    tool_counts[tc["name"]] = tool_counts.get(tc["name"], 0) + 1
                except Exception:
                    pass
    for name, count in sorted(tool_counts.items()):
        print(f"    {name}: {count}")

    # -------------------------------------------------------------------------
    # Step 4: Combine and validate
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 4: Combine and deduplicate")
    print("=" * 60)

    combined = tc_examples + kn_examples + diverse

    # Dedup by human content hash
    seen = set()
    deduped = []
    dupe_count = 0
    for ex in combined:
        convs = ex.get("conversations", [])
        human_turns = " ".join(
            c["value"] for c in convs
            if c["from"] == "human" and isinstance(c["value"], str)
        )
        h = hashlib.md5(human_turns.strip().lower().encode()).hexdigest()
        if h not in seen:
            seen.add(h)
            deduped.append(ex)
        else:
            dupe_count += 1

    rng.shuffle(deduped)

    print(f"  Before dedup: {len(combined)}")
    print(f"  Duplicates removed: {dupe_count}")
    print(f"  Final total: {len(deduped)}")

    # -------------------------------------------------------------------------
    # Step 5: Validate
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 5: Validate")
    print("=" * 60)

    issues = 0
    no_system = 0
    non_string = 0
    for ex in deduped:
        convs = ex.get("conversations", [])
        if not convs or convs[0]["from"] != "system":
            no_system += 1
            issues += 1
        for c in convs:
            if not isinstance(c.get("value"), str):
                non_string += 1
                issues += 1

    # Count categories
    tc_final = sum(1 for ex in deduped if any(
        "<|python_tag|>" in c.get("value", "")
        for c in ex.get("conversations", [])
        if c["from"] == "gpt" and isinstance(c.get("value"), str)
    ))
    kn_final = len(deduped) - tc_final

    # Count masked examples
    masked_final = 0
    for ex in deduped:
        for c in ex.get("conversations", []):
            if c["from"] == "gpt" and "<|python_tag|>" in c.get("value", ""):
                try:
                    tc = json.loads(c["value"].split("<|python_tag|>")[1])
                    name = tc.get("name", "")
                    if name.startswith(("fn_", "tool_", "op_", "func_", "api_", "action_")):
                        masked_final += 1
                except Exception:
                    pass
                break

    print(f"  Tool calling examples: {tc_final}")
    print(f"    Masked names: {masked_final}")
    print(f"    Real names: {tc_final - masked_final}")
    print(f"  Knowledge examples: {kn_final}")
    print(f"  Validation issues: {issues}")
    if no_system:
        print(f"    Missing system: {no_system}")
    if non_string:
        print(f"    Non-string values: {non_string}")

    # -------------------------------------------------------------------------
    # Step 6: Write output
    # -------------------------------------------------------------------------
    if args.dry_run:
        print(f"\n{'=' * 60}")
        print("DRY RUN — no file written")
        print("=" * 60)
    else:
        print(f"\n{'=' * 60}")
        print("STEP 6: Write augmented dataset")
        print("=" * 60)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(deduped, f, indent=2, ensure_ascii=False)

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"  Written to: {output_path}")
        print(f"  File size: {size_mb:.1f} MB")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"  Original dataset:     {len(data)} examples")
    print(f"  + Diverse generic:    +{len(diverse)} examples")
    print(f"  - Duplicates:         -{dupe_count}")
    print(f"  Final dataset:        {len(deduped)} examples")
    print(f"  Function masking:     {masked_final} examples ({masked_final/tc_final*100:.1f}% of tool calls)")
    print(f"  Validation:           {'PASS' if issues == 0 else 'FAIL'}")


if __name__ == "__main__":
    sys.exit(main())
