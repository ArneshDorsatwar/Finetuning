#!/usr/bin/env python3
"""
Generate Llama 3.1 native tool calling training data for Ember/FireWeave.

Produces training examples in ShareGPT format with correct roles:
  system, human (user), gpt (assistant), ipython (tool result)

Supports two modes:
  local  - Template-based generation (fast, no API needed)
  claude - Uses Claude API for varied queries and Q&A (higher quality)

Usage:
    python scripts/generate_tool_calling_data.py --count 3000 --output data/processed/tool_calling_train.json
    python scripts/generate_tool_calling_data.py --count 3000 --provider claude --output data/processed/tool_calling_train.json
    python scripts/generate_tool_calling_data.py --count 100 --dry-run
    python scripts/generate_tool_calling_data.py --count 500 --category tool_call
    python scripts/generate_tool_calling_data.py --stats
"""

import json
import os
import random
import argparse
import hashlib
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# =============================================================================
# CONSTANTS
# =============================================================================

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

DEVICE_GROUPS = [
    "US-East-DC1", "US-West-DC2", "EU-West-DC1", "EU-Central-DC2",
    "APAC", "APAC-SG", "EMEA-DC1", "EMEA-DC2", "LATAM-DC1",
    "US-Prod", "EU-Prod", "APAC-Prod", "DG-Datacenter", "DG-Branch",
    "DG-DMZ", "DG-Corp", "Shared",
]

ZONES = ["trust", "untrust", "dmz", "inside", "outside", "servers", "users", "management"]

RULE_NAMES = [
    "Allow-Web-Traffic", "Allow-HTTPS-Internal", "Allow-Internal-DNS",
    "Block-Legacy-Protocols", "Deny-Telnet", "Allow-SSH-JumpServer",
    "DMZ-to-Internal", "Web-Server-Access", "Allow-ICMP-Monitoring",
    "Deny-All-Default", "Allow-VPN-Traffic", "Allow-SMTP-Relay",
    "Allow-NTP-Sync", "Block-P2P", "Allow-Database-Access",
    "Allow-LDAP-Auth", "Deny-External-RDP", "Allow-SIP-Traffic",
    "Legacy-FTP-Allow", "Test-Rule-2023", "Old-VPN-Access",
    "Allow-Backup-Traffic", "Deny-Outbound-SSH", "Allow-Proxy-Access",
    "Old-Migration-Rule", "Temp-Debug-Rule", "Allow-HA-Sync",
]

ADMIN_NAMES = ["jsmith", "admin", "netops", "security-team", "alee", "mjohnson", "firewall-admin"]

# IP pools for realistic variety
IP_POOLS = {
    "internal_10": [f"10.{a}.{b}.{c}" for a in range(0, 256, 17) for b in range(0, 256, 31) for c in range(1, 255, 37)],
    "internal_172": [f"172.{a}.{b}.{c}" for a in range(16, 32, 2) for b in range(0, 256, 29) for c in range(1, 255, 41)],
    "internal_192": [f"192.168.{b}.{c}" for b in range(0, 256, 13) for c in range(1, 255, 23)],
    "public": [f"{a}.{b}.{c}.{d}" for a in [203, 198, 52, 40, 34, 151] for b in range(0, 114, 37) for c in range(10, 200, 47) for d in range(1, 255, 53)],
}

SUBNETS = [
    "10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.10.0.0/16",
    "172.16.0.0/12", "172.16.0.0/24", "172.20.0.0/16",
    "192.168.0.0/16", "192.168.1.0/24", "192.168.10.0/24",
]

PORTS_AND_SERVICES = [
    (22, "SSH", "tcp"), (25, "SMTP", "tcp"), (53, "DNS", "udp"),
    (80, "HTTP", "tcp"), (443, "HTTPS", "tcp"), (3306, "MySQL", "tcp"),
    (3389, "RDP", "tcp"), (5432, "PostgreSQL", "tcp"), (8080, "HTTP-Alt", "tcp"),
    (8443, "HTTPS-Alt", "tcp"), (27017, "MongoDB", "tcp"), (6379, "Redis", "tcp"),
]

FRAMEWORKS = ["pci-dss", "soc2", "nist", "hipaa", "cis"]


def random_ip(pool="internal_10"):
    return random.choice(IP_POOLS[pool])


def random_public_ip():
    return random_ip("public")


def random_internal_ip():
    pool = random.choice(["internal_10", "internal_172", "internal_192"])
    return random_ip(pool)


def random_dg():
    return random.choice(DEVICE_GROUPS)


def random_zone():
    return random.choice(ZONES)


def random_rule():
    return random.choice(RULE_NAMES)


def random_admin():
    return random.choice(ADMIN_NAMES)


def random_port_service():
    return random.choice(PORTS_AND_SERVICES)


def random_timestamp(days_back=30):
    dt = datetime.now() - timedelta(days=random.randint(0, days_back), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# =============================================================================
# TOOL SCHEMAS (compact single-line for system messages)
# =============================================================================

TOOL_SCHEMAS = {
    "search_objects": '{"name": "search_objects", "description": "Search for address and service objects across all Panoramas", "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "IP address, subnet, or object name"}, "object_type": {"type": "string", "description": "Optional: ip, address-group, service-group, tag"}, "device_group": {"type": "string", "description": "Optional device group filter"}}, "required": ["query"]}}',
    "find_unused_rules": '{"name": "find_unused_rules", "description": "Find security rules with zero hit count", "parameters": {"type": "object", "properties": {"days": {"type": "integer", "description": "Days to check (default 90)"}}}}',
    "list_unused_objects": '{"name": "list_unused_objects", "description": "List objects not referenced by any rule", "parameters": {"type": "object", "properties": {"object_type": {"type": "string", "description": "Type: address-group, service-group, tag"}, "device_group": {"type": "string"}}}}',
    "find_shadowed_rules": '{"name": "find_shadowed_rules", "description": "Find rules overshadowed by higher-priority rules", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}}}}',
    "search_rules": '{"name": "search_rules", "description": "Search security rules by criteria", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}, "source_zone": {"type": "string"}, "destination_zone": {"type": "string"}, "action": {"type": "string", "description": "allow, deny, or drop"}, "has_logging": {"type": "boolean"}}}}',
    "nat_check": '{"name": "nat_check", "description": "Test NAT policy matching for traffic flows", "parameters": {"type": "object", "properties": {"src_ip": {"type": "string"}, "dst_ip": {"type": "string"}, "src_zone": {"type": "string"}, "dst_zone": {"type": "string"}}, "required": ["src_ip", "dst_ip"]}}',
    "get_rule_statistics": '{"name": "get_rule_statistics", "description": "Get aggregate rule counts and security posture", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}}}}',
    "get_rule_hit_count": '{"name": "get_rule_hit_count", "description": "Get hit count for a specific rule", "parameters": {"type": "object", "properties": {"rule_id": {"type": "string"}, "time_range": {"type": "string", "description": "7d, 30d, or 90d"}}, "required": ["rule_id"]}}',
    "check_traffic_flow": '{"name": "check_traffic_flow", "description": "Check if traffic can flow between source and destination", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}, "port": {"type": "integer"}, "protocol": {"type": "string"}}, "required": ["source", "destination"]}}',
    "run_compliance_scan": '{"name": "run_compliance_scan", "description": "Run compliance check against a framework", "parameters": {"type": "object", "properties": {"framework": {"type": "string", "description": "pci-dss, soc2, nist, hipaa, or cis"}, "firewall": {"type": "string", "description": "Device group (optional)"}}, "required": ["framework"]}}',
    "get_dnat_exposure": '{"name": "get_dnat_exposure", "description": "Find services exposed via DNAT", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}}}}',
    "check_access": '{"name": "check_access", "description": "Verify if traffic is allowed by expanded rules", "parameters": {"type": "object", "properties": {"source_ip": {"type": "string"}, "destination_ip": {"type": "string"}, "protocol": {"type": "string"}, "port": {"type": "integer"}, "device_group": {"type": "string"}}, "required": ["source_ip", "destination_ip"]}}',
    "query_audit_logs": '{"name": "query_audit_logs", "description": "Search audit/config/system logs", "parameters": {"type": "object", "properties": {"log_type": {"type": "string", "description": "audit, config, or system"}, "search": {"type": "string"}, "admin": {"type": "string"}, "limit": {"type": "integer"}}}}',
    "get_audit_diff": '{"name": "get_audit_diff", "description": "Get before/after diff for a change event", "parameters": {"type": "object", "properties": {"event_id": {"type": "string"}}, "required": ["event_id"]}}',
    "compare_configs": '{"name": "compare_configs", "description": "Compare running vs candidate config", "parameters": {"type": "object", "properties": {"source_a_type": {"type": "string"}, "source_b_type": {"type": "string"}, "scope": {"type": "string"}, "device_group": {"type": "string"}}}}',
    "get_critical_findings": '{"name": "get_critical_findings", "description": "Get critical security findings", "parameters": {"type": "object", "properties": {"provider": {"type": "string", "description": "aws, azure, gcp, or all"}}}}',
    "get_snow_changes": '{"name": "get_snow_changes", "description": "Get open ServiceNow change requests", "parameters": {"type": "object", "properties": {}}}',
    "get_vpn_health": '{"name": "get_vpn_health", "description": "Get VPN tunnel health status", "parameters": {"type": "object", "properties": {}}}',
    "get_jira_issues": '{"name": "get_jira_issues", "description": "Get open Jira firewall change issues", "parameters": {"type": "object", "properties": {}}}',
    "find_duplicate_objects": '{"name": "find_duplicate_objects", "description": "Find duplicate address/service objects", "parameters": {"type": "object", "properties": {"object_type": {"type": "string", "description": "address, service, address-group, service-group"}}}}',
    "create_firewall_rule": '{"name": "create_firewall_rule", "description": "Create a firewall security rule", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}, "port": {"type": "string"}, "action": {"type": "string"}}, "required": ["source", "destination", "action"]}}',
    "analyze_attack_path": '{"name": "analyze_attack_path", "description": "Analyze potential attack paths from source to target", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "target": {"type": "string"}}, "required": ["source", "target"]}}',
}

# Which tools to include in system message for each example category
# Varies for realism — not every example shows all 22 tools
TOOL_SETS = {
    "search_focused": ["search_objects", "find_unused_rules", "find_shadowed_rules", "search_rules"],
    "traffic_focused": ["check_traffic_flow", "check_access", "nat_check", "search_objects"],
    "compliance_focused": ["run_compliance_scan", "search_rules", "get_rule_statistics"],
    "audit_focused": ["query_audit_logs", "get_audit_diff", "compare_configs"],
    "posture_focused": ["get_rule_statistics", "get_dnat_exposure", "get_critical_findings", "find_unused_rules"],
    "itsm_focused": ["get_snow_changes", "get_jira_issues", "search_objects"],
    "full": list(TOOL_SCHEMAS.keys()),
    "minimal": ["search_objects"],
}


def build_system_message(tool_names: List[str]) -> str:
    """Build system message with tool schemas."""
    prompt = random.choice(SYSTEM_PROMPTS)
    schemas = "\n".join(TOOL_SCHEMAS[t] for t in tool_names if t in TOOL_SCHEMAS)
    return f"{prompt}\n\nEnvironment: ipython\n\n{schemas}"


def pick_query(tool_name: str, template_category: str = "no_dg", **format_kwargs) -> str:
    """Pick a user query — tries Claude first, falls back to templates.

    For template_category: 'no_dg', 'with_dg', 'with_days', or None for flat list.
    """
    # Try Claude-generated query
    claude_q = get_claude_query(tool_name, **format_kwargs)
    if claude_q:
        return claude_q

    # Fall back to templates
    templates = QUERY_TEMPLATES.get(tool_name, [])
    if isinstance(templates, dict):
        templates = templates.get(template_category, templates.get("no_dg", []))
    if not templates:
        return f"run {tool_name}"
    query = random.choice(templates)
    try:
        return query.format(**format_kwargs)
    except KeyError:
        return query


# =============================================================================
# USER QUERY TEMPLATES
# =============================================================================

QUERY_TEMPLATES = {
    "search_objects": {
        "no_dg": [
            "where is {ip}?",
            "find {ip}",
            "look up {ip}",
            "locate {ip}",
            "search for {ip}",
            "{ip}",
            "what objects contain {ip}?",
            "where does {ip} live?",
            "find object for {ip}",
            "is {ip} in any firewall objects?",
        ],
        "with_dg": [
            "check {ip} in {dg}",
            "where is {ip} in {dg}?",
            "find {ip} in {dg}",
            "look up {ip} in {dg}",
            "search {ip} in device group {dg}",
        ],
    },
    "find_unused_rules": {
        "no_dg": [
            "find unused rules",
            "show me unused rules",
            "any rules with zero hits?",
            "which rules haven't been used?",
            "find rules with no traffic",
            "show inactive rules",
        ],
        "with_dg": [
            "find unused rules in {dg}",
            "any unused rules in {dg}?",
            "what rules haven't been used in {dg}?",
            "show inactive rules in {dg}",
        ],
        "with_days": [
            "find rules unused for {days} days",
            "show rules with no hits in {days} days",
        ],
    },
    "list_unused_objects": {
        "no_dg": [
            "show unused address groups",
            "find orphaned objects",
            "any unused service groups?",
            "list objects not in any rule",
        ],
        "with_dg": [
            "show me unused address groups in {dg}",
            "find orphaned objects in {dg}",
            "unused tags in {dg}",
        ],
    },
    "find_shadowed_rules": {
        "no_dg": [
            "find shadowed rules",
            "are there any shadowed rules?",
            "check for overshadowed rules",
            "any dead rules?",
        ],
        "with_dg": [
            "are there any shadowed rules in {dg}?",
            "find shadowed rules in {dg}",
            "check for dead rules in {dg}",
        ],
    },
    "search_rules": [
        "show me deny rules without logging in {dg}",
        "find allow rules from {zone1} to {zone2}",
        "show rules without logging",
        "find deny rules in {dg}",
        "show all allow rules from untrust to trust",
        "find rules with logging disabled",
    ],
    "nat_check": [
        "does {src} get NATted when going to {dst}?",
        "check NAT for {src} to {dst}",
        "what's the NAT translation from {src} to {dst}?",
        "is {src} translated when reaching {dst}?",
        "NAT check {src} to {dst}",
    ],
    "get_rule_statistics": {
        "no_dg": [
            "how many rules do we have?",
            "show rule statistics",
            "give me a rule count summary",
            "what's our rule posture?",
        ],
        "with_dg": [
            "how many rules in {dg}?",
            "show rule stats for {dg}",
            "rule count in {dg}",
        ],
    },
    "get_rule_hit_count": [
        "how many hits does {rule} have?",
        "check hit count for {rule}",
        "is {rule} being used?",
        "show traffic stats for {rule}",
    ],
    "check_traffic_flow": [
        "can {src} reach {dst} on port {port}?",
        "is traffic from {src} to {dst} on port {port} allowed?",
        "check if {src} can talk to {dst} on {port}",
        "test traffic flow from {src} to {dst} port {port}",
        "is {src} to {dst} on {port}/{proto} allowed?",
    ],
    "run_compliance_scan": {
        "no_dg": [
            "run {framework} compliance check",
            "scan for {framework} compliance",
            "check {framework} compliance",
            "{framework} scan",
        ],
        "with_dg": [
            "run {framework} compliance check on {dg}",
            "scan {dg} for {framework} compliance",
            "check {framework} in {dg}",
        ],
    },
    "get_dnat_exposure": {
        "no_dg": [
            "what services are exposed to the internet?",
            "show DNAT exposure",
            "any internet-facing services?",
            "show published services",
        ],
        "with_dg": [
            "what's exposed to the internet in {dg}?",
            "show DNAT in {dg}",
        ],
    },
    "check_access": [
        "can {src} access {dst} on port {port}?",
        "verify access from {src} to {dst} on {port}",
        "check if {src} can reach {dst} port {port}",
        "is {src} allowed to connect to {dst} on {port}?",
    ],
    "query_audit_logs": [
        "who made changes yesterday?",
        "show recent audit logs",
        "what did {admin} change?",
        "show config changes for {rule}",
        "any changes in the last 24 hours?",
        "who changed {rule}?",
    ],
    "get_audit_diff": [
        "show me the diff for event {event_id}",
        "what changed in {event_id}?",
        "get diff for {event_id}",
    ],
    "compare_configs": {
        "no_dg": [
            "are there any pending changes?",
            "compare running vs candidate config",
            "show pending config changes",
            "what's in the candidate config?",
        ],
        "with_dg": [
            "are there any pending changes in {dg}?",
            "compare configs in {dg}",
            "pending changes in {dg}?",
        ],
    },
    "get_critical_findings": [
        "any critical security findings?",
        "show critical vulnerabilities",
        "what are the top security risks?",
        "critical findings report",
        "any critical findings in AWS?",
    ],
    "get_snow_changes": [
        "any open ServiceNow changes?",
        "show SNOW change requests",
        "pending ServiceNow tickets?",
        "open change requests?",
    ],
    "get_vpn_health": [
        "how are the VPN tunnels?",
        "VPN tunnel status",
        "check VPN health",
        "any VPN tunnels down?",
    ],
    "get_jira_issues": [
        "any open Jira issues for firewall changes?",
        "show Jira tickets",
        "pending Jira firewall issues?",
        "open firewall change requests in Jira?",
    ],
    "find_duplicate_objects": [
        "are there duplicate address objects?",
        "find duplicate service objects",
        "any duplicate objects?",
        "show duplicate address groups",
    ],
    "create_firewall_rule": [
        "create a rule allowing {src} to access {dst} on port {port}",
        "add a rule to allow {src} to {dst} on {port}",
        "create deny rule from {src} to {dst}",
        "block {src} from reaching {dst}",
    ],
    "analyze_attack_path": [
        "analyze attack path from {src} to {dst}",
        "can an attacker reach {dst} from {src}?",
        "show attack path from {src} to {dst}",
    ],
}

# =============================================================================
# TOOL RESULT GENERATORS
# =============================================================================

def gen_result_search_objects(ip: str, dg: Optional[str] = None) -> dict:
    target_dg = dg or random_dg()
    zone = random_zone()
    rules = random.sample(RULE_NAMES, k=random.randint(1, 3))
    return {
        "status": "success",
        "results": [{
            "name": f"h-{ip}",
            "type": "ip-netmask",
            "value": f"{ip}/32",
            "device_group": target_dg,
            "zone": zone,
            "used_in_rules": rules,
        }]
    }


def gen_result_search_objects_empty() -> dict:
    return {"status": "success", "results": []}


def gen_result_find_unused_rules(dg: Optional[str] = None) -> dict:
    count = random.randint(1, 6)
    rules = []
    for _ in range(count):
        age = random.randint(90, 900)
        rules.append({
            "name": random.choice(["Legacy-FTP-Allow", "Test-Rule-2023", "Old-VPN-Access",
                                    "Temp-Debug-Rule", "Old-Migration-Rule", "Decom-Server-Rule",
                                    "Pre-Migration-Allow", "Test-NAT-Rule"]),
            "hit_count": 0,
            "last_hit": random_timestamp(365) if random.random() > 0.5 else None,
            "age_days": age,
            "device_group": dg or random_dg(),
        })
    return {"status": "success", "count": count, "rules": rules}


def gen_result_list_unused_objects(obj_type: str, dg: Optional[str] = None) -> dict:
    count = random.randint(1, 4)
    objects = []
    for i in range(count):
        objects.append({
            "name": f"{'Legacy' if random.random() > 0.5 else 'Test'}-{obj_type.title()}-{random.randint(1,99)}",
            "members": random.randint(1, 10),
            "device_group": dg or random_dg(),
        })
    return {"status": "success", "count": count, "objects": objects}


def gen_result_find_shadowed_rules(dg: Optional[str] = None) -> dict:
    count = random.randint(0, 3)
    rules = []
    for _ in range(count):
        pos = random.randint(20, 100)
        shadow_pos = random.randint(1, pos - 1)
        rules.append({
            "name": random_rule(),
            "position": pos,
            "shadowed_by": random_rule(),
            "shadowed_by_position": shadow_pos,
            "reason": random.choice([
                "Higher rule permits all HTTP traffic, making this rule unreachable",
                "Broader source/destination in higher rule covers all matches",
                "Higher rule with 'any' service shadows this specific-service rule",
            ]),
        })
    return {"status": "success", "count": count, "shadowed_rules": rules}


def gen_result_search_rules(action: str = "deny", logging: bool = False, dg: Optional[str] = None) -> dict:
    count = random.randint(1, 5)
    rules = []
    for _ in range(count):
        rules.append({
            "name": random_rule(),
            "source_zone": random_zone(),
            "destination_zone": random_zone(),
            "action": action,
            "logging": logging,
            "device_group": dg or random_dg(),
        })
    return {"status": "success", "count": count, "rules": rules}


def gen_result_nat_check(src: str, dst: str) -> dict:
    if random.random() > 0.2:
        return {
            "status": "success",
            "nat_match": True,
            "rule_name": random.choice(["Internet-SNAT", "DMZ-SNAT", "VPN-SNAT", "Cloud-NAT"]),
            "type": random.choice(["source-nat", "destination-nat"]),
            "translated_source": random_public_ip(),
            "device_group": random_dg(),
        }
    return {"status": "success", "nat_match": False, "message": "No NAT rule matched"}


def gen_result_get_rule_statistics(dg: Optional[str] = None) -> dict:
    total = random.randint(500, 8000)
    allow = int(total * random.uniform(0.6, 0.8))
    deny = total - allow
    logged = int(total * random.uniform(0.7, 0.95))
    return {
        "status": "success",
        "total_rules": total,
        "device_groups": random.randint(10, 150),
        "allow_rules": allow,
        "deny_rules": deny,
        "rules_with_logging": logged,
        "rules_without_logging": total - logged,
    }


def gen_result_get_rule_hit_count(rule: str) -> dict:
    hits = random.randint(0, 5000000)
    return {
        "status": "success",
        "rule_name": rule,
        "hit_count": hits,
        "last_hit": random_timestamp(7) if hits > 0 else None,
        "time_range": random.choice(["7d", "30d", "90d"]),
        "daily_average": hits // 30 if hits > 0 else 0,
    }


def gen_result_check_traffic_flow(src: str, dst: str, port: int) -> dict:
    allowed = random.random() > 0.3
    return {
        "status": "success",
        "verdict": "ALLOW" if allowed else "DENY",
        "matching_rule": random_rule(),
        "device_group": random_dg(),
        "src_zone": random_zone(),
        "dst_zone": random_zone(),
    }


def gen_result_run_compliance_scan(framework: str, dg: Optional[str] = None) -> dict:
    score = random.randint(55, 98)
    passed = random.randint(15, 30)
    failed = random.randint(1, 8)
    findings_pool = {
        "pci-dss": [
            {"check": "1.2.1", "description": "Restrict inbound to necessary protocols", "finding": f"{random.randint(1,5)} rules allow 'any' service"},
            {"check": "1.3.4", "description": "No unauthorized outbound from CDE", "finding": f"{random.randint(1,3)} outbound rules lack destination restriction"},
            {"check": "10.1", "description": "Audit trails for system components", "finding": f"{random.randint(5,20)} rules without logging"},
        ],
        "soc2": [
            {"check": "CC6.1", "description": "Logical access security", "finding": f"{random.randint(5,20)} rules without logging"},
            {"check": "CC7.2", "description": "System monitoring", "finding": "No alert for failed login attempts"},
        ],
        "nist": [
            {"check": "AC-4", "description": "Information flow enforcement", "finding": f"{random.randint(1,5)} overly permissive rules"},
            {"check": "AU-2", "description": "Audit events", "finding": f"{random.randint(5,15)} rules lack logging"},
        ],
        "hipaa": [
            {"check": "164.312(a)", "description": "Access control", "finding": f"{random.randint(1,4)} rules allow broad access to ePHI segments"},
            {"check": "164.312(b)", "description": "Audit controls", "finding": f"{random.randint(3,10)} rules without audit logging"},
        ],
        "cis": [
            {"check": "CIS-4.1", "description": "Restrict unnecessary services", "finding": f"{random.randint(1,5)} rules allow 'any' service"},
        ],
    }
    chosen = random.sample(findings_pool.get(framework, findings_pool["pci-dss"]), k=min(failed, len(findings_pool.get(framework, []))))
    for f in chosen:
        f["status"] = "FAIL"
    return {
        "status": "success",
        "framework": framework.upper().replace("-", "-"),
        "score": score,
        "checks_passed": passed,
        "checks_failed": failed,
        "findings": chosen,
    }


def gen_result_get_dnat_exposure(dg: Optional[str] = None) -> dict:
    count = random.randint(1, 4)
    services = []
    for _ in range(count):
        port, svc, _ = random_port_service()
        services.append({
            "public_ip": random_public_ip(),
            "internal_ip": random_internal_ip(),
            "port": port,
            "service": svc,
            "nat_rule": f"DNAT-{svc}-{random.randint(1,9)}",
            "device_group": dg or random_dg(),
        })
    return {"status": "success", "exposed_services": services}


def gen_result_check_access(src: str, dst: str, port: int) -> dict:
    allowed = random.random() > 0.4
    return {
        "status": "success",
        "allowed": allowed,
        "matching_rule": random_rule(),
        "action": "allow" if allowed else "deny",
        "device_group": random_dg(),
        "src_zone": random_zone(),
        "dst_zone": random_zone(),
    }


def gen_result_query_audit_logs(admin: Optional[str] = None) -> dict:
    count = random.randint(2, 6)
    logs = []
    for _ in range(count):
        logs.append({
            "timestamp": random_timestamp(3),
            "admin": admin or random_admin(),
            "action": random.choice(["edit", "create", "delete", "commit", "move"]),
            "target": random_rule(),
            "device_group": random_dg(),
        })
    return {"status": "success", "count": count, "logs": logs}


def gen_result_get_audit_diff(event_id: str) -> dict:
    fields = random.sample([
        {"field": "destination", "before": "10.0.0.0/24", "after": "10.0.0.0/16"},
        {"field": "source", "before": "192.168.1.0/24", "after": "192.168.0.0/16"},
        {"field": "log_forwarding", "before": None, "after": "default"},
        {"field": "action", "before": "deny", "after": "allow"},
        {"field": "service", "before": "application-default", "after": "any"},
        {"field": "description", "before": "", "after": "Updated per CHG0012345"},
    ], k=random.randint(1, 3))
    return {
        "status": "success",
        "event_id": event_id,
        "admin": random_admin(),
        "timestamp": random_timestamp(7),
        "changes": fields,
    }


def gen_result_compare_configs(dg: Optional[str] = None) -> dict:
    has_changes = random.random() > 0.3
    changes = []
    if has_changes:
        for _ in range(random.randint(1, 4)):
            changes.append({
                "type": random.choice(["modified", "added", "deleted"]),
                "object": random_rule(),
                "category": random.choice(["security-rules", "nat-rules", "objects"]),
                "detail": random.choice([
                    "destination changed /24 to /16",
                    "new allow rule for SSH",
                    "logging enabled",
                    "rule disabled",
                    "source zone changed to dmz",
                ]),
            })
    return {"status": "success", "has_changes": has_changes, "changes": changes}


def gen_result_get_critical_findings(provider: Optional[str] = None) -> dict:
    findings = random.sample([
        {"severity": "critical", "title": "RDP exposed to internet", "source": "aws", "resource": f"sg-{random.randint(10000,99999)}", "description": "Security group allows 0.0.0.0/0 on port 3389"},
        {"severity": "critical", "title": "SSH open to world", "source": "azure", "resource": f"nsg-{random.randint(100,999)}", "description": "NSG allows 0.0.0.0/0 on port 22"},
        {"severity": "high", "title": "Any-service allow rule", "source": "panorama", "resource": "Allow-All-Services", "description": "Rule allows any service from untrust to trust"},
        {"severity": "high", "title": "Expired SSL certificate", "source": "panorama", "resource": "decryption-cert-01", "description": "SSL forward proxy certificate expired 15 days ago"},
        {"severity": "critical", "title": "Public S3 bucket", "source": "aws", "resource": f"s3-backup-{random.randint(100,999)}", "description": "S3 bucket has public read access"},
    ], k=random.randint(1, 3))
    if provider:
        findings = [f for f in findings if f["source"] == provider] or findings[:1]
    return {"status": "success", "count": len(findings), "findings": findings}


def gen_result_get_snow_changes() -> dict:
    count = random.randint(0, 4)
    changes = []
    for i in range(count):
        changes.append({
            "number": f"CHG{random.randint(10000,99999)}",
            "short_description": random.choice([
                "Add HTTPS access for new web servers",
                "Remove legacy FTP rules",
                "Enable logging on deny rules",
                "Add NAT for new DMZ segment",
                "Update VPN peer configuration",
            ]),
            "state": random.choice(["implement", "scheduled", "review", "approve"]),
            "assigned_to": random_admin(),
            "priority": random.choice(["2 - High", "3 - Moderate", "4 - Low"]),
        })
    return {"status": "success", "count": count, "changes": changes}


def gen_result_get_vpn_health() -> dict:
    tunnels = []
    for name in random.sample(["VPN-to-AWS-East", "VPN-to-Azure-West", "VPN-to-GCP-Central",
                                "VPN-to-Branch-01", "VPN-to-DR-Site", "VPN-to-Partner"], k=random.randint(2, 4)):
        up = random.random() > 0.2
        tunnels.append({
            "name": name,
            "status": "up" if up else "down",
            "ike_phase": "active" if up else "failed",
            "uptime": f"{random.randint(1,90)}d {random.randint(0,23)}h" if up else "0",
            "peer_ip": random_public_ip(),
            **({"last_up": random_timestamp(7)} if not up else {}),
        })
    return {"status": "success", "tunnels": tunnels}


def gen_result_get_jira_issues() -> dict:
    count = random.randint(0, 3)
    issues = []
    for i in range(count):
        issues.append({
            "key": f"FW-{random.randint(1000,9999)}",
            "summary": random.choice([
                "Allow MongoDB access from app-tier to db-tier",
                "Block outbound SMTP from user segment",
                "Add logging to deny rules in APAC",
                "Create NAT rule for new public IP",
                "Remove deprecated VPN rules",
            ]),
            "status": random.choice(["In Progress", "Open", "Review", "Approved"]),
            "assignee": random_admin(),
            "priority": random.choice(["High", "Medium", "Low"]),
            "created": (datetime.now() - timedelta(days=random.randint(1, 30))).strftime("%Y-%m-%d"),
        })
    return {"status": "success", "count": count, "issues": issues}


def gen_result_find_duplicate_objects(obj_type: str = "address") -> dict:
    count = random.randint(1, 4)
    dups = []
    for _ in range(count):
        ip = random_internal_ip()
        dg = random_dg()
        dups.append({
            "value": f"{ip}/32",
            "objects": [
                {"name": f"h-{ip}", "device_group": dg},
                {"name": f"{random.choice(['WebServer', 'AppServer', 'DBHost', 'Server'])}-{random.randint(1,99)}", "device_group": dg},
            ],
        })
    return {"status": "success", "count": count, "duplicates": dups}


def gen_result_create_firewall_rule(src: str, dst: str, port: str, action: str) -> dict:
    return {
        "status": "success",
        "message": "Rule creation request submitted. Use the Batch Deploy feature in FireWeave to deploy this rule to Panorama.",
        "suggested_rule": {
            "name": f"{'Allow' if action == 'allow' else 'Deny'}-{src.replace('/', '-')}-to-{dst.replace('/', '-')}",
            "source": src,
            "destination": dst,
            "service": f"tcp/{port}" if port else "any",
            "action": action,
        },
    }


def gen_result_analyze_attack_path(src: str, target: str) -> dict:
    hops = random.randint(2, 5)
    path = []
    for i in range(hops):
        path.append({
            "hop": i + 1,
            "ip": random_internal_ip() if i < hops - 1 else target,
            "zone": random_zone(),
            "rule": random_rule(),
            "action": "allow" if random.random() > 0.3 else "deny",
        })
    return {
        "status": "success",
        "source": src,
        "target": target,
        "reachable": all(h["action"] == "allow" for h in path),
        "hops": hops,
        "path": path,
    }


def gen_result_error() -> dict:
    return {"status": "error", "error": random.choice([
        "Connection to Panorama timed out after 30s",
        "Authentication failed - API key expired",
        "Device group not found",
        "Rate limit exceeded, try again in 60s",
        "Internal server error",
    ])}


# =============================================================================
# PRESENTATION GENERATORS
# =============================================================================

def present_search_objects(result: dict, ip: str) -> str:
    if not result["results"]:
        return f"No objects found for **{ip}** in any Panorama source. This IP is not defined in any address objects, groups, or NAT rules."
    r = result["results"][0]
    rules_str = ", ".join(f"**{r_name}**" for r_name in r["used_in_rules"])
    num_rules = len(r["used_in_rules"])
    ref_label = "rule" if num_rules == 1 else f"{num_rules} rules"
    return (
        f"| Object | Type | Value | Device Group | Zone |\n"
        f"|--------|------|-------|-------------|------|\n"
        f"| {r['name']} | {r['type']} | {r['value']} | {r['device_group']} | {r['zone']} |\n\n"
        f"Referenced in {ref_label}: {rules_str}."
    )


def present_find_unused_rules(result: dict) -> str:
    if result["count"] == 0:
        return "No unused rules found. All rules have recent hit counts."
    lines = [f"Found **{result['count']} unused rules** (90-day window):\n"]
    lines.append("| Rule | Device Group | Age (days) | Last Hit |")
    lines.append("|------|-------------|------------|----------|")
    for r in result["rules"][:5]:
        last = r["last_hit"][:10] if r["last_hit"] else "Never"
        lines.append(f"| {r['name']} | {r['device_group']} | {r['age_days']} | {last} |")
    oldest = max(result["rules"], key=lambda x: x["age_days"])
    lines.append(f"\n**{oldest['name']}** ({oldest['age_days']} days) is a strong removal candidate.")
    return "\n".join(lines)


def present_generic_table(result: dict, tool_name: str) -> str:
    """Generic fallback presenter for tools without custom formatting."""
    return json.dumps(result, indent=2)


# =============================================================================
# EXAMPLE GENERATORS
# =============================================================================

def generate_tool_call_example(tool_name: str) -> Dict[str, Any]:
    """Generate a single tool call → result → presentation example.
    When Claude provider is active, uses Claude for more varied queries and presentations.
    """
    ip = random_internal_ip()
    dst = random_internal_ip()
    port, svc, proto = random_port_service()
    dg = random_dg()
    rule = random_rule()
    admin = random_admin()
    framework = random.choice(FRAMEWORKS)

    # Pick tool set that includes this tool
    tool_set_name = "minimal"
    for name, tools in TOOL_SETS.items():
        if tool_name in tools and name != "full":
            tool_set_name = name
            break
    tool_set = TOOL_SETS[tool_set_name]
    if tool_name not in tool_set:
        tool_set = [tool_name]

    system_msg = build_system_message(tool_set)

    # Generate query, tool call params, result, and presentation based on tool
    if tool_name == "search_objects":
        use_dg = random.random() > 0.6
        empty_result = random.random() < 0.15  # 15% chance of no results
        if use_dg:
            query = pick_query("search_objects", "with_dg", ip=ip, dg=dg)
            params = {"query": ip, "device_group": dg}
            result = gen_result_search_objects_empty() if empty_result else gen_result_search_objects(ip, dg)
        else:
            query = pick_query("search_objects", "no_dg", ip=ip)
            params = {"query": ip}
            result = gen_result_search_objects_empty() if empty_result else gen_result_search_objects(ip)
        presentation = present_search_objects(result, ip)

    elif tool_name == "find_unused_rules":
        variant = random.random()
        if variant < 0.35:  # 35% with device group
            query = pick_query("find_unused_rules", "with_dg", dg=dg)
            params = {"device_group": dg}
        elif variant < 0.55:  # 20% with days param
            days = random.choice([30, 60, 90, 180, 365])
            query = pick_query("find_unused_rules", "with_days", days=days)
            params = {"days": days}
        else:  # 45% plain
            query = pick_query("find_unused_rules", "no_dg")
            params = {}
        result = gen_result_find_unused_rules(dg if variant < 0.35 else None)
        presentation = present_find_unused_rules(result)

    elif tool_name == "list_unused_objects":
        obj_type = random.choice(["address-group", "service-group", "tag"])
        use_dg = random.random() > 0.5
        if use_dg:
            query = pick_query("list_unused_objects", "with_dg", dg=dg)
            params = {"object_type": obj_type, "device_group": dg}
        else:
            query = pick_query("list_unused_objects", "no_dg")
            params = {"object_type": obj_type}
        result = gen_result_list_unused_objects(obj_type, dg if use_dg else None)
        lines = [f"Found **{result['count']} unused {obj_type}s**" + (f" in **{dg}**" if use_dg else "") + ":\n"]
        lines.append(f"| {obj_type.title()} | Members | Status |")
        lines.append("|" + "-" * 20 + "|---------|--------|")
        for o in result["objects"]:
            lines.append(f"| {o['name']} | {o['members']} | Not referenced in any rule |")
        presentation = "\n".join(lines)

    elif tool_name == "find_shadowed_rules":
        use_dg = random.random() > 0.4
        if use_dg:
            query = pick_query("find_shadowed_rules", "with_dg", dg=dg)
            params = {"device_group": dg}
        else:
            query = pick_query("find_shadowed_rules", "no_dg")
            params = {}
        result = gen_result_find_shadowed_rules(dg if use_dg else None)
        if result["count"] == 0:
            presentation = f"No shadowed rules found" + (f" in **{dg}**" if use_dg else "") + ". All rules are reachable."
        else:
            lines = [f"Found **{result['count']} shadowed rule{'s' if result['count'] > 1 else ''}**" + (f" in **{dg}**" if use_dg else "") + ":\n"]
            lines.append("| Shadowed Rule | Position | Shadowed By | Position | Reason |")
            lines.append("|--------------|----------|-------------|----------|--------|")
            for r in result["shadowed_rules"]:
                lines.append(f"| {r['name']} | #{r['position']} | {r['shadowed_by']} | #{r['shadowed_by_position']} | {r['reason']} |")
            presentation = "\n".join(lines)

    elif tool_name == "search_rules":
        action = random.choice(["allow", "deny"])
        logging = random.choice([True, False])
        use_dg = random.random() > 0.4  # 60% include device group
        query = pick_query("search_rules", None, dg=dg, zone1=random_zone(), zone2=random_zone())
        params = {"action": action, "has_logging": logging}
        if use_dg:
            params["device_group"] = dg
        result = gen_result_search_rules(action, logging, dg if use_dg else None)
        dg_label = f" in **{dg}**" if use_dg else ""
        lines = [f"Found **{result['count']} {action} rules** {'with' if logging else 'without'} logging{dg_label}:\n"]
        lines.append("| Rule | Source Zone | Dest Zone | Action | Logging |")
        lines.append("|------|-----------|-----------|--------|---------|")
        for r in result["rules"][:5]:
            lines.append(f"| {r['name']} | {r['source_zone']} | {r['destination_zone']} | {r['action']} | {'enabled' if r['logging'] else 'disabled'} |")
        presentation = "\n".join(lines)

    elif tool_name == "nat_check":
        query = pick_query("nat_check", None, src=ip, dst=dst)
        params = {"src_ip": ip, "dst_ip": dst}
        result = gen_result_nat_check(ip, dst)
        if result.get("nat_match"):
            presentation = (
                f"Yes. Traffic from **{ip}** to **{dst}** matches NAT rule **{result['rule_name']}** in **{result['device_group']}**.\n\n"
                f"| Field | Value |\n|-------|-------|\n"
                f"| NAT Rule | {result['rule_name']} |\n"
                f"| Type | {result['type'].replace('-', ' ').title()} |\n"
                f"| Original Source | {ip} |\n"
                f"| Translated Source | {result['translated_source']} |"
            )
        else:
            presentation = f"No NAT translation found for traffic from **{ip}** to **{dst}**. Traffic passes without address translation."

    elif tool_name == "get_rule_statistics":
        use_dg = random.random() > 0.5
        if use_dg:
            query = pick_query("get_rule_statistics", "with_dg", dg=dg)
            params = {"device_group": dg}
        else:
            query = pick_query("get_rule_statistics", "no_dg")
            params = {}
        result = gen_result_get_rule_statistics(dg if use_dg else None)
        nolog_pct = round(result["rules_without_logging"] / result["total_rules"] * 100)
        presentation = (
            f"| Metric | Count |\n|--------|-------|\n"
            f"| Total rules | {result['total_rules']:,} |\n"
            f"| Device groups | {result['device_groups']} |\n"
            f"| Allow rules | {result['allow_rules']:,} |\n"
            f"| Deny rules | {result['deny_rules']:,} |\n"
            f"| With logging | {result['rules_with_logging']:,} ({100-nolog_pct}%) |\n"
            f"| Without logging | {result['rules_without_logging']:,} ({nolog_pct}%) |\n\n"
            f"{nolog_pct}% of rules lack logging — consider enabling log forwarding for visibility."
        )

    elif tool_name == "get_rule_hit_count":
        query = pick_query("get_rule_hit_count", None, rule=rule)
        params = {"rule_id": rule}
        result = gen_result_get_rule_hit_count(rule)
        if result["hit_count"] > 0:
            presentation = (
                f"**{rule}** — {result['time_range']} stats:\n\n"
                f"| Metric | Value |\n|--------|-------|\n"
                f"| Total hits | {result['hit_count']:,} |\n"
                f"| Daily average | {result['daily_average']:,} |\n"
                f"| Last hit | {result['last_hit'][:16].replace('T', ' ')} UTC |\n\n"
                f"This is an actively used rule."
            )
        else:
            presentation = f"**{rule}** has **zero hits** in the {result['time_range']} window. This rule is a candidate for removal."

    elif tool_name == "check_traffic_flow":
        query = pick_query("check_traffic_flow", None, src=ip, dst=dst, port=port, proto=proto)
        params = {"source": ip, "destination": dst, "port": port, "protocol": proto}
        result = gen_result_check_traffic_flow(ip, dst, port)
        verdict = result["verdict"]
        presentation = (
            f"**{verdict}**. Traffic from {ip} to {dst}:{port}/{proto} is {'permitted' if verdict == 'ALLOW' else 'blocked'}.\n\n"
            f"| Field | Value |\n|-------|-------|\n"
            f"| Verdict | {verdict} |\n"
            f"| Matching Rule | {result['matching_rule']} |\n"
            f"| Device Group | {result['device_group']} |\n"
            f"| Source Zone | {result['src_zone']} |\n"
            f"| Dest Zone | {result['dst_zone']} |"
        )

    elif tool_name == "run_compliance_scan":
        use_dg = random.random() > 0.5
        if use_dg:
            query = pick_query("run_compliance_scan", "with_dg", framework=framework, dg=dg)
            params = {"framework": framework, "firewall": dg}
        else:
            query = pick_query("run_compliance_scan", "no_dg", framework=framework)
            params = {"framework": framework}
        result = gen_result_run_compliance_scan(framework, dg if use_dg else None)
        lines = [f"**{result['framework']} Compliance**" + (f": {dg}" if use_dg else "") + f" — Score: **{result['score']}/100**\n"]
        lines.append(f"| Passed | Failed |\n|--------|--------|\n| {result['checks_passed']} | {result['checks_failed']} |\n")
        if result["findings"]:
            lines.append("Findings:\n\n| Check | Description | Finding |\n|-------|-------------|---------|")
            for f in result["findings"]:
                lines.append(f"| {f['check']} | {f['description']} | {f['finding']} |")
        presentation = "\n".join(lines)

    elif tool_name == "get_dnat_exposure":
        use_dg = random.random() > 0.6
        if use_dg:
            query = pick_query("get_dnat_exposure", "with_dg", dg=dg)
            params = {"device_group": dg}
        else:
            query = pick_query("get_dnat_exposure", "no_dg")
            params = {}
        result = gen_result_get_dnat_exposure(dg if use_dg else None)
        lines = [f"Found **{len(result['exposed_services'])} internet-exposed services**:\n"]
        lines.append("| Public IP | Internal IP | Port | Service | NAT Rule | Device Group |")
        lines.append("|-----------|-------------|------|---------|----------|-------------|")
        for s in result["exposed_services"]:
            lines.append(f"| {s['public_ip']} | {s['internal_ip']} | {s['port']} | {s['service']} | {s['nat_rule']} | {s['device_group']} |")
        presentation = "\n".join(lines)

    elif tool_name == "check_access":
        query = pick_query("check_access", None, src=ip, dst=dst, port=port)
        params = {"source_ip": ip, "destination_ip": dst, "protocol": proto, "port": port}
        result = gen_result_check_access(ip, dst, port)
        allowed = result["allowed"]
        presentation = (
            f"**{'ALLOWED' if allowed else 'DENIED'}**. {'Traffic' if allowed else svc} from {ip} to {dst}:{port} is {'permitted' if allowed else 'blocked'}.\n\n"
            f"| Field | Value |\n|-------|-------|\n"
            f"| Action | {result['action'].title()} |\n"
            f"| Matching Rule | {result['matching_rule']} |\n"
            f"| Source Zone | {result['src_zone']} |\n"
            f"| Dest Zone | {result['dst_zone']} |\n"
            f"| Device Group | {result['device_group']} |"
        )

    elif tool_name == "query_audit_logs":
        variant = random.random()
        if variant < 0.35:
            # User asks about a specific admin
            query = pick_query("query_audit_logs", None, admin=admin, rule=rule)
            params = {"log_type": "audit", "admin": admin, "limit": 20}
            result = gen_result_query_audit_logs(admin)
        elif variant < 0.65:
            # User asks about a specific rule
            query = random.choice([f"show config changes for {rule}", f"who changed {rule}?"])
            params = {"log_type": "audit", "search": rule, "limit": 20}
            # Make result reference the searched rule
            result = gen_result_query_audit_logs()
            for log_entry in result["logs"]:
                log_entry["target"] = rule
        else:
            # General audit log query
            query = random.choice(["who made changes yesterday?", "show recent audit logs", "any changes in the last 24 hours?"])
            params = {"log_type": "audit", "limit": 20}
            result = gen_result_query_audit_logs()
        lines = ["Recent audit log entries:\n"]
        lines.append("| Time (UTC) | Admin | Action | Target | Device Group |")
        lines.append("|-----------|-------|--------|--------|-------------|")
        for l in result["logs"][:5]:
            lines.append(f"| {l['timestamp'][:16].replace('T', ' ')} | {l['admin']} | {l['action']} | {l['target']} | {l['device_group']} |")
        presentation = "\n".join(lines)

    elif tool_name == "get_audit_diff":
        event_id = f"EVT-{random.randint(10000, 99999)}"
        query = pick_query("get_audit_diff", None, event_id=event_id)
        params = {"event_id": event_id}
        result = gen_result_get_audit_diff(event_id)
        lines = [f"**Event {event_id}** by **{result['admin']}** at {result['timestamp'][:16].replace('T', ' ')} UTC:\n"]
        lines.append("| Field | Before | After |")
        lines.append("|-------|--------|-------|")
        for c in result["changes"]:
            before = c["before"] if c["before"] else "*(none)*"
            lines.append(f"| {c['field']} | {before} | {c['after']} |")
        presentation = "\n".join(lines)

    elif tool_name == "compare_configs":
        use_dg = random.random() > 0.4
        if use_dg:
            query = pick_query("compare_configs", "with_dg", dg=dg)
            params = {"device_group": dg}
        else:
            query = pick_query("compare_configs", "no_dg")
            params = {}
        result = gen_result_compare_configs(dg if use_dg else None)
        if not result["has_changes"]:
            presentation = f"No pending changes" + (f" in **{dg}**" if use_dg else "") + ". Running and candidate configs are in sync."
        else:
            lines = [f"**{len(result['changes'])} pending changes**" + (f" in **{dg}**" if use_dg else "") + ":\n"]
            lines.append("| Type | Object | Category | Detail |")
            lines.append("|------|--------|----------|--------|")
            for c in result["changes"]:
                lines.append(f"| {c['type'].title()} | {c['object']} | {c['category']} | {c['detail']} |")
            lines.append("\nReview before committing.")
            presentation = "\n".join(lines)

    elif tool_name == "get_critical_findings":
        provider = random.choice([None, "aws", "azure"])
        query = pick_query("get_critical_findings", None)
        params = {"provider": provider} if provider else {}
        result = gen_result_get_critical_findings(provider)
        lines = [f"Found **{result['count']} critical/high findings**:\n"]
        lines.append("| Severity | Title | Source | Resource |")
        lines.append("|----------|-------|--------|----------|")
        for f in result["findings"]:
            lines.append(f"| {f['severity'].upper()} | {f['title']} | {f['source'].upper()} | {f['resource']} |")
        presentation = "\n".join(lines)

    elif tool_name == "get_snow_changes":
        query = pick_query("get_snow_changes", None)
        params = {}
        result = gen_result_get_snow_changes()
        if result["count"] == 0:
            presentation = "No open ServiceNow change requests."
        else:
            lines = [f"**{result['count']} open ServiceNow changes**:\n"]
            lines.append("| Change # | Description | State | Assigned To | Priority |")
            lines.append("|----------|------------|-------|-------------|----------|")
            for c in result["changes"]:
                lines.append(f"| {c['number']} | {c['short_description']} | {c['state'].title()} | {c['assigned_to']} | {c['priority']} |")
            presentation = "\n".join(lines)

    elif tool_name == "get_vpn_health":
        query = pick_query("get_vpn_health", None)
        params = {}
        result = gen_result_get_vpn_health()
        lines = ["| Tunnel | Status | IKE Phase | Uptime | Peer IP |"]
        lines.append("|--------|--------|-----------|--------|---------|")
        down_tunnels = []
        for t in result["tunnels"]:
            status = t["status"].upper() if t["status"] == "up" else f"**{t['status'].upper()}**"
            uptime = t["uptime"] if t["status"] == "up" else "-"
            lines.append(f"| {t['name']} | {status} | {t['ike_phase']} | {uptime} | {t['peer_ip']} |")
            if t["status"] == "down":
                down_tunnels.append(t)
        if down_tunnels:
            t = down_tunnels[0]
            lines.append(f"\n**{t['name']}** is down (IKE negotiation failed). Check if the peer at {t['peer_ip']} is reachable and verify pre-shared key configuration.")
        presentation = "\n".join(lines)

    elif tool_name == "get_jira_issues":
        query = pick_query("get_jira_issues", None)
        params = {}
        result = gen_result_get_jira_issues()
        if result["count"] == 0:
            presentation = "No open Jira firewall change issues."
        else:
            lines = [f"**{result['count']} open Jira issue{'s' if result['count'] > 1 else ''}**:\n"]
            lines.append("| Key | Summary | Status | Assignee | Priority |")
            lines.append("|-----|---------|--------|----------|----------|")
            for i in result["issues"]:
                lines.append(f"| {i['key']} | {i['summary']} | {i['status']} | {i['assignee']} | {i['priority']} |")
            presentation = "\n".join(lines)

    elif tool_name == "find_duplicate_objects":
        obj_type = random.choice(["address", "service"])
        query = pick_query("find_duplicate_objects", None)
        params = {"object_type": obj_type}
        result = gen_result_find_duplicate_objects(obj_type)
        lines = [f"Found **{result['count']} duplicate {obj_type} pairs**:\n"]
        lines.append("| Value | Object 1 | Object 2 | Device Group |")
        lines.append("|-------|----------|----------|-------------|")
        for d in result["duplicates"]:
            lines.append(f"| {d['value']} | {d['objects'][0]['name']} | {d['objects'][1]['name']} | {d['objects'][0]['device_group']} |")
        lines.append("\nConsolidate each pair into a single canonical object and update rule references.")
        presentation = "\n".join(lines)

    elif tool_name == "create_firewall_rule":
        action = random.choice(["allow", "deny"])
        src_ip = random_internal_ip() + "/24" if random.random() > 0.5 else random_internal_ip()
        dst_ip = random_internal_ip()
        query = pick_query("create_firewall_rule", None, src=src_ip, dst=dst_ip, port=port)
        params = {"source": src_ip, "destination": dst_ip, "port": str(port), "action": action}
        result = gen_result_create_firewall_rule(src_ip, dst_ip, str(port), action)
        sr = result["suggested_rule"]
        presentation = (
            f"Rule creation request submitted:\n\n"
            f"| Field | Value |\n|-------|-------|\n"
            f"| Name | {sr['name']} |\n"
            f"| Source | {sr['source']} |\n"
            f"| Destination | {sr['destination']} |\n"
            f"| Service | {sr['service']} |\n"
            f"| Action | {sr['action'].title()} |\n\n"
            f"Use the **Batch Deploy** feature in FireWeave to review and push this rule to Panorama."
        )

    elif tool_name == "analyze_attack_path":
        query = pick_query("analyze_attack_path", None, src=ip, dst=dst)
        params = {"source": ip, "target": dst}
        result = gen_result_analyze_attack_path(ip, dst)
        lines = [f"Attack path from **{ip}** to **{dst}**: **{'REACHABLE' if result['reachable'] else 'BLOCKED'}** ({result['hops']} hops)\n"]
        lines.append("| Hop | IP | Zone | Rule | Action |")
        lines.append("|-----|-----|------|------|--------|")
        for h in result["path"]:
            lines.append(f"| {h['hop']} | {h['ip']} | {h['zone']} | {h['rule']} | {h['action'].upper()} |")
        if result["reachable"]:
            lines.append(f"\nThe target is reachable through {result['hops']} firewall hops. Review whether all allow rules in the path are justified.")
        else:
            blocked = next(h for h in result["path"] if h["action"] == "deny")
            lines.append(f"\nBlocked at hop {blocked['hop']} by rule **{blocked['rule']}** in zone **{blocked['zone']}**.")
        presentation = "\n".join(lines)

    else:
        raise ValueError(f"Unknown tool: {tool_name}")

    # Build the conversation
    tool_call = {"name": tool_name, "parameters": params}
    conversations = [
        {"from": "system", "value": system_msg},
        {"from": "human", "value": query},
        {"from": "gpt", "value": f"<|python_tag|>{json.dumps(tool_call)}"},
        {"from": "ipython", "value": json.dumps(result)},
        {"from": "gpt", "value": presentation},
    ]

    return {"conversations": conversations, "_category": "tool_call", "_tool": tool_name}


# =============================================================================
# CONVERSATIONAL EXAMPLES (no tool call)
# =============================================================================

KNOWLEDGE_QA = [
    ("what is a shadowed rule?",
     "A shadowed rule is a security rule that never matches traffic because a higher-priority rule with broader or identical match criteria processes the traffic first. The shadowed rule is effectively dead — it exists in the rulebase but has no operational impact.\n\nCommon causes:\n- A permit-any rule above more specific rules\n- Duplicate rules at different positions\n- Rules with overlapping source/destination/service criteria\n\nShadowed rules should be removed to reduce rulebase complexity and avoid confusion during audits. I can scan for shadowed rules in a specific device group if you'd like."),
    ("what is PCI-DSS?",
     "PCI-DSS (Payment Card Industry Data Security Standard) is a set of security standards for organizations that handle credit card data. For firewall teams, the key requirements are:\n\n1. **Requirement 1**: Install and maintain a firewall configuration to protect cardholder data\n2. **Requirement 7**: Restrict access to cardholder data on a need-to-know basis\n3. **Requirement 10**: Track and monitor all access to network resources and cardholder data\n\nKey firewall-specific controls:\n- No rules with 'any' service to/from the CDE (cardholder data environment)\n- All rules must have logging enabled\n- Rules must be reviewed at least every 6 months\n- Default deny for all traffic not explicitly allowed\n\nI can run a PCI-DSS compliance scan against your firewall policies if you'd like."),
    ("what are best practices for firewall rule logging?",
     "Key logging best practices for Palo Alto firewalls:\n\n1. **Enable log-at-session-end on all rules** — This captures the full session including bytes transferred and duration.\n\n2. **Use log forwarding profiles** — Send logs to a SIEM (Splunk, QRadar, Sentinel) for correlation and alerting.\n\n3. **Log deny rules** — Dropped traffic is critical for threat detection. Many compliance frameworks require logging of denied connections.\n\n4. **Tag rules with log profiles by function** — Use different forwarding profiles for DMZ rules vs internal rules to manage log volume.\n\n5. **Don't log noise rules** — Rules matching broadcast/multicast or known internal health checks can be excluded to reduce SIEM costs.\n\nI can check which rules in your environment lack logging — just tell me the device group."),
    ("explain zone-based firewall architecture",
     "Zone-based firewall architecture segments your network into security zones, each with a defined trust level. Traffic between zones is controlled by security policies.\n\n**Common Zones:**\n- **Trust** (internal): Corporate LAN, highest trust\n- **Untrust** (external): Internet-facing, lowest trust\n- **DMZ**: Semi-trusted, hosts public-facing services\n- **Management**: Isolated zone for device management\n\n**Key Principles:**\n1. Traffic within the same zone is typically allowed\n2. Traffic between zones must match an explicit security rule\n3. Default deny — no rule = no access\n4. Least privilege — only allow what's needed\n\nOn Palo Alto firewalls, zones are bound to interfaces. Each rule specifies source zone, destination zone, and the allowed applications/services."),
    ("how can I improve the security posture of my firewalls?",
     "Here are the highest-impact improvements for Palo Alto firewall posture:\n\n1. **Eliminate any-service rules** — Replace broad rules with application-specific or port-specific rules. This is the #1 PCI-DSS finding.\n\n2. **Enable security profiles on all allow rules** — Antivirus, anti-spyware, vulnerability protection, URL filtering, and WildFire.\n\n3. **Remove unused rules** — Rules with zero hits over 90+ days are dead weight. I can scan for these.\n\n4. **Fix shadowed rules** — Rules that never match because of higher-priority broad rules.\n\n5. **Enable logging on deny rules** — Critical for incident response and compliance.\n\n6. **Review DNAT exposure** — Internet-facing services via DNAT are your attack surface.\n\n7. **Run compliance scans** — PCI-DSS and CIS benchmarks identify specific gaps.\n\nWant me to run any of these checks? Just tell me the device group."),
    ("what is the difference between check_traffic_flow and check_access?",
     "`check_traffic_flow` and `check_access` both verify if traffic is allowed, but differ in how they work:\n\n**check_traffic_flow** (maps to `policy_path_check`):\n- Queries Panorama's `test security-policy-match` API\n- Evaluates the actual live policy on the firewall\n- Considers security profiles, application identification, and NAT\n- Slower but more accurate — reflects real-time state\n\n**check_access**:\n- Uses pre-expanded rule data stored in FireWeave's database\n- Faster lookup against pre-computed allow/deny decisions\n- May not reflect very recent changes until next sync\n- Good for bulk access verification\n\nFor a single quick check, either works. For bulk verification of many flows, `check_access` is faster."),
    ("what is a NAT policy?",
     "A NAT (Network Address Translation) policy translates IP addresses as traffic passes through a firewall. On Palo Alto firewalls:\n\n**Source NAT (SNAT):**\n- Translates the source IP of outbound traffic\n- Common use: Internal hosts use a public IP when accessing the internet\n- Types: Dynamic IP and Port, Dynamic IP, Static IP\n\n**Destination NAT (DNAT):**\n- Translates the destination IP of inbound traffic\n- Common use: Route internet traffic to internal servers (e.g., web servers, mail servers)\n- Creates your externally visible attack surface\n\n**Key Points:**\n- NAT is evaluated BEFORE security policy\n- Security rules see post-NAT addresses for DNAT and pre-NAT addresses for SNAT\n- NAT rules are zone-based, not interface-based\n\nI can check NAT translations for specific traffic flows if you provide source and destination IPs."),
    ("what is SOC2 compliance?",
     "SOC 2 (System and Organization Controls) is an auditing framework developed by AICPA. It evaluates how organizations manage customer data based on five Trust Services Criteria:\n\n1. **Security** — Protection against unauthorized access\n2. **Availability** — System uptime and accessibility\n3. **Processing Integrity** — Accurate and complete data processing\n4. **Confidentiality** — Protection of sensitive information\n5. **Privacy** — Personal information handling\n\nFor firewall teams, key SOC 2 requirements include:\n- **CC6.1**: Logical access controls with audit trails\n- **CC7.2**: System monitoring and anomaly detection\n- All firewall rules must have logging enabled\n- Regular access reviews and rule attestation\n\nI can run a SOC2 compliance scan to check your firewall policies against these controls."),
    ("explain the concept of least privilege in firewall rules",
     "Least privilege in firewall rules means each rule should only allow the minimum access required for a specific business function. In practice:\n\n1. **Specific sources** — Use individual IPs or small subnets, not 'any'\n2. **Specific destinations** — Target exact servers, not entire zones\n3. **Specific services** — Allow only needed ports/applications, never 'any'\n4. **No overly broad rules** — A rule allowing 'trust' to 'untrust' with 'any' service violates least privilege\n\n**How to enforce:**\n- Review rules with 'any' in source, destination, or service fields\n- Check for rules with 'any' application on Palo Alto (use App-ID instead)\n- Regularly audit rule hit counts — unused rules indicate over-provisioned access\n- Use address groups and service groups for management, but keep them focused\n\nI can find overly permissive rules in your environment if you tell me the device group."),
    ("what is HIPAA and how does it relate to firewalls?",
     "HIPAA (Health Insurance Portability and Accountability Act) requires healthcare organizations to protect electronic Protected Health Information (ePHI). For firewall teams:\n\n**Technical Safeguards (164.312):**\n- **(a) Access Control**: Restrict network access to ePHI systems\n- **(b) Audit Controls**: Log all access to ePHI network segments\n- **(c) Integrity**: Protect ePHI from unauthorized modification in transit\n- **(d) Transmission Security**: Encrypt ePHI crossing network boundaries\n\n**Firewall Requirements:**\n- Segment ePHI systems into dedicated zones\n- Apply strict rules between ePHI zones and other network segments\n- Enable logging on all rules touching ePHI segments\n- Block unauthorized protocols to/from healthcare systems\n- Regular compliance reviews and documentation\n\nI can run a HIPAA compliance scan against your firewall policies to identify gaps."),
    ("how does Panorama device group hierarchy work?",
     "Panorama uses a hierarchical device group structure for managing Palo Alto firewalls at scale:\n\n**Hierarchy:**\n- **Shared** (top level) — Rules and objects inherited by all device groups\n- **Parent device groups** — Mid-level groupings (e.g., by region)\n- **Child device groups** — Specific firewalls or clusters\n\n**Rule Processing Order:**\n1. Pre-rules (from Panorama, top-down through hierarchy)\n2. Local rules (on the firewall itself)\n3. Post-rules (from Panorama, top-down through hierarchy)\n\n**Key Concepts:**\n- Objects defined at a higher level are available to all child groups\n- Rules pushed from Panorama pre-rules take priority over local rules\n- Post-rules act as a catch-all below local rules\n- Best practice: Use pre-rules for security baselines, post-rules for default deny\n\nThis is why device group matters when searching for objects — an IP might exist at different levels."),
    ("what is a security profile in Palo Alto?",
     "Security profiles on Palo Alto firewalls add deep inspection beyond basic allow/deny decisions. They're attached to security rules to inspect allowed traffic:\n\n**Profile Types:**\n- **Antivirus**: Scans for malware in files and content\n- **Anti-Spyware**: Detects C2 callbacks and spyware communication\n- **Vulnerability Protection**: Blocks known exploit attempts\n- **URL Filtering**: Controls web access by category\n- **WildFire Analysis**: Sends unknown files to sandbox for analysis\n- **File Blocking**: Blocks specific file types\n\n**Best Practice:**\n- Create a **Security Profile Group** combining all profile types\n- Apply it to every allow rule\n- Rules without security profiles only do allow/deny — they don't inspect traffic content\n\nA common audit finding is allow rules with no security profiles attached."),
    ("what is NIST Cybersecurity Framework?",
     "The NIST Cybersecurity Framework (CSF) provides a structured approach to managing cybersecurity risk. It's organized into five core functions:\n\n1. **Identify** — Asset management, risk assessment\n2. **Protect** — Access control, awareness training, data security\n3. **Detect** — Monitoring, detection processes\n4. **Respond** — Response planning, communications, mitigation\n5. **Recover** — Recovery planning, improvements\n\n**Firewall-Relevant Controls:**\n- **PR.AC-5**: Network integrity (segmentation, traffic filtering)\n- **PR.PT-4**: Communications and control networks protection\n- **DE.CM-1**: Network monitoring for security events\n- **AC-4**: Information flow enforcement\n\nI can run a NIST compliance scan to check your firewall policies against these controls."),
    ("what is zero trust architecture?",
     "Zero Trust is a security model based on the principle of \"never trust, always verify.\" Unlike traditional perimeter-based security:\n\n**Core Principles:**\n1. **No implicit trust** — Every access request is verified regardless of source location\n2. **Least privilege** — Minimum required access for each user/device/workload\n3. **Micro-segmentation** — Fine-grained network segments with strict controls between them\n4. **Continuous verification** — Re-authenticate and re-authorize throughout the session\n\n**Firewall Implementation:**\n- Intra-zone rules (not just inter-zone) — traffic within the same zone is also inspected\n- Application-level controls using App-ID instead of port-based rules\n- User-ID integration for identity-based policies\n- SSL decryption for visibility into encrypted traffic\n- Device posture checks before granting access\n\nZero Trust doesn't eliminate firewalls — it makes them more granular and policy-driven."),
    ("what tools are available in FireWeave?",
     "FireWeave provides several analysis and management tools through the Ember AI assistant:\n\n**Search & Discovery:**\n- `search_objects` — Find where an IP or object lives across all Panoramas\n- `search_rules` — Search rules by zone, action, logging status\n- `check_access` — Quick access verification using pre-expanded rules\n\n**Policy Analysis:**\n- `find_unused_rules` — Rules with zero hit count\n- `find_shadowed_rules` — Rules overshadowed by higher-priority rules\n- `find_duplicate_objects` — Duplicate address/service objects\n- `list_unused_objects` — Objects not referenced by any rule\n\n**Traffic & NAT:**\n- `check_traffic_flow` — Check if traffic is allowed between IPs\n- `nat_check` — Verify NAT translations\n- `get_dnat_exposure` — Internet-exposed services via DNAT\n\n**Compliance & Audit:**\n- `run_compliance_scan` — PCI-DSS, SOC2, NIST, HIPAA, CIS\n- `query_audit_logs` — Who changed what and when\n- `get_audit_diff` — Before/after configuration diff\n- `compare_configs` — Running vs candidate config\n\n**Integrations:**\n- `get_snow_changes` — ServiceNow change requests\n- `get_jira_issues` — Jira firewall tickets\n- `get_vpn_health` — VPN tunnel status\n- `get_critical_findings` — Critical security findings\n\nWhat would you like me to check?"),
    ("how do I interpret a compliance scan score?",
     "Compliance scan scores in FireWeave represent how well your firewall policies align with a specific framework:\n\n**Score Ranges:**\n- **90-100**: Excellent — minor improvements only\n- **75-89**: Good — some findings need attention\n- **60-74**: Fair — significant gaps to address\n- **Below 60**: Poor — critical issues requiring immediate action\n\n**What the Score Includes:**\n- Number of checks passed vs failed\n- Severity weighting (critical findings reduce score more)\n- Coverage across all framework requirements\n\n**How to Improve:**\n1. Fix critical findings first (rules with 'any' service, missing logging)\n2. Address high-severity items next\n3. Run the scan again after remediation to verify improvement\n4. Schedule regular scans (monthly recommended)\n\n**Important**: The score is a point-in-time assessment. Rule changes after the scan aren't reflected until you re-scan."),
    ("what is a device group in Panorama?",
     "A device group in Panorama is a logical container for organizing managed firewalls and their shared configuration:\n\n**Purpose:**\n- Group firewalls by function, location, or role\n- Share common security policies, NAT rules, and objects\n- Manage configuration at scale instead of per-device\n\n**Common Organization:**\n- By region: US-East-DC1, EU-West-DC1, APAC\n- By function: DG-Datacenter, DG-Branch, DG-DMZ\n- By environment: DG-Production, DG-Staging, DG-Dev\n\n**Key Behaviors:**\n- Objects and rules at higher levels are inherited by child groups\n- Pre-rules from Panorama execute before local firewall rules\n- Post-rules execute after local rules\n- Each firewall belongs to exactly one device group\n\nIn FireWeave, most tools accept an optional `device_group` parameter to scope results. If omitted, all device groups are searched."),
    ("what should I do during a security incident involving firewall rules?",
     "During a security incident involving firewall rules, follow this structured approach:\n\n**Immediate Actions (Minutes):**\n1. Identify the compromised IPs and affected zones\n2. Check if malicious traffic is currently flowing using traffic flow analysis\n3. Create emergency deny rules to block attacker IPs if needed\n4. Enable maximum logging on affected rules and zones\n\n**Investigation (Hours):**\n1. Query audit logs to see if any rules were recently changed\n2. Check configuration diffs for unauthorized modifications\n3. Identify all rules that allow traffic to/from compromised hosts\n4. Review DNAT exposure for internet-facing attack vectors\n\n**Remediation (Days):**\n1. Remove or disable compromised rules\n2. Tighten overly permissive rules identified during investigation\n3. Run a compliance scan to check overall posture\n4. Document findings and timeline for incident report\n\nI can help with any of these steps — searching IPs, checking audit logs, or running compliance scans."),
]

GREETINGS = [
    ("hey", "Hey. I'm Ember, your FireWeave security analyst. I can help with:\n\n- **IP lookups** — Find where an address lives in your firewall objects\n- **Rule analysis** — Unused, shadowed, or redundant rules\n- **Compliance scans** — PCI-DSS, SOC2, NIST, HIPAA, CIS\n- **NAT checks** — Verify NAT translations for traffic flows\n- **Audit logs** — Who changed what and when\n\nWhat would you like to look into?"),
    ("hi", "Hi. I'm Ember — I help with firewall policy analysis, compliance, and troubleshooting in FireWeave. What can I look up for you?"),
    ("hello", "Hello. What would you like to check in your firewall environment today?"),
    ("good morning", "Good morning. Ready to help with any firewall or security questions. What do you need?"),
    ("thanks", "You're welcome. Let me know if you need anything else."),
    ("thank you, that's helpful", "Glad that helped. I'm here if you need more analysis."),
    ("who are you?", "I'm Ember, a network security analyst embedded in the FireWeave platform. I can search your firewall objects, analyze rules, run compliance scans, check NAT translations, and query audit logs. I work with your Panorama data through FireWeave's API.\n\nWhat would you like to look into?"),
]


def generate_conversational_example(with_tools: bool = True) -> Dict[str, Any]:
    """Generate a conversational example (no tool call).
    When Claude provider is active, uses Claude for more varied Q&A pairs.
    """
    if random.random() > 0.6:
        question, answer = random.choice(GREETINGS)
    else:
        # Try Claude-generated Q&A first, fall back to static pool
        claude_qa = get_claude_qa()
        if claude_qa and random.random() > 0.3:  # 70% Claude, 30% static for mix
            question, answer = claude_qa
        else:
            question, answer = random.choice(KNOWLEDGE_QA)

    if with_tools:
        tool_set = random.choice(["search_focused", "traffic_focused", "compliance_focused", "minimal"])
        system_msg = build_system_message(TOOL_SETS[tool_set])
    else:
        system_msg = random.choice(SYSTEM_PROMPTS)

    conversations = [
        {"from": "system", "value": system_msg},
        {"from": "human", "value": question},
        {"from": "gpt", "value": answer},
    ]

    return {"conversations": conversations, "_category": "conversational"}


# =============================================================================
# MULTI-TURN EXAMPLES
# =============================================================================

def generate_multi_turn_example() -> Dict[str, Any]:
    """Generate a multi-turn conversation with follow-up tool calls.
    Supports multiple starting patterns: IP lookup, compliance scan, unused rules.
    """
    ip = random_internal_ip()
    dg = random_dg()

    pattern = random.choice(["ip_lookup", "ip_lookup", "compliance_drilldown", "unused_rules_followup"])

    if pattern == "ip_lookup":
        # Pattern 1: IP lookup → contextual follow-up (original)
        tool_set = random.choice(["search_focused", "traffic_focused", "posture_focused"])
        system_msg = build_system_message(TOOL_SETS[tool_set])

        result1 = gen_result_search_objects(ip)
        found_dg = result1["results"][0]["device_group"]

        follow_up_type = random.choice(["unused_rules", "shadowed_rules", "compliance", "stats"])
        if follow_up_type == "unused_rules":
            follow_query = random.choice(["are there any unused rules there?", "any unused rules in that device group?", "check for unused rules there"])
            follow_params = {"device_group": found_dg}
            follow_result = gen_result_find_unused_rules(found_dg)
            follow_presentation = present_find_unused_rules(follow_result)
            follow_tool = "find_unused_rules"
        elif follow_up_type == "shadowed_rules":
            follow_query = random.choice(["any shadowed rules there?", "check for shadowed rules in that device group"])
            follow_params = {"device_group": found_dg}
            follow_result = gen_result_find_shadowed_rules(found_dg)
            follow_tool = "find_shadowed_rules"
            if follow_result["count"] == 0:
                follow_presentation = f"No shadowed rules found in **{found_dg}**. All rules are reachable."
            else:
                lines = [f"Found **{follow_result['count']} shadowed rules** in **{found_dg}**:\n"]
                lines.append("| Rule | Position | Shadowed By |")
                lines.append("|------|----------|-------------|")
                for r in follow_result["shadowed_rules"]:
                    lines.append(f"| {r['name']} | #{r['position']} | {r['shadowed_by']} |")
                follow_presentation = "\n".join(lines)
        elif follow_up_type == "compliance":
            fw = random.choice(FRAMEWORKS)
            follow_query = random.choice([f"run {fw} check on that device group", f"check {fw} compliance there"])
            follow_params = {"framework": fw, "firewall": found_dg}
            follow_result = gen_result_run_compliance_scan(fw, found_dg)
            follow_tool = "run_compliance_scan"
            follow_presentation = f"**{follow_result['framework']} Compliance: {found_dg}** — Score: **{follow_result['score']}/100** ({follow_result['checks_passed']} passed, {follow_result['checks_failed']} failed)"
        else:
            follow_query = random.choice(["how many rules there?", "show rule stats for that device group"])
            follow_params = {"device_group": found_dg}
            follow_result = gen_result_get_rule_statistics(found_dg)
            follow_tool = "get_rule_statistics"
            nolog_pct = round(follow_result["rules_without_logging"] / follow_result["total_rules"] * 100)
            follow_presentation = (
                f"| Metric | Count |\n|--------|-------|\n"
                f"| Total rules | {follow_result['total_rules']:,} |\n"
                f"| Allow rules | {follow_result['allow_rules']:,} |\n"
                f"| Deny rules | {follow_result['deny_rules']:,} |\n"
                f"| With logging | {follow_result['rules_with_logging']:,} |\n"
                f"| Without logging | {follow_result['rules_without_logging']:,} ({nolog_pct}%) |\n\n"
                f"{nolog_pct}% of rules in **{found_dg}** lack logging."
            )

        conversations = [
            {"from": "system", "value": system_msg},
            {"from": "human", "value": random.choice([f"where is {ip}?", f"find {ip}", f"look up {ip}"])},
            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': 'search_objects', 'parameters': {'query': ip}})}"},
            {"from": "ipython", "value": json.dumps(result1)},
            {"from": "gpt", "value": present_search_objects(result1, ip)},
            {"from": "human", "value": follow_query},
            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': follow_tool, 'parameters': follow_params})}"},
            {"from": "ipython", "value": json.dumps(follow_result)},
            {"from": "gpt", "value": follow_presentation},
        ]

    elif pattern == "compliance_drilldown":
        # Pattern 2: Compliance scan → drill down into failing rules
        tool_set = ["run_compliance_scan", "search_rules", "get_rule_statistics"]
        system_msg = build_system_message(tool_set)
        fw = random.choice(FRAMEWORKS)

        result1 = gen_result_run_compliance_scan(fw, dg)
        pres1 = f"**{result1['framework']} Compliance: {dg}** — Score: **{result1['score']}/100** ({result1['checks_passed']} passed, {result1['checks_failed']} failed)"
        if result1["findings"]:
            pres1 += "\n\n| Check | Description | Finding |\n|-------|-------------|---------|"
            for f in result1["findings"]:
                pres1 += f"\n| {f['check']} | {f['description']} | {f['finding']} |"

        follow_query = random.choice(["show me the rules without logging", "which rules are failing?", "show me the deny rules without logging"])
        follow_result = gen_result_search_rules("deny", False, dg)
        follow_pres = f"Found **{follow_result['count']} deny rules without logging** in **{dg}**:\n\n"
        follow_pres += "| Rule | Source Zone | Dest Zone | Action | Logging |\n|------|-----------|-----------|--------|---------|"
        for r in follow_result["rules"][:5]:
            follow_pres += f"\n| {r['name']} | {r['source_zone']} | {r['destination_zone']} | {r['action']} | disabled |"
        follow_pres += "\n\nEnable log forwarding on these rules to improve compliance score."

        conversations = [
            {"from": "system", "value": system_msg},
            {"from": "human", "value": f"run {fw} compliance scan on {dg}"},
            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': 'run_compliance_scan', 'parameters': {'framework': fw, 'firewall': dg}})}"},
            {"from": "ipython", "value": json.dumps(result1)},
            {"from": "gpt", "value": pres1},
            {"from": "human", "value": follow_query},
            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': 'search_rules', 'parameters': {'device_group': dg, 'action': 'deny', 'has_logging': False}})}"},
            {"from": "ipython", "value": json.dumps(follow_result)},
            {"from": "gpt", "value": follow_pres},
        ]

    else:
        # Pattern 3: Unused rules → check hit count on specific rule
        tool_set = ["find_unused_rules", "get_rule_hit_count", "search_objects"]
        system_msg = build_system_message(tool_set)

        result1 = gen_result_find_unused_rules(dg)
        pres1 = present_find_unused_rules(result1)
        if result1["rules"]:
            target_rule = result1["rules"][0]["name"]
        else:
            target_rule = random_rule()

        follow_query = random.choice([f"check the hit count for {target_rule}", f"is {target_rule} really unused?", f"show traffic stats for {target_rule}"])
        follow_result = gen_result_get_rule_hit_count(target_rule)
        if follow_result["hit_count"] > 0:
            follow_pres = (
                f"**{target_rule}** actually has **{follow_result['hit_count']:,} hits** in the {follow_result['time_range']} window. "
                f"Last hit: {follow_result['last_hit'][:16].replace('T', ' ')} UTC. This rule is active — do not remove."
            )
        else:
            follow_pres = f"Confirmed: **{target_rule}** has **zero hits** in the {follow_result['time_range']} window. Safe to remove."

        conversations = [
            {"from": "system", "value": system_msg},
            {"from": "human", "value": f"find unused rules in {dg}"},
            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': 'find_unused_rules', 'parameters': {'device_group': dg}})}"},
            {"from": "ipython", "value": json.dumps(result1)},
            {"from": "gpt", "value": pres1},
            {"from": "human", "value": follow_query},
            {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': 'get_rule_hit_count', 'parameters': {'rule_id': target_rule}})}"},
            {"from": "ipython", "value": json.dumps(follow_result)},
            {"from": "gpt", "value": follow_pres},
        ]

    return {"conversations": conversations, "_category": "multi_turn"}


# =============================================================================
# ERROR HANDLING EXAMPLES
# =============================================================================

def generate_error_example() -> Dict[str, Any]:
    """Generate a tool call that returns an error."""
    tool_name = random.choice([
        "search_objects", "check_traffic_flow", "run_compliance_scan", "nat_check",
        "find_unused_rules", "find_shadowed_rules", "check_access", "query_audit_logs",
        "compare_configs", "get_critical_findings",
    ])
    ip = random_internal_ip()
    dst = random_internal_ip()

    tool_set = [tool_name]
    system_msg = build_system_message(tool_set)

    dg = random_dg()
    if tool_name == "search_objects":
        query = f"find {ip}"
        params = {"query": ip}
    elif tool_name == "check_traffic_flow":
        query = f"can {ip} reach {dst} on port 443?"
        params = {"source": ip, "destination": dst, "port": 443, "protocol": "tcp"}
    elif tool_name == "run_compliance_scan":
        fw = random.choice(FRAMEWORKS)
        query = f"run {fw} scan"
        params = {"framework": fw}
    elif tool_name == "nat_check":
        query = f"check NAT for {ip} to {dst}"
        params = {"src_ip": ip, "dst_ip": dst}
    elif tool_name == "find_unused_rules":
        query = f"find unused rules in {dg}"
        params = {"device_group": dg}
    elif tool_name == "find_shadowed_rules":
        query = f"check for shadowed rules in {dg}"
        params = {"device_group": dg}
    elif tool_name == "check_access":
        query = f"can {ip} access {dst} on port 443?"
        params = {"source_ip": ip, "destination_ip": dst, "port": 443}
    elif tool_name == "query_audit_logs":
        query = "show recent audit logs"
        params = {"log_type": "audit", "limit": 20}
    elif tool_name == "compare_configs":
        query = f"any pending changes in {dg}?"
        params = {"device_group": dg}
    elif tool_name == "get_critical_findings":
        query = "any critical security findings?"
        params = {}
    else:
        query = f"check NAT for {ip} to {dst}"
        params = {"src_ip": ip, "dst_ip": dst}

    result = gen_result_error()
    error_msg = result["error"]

    error_responses = {
        "Connection to Panorama timed out after 30s": "The search failed — Panorama connection timed out. This usually means the Panorama appliance is unreachable or under heavy load. Try again in a few minutes, or check the Panorama health status in the FireWeave dashboard.",
        "Authentication failed - API key expired": "The request failed — the API key for Panorama has expired. Contact your FireWeave administrator to refresh the API credentials.",
        "Device group not found": "That device group wasn't found. Check the device group name and try again. You can ask me to show rule statistics to see available device groups.",
        "Rate limit exceeded, try again in 60s": "Rate limit hit — too many requests to Panorama. Wait about a minute and try again.",
        "Internal server error": "An internal error occurred. This is likely a temporary issue. Try again, and if it persists, check the FireWeave service logs.",
    }

    presentation = error_responses.get(error_msg, f"The tool returned an error: {error_msg}. Please try again or contact your administrator.")

    conversations = [
        {"from": "system", "value": system_msg},
        {"from": "human", "value": query},
        {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': tool_name, 'parameters': params})}"},
        {"from": "ipython", "value": json.dumps(result)},
        {"from": "gpt", "value": presentation},
    ]

    return {"conversations": conversations, "_category": "error"}


# =============================================================================
# CONFIRMATION FLOW EXAMPLES
# =============================================================================

def generate_confirmation_example() -> Dict[str, Any]:
    """Generate a suggestion → confirmation → tool call flow."""
    tool_name = random.choice([
        "find_unused_rules", "find_shadowed_rules", "run_compliance_scan",
        "get_dnat_exposure", "find_duplicate_objects", "compare_configs",
        "get_critical_findings", "get_vpn_health",
    ])
    dg = random_dg()

    tool_set = [tool_name, "search_objects"]
    system_msg = build_system_message(tool_set)

    suggestions = {
        "find_unused_rules": {
            "query": f"I want to clean up the rulebase in {dg}",
            "suggestion": f"I can help with rulebase cleanup in {dg}. I'll start by finding unused rules — those with zero hits in the last 90 days. Want me to run that scan?",
            "params": {"device_group": dg},
        },
        "find_shadowed_rules": {
            "query": f"help me optimize rules in {dg}",
            "suggestion": f"I can analyze the rulebase in {dg} for optimization. First step is finding shadowed rules — rules that never match because a broader rule above catches all their traffic. Want me to check?",
            "params": {"device_group": dg},
        },
        "run_compliance_scan": {
            "query": "we have a PCI audit coming up",
            "suggestion": "I can run a PCI-DSS compliance scan against your firewall policies to identify gaps before the audit. Want me to scan all device groups or a specific one?",
            "params": {"framework": "pci-dss"},
        },
        "get_dnat_exposure": {
            "query": "I'm worried about our attack surface",
            "suggestion": "I can check what services are exposed to the internet via DNAT rules — these form your external attack surface. Want me to scan for exposed services?",
            "params": {},
        },
        "find_duplicate_objects": {
            "query": "our object list is a mess",
            "suggestion": "I can find duplicate address and service objects across your device groups. Consolidating duplicates simplifies management and reduces commit times. Want me to scan?",
            "params": {"object_type": "address"},
        },
        "compare_configs": {
            "query": f"I'm about to do a maintenance window on {dg}",
            "suggestion": f"Before the maintenance window, I can compare the running config against the candidate config in {dg} to see if there are any pending uncommitted changes. Want me to check?",
            "params": {"device_group": dg},
        },
        "get_critical_findings": {
            "query": "our CISO wants a risk summary",
            "suggestion": "I can pull all critical and high-severity security findings across your firewall and cloud environments. Want me to generate the findings report?",
            "params": {},
        },
        "get_vpn_health": {
            "query": "users are complaining about VPN issues",
            "suggestion": "I can check the health status of all VPN tunnels including IKE phase and uptime. Want me to run a VPN health check?",
            "params": {},
        },
    }

    s = suggestions[tool_name]
    confirmation = random.choice(["yes", "yes go ahead", "sure", "do it", "go ahead", "yes please", "run it"])

    # Generate result based on tool
    if tool_name == "find_unused_rules":
        result = gen_result_find_unused_rules(dg)
        presentation = present_find_unused_rules(result)
    elif tool_name == "find_shadowed_rules":
        result = gen_result_find_shadowed_rules(dg)
        if result["count"] == 0:
            presentation = f"No shadowed rules found in **{dg}**. All rules are reachable."
        else:
            presentation = f"Found **{result['count']} shadowed rules** in **{dg}**."
    elif tool_name == "run_compliance_scan":
        result = gen_result_run_compliance_scan("pci-dss")
        presentation = f"**PCI-DSS Compliance** — Score: **{result['score']}/100** ({result['checks_passed']} passed, {result['checks_failed']} failed)"
    elif tool_name == "get_dnat_exposure":
        result = gen_result_get_dnat_exposure()
        presentation = f"Found **{len(result['exposed_services'])} internet-exposed services**."
    elif tool_name == "compare_configs":
        result = gen_result_compare_configs(dg)
        if not result["has_changes"]:
            presentation = f"No pending changes in **{dg}**. Running and candidate configs are in sync."
        else:
            presentation = f"**{len(result['changes'])} pending changes** in **{dg}**. Review before committing."
    elif tool_name == "get_critical_findings":
        result = gen_result_get_critical_findings()
        presentation = f"Found **{result['count']} critical/high findings** across your environment."
    elif tool_name == "get_vpn_health":
        result = gen_result_get_vpn_health()
        down = [t for t in result["tunnels"] if t["status"] == "down"]
        if down:
            presentation = f"**{len(down)} of {len(result['tunnels'])} VPN tunnels are down**. Check IKE configuration on the affected peers."
        else:
            presentation = f"All **{len(result['tunnels'])} VPN tunnels** are up and healthy."
    else:
        result = gen_result_find_duplicate_objects()
        presentation = f"Found **{result['count']} duplicate address pairs**."

    conversations = [
        {"from": "system", "value": system_msg},
        {"from": "human", "value": s["query"]},
        {"from": "gpt", "value": s["suggestion"]},
        {"from": "human", "value": confirmation},
        {"from": "gpt", "value": f"<|python_tag|>{json.dumps({'name': tool_name, 'parameters': s['params']})}"},
        {"from": "ipython", "value": json.dumps(result)},
        {"from": "gpt", "value": presentation},
    ]

    return {"conversations": conversations, "_category": "confirmation"}


# =============================================================================
# MAIN GENERATION LOGIC
# =============================================================================

# Target ratios from spec
CATEGORY_RATIOS = {
    "tool_call": 0.30,          # IP-triggered tool calls
    "confirmation": 0.15,       # Confirmation flow
    "conversational_tools": 0.20,  # Conversational with tools available
    "knowledge": 0.15,          # Pure knowledge (no tools)
    "multi_turn": 0.10,         # Multi-turn conversations
    "error": 0.10,              # Error handling
}

# Tool distribution within tool_call category
TOOL_WEIGHTS = {
    "search_objects": 25,
    "check_traffic_flow": 8,
    "check_access": 7,
    "find_unused_rules": 10,
    "run_compliance_scan": 8,
    "nat_check": 7,
    "get_rule_statistics": 5,
    "search_rules": 5,
    "find_shadowed_rules": 5,
    "get_dnat_exposure": 3,
    "get_rule_hit_count": 3,
    "query_audit_logs": 3,
    "compare_configs": 2,
    "get_audit_diff": 2,
    "get_critical_findings": 2,
    "get_snow_changes": 1,
    "get_vpn_health": 1,
    "get_jira_issues": 1,
    "find_duplicate_objects": 2,
    "create_firewall_rule": 2,
    "analyze_attack_path": 1,
    "list_unused_objects": 2,
}


def weighted_tool_choice() -> str:
    tools = list(TOOL_WEIGHTS.keys())
    weights = list(TOOL_WEIGHTS.values())
    return random.choices(tools, weights=weights, k=1)[0]


def prewarm_claude_cache():
    """Pre-generate Claude queries for all tools to avoid per-example API calls."""
    if _claude_provider is None:
        return

    print("\nPre-warming Claude query cache...")
    for tool_name in TOOL_SCHEMAS:
        _claude_provider.generate_queries(tool_name, count=30)

    print("Pre-warming Claude knowledge Q&A cache...")
    _claude_provider.generate_knowledge_qa(count=15)
    print()


def generate_dataset(total_count: int, seed: int = 42) -> List[Dict]:
    """Generate the full dataset according to target ratios."""
    random.seed(seed)
    examples = []
    seen_hashes = set()

    # Pre-warm Claude caches (batch all API calls upfront)
    prewarm_claude_cache()

    # Calculate counts per category
    counts = {cat: max(1, int(total_count * ratio)) for cat, ratio in CATEGORY_RATIOS.items()}
    # Adjust to hit exact total
    diff = total_count - sum(counts.values())
    counts["tool_call"] += diff

    print(f"Generating {total_count} examples:")
    for cat, count in counts.items():
        print(f"  {cat}: {count}")

    # Generate each category
    for _ in range(counts["tool_call"]):
        tool = weighted_tool_choice()
        ex = generate_tool_call_example(tool)
        examples.append(ex)

    for _ in range(counts["confirmation"]):
        examples.append(generate_confirmation_example())

    for _ in range(counts["conversational_tools"]):
        examples.append(generate_conversational_example(with_tools=True))

    for _ in range(counts["knowledge"]):
        examples.append(generate_conversational_example(with_tools=False))

    for _ in range(counts["multi_turn"]):
        examples.append(generate_multi_turn_example())

    for _ in range(counts["error"]):
        examples.append(generate_error_example())

    # Deduplicate by hashing key conversation content
    # For tool calls: hash human message (IPs make them unique)
    # For conversational/confirmation: hash human + gpt values (varied results make them unique)
    unique = []
    for ex in examples:
        cat = ex.get("_category", "")
        if cat == "tool_call":
            # Human messages contain random IPs, so they're mostly unique
            key_parts = [c["value"] for c in ex["conversations"] if c["from"] == "human"]
        else:
            # Include all non-system content for uniqueness
            key_parts = [c["value"][:200] for c in ex["conversations"] if c["from"] != "system"]
        key = hashlib.md5(json.dumps(key_parts, sort_keys=True).encode()).hexdigest()
        if key not in seen_hashes:
            seen_hashes.add(key)
            unique.append(ex)

    print(f"\nGenerated: {len(examples)}, After dedup: {len(unique)}")

    # Shuffle
    random.shuffle(unique)
    return unique


def strip_metadata(examples: List[Dict]) -> List[Dict]:
    """Remove internal metadata fields before saving."""
    cleaned = []
    for ex in examples:
        cleaned.append({"conversations": ex["conversations"]})
    return cleaned


def print_stats(examples: List[Dict]):
    """Print dataset statistics."""
    from collections import Counter
    cats = Counter(ex.get("_category", "unknown") for ex in examples)
    tools = Counter(ex.get("_tool", "n/a") for ex in examples)

    print("\n=== Dataset Statistics ===")
    print(f"Total examples: {len(examples)}")
    print(f"\nBy category:")
    for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"  {cat}: {count} ({count/len(examples)*100:.1f}%)")
    print(f"\nBy tool (tool_call category only):")
    for tool, count in sorted(tools.items(), key=lambda x: -x[1]):
        if tool != "n/a":
            print(f"  {tool}: {count}")

    # Check format correctness
    errors = []
    for i, ex in enumerate(examples):
        convs = ex["conversations"]
        if not convs:
            errors.append(f"Example {i}: empty conversations")
            continue
        if convs[0]["from"] != "system":
            errors.append(f"Example {i}: first message not system")
        for c in convs:
            if c["from"] == "gpt" and "<|python_tag|>" in c["value"]:
                # Verify it starts with the tag
                if not c["value"].startswith("<|python_tag|>"):
                    errors.append(f"Example {i}: tool call has text before <|python_tag|>")
                # Verify valid JSON after tag
                try:
                    json_str = c["value"].replace("<|python_tag|>", "")
                    parsed = json.loads(json_str)
                    if "name" not in parsed or "parameters" not in parsed:
                        errors.append(f"Example {i}: tool call missing name/parameters")
                except json.JSONDecodeError:
                    errors.append(f"Example {i}: invalid JSON in tool call")

    if errors:
        print(f"\n!!! {len(errors)} FORMAT ERRORS:")
        for e in errors[:10]:
            print(f"  {e}")
    else:
        print(f"\nFormat validation: ALL PASSED")


# =============================================================================
# CLAUDE API INTEGRATION
# =============================================================================

class ClaudeProvider:
    """Uses Claude API to generate varied user queries, knowledge Q&A, and presentations."""

    def __init__(self, model: str = "claude-sonnet-4-5-20250929"):
        try:
            import anthropic
        except ImportError:
            raise ImportError("anthropic package required. Install with: pip install anthropic")

        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not found in environment. Set it or use a .env file.")

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = model
        self._query_cache: Dict[str, List[str]] = {}
        self._qa_cache: List[tuple] = []
        self._presentation_cache: Dict[str, List[str]] = {}
        self.total_input_tokens = 0
        self.total_output_tokens = 0

    def _call(self, system: str, prompt: str, max_tokens: int = 2000, temperature: float = 0.9) -> str:
        """Make a Claude API call with rate-limit retry."""
        for attempt in range(3):
            try:
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system,
                    messages=[{"role": "user", "content": prompt}],
                )
                self.total_input_tokens += message.usage.input_tokens
                self.total_output_tokens += message.usage.output_tokens
                return message.content[0].text
            except Exception as e:
                if "rate_limit" in str(e).lower() or "429" in str(e):
                    wait = 10 * (attempt + 1)
                    print(f"  Rate limited, waiting {wait}s...")
                    time.sleep(wait)
                else:
                    print(f"  Claude API error: {e}")
                    return ""
        return ""

    def generate_queries(self, tool_name: str, count: int = 30) -> List[str]:
        """Generate varied user queries for a specific tool."""
        if tool_name in self._query_cache and len(self._query_cache[tool_name]) >= count:
            return self._query_cache[tool_name]

        schema = TOOL_SCHEMAS.get(tool_name, "")

        system = (
            "You are generating training data for a network security AI chatbot called Ember "
            "that runs on the FireWeave platform. Generate realistic user queries that would "
            "trigger a specific tool call. Users are network engineers interacting with a chat interface."
        )

        # Build example queries from templates
        existing = QUERY_TEMPLATES.get(tool_name, [])
        if isinstance(existing, dict):
            sample_queries = []
            for key, templates in existing.items():
                sample_queries.extend(templates[:2])
        elif isinstance(existing, list):
            sample_queries = existing[:3]
        else:
            sample_queries = []

        prompt = (
            f"Generate {count} unique, natural user queries that would trigger the `{tool_name}` tool.\n\n"
            f"Tool schema:\n{schema}\n\n"
            f"Example queries (for style reference only — generate NEW ones, don't copy):\n"
            + "\n".join(f"- {q}" for q in sample_queries) + "\n\n"
            "Rules:\n"
            "- Use placeholder {ip} for IP addresses, {dg} for device groups, {rule} for rule names\n"
            "- Mix casual and formal styles\n"
            "- Include typos/shorthand occasionally (real users do this)\n"
            "- Some should include a device group, some should not\n"
            "- Vary between questions, commands, and terse lookups\n"
            "- Keep each query on its own line, no numbering or bullets\n"
            f"\nOutput exactly {count} queries, one per line:"
        )

        response = self._call(system, prompt, max_tokens=2000)
        queries = [line.strip().lstrip("- ").lstrip("0123456789.") .strip()
                   for line in response.strip().split("\n")
                   if line.strip() and not line.startswith("#")]
        queries = [q for q in queries if len(q) > 3 and len(q) < 200]

        if queries:
            self._query_cache[tool_name] = queries
            print(f"  Claude generated {len(queries)} queries for {tool_name}")
        return queries

    def generate_knowledge_qa(self, count: int = 15) -> List[tuple]:
        """Generate varied knowledge Q&A pairs about network security and FireWeave."""
        if len(self._qa_cache) >= count:
            return self._qa_cache

        system = (
            "You are generating training Q&A pairs for a network security AI called Ember. "
            "Ember is embedded in the FireWeave platform which manages firewalls (Palo Alto Panorama), "
            "runs compliance scans, checks traffic flows, and integrates with ServiceNow/Jira. "
            "Answers should be concise, technical, and use markdown formatting."
        )

        existing_topics = [q for q, _ in KNOWLEDGE_QA[:5]]

        prompt = (
            f"Generate {count} Q&A pairs about network security, firewalls, and the FireWeave platform.\n\n"
            "Topics to cover (vary across ALL of these):\n"
            "- Palo Alto firewall concepts (App-ID, zone-based policy, Panorama, device groups)\n"
            "- Network security fundamentals (firewalls, IDS/IPS, VPN, NAT, DMZ)\n"
            "- Compliance frameworks (PCI-DSS, SOC2, NIST, HIPAA, CIS)\n"
            "- FireWeave features (traffic flow analysis, rule cleanup, compliance scanning)\n"
            "- Security best practices (least privilege, segmentation, logging)\n"
            "- Incident response, change management, audit trails\n"
            "- Cloud security (AWS, Azure, GCP security groups/NSGs)\n"
            "- VPN troubleshooting, certificate management\n\n"
            "Existing topics already covered (DON'T repeat these):\n"
            + "\n".join(f"- {t}" for t in existing_topics) + "\n\n"
            "Format each pair as:\n"
            "Q: <user question>\n"
            "A: <detailed answer with markdown formatting, 3-8 sentences, include bullet points or tables where appropriate>\n"
            "---\n"
            "\nRules:\n"
            "- Questions should sound like a network engineer talking to a colleague\n"
            "- Answers should be direct and technical, not chatbot-like\n"
            "- Include specific commands, config snippets, or examples where relevant\n"
            "- Some answers should mention that Ember/FireWeave can help with related checks\n"
            "- Keep answers between 100-400 words\n"
        )

        response = self._call(system, prompt, max_tokens=4000)

        pairs = []
        current_q, current_a = None, None
        for line in response.split("\n"):
            line = line.strip()
            if line.startswith("Q:"):
                if current_q and current_a:
                    pairs.append((current_q, current_a))
                current_q = line[2:].strip()
                current_a = None
            elif line.startswith("A:"):
                current_a = line[2:].strip()
            elif line == "---":
                if current_q and current_a:
                    pairs.append((current_q, current_a))
                current_q, current_a = None, None
            elif current_a is not None and line:
                current_a += "\n" + line

        if current_q and current_a:
            pairs.append((current_q, current_a))

        if pairs:
            # Accumulate Q&A pairs across calls, dedup by question
            existing_qs = {q for q, _ in self._qa_cache}
            for q, a in pairs:
                if q not in existing_qs:
                    self._qa_cache.append((q, a))
                    existing_qs.add(q)
            print(f"  Claude generated {len(pairs)} knowledge Q&A pairs (total: {len(self._qa_cache)})")
        return self._qa_cache

    def generate_presentations(self, tool_name: str, result_json: str, count: int = 10) -> List[str]:
        """Generate varied presentation text for tool results."""
        cache_key = tool_name
        if cache_key in self._presentation_cache and len(self._presentation_cache[cache_key]) >= 3:
            return self._presentation_cache[cache_key]

        system = (
            "You are Ember, a senior network security analyst. Present tool results directly "
            "using markdown tables. Be concise and technical. Don't narrate your process — just present findings."
        )

        prompt = (
            f"The `{tool_name}` tool returned this JSON result:\n"
            f"```json\n{result_json}\n```\n\n"
            f"Generate {count} different ways to present these results to a network engineer.\n"
            "Rules:\n"
            "- Use markdown tables for structured data\n"
            "- Be direct — don't say 'I found' or 'Let me show you'\n"
            "- Include actionable observations (e.g., 'consider removing', 'enable logging')\n"
            "- Vary the format: some compact, some detailed\n"
            "- Each presentation separated by ===\n"
        )

        response = self._call(system, prompt, max_tokens=3000)
        presentations = [p.strip() for p in response.split("===") if p.strip() and len(p.strip()) > 20]

        if presentations:
            self._presentation_cache[cache_key] = presentations
        return presentations

    def print_usage(self):
        """Print token usage summary."""
        print(f"\n=== Claude API Usage ===")
        print(f"  Input tokens:  {self.total_input_tokens:,}")
        print(f"  Output tokens: {self.total_output_tokens:,}")
        est_cost = (self.total_input_tokens * 3 / 1_000_000) + (self.total_output_tokens * 15 / 1_000_000)
        print(f"  Est. cost:     ${est_cost:.2f}")


# Global provider instance (set in main)
_claude_provider: Optional[ClaudeProvider] = None


def get_claude_query(tool_name: str, **format_kwargs) -> Optional[str]:
    """Try to get a Claude-generated query, falling back to templates."""
    if _claude_provider is None:
        return None

    queries = _claude_provider.generate_queries(tool_name)
    if not queries:
        return None

    # Pick a random query and fill in placeholders
    query = random.choice(queries)
    try:
        for key, val in format_kwargs.items():
            query = query.replace(f"{{{key}}}", str(val))
        # Replace any remaining placeholders with random values
        if "{ip}" in query:
            query = query.replace("{ip}", random_internal_ip())
        if "{dg}" in query:
            query = query.replace("{dg}", random_dg())
        if "{rule}" in query:
            query = query.replace("{rule}", random_rule())
        if "{admin}" in query:
            query = query.replace("{admin}", random_admin())
        if "{port}" in query:
            port, _, _ = random_port_service()
            query = query.replace("{port}", str(port))
        return query
    except Exception:
        return None


def get_claude_qa() -> Optional[tuple]:
    """Try to get a Claude-generated knowledge Q&A pair."""
    if _claude_provider is None:
        return None

    pairs = _claude_provider.generate_knowledge_qa()
    if not pairs:
        return None

    return random.choice(pairs)


def get_claude_presentation(tool_name: str, result: dict) -> Optional[str]:
    """Try to get a Claude-generated presentation for tool results."""
    if _claude_provider is None:
        return None

    result_json = json.dumps(result, indent=2)
    presentations = _claude_provider.generate_presentations(tool_name, result_json)
    if not presentations:
        return None

    return random.choice(presentations)


# =============================================================================
# CLI & MAIN
# =============================================================================

def main():
    global _claude_provider

    parser = argparse.ArgumentParser(description="Generate Ember/FireWeave tool calling training data")
    parser.add_argument("--count", type=int, default=3000, help="Number of examples to generate (default: 3000)")
    parser.add_argument("--output", type=str, default="data/processed/tool_calling_train.json", help="Output file path")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility")
    parser.add_argument("--dry-run", action="store_true", help="Generate and print stats without saving")
    parser.add_argument("--stats", action="store_true", help="Print stats for existing dataset")
    parser.add_argument("--category", type=str, choices=list(CATEGORY_RATIOS.keys()), help="Generate only one category")
    parser.add_argument("--keep-metadata", action="store_true", help="Keep _category and _tool fields in output")
    parser.add_argument("--provider", type=str, choices=["local", "claude"], default="local",
                        help="Generation provider: local (template-based) or claude (API-enhanced)")
    parser.add_argument("--claude-model", type=str, default="claude-sonnet-4-5-20250929",
                        help="Claude model to use (default: claude-sonnet-4-5-20250929)")
    args = parser.parse_args()

    # Load .env file if present
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass

    if args.stats:
        with open(args.output, "r") as f:
            data = json.load(f)
        print_stats(data)
        return

    # Initialize Claude provider if requested
    if args.provider == "claude":
        try:
            _claude_provider = ClaudeProvider(model=args.claude_model)
            print(f"Claude provider initialized (model: {args.claude_model})")
            print("Claude will enhance query variety, knowledge Q&A, and presentations.\n")
        except (ImportError, ValueError) as e:
            print(f"Warning: Could not initialize Claude provider: {e}")
            print("Falling back to local template-based generation.\n")
            _claude_provider = None

    examples = generate_dataset(args.count, args.seed)

    if args.category:
        examples = [ex for ex in examples if ex.get("_category") == args.category]
        print(f"Filtered to {len(examples)} examples of category '{args.category}'")

    print_stats(examples)

    if _claude_provider:
        _claude_provider.print_usage()

    if not args.dry_run:
        output = examples if args.keep_metadata else strip_metadata(examples)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        print(f"\nSaved to {args.output} ({len(output)} examples)")


if __name__ == "__main__":
    main()
