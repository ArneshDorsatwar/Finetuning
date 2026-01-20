#!/usr/bin/env python3
"""
Function Calling Training Data Generator for FireWeave Integration

This script generates training data that teaches the model to:
1. Understand user intent and map it to FireWeave tool calls
2. Output structured JSON function calls
3. Handle multi-step workflows
4. Provide explanations alongside tool calls

The training format follows the ChatML/ShareGPT format with function calling conventions.
"""

import json
import os
import random
from typing import List, Dict, Any
from dotenv import load_dotenv

load_dotenv()

# =============================================================================
# FIREWEAVE TOOL DEFINITIONS
# =============================================================================

FIREWEAVE_TOOLS = {
    "traffic_flow_analysis": {
        "name": "traffic_flow_analysis",
        "description": "Check if traffic between source and destination is allowed through the firewall",
        "parameters": {
            "type": "object",
            "properties": {
                "source_ip": {"type": "string", "description": "Source IP address (e.g., 10.1.1.100)"},
                "destination_ip": {"type": "string", "description": "Destination IP address (e.g., 192.168.1.50)"},
                "port": {"type": "integer", "description": "Destination port number (e.g., 443, 22, 80)"},
                "protocol": {"type": "string", "enum": ["tcp", "udp", "icmp"], "description": "Protocol type"},
                "device_group": {"type": "string", "description": "Optional: specific device group to check"}
            },
            "required": ["source_ip", "destination_ip", "port", "protocol"]
        }
    },
    "nat_check": {
        "name": "nat_check",
        "description": "Test NAT policy matches and see how traffic would be translated",
        "parameters": {
            "type": "object",
            "properties": {
                "source_ip": {"type": "string", "description": "Original source IP"},
                "destination_ip": {"type": "string", "description": "Original destination IP"},
                "port": {"type": "integer", "description": "Destination port"},
                "zone_from": {"type": "string", "description": "Source security zone"},
                "zone_to": {"type": "string", "description": "Destination security zone"}
            },
            "required": ["source_ip", "destination_ip", "port", "zone_from", "zone_to"]
        }
    },
    "rule_search": {
        "name": "rule_search",
        "description": "Search for security rules matching specific criteria",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query (e.g., 'ssh', 'any-any', rule name)"},
                "device_group": {"type": "string", "description": "Device group to search in"},
                "rule_type": {"type": "string", "enum": ["security", "nat", "decryption", "qos"], "description": "Type of rule to search"},
                "filters": {
                    "type": "object",
                    "properties": {
                        "source_zone": {"type": "string"},
                        "destination_zone": {"type": "string"},
                        "application": {"type": "string"},
                        "action": {"type": "string", "enum": ["allow", "deny", "drop"]}
                    }
                }
            },
            "required": ["query"]
        }
    },
    "compliance_scan": {
        "name": "compliance_scan",
        "description": "Run compliance scan against security frameworks",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["PCI-DSS", "SOC2", "NIST", "CIS", "HIPAA", "ISO27001"], "description": "Compliance framework to check against"},
                "device_groups": {"type": "array", "items": {"type": "string"}, "description": "Device groups to scan"},
                "severity_filter": {"type": "string", "enum": ["critical", "high", "medium", "low", "all"], "description": "Minimum severity to report"}
            },
            "required": ["framework", "device_groups"]
        }
    },
    "shadowed_rules_check": {
        "name": "shadowed_rules_check",
        "description": "Find rules that are shadowed by other rules and never match traffic",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string", "description": "Device group to analyze"},
                "rulebase": {"type": "string", "enum": ["pre-rulebase", "post-rulebase"], "description": "Which rulebase to check"}
            },
            "required": ["device_group"]
        }
    },
    "unused_rules_check": {
        "name": "unused_rules_check",
        "description": "Find rules with zero hit count that may be candidates for removal",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string", "description": "Device group to analyze"},
                "days_threshold": {"type": "integer", "description": "Number of days with no hits to consider unused", "default": 30}
            },
            "required": ["device_group"]
        }
    },
    "object_lookup": {
        "name": "object_lookup",
        "description": "Search for address or service objects across device groups",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "IP, CIDR, FQDN, or object name to search for"},
                "object_type": {"type": "string", "enum": ["address", "address-group", "service", "service-group"], "description": "Type of object to search"},
                "device_group": {"type": "string", "description": "Optional: limit search to specific device group"}
            },
            "required": ["query", "object_type"]
        }
    },
    "deduplication_scan": {
        "name": "deduplication_scan",
        "description": "Find duplicate or similar objects that can be consolidated",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string", "description": "Device group to analyze"},
                "object_type": {"type": "string", "enum": ["address", "service"], "description": "Type of objects to check for duplicates"},
                "similarity_threshold": {"type": "number", "description": "Similarity threshold (0.0-1.0)", "default": 0.95}
            },
            "required": ["device_group", "object_type"]
        }
    },
    "create_rule": {
        "name": "create_rule",
        "description": "Create a new security rule in the specified device group",
        "parameters": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Rule name"},
                "device_group": {"type": "string", "description": "Target device group"},
                "rulebase": {"type": "string", "enum": ["pre-rulebase", "post-rulebase"]},
                "source_zone": {"type": "array", "items": {"type": "string"}},
                "destination_zone": {"type": "array", "items": {"type": "string"}},
                "source_address": {"type": "array", "items": {"type": "string"}},
                "destination_address": {"type": "array", "items": {"type": "string"}},
                "application": {"type": "array", "items": {"type": "string"}},
                "service": {"type": "array", "items": {"type": "string"}},
                "action": {"type": "string", "enum": ["allow", "deny", "drop"]},
                "log_start": {"type": "boolean", "default": False},
                "log_end": {"type": "boolean", "default": True},
                "profile_setting": {"type": "string", "description": "Security profile group to apply"},
                "description": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["name", "device_group", "source_zone", "destination_zone", "action"]
        }
    },
    "batch_deploy": {
        "name": "batch_deploy",
        "description": "Deploy multiple rules to a device group with specified placement",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string", "description": "Target device group"},
                "rulebase": {"type": "string", "enum": ["pre-rulebase", "post-rulebase"]},
                "placement": {"type": "string", "enum": ["top", "bottom", "before", "after"], "description": "Where to place the rules"},
                "reference_rule": {"type": "string", "description": "Reference rule for before/after placement"},
                "rules": {"type": "array", "items": {"type": "object"}, "description": "Array of rule objects to deploy"},
                "auto_commit": {"type": "boolean", "default": False, "description": "Whether to auto-commit after deployment"}
            },
            "required": ["device_group", "rulebase", "placement", "rules"]
        }
    },
    "mass_edit": {
        "name": "mass_edit",
        "description": "Modify multiple rules matching specific filters",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string"},
                "filters": {
                    "type": "object",
                    "description": "Filters to select rules",
                    "properties": {
                        "name_contains": {"type": "string"},
                        "tag": {"type": "string"},
                        "source_zone": {"type": "string"},
                        "destination_zone": {"type": "string"},
                        "action": {"type": "string"},
                        "has_logging": {"type": "boolean"},
                        "has_profile": {"type": "boolean"}
                    }
                },
                "actions": {
                    "type": "object",
                    "description": "Actions to apply to matching rules",
                    "properties": {
                        "add_tag": {"type": "string"},
                        "remove_tag": {"type": "string"},
                        "enable_logging": {"type": "boolean"},
                        "set_profile": {"type": "string"},
                        "add_description": {"type": "string"},
                        "set_action": {"type": "string"}
                    }
                },
                "preview_only": {"type": "boolean", "default": True, "description": "Preview changes without applying"}
            },
            "required": ["device_group", "filters", "actions"]
        }
    },
    "topology_collect": {
        "name": "topology_collect",
        "description": "Trigger a new topology collection from Panorama",
        "parameters": {
            "type": "object",
            "properties": {
                "panorama_id": {"type": "string", "description": "ID of the Panorama instance"},
                "full_collection": {"type": "boolean", "default": True, "description": "Full or incremental collection"}
            },
            "required": ["panorama_id"]
        }
    },
    "get_device_groups": {
        "name": "get_device_groups",
        "description": "List all device groups in the Panorama hierarchy",
        "parameters": {
            "type": "object",
            "properties": {
                "panorama_id": {"type": "string", "description": "Optional: specific Panorama instance"},
                "include_hierarchy": {"type": "boolean", "default": True, "description": "Include parent-child relationships"}
            }
        }
    },
    "get_zones": {
        "name": "get_zones",
        "description": "List security zones for a device group or template",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string"},
                "template": {"type": "string"}
            }
        }
    },
    "rule_hit_count": {
        "name": "rule_hit_count",
        "description": "Get hit count statistics for rules",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string"},
                "rule_names": {"type": "array", "items": {"type": "string"}, "description": "Specific rules to check"},
                "time_range": {"type": "string", "enum": ["24h", "7d", "30d", "90d"], "description": "Time range for hit count"}
            },
            "required": ["device_group"]
        }
    },
    "export_rules": {
        "name": "export_rules",
        "description": "Export rules to Excel/CSV format",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string"},
                "rulebase": {"type": "string", "enum": ["pre-rulebase", "post-rulebase", "both"]},
                "format": {"type": "string", "enum": ["excel", "csv", "json"]},
                "filters": {"type": "object", "description": "Optional filters to limit export"}
            },
            "required": ["device_group", "format"]
        }
    },
    "import_rules": {
        "name": "import_rules",
        "description": "Import rules from Excel/CSV file",
        "parameters": {
            "type": "object",
            "properties": {
                "device_group": {"type": "string"},
                "file_path": {"type": "string", "description": "Path to the import file"},
                "rulebase": {"type": "string", "enum": ["pre-rulebase", "post-rulebase"]},
                "validate_only": {"type": "boolean", "default": True, "description": "Only validate, don't import"}
            },
            "required": ["device_group", "file_path", "rulebase"]
        }
    }
}

# =============================================================================
# TRAINING EXAMPLES - FUNCTION CALLING SCENARIOS
# =============================================================================

FUNCTION_CALLING_EXAMPLES = [
    # ==================== TRAFFIC ANALYSIS ====================
    {
        "user": "Can you check if traffic from 10.1.1.50 to 192.168.100.25 on port 443 is allowed?",
        "assistant_thought": "The user wants to verify if HTTPS traffic between two IPs is allowed. I'll use the traffic_flow_analysis tool.",
        "tool_calls": [
            {
                "name": "traffic_flow_analysis",
                "arguments": {
                    "source_ip": "10.1.1.50",
                    "destination_ip": "192.168.100.25",
                    "port": 443,
                    "protocol": "tcp"
                }
            }
        ],
        "assistant_response": "I'm checking the traffic flow from 10.1.1.50 to 192.168.100.25 on port 443/TCP. This will analyze the security policies to determine if this HTTPS traffic is permitted and show which rule would match."
    },
    {
        "user": "Is SSH allowed from the jump server at 10.50.1.10 to the database server 172.16.5.100?",
        "assistant_thought": "SSH uses port 22/TCP. I need to check traffic flow between these hosts.",
        "tool_calls": [
            {
                "name": "traffic_flow_analysis",
                "arguments": {
                    "source_ip": "10.50.1.10",
                    "destination_ip": "172.16.5.100",
                    "port": 22,
                    "protocol": "tcp"
                }
            }
        ],
        "assistant_response": "I'm analyzing whether SSH (port 22/TCP) is allowed from your jump server 10.50.1.10 to the database server at 172.16.5.100. The analysis will show the matching rule and any security profiles applied."
    },
    {
        "user": "Check if servers in 10.0.0.0/24 can reach the internet on ports 80 and 443",
        "assistant_thought": "The user wants to check internet access for a subnet. I'll check both HTTP and HTTPS. Using 0.0.0.0/0 or a common internet IP as destination.",
        "tool_calls": [
            {
                "name": "traffic_flow_analysis",
                "arguments": {
                    "source_ip": "10.0.0.1",
                    "destination_ip": "8.8.8.8",
                    "port": 80,
                    "protocol": "tcp"
                }
            },
            {
                "name": "traffic_flow_analysis",
                "arguments": {
                    "source_ip": "10.0.0.1",
                    "destination_ip": "8.8.8.8",
                    "port": 443,
                    "protocol": "tcp"
                }
            }
        ],
        "assistant_response": "I'm checking internet access for the 10.0.0.0/24 subnet. Running two analyses:\n1. HTTP (port 80) to internet\n2. HTTPS (port 443) to internet\n\nThis will show which rules allow or block outbound web traffic."
    },

    # ==================== NAT CHECKS ====================
    {
        "user": "How would traffic from internal server 192.168.1.100 be NATted when going to the internet?",
        "assistant_thought": "User wants to understand NAT translation for outbound traffic. I'll use nat_check with typical zones.",
        "tool_calls": [
            {
                "name": "nat_check",
                "arguments": {
                    "source_ip": "192.168.1.100",
                    "destination_ip": "8.8.8.8",
                    "port": 443,
                    "zone_from": "trust",
                    "zone_to": "untrust"
                }
            }
        ],
        "assistant_response": "I'm checking the NAT translation for traffic from 192.168.1.100 going to the internet. This will show:\n- Source NAT translation (what public IP it would use)\n- Any destination NAT if applicable\n- The matching NAT policy"
    },
    {
        "user": "What's the NAT policy for traffic from DMZ to the internal network?",
        "assistant_thought": "Checking NAT between DMZ and internal zones.",
        "tool_calls": [
            {
                "name": "nat_check",
                "arguments": {
                    "source_ip": "10.100.1.50",
                    "destination_ip": "192.168.1.100",
                    "port": 443,
                    "zone_from": "dmz",
                    "zone_to": "trust"
                }
            }
        ],
        "assistant_response": "I'm analyzing NAT policies for DMZ to internal traffic. This will reveal if there's source NAT, destination NAT, or no translation for this traffic path."
    },

    # ==================== RULE SEARCH ====================
    {
        "user": "Find all rules that allow SSH access",
        "assistant_thought": "Search for SSH-related rules across all device groups.",
        "tool_calls": [
            {
                "name": "rule_search",
                "arguments": {
                    "query": "ssh",
                    "rule_type": "security",
                    "filters": {
                        "action": "allow"
                    }
                }
            }
        ],
        "assistant_response": "I'm searching for all security rules that allow SSH access. This will find rules with:\n- 'ssh' in the name or description\n- SSH application configured\n- Port 22 in the service"
    },
    {
        "user": "Show me all deny rules in device group DG-Datacenter",
        "assistant_thought": "Filter for deny rules in a specific device group.",
        "tool_calls": [
            {
                "name": "rule_search",
                "arguments": {
                    "query": "*",
                    "device_group": "DG-Datacenter",
                    "rule_type": "security",
                    "filters": {
                        "action": "deny"
                    }
                }
            }
        ],
        "assistant_response": "I'm retrieving all deny rules from the DG-Datacenter device group. This helps identify explicit block policies and security boundaries."
    },
    {
        "user": "Find rules that use any-any configuration",
        "assistant_thought": "Search for overly permissive rules with 'any' in source/destination.",
        "tool_calls": [
            {
                "name": "rule_search",
                "arguments": {
                    "query": "any",
                    "rule_type": "security"
                }
            }
        ],
        "assistant_response": "I'm searching for rules with 'any' configurations. These overly permissive rules are security risks and compliance violations that should be reviewed."
    },

    # ==================== COMPLIANCE ====================
    {
        "user": "Run a PCI-DSS compliance check on all our production device groups",
        "assistant_thought": "Execute compliance scan with PCI-DSS framework on production DGs.",
        "tool_calls": [
            {
                "name": "compliance_scan",
                "arguments": {
                    "framework": "PCI-DSS",
                    "device_groups": ["DG-Production", "DG-Prod-Web", "DG-Prod-DB"],
                    "severity_filter": "all"
                }
            }
        ],
        "assistant_response": "I'm running a PCI-DSS compliance scan across your production device groups. This will check:\n- Requirement 1: Firewall configuration\n- Logging requirements\n- Segmentation controls\n- Access control policies\n\nThe report will show violations by severity with remediation guidance."
    },
    {
        "user": "Check HIPAA compliance for the healthcare device groups",
        "assistant_thought": "HIPAA compliance scan for healthcare environments.",
        "tool_calls": [
            {
                "name": "compliance_scan",
                "arguments": {
                    "framework": "HIPAA",
                    "device_groups": ["DG-Healthcare", "DG-EHR-Systems"],
                    "severity_filter": "high"
                }
            }
        ],
        "assistant_response": "I'm scanning your healthcare device groups for HIPAA compliance. This covers:\n- Technical safeguards for ePHI\n- Access controls\n- Audit logging\n- Encryption requirements\n\nFiltering for high-severity findings."
    },

    # ==================== RULE ANALYSIS ====================
    {
        "user": "Find shadowed rules in our main firewall policy",
        "assistant_thought": "Check for shadowed rules that never match traffic.",
        "tool_calls": [
            {
                "name": "shadowed_rules_check",
                "arguments": {
                    "device_group": "DG-Main",
                    "rulebase": "pre-rulebase"
                }
            }
        ],
        "assistant_response": "I'm analyzing the DG-Main pre-rulebase for shadowed rules. Shadowed rules are those that will never match traffic because earlier rules catch all matching traffic first. These are candidates for removal or reordering."
    },
    {
        "user": "What rules haven't been used in the last 30 days in DG-Branch?",
        "assistant_thought": "Check for unused rules based on hit count.",
        "tool_calls": [
            {
                "name": "unused_rules_check",
                "arguments": {
                    "device_group": "DG-Branch",
                    "days_threshold": 30
                }
            }
        ],
        "assistant_response": "I'm checking for rules in DG-Branch that haven't matched any traffic in 30 days. Unused rules add complexity and should be reviewed for:\n- Possible removal\n- Incorrect configuration\n- Seasonal traffic patterns"
    },

    # ==================== OBJECT MANAGEMENT ====================
    {
        "user": "Find all objects that contain the IP 10.1.1.100",
        "assistant_thought": "Search for address objects containing this IP.",
        "tool_calls": [
            {
                "name": "object_lookup",
                "arguments": {
                    "query": "10.1.1.100",
                    "object_type": "address"
                }
            }
        ],
        "assistant_response": "I'm searching for all address objects that contain 10.1.1.100. This includes:\n- Exact IP matches\n- CIDR ranges that include this IP\n- Address groups containing matching objects"
    },
    {
        "user": "Check for duplicate address objects in Shared",
        "assistant_thought": "Run deduplication scan on the Shared device group.",
        "tool_calls": [
            {
                "name": "deduplication_scan",
                "arguments": {
                    "device_group": "Shared",
                    "object_type": "address",
                    "similarity_threshold": 0.95
                }
            }
        ],
        "assistant_response": "I'm scanning the Shared device group for duplicate address objects. Using 95% similarity threshold to find:\n- Exact duplicates\n- Objects with same IP but different names\n- Overlapping CIDR ranges\n\nConsolidating these reduces policy complexity."
    },

    # ==================== RULE CREATION ====================
    {
        "user": "Create a rule to allow HTTPS from the web servers to the API servers",
        "assistant_thought": "Create a security rule for HTTPS between web and API tiers.",
        "tool_calls": [
            {
                "name": "create_rule",
                "arguments": {
                    "name": "Allow-Web-to-API-HTTPS",
                    "device_group": "DG-Production",
                    "rulebase": "pre-rulebase",
                    "source_zone": ["web-tier"],
                    "destination_zone": ["api-tier"],
                    "source_address": ["web-servers-group"],
                    "destination_address": ["api-servers-group"],
                    "application": ["ssl", "web-browsing"],
                    "service": ["application-default"],
                    "action": "allow",
                    "log_end": True,
                    "profile_setting": "Security-Profile-Standard",
                    "description": "Allow HTTPS from web tier to API tier",
                    "tags": ["web-api", "production"]
                }
            }
        ],
        "assistant_response": "I'm creating a security rule to allow HTTPS traffic from web servers to API servers:\n\n**Rule Details:**\n- Name: Allow-Web-to-API-HTTPS\n- Source: web-tier zone, web-servers-group\n- Destination: api-tier zone, api-servers-group\n- Application: SSL, Web-browsing\n- Action: Allow with logging\n- Profile: Security-Profile-Standard\n\nThe rule will be placed in the pre-rulebase of DG-Production."
    },
    {
        "user": "Block all traffic from the compromised host 10.5.5.100",
        "assistant_thought": "Create an urgent deny rule for incident response.",
        "tool_calls": [
            {
                "name": "create_rule",
                "arguments": {
                    "name": "BLOCK-Compromised-Host-10.5.5.100",
                    "device_group": "DG-Main",
                    "rulebase": "pre-rulebase",
                    "source_zone": ["any"],
                    "destination_zone": ["any"],
                    "source_address": ["10.5.5.100"],
                    "destination_address": ["any"],
                    "application": ["any"],
                    "service": ["any"],
                    "action": "deny",
                    "log_start": True,
                    "log_end": True,
                    "description": "INCIDENT RESPONSE: Block compromised host",
                    "tags": ["incident-response", "compromised", "urgent"]
                }
            }
        ],
        "assistant_response": "I'm creating an urgent block rule for the compromised host 10.5.5.100:\n\n**Incident Response Rule:**\n- Name: BLOCK-Compromised-Host-10.5.5.100\n- Action: DENY all traffic from this source\n- Logging: Both start and end (for forensics)\n- Tags: incident-response, compromised, urgent\n\n⚠️ This rule should be placed at the TOP of the rulebase to take immediate effect."
    },

    # ==================== MASS EDIT ====================
    {
        "user": "Enable logging on all rules that don't have it in DG-Branch",
        "assistant_thought": "Use mass edit to enable logging on rules without it.",
        "tool_calls": [
            {
                "name": "mass_edit",
                "arguments": {
                    "device_group": "DG-Branch",
                    "filters": {
                        "has_logging": False
                    },
                    "actions": {
                        "enable_logging": True
                    },
                    "preview_only": True
                }
            }
        ],
        "assistant_response": "I'm preparing a mass edit to enable logging on all rules in DG-Branch that currently lack logging.\n\n**Preview Mode:** This will show affected rules without making changes. Review the preview, then run again with preview_only=false to apply.\n\nLogging is essential for:\n- Compliance requirements\n- Security monitoring\n- Troubleshooting"
    },
    {
        "user": "Add the 'legacy' tag to all rules created before 2023",
        "assistant_thought": "Mass edit to tag old rules for identification.",
        "tool_calls": [
            {
                "name": "mass_edit",
                "arguments": {
                    "device_group": "DG-Production",
                    "filters": {
                        "created_before": "2023-01-01"
                    },
                    "actions": {
                        "add_tag": "legacy"
                    },
                    "preview_only": True
                }
            }
        ],
        "assistant_response": "I'm preparing to tag all rules created before 2023 as 'legacy' in DG-Production.\n\nThis helps identify:\n- Rules that may need review/modernization\n- Outdated configurations\n- Candidates for cleanup\n\nPreview mode will show matching rules first."
    },

    # ==================== MULTI-STEP WORKFLOWS ====================
    {
        "user": "I need to allow a new application server at 10.20.1.50 to access the database on 172.16.10.100 port 3306. Can you check if this is already allowed, and if not, create the rule?",
        "assistant_thought": "This is a two-step workflow: first check existing access, then create rule if needed.",
        "tool_calls": [
            {
                "name": "traffic_flow_analysis",
                "arguments": {
                    "source_ip": "10.20.1.50",
                    "destination_ip": "172.16.10.100",
                    "port": 3306,
                    "protocol": "tcp"
                }
            }
        ],
        "assistant_response": "I'll help you with this two-step process:\n\n**Step 1:** Checking if traffic from 10.20.1.50 to 172.16.10.100:3306 (MySQL) is already allowed.\n\nIf the traffic is currently blocked, I'll proceed to create a new rule for you. The rule will include:\n- Source: Application server 10.20.1.50\n- Destination: Database server 172.16.10.100\n- Service: MySQL (3306/TCP)\n- Appropriate security profiles"
    },
    {
        "user": "Before our audit next week, I need a full compliance report and a list of all rules without logging",
        "assistant_thought": "Multiple analyses needed: compliance scan and rule search for no-logging rules.",
        "tool_calls": [
            {
                "name": "compliance_scan",
                "arguments": {
                    "framework": "SOC2",
                    "device_groups": ["DG-Production", "DG-Shared"],
                    "severity_filter": "all"
                }
            },
            {
                "name": "rule_search",
                "arguments": {
                    "query": "*",
                    "rule_type": "security",
                    "filters": {
                        "has_logging": False
                    }
                }
            }
        ],
        "assistant_response": "I'm preparing your audit documentation with two analyses:\n\n**1. SOC2 Compliance Scan:**\n- Scanning all production device groups\n- Full severity coverage\n- Will provide remediation guidance\n\n**2. Rules Without Logging:**\n- Finding all security rules lacking log-at-session-end\n- These are compliance gaps that should be addressed before the audit\n\nI recommend addressing critical compliance findings and enabling logging on all identified rules before the audit."
    },

    # ==================== TOPOLOGY & ADMINISTRATION ====================
    {
        "user": "Refresh the topology data from Panorama",
        "assistant_thought": "Trigger a new topology collection.",
        "tool_calls": [
            {
                "name": "topology_collect",
                "arguments": {
                    "panorama_id": "panorama-prod-1",
                    "full_collection": True
                }
            }
        ],
        "assistant_response": "I'm triggering a full topology collection from Panorama. This will:\n- Fetch all device groups and hierarchies\n- Update security policies\n- Refresh object definitions\n- Update zone and interface mappings\n\nFull collection typically takes 30-60 seconds for large deployments. You'll be notified when complete."
    },
    {
        "user": "List all device groups",
        "assistant_thought": "Get device group hierarchy.",
        "tool_calls": [
            {
                "name": "get_device_groups",
                "arguments": {
                    "include_hierarchy": True
                }
            }
        ],
        "assistant_response": "I'm retrieving the complete device group hierarchy from Panorama. This shows:\n- All device groups\n- Parent-child relationships\n- Inheritance structure (Shared → Region → Site)"
    },
    {
        "user": "Export all rules from DG-Production to Excel",
        "assistant_thought": "Export rules to Excel format.",
        "tool_calls": [
            {
                "name": "export_rules",
                "arguments": {
                    "device_group": "DG-Production",
                    "rulebase": "both",
                    "format": "excel"
                }
            }
        ],
        "assistant_response": "I'm exporting all security rules from DG-Production to Excel format. The export includes:\n- Pre-rulebase rules\n- Post-rulebase rules\n- All rule attributes (zones, addresses, applications, profiles)\n- Hit count data if available\n\nThe file will be ready for download shortly."
    }
]

# =============================================================================
# GENERATE TRAINING DATA
# =============================================================================

def format_tool_call_training_example(example: Dict) -> Dict:
    """Format a single example into ShareGPT/ChatML training format with function calling."""

    # Build the assistant message with tool calls
    tool_calls_json = json.dumps(example["tool_calls"], indent=2)

    # Format for training: include both the reasoning and tool call
    assistant_content = f"""I'll help you with that.

**Analysis:** {example.get('assistant_thought', '')}

**Executing Tool Call:**
```json
{tool_calls_json}
```

{example['assistant_response']}"""

    return {
        "conversations": [
            {
                "from": "human",
                "value": example["user"]
            },
            {
                "from": "gpt",
                "value": assistant_content
            }
        ]
    }


def format_tool_call_with_result(example: Dict, result: str) -> Dict:
    """Format example with simulated tool result and follow-up response."""

    tool_calls_json = json.dumps(example["tool_calls"], indent=2)

    # First turn: user request and tool call
    assistant_turn1 = f"""I'll check that for you.

**Executing:**
```json
{tool_calls_json}
```"""

    # Simulated tool result
    tool_result = f"[Tool Result]\n{result}"

    # Second turn: interpretation of results
    assistant_turn2 = example['assistant_response']

    return {
        "conversations": [
            {"from": "human", "value": example["user"]},
            {"from": "gpt", "value": assistant_turn1},
            {"from": "human", "value": tool_result},
            {"from": "gpt", "value": assistant_turn2}
        ]
    }


def generate_tool_definition_examples() -> List[Dict]:
    """Generate examples that teach the model about available tools."""
    examples = []

    # Example: listing available tools
    tools_summary = "\n".join([
        f"- **{name}**: {info['description']}"
        for name, info in FIREWEAVE_TOOLS.items()
    ])

    examples.append({
        "conversations": [
            {
                "from": "human",
                "value": "What FireWeave tools and actions can you perform?"
            },
            {
                "from": "gpt",
                "value": f"""I can interact with FireWeave to perform various network security operations. Here are my available tools:

{tools_summary}

**Traffic Analysis:**
- Check if traffic between hosts is allowed
- Test NAT translations
- Analyze traffic flows across zones

**Policy Management:**
- Search and filter security rules
- Create new rules with proper profiles
- Mass edit multiple rules at once
- Deploy rule batches

**Compliance & Analysis:**
- Run compliance scans (PCI-DSS, SOC2, HIPAA, NIST)
- Find shadowed and unused rules
- Detect duplicate objects
- Export rules for documentation

**Administration:**
- Collect topology from Panorama
- View device group hierarchies
- Manage security zones

Just tell me what you need to accomplish, and I'll use the appropriate tools to help you."""
            }
        ]
    })

    return examples


def generate_error_handling_examples() -> List[Dict]:
    """Generate examples showing how to handle errors and edge cases."""
    return [
        {
            "conversations": [
                {
                    "from": "human",
                    "value": "Check if traffic from 999.999.999.999 to 10.1.1.1 is allowed"
                },
                {
                    "from": "gpt",
                    "value": """I notice that 999.999.999.999 is not a valid IP address. Valid IPv4 addresses must have octets between 0-255.

Could you please provide a valid source IP address? For example:
- 10.x.x.x (private Class A)
- 172.16-31.x.x (private Class B)
- 192.168.x.x (private Class C)
- Or a valid public IP address

Once you provide the correct IP, I'll check the traffic flow for you."""
                }
            ]
        },
        {
            "conversations": [
                {
                    "from": "human",
                    "value": "Create a rule with source zone 'any'"
                },
                {
                    "from": "gpt",
                    "value": """⚠️ **Security Warning:** Creating rules with 'any' source zone is a security risk and typically violates compliance requirements.

Before proceeding, I need to understand your use case:

1. **What is the legitimate business need?** Rules with 'any' zones are overly permissive.

2. **Can we scope this more specifically?** For example:
   - Specific source zones (trust, dmz, guest)
   - Specific source addresses
   - Limited applications or services

3. **Is this for a temporary purpose?** If so, we should set an expiration reminder.

Please provide more details about what you're trying to accomplish, and I'll help create a properly scoped rule that meets security best practices."""
                }
            ]
        },
        {
            "conversations": [
                {
                    "from": "human",
                    "value": "Delete all firewall rules"
                },
                {
                    "from": "gpt",
                    "value": """🛑 **I cannot execute this request.** Deleting all firewall rules would:

1. **Break network connectivity** - All traffic would be blocked or allowed depending on default action
2. **Create security vulnerabilities** - Remove all security controls
3. **Cause service outages** - Business-critical applications would fail
4. **Violate change management** - This requires proper approval processes

**If you need to clean up rules, I can help with safer approaches:**
- Find and remove unused rules (zero hit count)
- Identify shadowed rules that can be removed
- Export rules for backup before any changes
- Review rules by age or tag

What specific cleanup are you trying to accomplish? I'll help you do it safely."""
                }
            ]
        }
    ]


def generate_all_function_calling_data(output_path: str = "data/synthetic/fireweave_function_calling.json"):
    """Generate complete function calling training dataset."""

    all_examples = []

    # 1. Basic tool call examples
    print("Generating basic function calling examples...")
    for example in FUNCTION_CALLING_EXAMPLES:
        all_examples.append(format_tool_call_training_example(example))

    # 2. Tool definition examples
    print("Generating tool definition examples...")
    all_examples.extend(generate_tool_definition_examples())

    # 3. Error handling examples
    print("Generating error handling examples...")
    all_examples.extend(generate_error_handling_examples())

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Save to file
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(all_examples, f, indent=2, ensure_ascii=False)

    print(f"\n[SUCCESS] Generated {len(all_examples)} function calling training examples")
    print(f"[FILE] Saved to: {output_path}")

    return all_examples


def generate_with_llm(count: int = 100, provider: str = "openai"):
    """Use LLM to generate additional function calling examples."""

    prompt = """Generate {count} realistic user requests for a Palo Alto/Panorama firewall management system called FireWeave.

For each request, provide:
1. A natural user request (as someone would type it)
2. The tool(s) that should be called
3. The parameters for each tool call
4. A helpful response explaining what's being done

Available tools:
- traffic_flow_analysis: Check if traffic is allowed between hosts
- nat_check: Test NAT policy matches
- rule_search: Search for security rules
- compliance_scan: Run compliance checks (PCI-DSS, SOC2, HIPAA, NIST, CIS)
- shadowed_rules_check: Find rules that never match
- unused_rules_check: Find rules with zero hits
- object_lookup: Search for address/service objects
- deduplication_scan: Find duplicate objects
- create_rule: Create a new security rule
- batch_deploy: Deploy multiple rules
- mass_edit: Modify multiple rules at once
- topology_collect: Refresh data from Panorama
- get_device_groups: List device groups
- export_rules: Export rules to Excel/CSV

Generate varied scenarios including:
- Simple single-tool requests
- Multi-step workflows
- Compliance and audit preparation
- Incident response scenarios
- Day-to-day administration tasks

Format as JSON array with objects containing: user, tool_calls (array), assistant_response"""

    # Implementation would call the LLM API here
    # Similar to generate_synthetic_data.py
    pass


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generate FireWeave function calling training data")
    parser.add_argument("--output", type=str, default="data/synthetic/fireweave_function_calling.json",
                       help="Output file path")
    parser.add_argument("--generate-more", action="store_true",
                       help="Use LLM to generate additional examples")
    parser.add_argument("--count", type=int, default=100,
                       help="Number of additional examples to generate with LLM")

    args = parser.parse_args()

    # Generate the static examples
    examples = generate_all_function_calling_data(args.output)

    print(f"\nFunction calling training data ready!")
    print(f"Total examples: {len(examples)}")
    print(f"\nTo include in training, add this file to your dataset merge.")
