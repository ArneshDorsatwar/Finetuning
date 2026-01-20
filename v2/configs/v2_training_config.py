"""
Network Security Expert v2 - Training Configuration

Focus: Conceptual/Theoretical Knowledge for FireWeave Orchestration
Target: 20,000+ examples with chain-of-thought reasoning

This version focuses on:
1. InfoSec policies and frameworks (WHY behind rules)
2. Network security theory and best practices
3. Multi-step reasoning for complex workflows
4. FireWeave orchestration capabilities
"""

# =============================================================================
# V2 TOPIC TAXONOMY - CONCEPTUAL/THEORETICAL FOCUS
# =============================================================================

V2_TOPICS = {
    # =========================================================================
    # TIER 0: FIREWEAVE PLATFORM ORCHESTRATION (4,000 examples)
    # =========================================================================
    "fireweave-orchestration": {
        "description": "Multi-step workflow orchestration using FireWeave capabilities",
        "target_count": 800,
        "priority": 0,
        "subtopics": [
            "Traffic analysis workflows",
            "Rule lifecycle management",
            "Change request automation",
            "Compliance scan orchestration",
            "Attack path remediation workflows",
            "Multi-cloud policy synchronization"
        ],
        "requires_chain_of_thought": True,
        "example_prompt": """When a user asks to check if traffic is allowed and create a rule if not,
        the model should reason: 1) First check traffic path, 2) Analyze current rules,
        3) Determine if new rule needed, 4) Generate rule with proper zones/services,
        5) Validate against compliance, 6) Submit for approval"""
    },

    "fireweave-policy-intelligence": {
        "description": "Understanding and optimizing firewall policies using FireWeave",
        "target_count": 800,
        "priority": 0,
        "subtopics": [
            "Shadowed rule detection and remediation",
            "Rule consolidation strategies",
            "Object deduplication logic",
            "Policy optimization recommendations",
            "Rule hit count analysis",
            "Unused object identification"
        ],
        "requires_chain_of_thought": True
    },

    "fireweave-attack-surface": {
        "description": "Attack path analysis and blast radius calculation",
        "target_count": 600,
        "priority": 0,
        "subtopics": [
            "Kill chain visualization concepts",
            "Blast radius calculation methodology",
            "Internet exposure risk assessment",
            "Toxic combination detection",
            "Lateral movement path analysis",
            "Asset criticality scoring"
        ],
        "requires_chain_of_thought": True
    },

    "fireweave-multi-cloud": {
        "description": "Cross-cloud policy management and visibility",
        "target_count": 600,
        "priority": 0,
        "subtopics": [
            "AWS VPC/Security Group concepts",
            "Azure NSG/ASG theory",
            "GCP firewall rule model",
            "Cross-cloud policy consistency",
            "Unified topology understanding",
            "Transit Gateway/VNet Peering concepts"
        ],
        "requires_chain_of_thought": True
    },

    "fireweave-servicenow-automation": {
        "description": "End-to-end ServiceNow workflow automation",
        "target_count": 600,
        "priority": 0,
        "subtopics": [
            "Change request lifecycle",
            "Auto rule generation from tickets",
            "Evidence collection automation",
            "Approval workflow integration",
            "Ticket closure automation",
            "SLA compliance tracking"
        ],
        "requires_chain_of_thought": True
    },

    "fireweave-function-calling-v2": {
        "description": "Structured function calls for FireWeave API",
        "target_count": 600,
        "priority": 0,
        "subtopics": [
            "Traffic flow check functions",
            "Rule creation functions",
            "Compliance scan triggers",
            "Topology query functions",
            "Attack path analysis triggers",
            "ServiceNow integration functions"
        ],
        "requires_chain_of_thought": True
    },

    # =========================================================================
    # TIER 1: COMPLIANCE FRAMEWORKS - THEORY & CONCEPTS (4,000 examples)
    # =========================================================================
    "pci-dss-concepts": {
        "description": "PCI-DSS compliance theory and firewall requirements",
        "target_count": 700,
        "priority": 1,
        "subtopics": [
            "Requirement 1: Firewall configuration standards",
            "Network segmentation principles",
            "Cardholder data environment (CDE) isolation",
            "Documentation requirements",
            "Testing and monitoring requirements",
            "Change management for PCI compliance"
        ],
        "requires_chain_of_thought": True
    },

    "soc2-concepts": {
        "description": "SOC2 Trust Service Criteria and security controls",
        "target_count": 600,
        "priority": 1,
        "subtopics": [
            "Security principle controls",
            "Availability principle",
            "Processing integrity",
            "Confidentiality controls",
            "Privacy requirements",
            "Common criteria mapping"
        ],
        "requires_chain_of_thought": True
    },

    "nist-800-53-concepts": {
        "description": "NIST 800-53 security controls framework",
        "target_count": 700,
        "priority": 1,
        "subtopics": [
            "Access Control (AC) family",
            "System and Communications Protection (SC)",
            "Audit and Accountability (AU)",
            "Configuration Management (CM)",
            "Incident Response (IR)",
            "Risk Assessment (RA)"
        ],
        "requires_chain_of_thought": True
    },

    "hipaa-security-concepts": {
        "description": "HIPAA Security Rule technical safeguards",
        "target_count": 500,
        "priority": 1,
        "subtopics": [
            "Technical safeguards requirements",
            "Access control standards",
            "Audit controls",
            "Transmission security",
            "ePHI protection concepts",
            "Minimum necessary principle"
        ],
        "requires_chain_of_thought": True
    },

    "iso-27001-concepts": {
        "description": "ISO 27001 ISMS and Annex A controls",
        "target_count": 500,
        "priority": 1,
        "subtopics": [
            "Information security policies",
            "Asset management",
            "Access control (A.9)",
            "Cryptography (A.10)",
            "Operations security (A.12)",
            "Communications security (A.13)"
        ],
        "requires_chain_of_thought": True
    },

    "cis-controls-concepts": {
        "description": "CIS Critical Security Controls framework",
        "target_count": 500,
        "priority": 1,
        "subtopics": [
            "Implementation Groups (IG1, IG2, IG3)",
            "Control 1: Inventory of assets",
            "Control 12: Network infrastructure management",
            "Control 13: Network monitoring and defense",
            "Safeguard prioritization",
            "Metrics and measurement"
        ],
        "requires_chain_of_thought": True
    },

    "compliance-mapping": {
        "description": "Cross-framework compliance mapping and rationalization",
        "target_count": 500,
        "priority": 1,
        "subtopics": [
            "Control mapping across frameworks",
            "Unified compliance approach",
            "Evidence reuse strategies",
            "Gap analysis methodology",
            "Continuous compliance monitoring",
            "Audit preparation strategies"
        ],
        "requires_chain_of_thought": True
    },

    # =========================================================================
    # TIER 2: NETWORK SECURITY THEORY (4,000 examples)
    # =========================================================================
    "defense-in-depth": {
        "description": "Layered security architecture principles",
        "target_count": 600,
        "priority": 2,
        "subtopics": [
            "Defense in depth philosophy",
            "Security layer design",
            "Compensating controls",
            "Fail-safe vs fail-secure",
            "Security zone architecture",
            "DMZ design principles"
        ],
        "requires_chain_of_thought": True
    },

    "zero-trust-architecture": {
        "description": "Zero Trust security model and implementation",
        "target_count": 700,
        "priority": 2,
        "subtopics": [
            "Never trust, always verify",
            "Micro-segmentation concepts",
            "Identity-based access",
            "Least privilege principle",
            "Continuous verification",
            "NIST SP 800-207 concepts"
        ],
        "requires_chain_of_thought": True
    },

    "network-segmentation-theory": {
        "description": "Network segmentation strategies and design",
        "target_count": 700,
        "priority": 2,
        "subtopics": [
            "Segmentation rationale and benefits",
            "VLAN vs microsegmentation",
            "East-west traffic control",
            "Trust zone design",
            "Application-centric segmentation",
            "Workload isolation strategies"
        ],
        "requires_chain_of_thought": True
    },

    "firewall-architecture-concepts": {
        "description": "Firewall design patterns and best practices",
        "target_count": 600,
        "priority": 2,
        "subtopics": [
            "Stateful vs stateless inspection",
            "Application-layer firewalls",
            "Next-generation firewall concepts",
            "Rule ordering principles",
            "Implicit deny philosophy",
            "High availability design"
        ],
        "requires_chain_of_thought": True
    },

    "traffic-flow-analysis-theory": {
        "description": "Understanding network traffic patterns and analysis",
        "target_count": 500,
        "priority": 2,
        "subtopics": [
            "Traffic flow fundamentals",
            "NAT traversal concepts",
            "Routing decision factors",
            "Asymmetric routing issues",
            "Traffic inspection points",
            "Flow logging and analysis"
        ],
        "requires_chain_of_thought": True
    },

    "encryption-transit-concepts": {
        "description": "Data protection in transit principles",
        "target_count": 500,
        "priority": 2,
        "subtopics": [
            "TLS/SSL inspection considerations",
            "VPN tunnel concepts",
            "IPsec vs SSL VPN",
            "Certificate management principles",
            "Perfect forward secrecy",
            "Encryption policy design"
        ],
        "requires_chain_of_thought": True
    },

    "identity-access-concepts": {
        "description": "Identity and access management for network security",
        "target_count": 400,
        "priority": 2,
        "subtopics": [
            "User-ID integration concepts",
            "Role-based access control (RBAC)",
            "Attribute-based access control (ABAC)",
            "Group-based policies",
            "Dynamic user groups",
            "Authentication vs authorization"
        ],
        "requires_chain_of_thought": True
    },

    # =========================================================================
    # TIER 3: INFOSEC POLICY CONCEPTS (3,000 examples)
    # =========================================================================
    "security-policy-design": {
        "description": "Designing effective security policies",
        "target_count": 600,
        "priority": 3,
        "subtopics": [
            "Policy hierarchy (enterprise → technical)",
            "Policy vs standard vs procedure",
            "Policy lifecycle management",
            "Exception handling processes",
            "Policy enforcement mechanisms",
            "Policy review and update cycles"
        ],
        "requires_chain_of_thought": True
    },

    "change-management-theory": {
        "description": "Change management for security infrastructure",
        "target_count": 600,
        "priority": 3,
        "subtopics": [
            "Change advisory board concepts",
            "Risk assessment for changes",
            "Rollback planning",
            "Change windows and scheduling",
            "Emergency change procedures",
            "Post-implementation review"
        ],
        "requires_chain_of_thought": True
    },

    "risk-management-concepts": {
        "description": "Risk assessment and management frameworks",
        "target_count": 600,
        "priority": 3,
        "subtopics": [
            "Risk identification methods",
            "Threat modeling approaches",
            "Vulnerability assessment concepts",
            "Risk scoring and prioritization",
            "Risk treatment options",
            "Residual risk acceptance"
        ],
        "requires_chain_of_thought": True
    },

    "least-privilege-concepts": {
        "description": "Principle of least privilege implementation",
        "target_count": 400,
        "priority": 3,
        "subtopics": [
            "Least privilege philosophy",
            "Need-to-know vs need-to-access",
            "Privilege creep prevention",
            "Access recertification",
            "Just-in-time access",
            "Privileged access management"
        ],
        "requires_chain_of_thought": True
    },

    "separation-of-duties": {
        "description": "Separation of duties and dual control concepts",
        "target_count": 400,
        "priority": 3,
        "subtopics": [
            "Segregation of duties rationale",
            "Maker-checker workflows",
            "Approval hierarchies",
            "Conflict of interest prevention",
            "Audit trail requirements",
            "Role design for SoD"
        ],
        "requires_chain_of_thought": True
    },

    "documentation-standards": {
        "description": "Security documentation best practices",
        "target_count": 400,
        "priority": 3,
        "subtopics": [
            "Network diagram standards",
            "Rule documentation requirements",
            "Change history tracking",
            "Configuration baselines",
            "Audit evidence preparation",
            "Knowledge base management"
        ],
        "requires_chain_of_thought": True
    },

    # =========================================================================
    # TIER 4: THREAT & INCIDENT CONCEPTS (3,000 examples)
    # =========================================================================
    "threat-landscape-concepts": {
        "description": "Understanding modern threat actors and techniques",
        "target_count": 500,
        "priority": 4,
        "subtopics": [
            "Threat actor categorization",
            "MITRE ATT&CK framework concepts",
            "Common attack vectors",
            "Supply chain attack concepts",
            "Ransomware attack patterns",
            "APT characteristics"
        ],
        "requires_chain_of_thought": True
    },

    "incident-response-theory": {
        "description": "Incident response frameworks and methodology",
        "target_count": 600,
        "priority": 4,
        "subtopics": [
            "NIST incident response lifecycle",
            "Preparation phase concepts",
            "Detection and analysis",
            "Containment strategies",
            "Eradication and recovery",
            "Post-incident activities"
        ],
        "requires_chain_of_thought": True
    },

    "security-monitoring-concepts": {
        "description": "Security monitoring and detection principles",
        "target_count": 500,
        "priority": 4,
        "subtopics": [
            "Defense in depth for detection",
            "Log correlation concepts",
            "Baseline establishment",
            "Anomaly detection principles",
            "Alert prioritization",
            "False positive management"
        ],
        "requires_chain_of_thought": True
    },

    "vulnerability-management-theory": {
        "description": "Vulnerability management program concepts",
        "target_count": 500,
        "priority": 4,
        "subtopics": [
            "Vulnerability lifecycle",
            "CVSS scoring understanding",
            "Risk-based prioritization",
            "Patch management strategy",
            "Compensating controls",
            "Vulnerability disclosure"
        ],
        "requires_chain_of_thought": True
    },

    "forensics-concepts": {
        "description": "Digital forensics and evidence handling",
        "target_count": 400,
        "priority": 4,
        "subtopics": [
            "Chain of custody",
            "Evidence preservation",
            "Network forensics concepts",
            "Log integrity",
            "Timeline analysis",
            "Legal considerations"
        ],
        "requires_chain_of_thought": True
    },

    "business-continuity-concepts": {
        "description": "Business continuity and disaster recovery theory",
        "target_count": 500,
        "priority": 4,
        "subtopics": [
            "RTO and RPO concepts",
            "BIA methodology",
            "Recovery strategies",
            "Failover vs failback",
            "Testing and validation",
            "Communication plans"
        ],
        "requires_chain_of_thought": True
    },

    # =========================================================================
    # TIER 5: CLOUD SECURITY CONCEPTS (2,000 examples)
    # =========================================================================
    "shared-responsibility-model": {
        "description": "Cloud shared responsibility concepts",
        "target_count": 400,
        "priority": 5,
        "subtopics": [
            "IaaS vs PaaS vs SaaS responsibilities",
            "AWS shared responsibility",
            "Azure shared responsibility",
            "GCP shared responsibility",
            "Customer vs provider controls",
            "Compliance implications"
        ],
        "requires_chain_of_thought": True
    },

    "cloud-network-security-concepts": {
        "description": "Cloud-native network security principles",
        "target_count": 500,
        "priority": 5,
        "subtopics": [
            "Virtual network isolation",
            "Security groups vs NACLs",
            "Private endpoints concepts",
            "Service endpoints",
            "Cloud firewall positioning",
            "Egress filtering strategies"
        ],
        "requires_chain_of_thought": True
    },

    "cloud-identity-concepts": {
        "description": "Cloud IAM and identity federation",
        "target_count": 400,
        "priority": 5,
        "subtopics": [
            "IAM policy structure",
            "Cross-account access concepts",
            "Service account security",
            "Federation and SSO",
            "Conditional access policies",
            "Privilege escalation risks"
        ],
        "requires_chain_of_thought": True
    },

    "multi-cloud-strategy-concepts": {
        "description": "Multi-cloud security strategy and governance",
        "target_count": 400,
        "priority": 5,
        "subtopics": [
            "Multi-cloud rationale",
            "Consistent policy enforcement",
            "Cross-cloud visibility",
            "Vendor lock-in considerations",
            "Unified governance approach",
            "Cloud security posture management"
        ],
        "requires_chain_of_thought": True
    },

    "cloud-compliance-concepts": {
        "description": "Cloud compliance and audit considerations",
        "target_count": 300,
        "priority": 5,
        "subtopics": [
            "Cloud audit artifacts",
            "Compliance inheritance",
            "Data residency requirements",
            "Cloud provider certifications",
            "Continuous compliance monitoring",
            "Evidence collection automation"
        ],
        "requires_chain_of_thought": True
    }
}

# =============================================================================
# CHAIN-OF-THOUGHT REASONING TEMPLATES
# =============================================================================

REASONING_TEMPLATES = {
    "traffic_analysis": """
    Let me analyze this step by step:
    1. **Understand the request**: {request_summary}
    2. **Identify source and destination**: Source: {source}, Destination: {destination}, Service: {service}
    3. **Check traffic path**: I'll query FireWeave to trace the path and check rules
    4. **Analyze results**: {analysis}
    5. **Provide recommendation**: {recommendation}
    """,

    "compliance_assessment": """
    Let me evaluate this against compliance requirements:
    1. **Identify applicable framework**: {framework}
    2. **Relevant controls**: {controls}
    3. **Current state assessment**: {current_state}
    4. **Gap analysis**: {gaps}
    5. **Remediation recommendations**: {remediation}
    """,

    "attack_path_analysis": """
    Let me analyze the attack surface:
    1. **Identify entry points**: {entry_points}
    2. **Map potential paths**: {paths}
    3. **Calculate blast radius**: {blast_radius}
    4. **Assess criticality**: {criticality}
    5. **Prioritized remediation**: {remediation}
    """,

    "rule_optimization": """
    Let me analyze these rules for optimization:
    1. **Identify rule relationships**: {relationships}
    2. **Check for shadowing**: {shadowing}
    3. **Find consolidation opportunities**: {consolidation}
    4. **Validate no breakage**: {validation}
    5. **Recommended changes**: {changes}
    """,

    "change_request_workflow": """
    Let me process this change request:
    1. **Parse the request**: {request_details}
    2. **Validate requirements**: {validation}
    3. **Check compliance impact**: {compliance}
    4. **Generate rule configuration**: {rule_config}
    5. **Create deployment plan**: {deployment}
    6. **Prepare evidence**: {evidence}
    """
}

# =============================================================================
# FIREWEAVE FUNCTION SCHEMAS FOR ORCHESTRATION
# =============================================================================

FIREWEAVE_FUNCTIONS = {
    "check_traffic_flow": {
        "description": "Check if traffic is allowed between source and destination",
        "parameters": {
            "source_ip": "string - Source IP or CIDR",
            "destination_ip": "string - Destination IP or CIDR",
            "port": "integer - Destination port",
            "protocol": "string - tcp/udp/icmp",
            "device_group": "string - Optional specific device group to check"
        },
        "returns": "Traffic analysis result with matching rules"
    },

    "analyze_attack_path": {
        "description": "Analyze attack paths from source to target",
        "parameters": {
            "source": "string - Starting point (IP, zone, or 'internet')",
            "target": "string - Target asset or zone",
            "include_cloud": "boolean - Include cloud infrastructure",
            "max_hops": "integer - Maximum path length"
        },
        "returns": "Attack paths with risk scores and remediation"
    },

    "run_compliance_scan": {
        "description": "Run compliance scan against specified framework",
        "parameters": {
            "framework": "string - pci-dss, soc2, nist, hipaa, iso27001, cis",
            "scope": "string - device groups or 'all'",
            "include_evidence": "boolean - Generate evidence artifacts"
        },
        "returns": "Compliance findings with remediation guidance"
    },

    "find_shadowed_rules": {
        "description": "Find rules that are shadowed by more specific rules",
        "parameters": {
            "device_group": "string - Device group to analyze",
            "include_recommendations": "boolean - Include cleanup recommendations"
        },
        "returns": "List of shadowed rules with impact analysis"
    },

    "optimize_rule_base": {
        "description": "Analyze rule base for optimization opportunities",
        "parameters": {
            "device_group": "string - Device group to analyze",
            "analysis_type": "string - shadowed, unused, mergeable, or all"
        },
        "returns": "Optimization opportunities with safe changes"
    },

    "create_firewall_rule": {
        "description": "Generate firewall rule configuration",
        "parameters": {
            "name": "string - Rule name",
            "source_zone": "string - Source security zone",
            "destination_zone": "string - Destination security zone",
            "source_address": "string - Source IP/object",
            "destination_address": "string - Destination IP/object",
            "service": "string - Service/port",
            "action": "string - allow/deny",
            "logging": "boolean - Enable logging",
            "device_group": "string - Target device group"
        },
        "returns": "Rule configuration ready for deployment"
    },

    "submit_change_request": {
        "description": "Create ServiceNow change request for firewall change",
        "parameters": {
            "description": "string - Change description",
            "justification": "string - Business justification",
            "rules": "array - Rules to be created/modified",
            "schedule": "string - Deployment window",
            "rollback_plan": "string - Rollback procedure"
        },
        "returns": "ServiceNow ticket number and status"
    },

    "get_topology": {
        "description": "Query network topology across all platforms",
        "parameters": {
            "platform": "string - aws, azure, gcp, panorama, or all",
            "region": "string - Optional region filter",
            "include_connectivity": "boolean - Include peering/transit"
        },
        "returns": "Topology data with connectivity map"
    },

    "calculate_blast_radius": {
        "description": "Calculate blast radius if an asset is compromised",
        "parameters": {
            "asset": "string - Asset identifier (IP, hostname, or zone)",
            "include_lateral": "boolean - Include lateral movement paths"
        },
        "returns": "Reachable assets and risk assessment"
    },

    "check_internet_exposure": {
        "description": "Find assets exposed to the internet",
        "parameters": {
            "scope": "string - device groups or 'all'",
            "include_risk_score": "boolean - Calculate risk scores"
        },
        "returns": "Exposed assets with risk assessment"
    }
}

# =============================================================================
# TRAINING DATA GENERATION SETTINGS
# =============================================================================

GENERATION_SETTINGS = {
    "target_total_examples": 20000,
    "chain_of_thought_ratio": 0.7,  # 70% of examples include reasoning
    "function_calling_ratio": 0.3,  # 30% include function calls
    "multi_turn_ratio": 0.4,  # 40% are multi-turn conversations
    "max_turns_per_conversation": 5,
    "min_answer_length": 500,  # Longer answers for conceptual content
    "include_code_blocks": True,
    "include_examples": True,
    "format": "sharegpt"
}

# =============================================================================
# QUALITY SCORING CRITERIA FOR V2
# =============================================================================

V2_QUALITY_CRITERIA = {
    "conceptual_depth": {
        "weight": 0.25,
        "indicators": [
            "explains WHY not just WHAT",
            "references security principles",
            "discusses trade-offs",
            "mentions risk considerations"
        ]
    },
    "reasoning_quality": {
        "weight": 0.25,
        "indicators": [
            "step-by-step analysis",
            "logical flow",
            "considers alternatives",
            "validates assumptions"
        ]
    },
    "practical_applicability": {
        "weight": 0.20,
        "indicators": [
            "actionable recommendations",
            "FireWeave-specific guidance",
            "clear next steps",
            "considers implementation"
        ]
    },
    "compliance_awareness": {
        "weight": 0.15,
        "indicators": [
            "mentions relevant frameworks",
            "compliance implications",
            "audit considerations",
            "evidence requirements"
        ]
    },
    "completeness": {
        "weight": 0.15,
        "indicators": [
            "addresses all aspects",
            "handles edge cases",
            "provides verification steps",
            "includes caveats"
        ]
    }
}

# Calculate total target examples
def get_total_target():
    return sum(topic["target_count"] for topic in V2_TOPICS.values())

if __name__ == "__main__":
    print(f"V2 Training Configuration")
    print(f"=" * 50)
    print(f"Total topics: {len(V2_TOPICS)}")
    print(f"Target examples: {get_total_target():,}")
    print(f"\nTopics by tier:")

    tiers = {}
    for name, config in V2_TOPICS.items():
        tier = config["priority"]
        if tier not in tiers:
            tiers[tier] = []
        tiers[tier].append((name, config["target_count"]))

    for tier in sorted(tiers.keys()):
        total = sum(count for _, count in tiers[tier])
        print(f"\n  Tier {tier}: {total:,} examples")
        for name, count in tiers[tier]:
            print(f"    - {name}: {count}")
