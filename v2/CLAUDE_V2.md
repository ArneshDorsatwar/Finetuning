# Network Security Expert v2 - Training System

**Version**: 2.0.0
**Last Updated**: 2026-01-20
**Purpose**: Fine-tune Llama 3.1 8B for conceptual/theoretical network security knowledge with FireWeave orchestration

---

## Overview

Version 2 of the Network Security Expert focuses on **conceptual understanding** and **theoretical knowledge** rather than step-by-step commands. The model is designed to:

1. **Understand WHY** - Explain the reasoning behind security decisions
2. **Think step-by-step** - Use chain-of-thought reasoning for complex problems
3. **Orchestrate FireWeave** - Trigger platform actions via function calling
4. **Ensure compliance** - Reference relevant frameworks (PCI-DSS, SOC2, NIST, HIPAA, ISO 27001)
5. **Multi-turn conversations** - Guide users through complex workflows

---

## What is FireWeave?

**FireWeave** is an AI-Powered Platform for Enterprise Firewall Automation that unifies:
- **Palo Alto Panorama** with 500+ device groups
- **Multi-cloud**: AWS, Azure, and GCP
- **ServiceNow** integration for change management

**Key Capabilities:**
- Deploy changes in **35 seconds** (not hours)
- **96% fewer errors** than manual processes
- **10x faster** than competitors
- **AI Assistant** for natural language policy queries
- **Attack Path Analysis** with blast radius calculation
- **Compliance scanning** (PCI-DSS, SOC2, NIST, HIPAA)

---

## v2 vs v1 Differences

| Aspect | v1 | v2 |
|--------|----|----|
| **Focus** | Commands & steps | Concepts & theory |
| **Reasoning** | Direct answers | Chain-of-thought |
| **Training data** | ~10,000 examples | ~20,000 examples |
| **Context length** | 2048 tokens | 4096 tokens |
| **LoRA rank** | 16 | 32 |
| **Function calling** | Basic | Comprehensive |
| **Multi-turn** | Limited | 40% of data |
| **Compliance depth** | Surface level | Framework-specific |

---

## Project Structure

```
v2/
├── CLAUDE_V2.md                        # THIS FILE
├── configs/
│   └── v2_training_config.py           # Topic taxonomy & settings
├── scripts/
│   └── generate_v2_data.py             # Data generation script
├── data/
│   ├── synthetic/                      # Generated training data
│   └── processed/
│       └── all_training_data_v2.json   # Combined dataset
├── notebooks/
│   └── train_v2_network_security.ipynb # Training notebook
└── models/
    ├── Modelfile                       # Ollama configuration
    └── gguf/                           # GGUF files (after training)
```

---

## Topic Taxonomy (~20,000 examples)

### Tier 0: FireWeave Platform Orchestration (4,000 examples)

| Topic | Examples | Description |
|-------|----------|-------------|
| fireweave-orchestration | 800 | Multi-step workflow automation |
| fireweave-policy-intelligence | 800 | Rule optimization & analysis |
| fireweave-attack-surface | 600 | Attack paths & blast radius |
| fireweave-multi-cloud | 600 | Cross-cloud visibility |
| fireweave-servicenow-automation | 600 | Ticket-to-deploy workflows |
| fireweave-function-calling-v2 | 600 | Structured API calls |

### Tier 1: Compliance Frameworks (4,000 examples)

| Topic | Examples | Description |
|-------|----------|-------------|
| pci-dss-concepts | 700 | Payment card security requirements |
| soc2-concepts | 600 | Trust Service Criteria |
| nist-800-53-concepts | 700 | Federal security controls |
| hipaa-security-concepts | 500 | Healthcare data protection |
| iso-27001-concepts | 500 | ISMS and Annex A controls |
| cis-controls-concepts | 500 | Critical Security Controls |
| compliance-mapping | 500 | Cross-framework rationalization |

### Tier 2: Network Security Theory (4,000 examples)

| Topic | Examples | Description |
|-------|----------|-------------|
| defense-in-depth | 600 | Layered security architecture |
| zero-trust-architecture | 700 | Never trust, always verify |
| network-segmentation-theory | 700 | Micro-segmentation concepts |
| firewall-architecture-concepts | 600 | Rule design principles |
| traffic-flow-analysis-theory | 500 | Traffic path understanding |
| encryption-transit-concepts | 500 | Data protection in transit |
| identity-access-concepts | 400 | User-ID and RBAC/ABAC |

### Tier 3: InfoSec Policy Concepts (3,000 examples)

| Topic | Examples | Description |
|-------|----------|-------------|
| security-policy-design | 600 | Policy hierarchy & lifecycle |
| change-management-theory | 600 | CAB & risk assessment |
| risk-management-concepts | 600 | Threat modeling & scoring |
| least-privilege-concepts | 400 | Need-to-know principles |
| separation-of-duties | 400 | Maker-checker workflows |
| documentation-standards | 400 | Audit evidence preparation |

### Tier 4: Threat & Incident Concepts (3,000 examples)

| Topic | Examples | Description |
|-------|----------|-------------|
| threat-landscape-concepts | 500 | MITRE ATT&CK & actors |
| incident-response-theory | 600 | NIST IR lifecycle |
| security-monitoring-concepts | 500 | Detection principles |
| vulnerability-management-theory | 500 | CVSS & prioritization |
| forensics-concepts | 400 | Evidence & chain of custody |
| business-continuity-concepts | 500 | RTO/RPO & BIA |

### Tier 5: Cloud Security Concepts (2,000 examples)

| Topic | Examples | Description |
|-------|----------|-------------|
| shared-responsibility-model | 400 | IaaS/PaaS/SaaS split |
| cloud-network-security-concepts | 500 | VPC & security groups |
| cloud-identity-concepts | 400 | IAM & federation |
| multi-cloud-strategy-concepts | 400 | Governance approach |
| cloud-compliance-concepts | 300 | Audit artifacts |

---

## FireWeave Functions for Orchestration

The v2 model is trained to generate structured function calls:

```python
FIREWEAVE_FUNCTIONS = {
    "check_traffic_flow": {
        "description": "Check if traffic is allowed between source and destination",
        "parameters": {
            "source_ip": "string",
            "destination_ip": "string",
            "port": "integer",
            "protocol": "string",
            "device_group": "string (optional)"
        }
    },

    "analyze_attack_path": {
        "description": "Analyze attack paths from source to target",
        "parameters": {
            "source": "string",
            "target": "string",
            "include_cloud": "boolean",
            "max_hops": "integer"
        }
    },

    "run_compliance_scan": {
        "description": "Run compliance scan against specified framework",
        "parameters": {
            "framework": "pci-dss | soc2 | nist | hipaa | iso27001 | cis",
            "scope": "string",
            "include_evidence": "boolean"
        }
    },

    "find_shadowed_rules": {
        "description": "Find rules that are shadowed by more specific rules",
        "parameters": {
            "device_group": "string",
            "include_recommendations": "boolean"
        }
    },

    "optimize_rule_base": {
        "description": "Analyze rule base for optimization opportunities",
        "parameters": {
            "device_group": "string",
            "analysis_type": "shadowed | unused | mergeable | all"
        }
    },

    "create_firewall_rule": {
        "description": "Generate firewall rule configuration",
        "parameters": {
            "name": "string",
            "source_zone": "string",
            "destination_zone": "string",
            "source_address": "string",
            "destination_address": "string",
            "service": "string",
            "action": "allow | deny",
            "logging": "boolean",
            "device_group": "string"
        }
    },

    "submit_change_request": {
        "description": "Create ServiceNow change request",
        "parameters": {
            "description": "string",
            "justification": "string",
            "rules": "array",
            "schedule": "string",
            "rollback_plan": "string"
        }
    },

    "get_topology": {
        "description": "Query network topology across all platforms",
        "parameters": {
            "platform": "aws | azure | gcp | panorama | all",
            "region": "string (optional)",
            "include_connectivity": "boolean"
        }
    },

    "calculate_blast_radius": {
        "description": "Calculate blast radius if asset is compromised",
        "parameters": {
            "asset": "string",
            "include_lateral": "boolean"
        }
    },

    "check_internet_exposure": {
        "description": "Find assets exposed to the internet",
        "parameters": {
            "scope": "string",
            "include_risk_score": "boolean"
        }
    }
}
```

---

## Chain-of-Thought Reasoning

v2 training data includes explicit reasoning steps:

```markdown
**Example Response Structure:**

Let me analyze this step by step:

**Understanding the Request**: [What the user needs]

**Security Considerations**: [Relevant security principles]
- Defense in depth implications
- Least privilege requirements
- Risk assessment

**Compliance Context**: [Applicable framework requirements]
- PCI-DSS Requirement X.X
- NIST 800-53 Control SC-X

**Analysis**: [Reasoning through options]
- Option A: Pros/cons
- Option B: Pros/cons
- Trade-offs to consider

**FireWeave Action**: [Function call if needed]
```json
{
  "function": "check_traffic_flow",
  "parameters": { ... }
}
```

**Recommendation**: [Specific guidance with justification]
```

---

## Data Generation

### Generate All Topics

```bash
cd v2
python scripts/generate_v2_data.py --provider openai --output-dir data/synthetic
```

### Generate Single Topic

```bash
python scripts/generate_v2_data.py --provider openai --topic pci-dss-concepts --count 100
```

### List Available Topics

```bash
python scripts/generate_v2_data.py --list-topics
```

### Generation Settings

```python
GENERATION_SETTINGS = {
    "target_total_examples": 20000,
    "chain_of_thought_ratio": 0.7,   # 70% include reasoning
    "function_calling_ratio": 0.3,   # 30% include function calls
    "multi_turn_ratio": 0.4,         # 40% multi-turn conversations
    "max_turns_per_conversation": 5,
    "min_answer_length": 500,
    "format": "sharegpt"
}
```

---

## Training Configuration

### v2 Hyperparameters

```python
# Model
max_seq_length = 4096   # Increased for reasoning chains
load_in_4bit = True

# LoRA (increased for better conceptual understanding)
r = 32
lora_alpha = 32
lora_dropout = 0
use_rslora = True  # Rank-stabilized LoRA

# Training
num_train_epochs = 3
per_device_train_batch_size = 1
gradient_accumulation_steps = 8  # Effective batch = 8
learning_rate = 1e-4  # Lower for stability
weight_decay = 0.01
warmup_ratio = 0.05
lr_scheduler_type = "cosine"
```

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU VRAM | 16GB | 24GB+ |
| System RAM | 32GB | 64GB |
| Storage | 100GB | 200GB |
| Training Time | 4-6 hours | 2-3 hours |

---

## Training Pipeline

### 1. Generate Training Data

```bash
# Generate all topics (may take several hours due to API rate limits)
python scripts/generate_v2_data.py --provider openai --batch-size 10 --delay 5

# Combine and validate
python scripts/combine_v2_data.py
```

### 2. Upload to Google Colab

1. Upload `v2/notebooks/train_v2_network_security.ipynb`
2. Upload `v2/data/processed/all_training_data_v2.json`
3. Run all cells

### 3. Export to GGUF

```python
# In Colab after training
model.save_pretrained_gguf(
    "/content/network-security-expert-v2-gguf",
    tokenizer,
    quantization_method=["q4_k_m", "q5_k_m", "q8_0"]
)
```

### 4. Download and Deploy

```bash
# Download GGUF from Colab/Drive
# Place in v2/models/gguf/

# Create Ollama model
cd v2/models
ollama create network-security-expert-v2 -f Modelfile

# Test
ollama run network-security-expert-v2
```

---

## v2 System Prompt

```
You are a Network Security Expert AI integrated with FireWeave - an enterprise firewall automation platform.

**Your Capabilities:**
- Deep understanding of network security CONCEPTS and THEORY
- Expertise in compliance frameworks (PCI-DSS, SOC2, NIST, HIPAA, ISO 27001)
- Multi-cloud security (AWS, Azure, GCP) and Palo Alto Panorama
- Attack path analysis and blast radius calculation
- ServiceNow integration for change management

**Your Approach:**
1. REASON step-by-step through complex problems
2. Explain the WHY behind security decisions
3. Reference relevant compliance requirements
4. Use FireWeave functions when action is needed
5. Consider security trade-offs and risks

**FireWeave Functions Available:**
- check_traffic_flow: Verify if traffic is allowed
- analyze_attack_path: Find attack paths and blast radius
- run_compliance_scan: Check against compliance frameworks
- find_shadowed_rules: Identify policy optimization opportunities
- create_firewall_rule: Generate rule configurations
- submit_change_request: Create ServiceNow tickets

Always prioritize security, explain your reasoning, and provide actionable guidance.
```

---

## Example Conversations

### Chain-of-Thought Reasoning

**User**: We need to allow our web servers to access a new payment API. Walk me through the security considerations.

**Assistant**:
```
Let me analyze this step by step:

**Understanding the Request**: You need to allow outbound traffic from web servers to a payment API, which likely processes sensitive cardholder data.

**Security Considerations**:

1. **PCI-DSS Implications**: Since this involves payment data, PCI-DSS Requirement 1 applies:
   - Requirement 1.2: Build firewall configurations that restrict connections between untrusted networks and CDE
   - Requirement 1.3: Prohibit direct public access between internet and CDE

2. **Principle of Least Privilege**:
   - Only specific web servers should access the API
   - Only required ports (likely 443/HTTPS)
   - Consider time-based restrictions if the API isn't needed 24/7

3. **Defense in Depth**:
   - TLS/SSL inspection to validate certificate
   - Application-layer filtering if possible
   - Logging for all traffic to payment API

**Analysis**:

The web tier is likely in a DMZ or semi-trusted zone. The payment API is external. We need to:
- Allow outbound HTTPS (443) only
- Restrict source to specific web server IPs or groups
- Enable logging for compliance evidence
- Consider egress filtering to specific API endpoint

**FireWeave Action**:
```json
{
  "function": "check_traffic_flow",
  "parameters": {
    "source_ip": "10.1.1.0/24",
    "destination_ip": "api.payment-provider.com",
    "port": 443,
    "protocol": "tcp"
  }
}
```

**Recommendation**:

1. First verify current traffic state with FireWeave
2. Create a specific allow rule with:
   - Source: Web server address group
   - Destination: Payment API FQDN object
   - Service: HTTPS only
   - Logging: Enabled (required for PCI-DSS)
3. Submit via ServiceNow for change control documentation
4. Test connectivity and verify in FireWeave

Would you like me to generate the rule configuration?
```

### Function Calling

**User**: Check if traffic from 10.1.1.100 to our database 192.168.50.10 on port 5432 is allowed.

**Assistant**:
```
I'll check this traffic path using FireWeave.

```json
{
  "function": "check_traffic_flow",
  "parameters": {
    "source_ip": "10.1.1.100",
    "destination_ip": "192.168.50.10",
    "port": 5432,
    "protocol": "tcp"
  }
}
```

**Analysis**: This appears to be traffic from what might be an application server (10.1.1.x) to a PostgreSQL database (port 5432).

**Security Considerations**:
- Database access should be strictly controlled (CIS Control 3.3)
- Only application servers that need database access should have it
- Consider if this follows least privilege principles

**Compliance Context**:
- PCI-DSS 1.3.4: Requires firewall rules to permit only established connections
- NIST SC-7: Boundary protection controls

If traffic is currently blocked and needs to be allowed, I recommend:
1. Verify the source is a legitimate application server
2. Ensure the rule is as specific as possible
3. Enable logging for audit trails
4. Document the business justification

Would you like me to analyze the blast radius if this server were compromised?
```

---

## Quality Criteria

v2 training data is evaluated on:

| Criterion | Weight | Description |
|-----------|--------|-------------|
| Conceptual Depth | 25% | Explains WHY, not just WHAT |
| Reasoning Quality | 25% | Logical step-by-step analysis |
| Practical Applicability | 20% | Actionable FireWeave guidance |
| Compliance Awareness | 15% | References relevant frameworks |
| Completeness | 15% | Addresses all aspects |

---

## Troubleshooting

### Data Generation

**Rate Limits**: Use `--delay 10` for 10-second delays between batches

**JSON Parse Errors**: The script handles malformed responses; check logs for warnings

### Training

**OOM Errors**: Reduce `per_device_train_batch_size` to 1, increase `gradient_accumulation_steps`

**Context Length**: If getting truncation warnings, review training data for overly long examples

### Inference

**Incomplete Reasoning**: Increase `num_ctx` in Modelfile to 4096+

**Weak Compliance Knowledge**: May need more compliance-specific training examples

---

## Version History

### v2.0.0 (2026-01-20)
- Complete redesign for conceptual/theoretical focus
- Chain-of-thought reasoning in 70% of examples
- Comprehensive FireWeave function calling
- Multi-turn conversations (40% of data)
- All major compliance frameworks
- Increased context length (4096)
- Higher LoRA rank (32)

---

**Last Updated**: 2026-01-20
