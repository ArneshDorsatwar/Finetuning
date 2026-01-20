# FireWeave - Complete Platform Reference

**Version**: 2.9.0
**Platform**: Enterprise Panorama Firewall Management
**Last Updated**: 2025-01-18

---

## Table of Contents

1. [What is FireWeave?](#what-is-fireweave)
2. [Target Users](#target-users)
3. [Core Features](#core-features)
4. [Technical Architecture](#technical-architecture)
5. [Key Workflows](#key-workflows)
6. [API Reference](#api-reference)
7. [Terminology & Concepts](#terminology--concepts)
8. [Common Use Cases](#common-use-cases)
9. [Troubleshooting Guide](#troubleshooting-guide)
10. [Configuration Reference](#configuration-reference)

---

## What is FireWeave?

**FireWeave** is an enterprise-grade web application for managing Palo Alto Networks Panorama firewall policies. It provides network security teams with advanced tools for:

- **Policy Analysis**: Traffic flow checking, NAT validation, rule optimization
- **Bulk Operations**: Mass rule creation, editing, and deployment
- **Compliance Automation**: PCI-DSS, SOC2, NIST, HIPAA framework checking
- **Cloud Integration**: AWS, Azure, GCP topology discovery and visualization
- **Change Management**: ServiceNow and Jira integration for ITSM workflows
- **AI-Assisted Analysis**: Natural language interface for policy queries

### Why FireWeave?

Managing enterprise firewalls presents several challenges:

| Challenge | FireWeave Solution |
|-----------|-------------------|
| Manual rule analysis is slow | Automated traffic flow analysis in seconds |
| Shadow rules waste resources | Automatic detection and cleanup recommendations |
| Compliance audits are tedious | One-click compliance scans with evidence |
| Bulk changes are error-prone | Batch deploy with validation and rollback |
| Change requests lack context | ServiceNow/Jira integration with auto-parsing |
| Cloud policies are separate | Unified view of on-prem + cloud policies |

### Platform Statistics

- **Backend**: Python 3.13 + FastAPI (307+ files, ~100K LOC)
- **Frontend**: React 18 + TypeScript (313+ files, ~72K LOC)
- **API Endpoints**: 420+ REST endpoints across 55 routers
- **Celery Tasks**: 38 background tasks for async processing
- **Database**: PostgreSQL with 76+ tables across 9 schemas

---

## Target Users

### Primary Users

| Role | Primary Tasks |
|------|--------------|
| **Network Security Engineers** | Rule creation, traffic analysis, troubleshooting |
| **Firewall Administrators** | Policy deployment, object management, topology collection |
| **Security Architects** | Compliance auditing, rule optimization, deduplication |
| **SOC Analysts** | Traffic flow verification, incident investigation |
| **IT Auditors** | Compliance reports, change history review |

### User Permissions (RBAC)

FireWeave implements role-based access control:

| Role | Capabilities |
|------|-------------|
| **Viewer** | Read-only access to topology, rules, analysis results |
| **Analyst** | Viewer + run analysis, compliance scans, traffic checks |
| **Editor** | Analyst + create/edit rules, import data, manage objects |
| **Admin** | Editor + system configuration, user management, integrations |
| **Super Admin** | Full access including multi-tenant management |

---

## Core Features

### 1. Traffic Flow Analysis

**Purpose**: Check if traffic between two endpoints is allowed through the firewall.

**How It Works**:
1. Enter source IP, destination IP, port, and protocol
2. FireWeave automatically detects source and destination zones
3. Evaluates rules across all device groups in the traffic path
4. Shows matching rules with hit counts and actions
5. Identifies NAT translation if applicable

**API Endpoint**: `POST /api/v1/traffic-analysis/check`

**Request Example**:
```json
{
  "source_ip": "10.1.1.100",
  "destination_ip": "192.168.1.50",
  "port": 443,
  "protocol": "tcp"
}
```

**Response Example**:
```json
{
  "allowed": true,
  "matching_rules": [
    {
      "name": "Allow-HTTPS-Outbound",
      "device_group": "HQ-Firewalls",
      "action": "allow",
      "position": 15
    }
  ],
  "path": [
    {"zone": "trust", "interface": "ethernet1/1"},
    {"zone": "untrust", "interface": "ethernet1/2"}
  ],
  "nat_applied": true,
  "nat_rule": "Source-NAT-Outbound"
}
```

**UI Location**: Analysis > Traffic Flow

---

### 2. NAT Check & Validation

**Purpose**: Test NAT policy matches against live Panorama configuration.

**How It Works**:
1. Uses Panorama's `test nat-policy-match` API
2. Automatically detects source IP from topology if not specified
3. Evaluates both source NAT (SNAT) and destination NAT (DNAT)
4. Shows the matched NAT rule with translated addresses

**API Endpoint**: `POST /api/v1/nat/check`

**Request Example**:
```json
{
  "source_ip": "10.1.1.100",
  "destination_ip": "203.0.113.50",
  "destination_port": 443,
  "protocol": "tcp",
  "zone_from": "trust",
  "zone_to": "untrust"
}
```

**UI Location**: Analysis > NAT Check

---

### 3. Rule Analysis & Optimization

**Purpose**: Identify problematic, redundant, or inefficient firewall rules.

**Analysis Types**:

| Analysis | Description |
|----------|-------------|
| **Shadowed Rules** | Rules that never match because a broader rule above catches all traffic |
| **Unused Rules** | Rules with zero hit count over a configurable time period |
| **Mergeable Rules** | Multiple rules that could be consolidated into one |
| **Any-Service Rules** | Rules allowing all services (security risk) |
| **No-Logging Rules** | Rules without logging enabled (visibility gap) |
| **No-Profile Rules** | Rules without security profiles attached |

**API Endpoints**:
- `GET /api/v1/analysis/shadowed-rules`
- `GET /api/v1/analysis/unused-rules`
- `GET /api/v1/analysis/mergeable-rules`
- `GET /api/v1/analysis/any-service-rules`
- `GET /api/v1/analysis/no-log-rules`

**UI Location**: Analysis > [Analysis Type]

---

### 4. Object Deduplication

**Purpose**: Find and consolidate duplicate address and service objects.

**How It Works**:
1. **Scan**: Analyze all objects for duplicates using 95% similarity threshold
2. **Cluster**: Group similar objects together
3. **Select**: Choose canonical (primary) object for each cluster
4. **Preview**: Review which references will be updated
5. **Execute**: Update all references and delete duplicates

**Supported Object Types**:
- Address Objects (IP addresses, FQDNs, ranges)
- Address Groups
- Service Objects (TCP/UDP ports)
- Service Groups

**API Endpoint**: `POST /api/v1/deduplication/scan`

**UI Location**: Analysis > Deduplication

---

### 5. Object Consolidation

**Purpose**: Promote local objects to shared scope to reduce duplication across device groups.

**Workflow**:
1. Scan for duplicate objects across device groups
2. Identify candidates for consolidation
3. Select objects to promote to "Shared" device group
4. Update all references in child device groups
5. Delete local copies

**Risk Levels**:
- **LOW**: Object only used in one device group
- **MEDIUM**: Object used in multiple device groups
- **HIGH**: Object used in security rules

**UI Location**: Analysis > Object Consolidation

---

### 6. Compliance Automation

**Purpose**: Automatically check firewall policies against security frameworks.

**Supported Frameworks**:

| Framework | Focus Areas |
|-----------|-------------|
| **PCI-DSS** | Cardholder data protection, network segmentation |
| **SOC2** | Security, availability, processing integrity |
| **NIST** | Risk management, security controls |
| **CIS** | Palo Alto hardening benchmarks |
| **HIPAA** | Healthcare data protection |

**Check Examples**:
- No "any-any-allow" rules in DMZ
- All rules have logging enabled
- No deprecated services (Telnet, FTP, etc.)
- Proper zone segmentation between trust levels
- Security profiles attached to allow rules

**API Endpoint**: `POST /api/v1/compliance/scan`

**Request Example**:
```json
{
  "device_group": "DC-Firewalls",
  "framework": "PCI-DSS",
  "categories": ["network_segmentation", "logging"]
}
```

**Response Example**:
```json
{
  "score": 85,
  "total_checks": 42,
  "passed": 36,
  "failed": 6,
  "findings": [
    {
      "check_id": "PCI-1.2.1",
      "description": "Inbound traffic restricted to necessary ports",
      "status": "failed",
      "affected_rules": ["Any-Allow-DMZ"],
      "remediation": "Replace 'any' service with specific ports"
    }
  ]
}
```

**UI Location**: Compliance > [Framework Name]

---

### 7. Bulk Import & Export

**Purpose**: Create firewall rules from spreadsheets, documents, or ServiceNow change requests.

**Supported Import Formats**:
- **XLSX** (Excel): Multi-sheet support with header detection
- **CSV**: Standard comma-separated values
- **DOCX**: Table extraction from Word documents
- **ServiceNow FCR**: Firewall Change Request form attachments

**Import Workflow**:
1. Upload file or select ServiceNow change request
2. Map columns to rule fields (source, destination, port, action)
3. Validate data and resolve errors
4. Preview generated rules
5. Deploy to Panorama (single or batch)

**Export Formats**:
- Panorama set commands (CLI)
- Excel spreadsheet
- CSV file
- JSON

**API Endpoints**:
- `POST /api/v1/bulk-import/upload`
- `POST /api/v1/bulk-import/parse`
- `GET /api/v1/bulk-export/set-commands`

**UI Location**: Automation > Bulk Import

---

### 8. Batch Deploy

**Purpose**: Deploy multiple firewall rules at once with validation and smart profile selection.

**Features**:
- **Validation**: Check object existence before deployment
- **Smart Profiles**: Auto-select log forwarding and security profiles
- **Placement**: Position rules at top, bottom, or relative to anchor rule
- **Preview**: See exactly what will be created before deployment
- **Rollback**: Undo batch deployments if needed

**Placement Options**:
- **Top of rulebase**: Insert at position 1
- **Bottom of rulebase**: Append after last rule
- **Above anchor**: Position above a specific existing rule

**API Endpoint**: `POST /api/v1/batch-deploy`

**Request Example**:
```json
{
  "device_group": "DC-Firewalls",
  "rulebase": "pre",
  "placement": {
    "position": "above",
    "anchor_rule_name": "Block-All"
  },
  "rules": [
    {
      "name": "Allow-Web-Servers",
      "source": ["Web-Servers-Group"],
      "destination": ["Database-Servers"],
      "service": ["tcp-443", "tcp-3306"],
      "action": "allow"
    }
  ]
}
```

**UI Location**: Automation > Batch Deploy

---

### 9. Mass Edit

**Purpose**: Modify multiple existing rules at once using filters and actions.

**Filter Conditions** (15+ types):
- Rule name (contains, starts with, regex)
- Source/destination zone
- Source/destination address
- Service/application
- Tag
- Logging status
- Security profile

**Actions** (25+ types):
- Enable/disable logging
- Add/remove/replace tags
- Set security profile group
- Add/remove source/destination addresses
- Change zone
- Enable/disable rule
- Set description

**Risk Assessment**:
| Level | Description | Approval |
|-------|-------------|----------|
| **Low** | Non-impacting changes (tags, descriptions) | Auto-approved |
| **Medium** | Visibility changes (logging) | Requires approval |
| **High** | Security changes (profiles, zones) | Requires 2-person approval |
| **Critical** | Allow/deny changes, rule deletion | Requires admin approval |

**Workflow**:
1. Build filter to select rules
2. Define actions to apply
3. Preview matched rules and changes
4. Submit for approval (if required)
5. Execute with full audit logging
6. Rollback if needed

**API Endpoint**: `POST /api/v1/mass-edit/jobs`

**UI Location**: Automation > Mass Edit

---

### 10. ServiceNow Integration

**Purpose**: Automatically receive and process firewall change requests from ServiceNow.

**Integration Methods**:
- **Webhook**: Real-time notifications when changes are created/updated
- **Table API**: Fetch open change requests on-demand
- **FCR Forms**: Parse Firewall Change Request form attachments

**Workflow**:
1. ServiceNow sends webhook when FCR is created
2. FireWeave parses the attached Excel/CSV file
3. Rules are extracted and validated
4. Analyst reviews in FireWeave dashboard
5. Approved rules are deployed to Panorama
6. ServiceNow ticket is updated with deployment status

**Configuration**:
```bash
SNOW_INSTANCE_URL=https://your-instance.service-now.com
SNOW_WEBHOOK_SECRET=your-webhook-secret
SNOW_TABLE_API_USER=api-user
SNOW_TABLE_API_PASSWORD=api-password
```

**API Endpoints**:
- `POST /api/v1/servicenow/webhook` (receive notifications)
- `GET /api/v1/servicenow/changes` (list open changes)
- `POST /api/v1/servicenow/changes/{id}/execute` (deploy rules)

**UI Location**: Integrations > ServiceNow Dashboard

---

### 11. Jira Integration

**Purpose**: Process firewall requests from Jira tickets.

**Features**:
- JQL-based issue fetching
- Automatic rule parsing from issue descriptions
- Evidence upload after deployment
- Issue status transitions

**Supported Formats in Issue Body**:
- Markdown tables
- CSV blocks
- JSON blocks
- Key-value pairs

**API Endpoints**:
- `GET /api/v1/jira/issues` (JQL query)
- `POST /api/v1/jira/issues/{key}/execute` (deploy and update)

**UI Location**: Integrations > Jira Dashboard

---

### 12. Topology Collection

**Purpose**: Collect and cache Panorama configuration for fast analysis.

**How It Works**:
1. Single API call fetches entire Panorama running config
2. XML is parsed locally (15x faster than parallel chunk fetching)
3. Data is normalized into PostgreSQL tables
4. Version is created with SHA256 checksum
5. Post-collection analysis tasks run in parallel

**Performance**:
- Collection time: ~55 seconds (vs 14 minutes with old parallel method)
- API calls: ~4 (vs ~2,800 with old method)

**Scheduling**:
- Default: Every 4 hours via Celery Beat
- On-demand: Manual collection via UI or API

**API Endpoints**:
- `POST /api/v1/panorama/topology/collect` (trigger collection)
- `GET /api/v1/panorama/topology/status` (check status)
- `GET /api/v1/panorama/topology/progress` (real-time progress)

**UI Location**: Admin > Topology Status

---

### 13. Topology Versioning

**Purpose**: Maintain version history of Panorama configuration with instant rollback.

**Features**:
- Immutable snapshots with SHA256 checksums
- Normalized storage in 13 PostgreSQL tables
- 85% storage reduction via gzip compression
- Atomic version switching
- Change audit log for compliance (SOC2, PCI-DSS ready)

**Rollback Workflow**:
1. View version history
2. Compare versions (diff view)
3. Select version to activate
4. Confirm rollback
5. All analysis uses the activated version

**API Endpoints**:
- `GET /api/v1/topology/versions` (list versions)
- `GET /api/v1/topology/versions/{id}` (version details)
- `POST /api/v1/topology/versions/{id}/activate` (rollback)
- `GET /api/v1/topology/versions/compare` (diff)

**UI Location**: Admin > Topology Versions

---

### 14. Device Group Hierarchy

**Purpose**: Visualize and understand the Panorama device group structure.

**Features**:
- Interactive tree visualization
- Local vs. inherited object counts
- Rule evaluation order display
- Effective scope resolution for rule creation
- Inheritance chain visualization

**Understanding Inheritance**:
```
Shared
├── North-America
│   ├── US-East (inherits from North-America, Shared)
│   │   └── NYC-DC (inherits from US-East, North-America, Shared)
│   └── US-West
└── Europe
    └── London-DC
```

Objects and rules in "Shared" are available to all device groups. Objects in "North-America" are only available to its children.

**API Endpoint**: `GET /api/v1/device-group-hierarchy`

**UI Location**: Configuration > Device Group Hierarchy

---

### 15. Template Stack Hierarchy

**Purpose**: Manage template stacks and detect configuration overrides.

**Features**:
- Template inheritance chain visualization
- Priority ordering (templates applied in order)
- Override detection and severity classification
- Firewall assignment tracking
- Override resolution workflow

**Override Severity**:
- **Critical**: Security-related overrides (admin accounts, auth settings)
- **Warning**: Network configuration overrides (interfaces, routing)
- **Info**: Cosmetic overrides (timezone, hostname)

**API Endpoints**:
- `GET /api/v1/template-stacks` (list stacks)
- `GET /api/v1/template-stacks/{name}/hierarchy` (inheritance chain)
- `GET /api/v1/template-stacks/overrides` (find overrides)

**UI Location**: Configuration > Template Stacks

---

### 16. Cloud Integration (AWS/Azure/GCP)

**Purpose**: Discover and visualize cloud network topology alongside on-prem firewalls.

**AWS Features**:
- VPC, subnet, route table discovery
- Security Groups and Network ACLs
- EC2 instances, ENIs, Elastic IPs
- VPC endpoints and peering connections
- Internet exposure analysis

**Azure Features**:
- VNets, subnets, NSGs
- Virtual machines, NICs
- Load balancers, application gateways
- ExpressRoute connections

**GCP Features**:
- VPCs, subnets, firewall rules
- Routes, VPN tunnels, Cloud Routers
- Peering connections, NAT gateways
- Traffic flow analysis with firewall evaluation

**API Endpoints**:
- `GET /api/v1/cloud/aws/topology`
- `GET /api/v1/cloud/azure/topology`
- `GET /api/v1/cloud/gcp/topology`

**UI Location**: Cloud > [Provider] Topology

---

### 17. AI Chat Orchestrator

**Purpose**: Natural language interface for firewall policy analysis.

**Capabilities**:
- "Is traffic from 10.1.1.1 to 192.168.1.1 port 443 allowed?"
- "Check compliance for PCI-DSS"
- "Find shadowed rules in the DMZ"
- "What NAT rule translates traffic to 203.0.113.50?"

**LangChain Tools Available**:
| Tool | Description |
|------|-------------|
| `policy_path_check` | Traffic flow analysis |
| `nat_check` | NAT rule validation |
| `compliance_scan` | Compliance framework check |
| `ember_search` | Application lookup |
| `search_objects` | Object search |
| `find_shadowed_rules` | Shadow detection |
| `list_unused_objects` | Cleanup analysis |
| `get_rule_details` | Rule inspection |

**Multi-Step Workflows**:
- Compliance audit with remediation
- NAT troubleshooting
- Policy cleanup wizard

**API Endpoint**: `POST /api/v1/chat` (separate microservice on port 8081)

**UI Location**: AI Chat (sidebar)

---

### 18. System Health Monitoring

**Purpose**: Monitor FireWeave infrastructure and Panorama connectivity.

**Health Checks**:
- CPU, memory, disk usage
- PostgreSQL connectivity and performance
- Redis connectivity and memory
- Celery worker status and queue depth
- Panorama API connectivity
- Cloud connector status

**Quick Actions**:
- Restart Celery workers
- Clear Redis cache
- Export diagnostic bundle
- Force topology collection

**API Endpoint**: `GET /api/v1/health/detailed`

**UI Location**: Admin > System Health

---

### 19. Audit Log Management

**Purpose**: Sync and analyze Panorama audit logs for change tracking.

**Features**:
- Sync from Panorama API (audit, config, system logs)
- Structured before/after diffs
- Field-level change tracking
- 80-90% storage compression
- 90-day retention (configurable)
- Search and filter by user, action, time

**API Endpoints**:
- `POST /api/v1/audit/sync` (sync from Panorama)
- `GET /api/v1/audit/logs` (search logs)
- `GET /api/v1/audit/logs/{id}/diff` (view changes)

**UI Location**: Audit > Log Explorer

---

### 20. VPN Automation

**Purpose**: Automate site-to-site VPN configuration.

**7-Step Wizard**:
1. Select VPN type (IKEv1/IKEv2)
2. Configure tunnel interface
3. Enter peer details (IP, ID)
4. Build crypto profiles (IKE + IPsec)
5. Generate routes
6. Create security policies
7. Review and deploy

**Features**:
- Template-based VPN deployment
- Auto-route generation
- Security policy creation
- Crypto profile builder (Phase 1 + Phase 2)

**API Endpoints**:
- `POST /api/v1/vpn/configuration` (create VPN)
- `GET /api/v1/vpn/templates` (list templates)

**UI Location**: Automation > VPN Wizard

---

## Technical Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                          Frontend (React)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │   48 Pages   │  │107 Components│  │ 39 API Clients│              │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │        State: React Query + Zustand + Context                 │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                  ↕ REST API (HTTPS)
┌─────────────────────────────────────────────────────────────────────┐
│                          Backend (FastAPI)                           │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  55 Routers  │  │  65 Services │  │34 Repositories│              │
│  │  420+ Endpoints│ │              │  │              │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│                                                                      │
│  ┌──────────────────────────────────────────────────────────────┐   │
│  │                    Celery Task Queue                          │   │
│  │  38 Tasks → Redis Broker → Workers → Flower Monitoring        │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                  ↕
┌─────────────────────────────────────────────────────────────────────┐
│                          Data Layer                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │  PostgreSQL  │  │    Redis     │  │   Panorama   │               │
│  │  76+ Tables  │  │  Cache/Queue │  │    API       │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
│                                                                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │
│  │     AWS      │  │    Azure     │  │     GCP      │               │
│  │     SDK      │  │     SDK      │  │     SDK      │               │
│  └──────────────┘  └──────────────┘  └──────────────┘               │
└─────────────────────────────────────────────────────────────────────┘
```

### Database Schema

**Schemas**:
| Schema | Purpose |
|--------|---------|
| `public` | Core application tables |
| `core` | Device groups, templates, hierarchy |
| `topology` | Versioned topology snapshots |
| `analysis` | Pre-computed analysis results |
| `audit` | Audit logs and change tracking |
| `catalog` | Network objects lookup |
| `aws` | AWS topology and security |
| `azure` | Azure resources |
| `gcp` | GCP resources |

### Celery Task Queues

| Queue | Priority | Use Case |
|-------|----------|----------|
| `critical` | Highest | Authentication, urgent notifications |
| `high` | High | Topology collection, compliance scans |
| `default` | Normal | Analysis, reports, exports |
| `low` | Low | Maintenance, cleanup, statistics |

---

## Key Workflows

### Workflow 1: Process a Firewall Change Request

**Scenario**: A ServiceNow ticket contains a request to allow web server access to a database.

1. **Receive Notification**
   - ServiceNow webhook notifies FireWeave
   - Ticket appears in ServiceNow Dashboard

2. **Review Request**
   - Open ticket in FireWeave
   - View parsed rules from FCR attachment
   - Check for existing similar rules

3. **Validate Rules**
   - Verify source/destination objects exist
   - Check for conflicts with existing rules
   - Run traffic flow analysis for existing path

4. **Deploy Rules**
   - Select device group and rulebase
   - Choose placement (top, bottom, above anchor)
   - Preview changes
   - Deploy with batch deploy

5. **Update Ticket**
   - ServiceNow ticket auto-updated with deployment status
   - Evidence attached (rule names, commit IDs)

---

### Workflow 2: Clean Up Unused Rules

**Scenario**: Reduce firewall complexity by removing rules that haven't been used.

1. **Run Analysis**
   - Navigate to Analysis > Unused Rules
   - Set minimum days unused (e.g., 90 days)
   - Run analysis

2. **Review Results**
   - Sort by hit count and last hit date
   - Filter by device group or zone
   - Export list for review

3. **Disable First**
   - Use Mass Edit to disable selected rules
   - Set 30-day monitoring period

4. **Delete After Validation**
   - If no impact, delete disabled rules
   - Mass Edit with delete action
   - Requires approval for high-impact changes

---

### Workflow 3: Compliance Audit

**Scenario**: Prepare for a PCI-DSS audit.

1. **Run Compliance Scan**
   - Select PCI-DSS framework
   - Choose device groups in scope
   - Run scan

2. **Review Findings**
   - View failed checks with evidence
   - See affected rules for each finding
   - Read remediation guidance

3. **Remediate Issues**
   - Use Mass Edit for bulk fixes (e.g., enable logging)
   - Manually fix complex issues
   - Re-run scan to verify

4. **Export Report**
   - Generate PDF compliance report
   - Include evidence for passed checks
   - Submit to auditor

---

### Workflow 4: Troubleshoot Connectivity

**Scenario**: Application team reports connectivity issues between app server and database.

1. **Gather Information**
   - Source IP: 10.1.1.100 (app server)
   - Destination IP: 10.2.2.50 (database)
   - Port: 3306 (MySQL)

2. **Run Traffic Flow Analysis**
   - Enter flow parameters
   - Analyze traffic path

3. **Interpret Results**
   - If blocked: See which rule is blocking
   - If shadowed: Identify the shadowing rule
   - If allowed: Check NAT translation

4. **Check NAT**
   - Run NAT Check for the same flow
   - Verify source IP is translated if expected
   - Check destination NAT for load-balanced services

5. **Resolve Issue**
   - Create new rule if missing
   - Modify existing rule if incorrect
   - Report finding if application misconfigured

---

## API Reference

### Authentication

All API requests require a valid JWT token or session cookie.

**Login**:
```bash
curl -X POST http://localhost:8000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'
```

**Response**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer"
}
```

**Using Token**:
```bash
curl -X GET http://localhost:8000/api/v1/rules/security \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIs..."
```

### Core Endpoints

| Category | Endpoint | Method | Description |
|----------|----------|--------|-------------|
| **Traffic** | `/api/v1/traffic-analysis/check` | POST | Check traffic flow |
| **NAT** | `/api/v1/nat/check` | POST | Test NAT policy |
| **Rules** | `/api/v1/rules/security` | GET | List security rules |
| **Rules** | `/api/v1/rules/create` | POST | Create rule |
| **Objects** | `/api/v1/objects/address` | GET | List address objects |
| **Objects** | `/api/v1/objects/lookup` | POST | IP/subnet lookup |
| **Compliance** | `/api/v1/compliance/scan` | POST | Run compliance check |
| **Analysis** | `/api/v1/analysis/shadowed-rules` | GET | Find shadowed rules |
| **Dedup** | `/api/v1/deduplication/scan` | POST | Find duplicates |
| **Topology** | `/api/v1/panorama/topology/collect` | POST | Trigger collection |
| **Jobs** | `/api/v1/jobs/{id}` | GET | Get job status |
| **Health** | `/api/v1/health/detailed` | GET | System health |

### Error Response Format

All errors follow a standardized envelope:

```json
{
  "error": {
    "code": "VALIDATION.INVALID_IP",
    "message": "Invalid IP address format",
    "details": {
      "field": "source_ip",
      "value": "256.1.1.1"
    },
    "trace_id": "abc123def456"
  }
}
```

**Error Code Namespaces**:
- `AUTH.*` - Authentication errors
- `VALIDATION.*` - Input validation errors
- `PANORAMA.*` - Panorama API errors
- `OBJECTS.*` - Object operation errors
- `POLICY.*` - Policy errors

---

## Terminology & Concepts

### Panorama Terms

| Term | Definition |
|------|------------|
| **Panorama** | Palo Alto's centralized management platform for firewalls |
| **Device Group** | Logical grouping of firewalls that share policy |
| **Shared** | Special device group; objects here are available to all |
| **Pre-Rulebase** | Rules evaluated before local firewall rules |
| **Post-Rulebase** | Rules evaluated after local firewall rules |
| **Template Stack** | Configuration templates applied to firewalls |
| **Zone** | Security boundary (trust, untrust, DMZ, etc.) |
| **Security Rule** | Policy that allows/denies traffic |
| **NAT Rule** | Policy that translates IP addresses |
| **Address Object** | Named IP address, FQDN, or range |
| **Service Object** | Named TCP/UDP port or port range |
| **Security Profile** | Threat prevention, URL filtering, etc. |

### FireWeave Terms

| Term | Definition |
|------|------------|
| **Topology** | Cached snapshot of Panorama configuration |
| **Topology Collection** | Process of fetching config from Panorama |
| **Shadowed Rule** | Rule that never matches due to broader rule above |
| **Mergeable Rules** | Rules that could be consolidated |
| **Deduplication** | Finding and removing duplicate objects |
| **Consolidation** | Promoting local objects to shared scope |
| **Batch Deploy** | Creating multiple rules in one operation |
| **Mass Edit** | Modifying multiple rules with filters |
| **FCR** | Firewall Change Request (ServiceNow form) |

### Network Terms

| Term | Definition |
|------|------------|
| **CIDR** | Classless Inter-Domain Routing (e.g., 10.0.0.0/8) |
| **NAT** | Network Address Translation |
| **SNAT** | Source NAT (changes source IP) |
| **DNAT** | Destination NAT (changes destination IP) |
| **FQDN** | Fully Qualified Domain Name |
| **ACL** | Access Control List |
| **VPC** | Virtual Private Cloud (AWS) |
| **VNet** | Virtual Network (Azure) |
| **NSG** | Network Security Group (Azure) |

---

## Common Use Cases

### Use Case 1: "Is traffic allowed?"

**Question**: Is traffic from 10.1.1.100 to 192.168.1.50 on port 443 allowed?

**How to Check**:
1. Navigate to Analysis > Traffic Flow
2. Enter:
   - Source IP: 10.1.1.100
   - Destination IP: 192.168.1.50
   - Port: 443
   - Protocol: TCP
3. Click Analyze
4. Review matching rules

**API**:
```bash
curl -X POST 'http://localhost:8000/api/v1/traffic-analysis/check' \
  -H 'Content-Type: application/json' \
  -d '{
    "source_ip": "10.1.1.100",
    "destination_ip": "192.168.1.50",
    "port": 443,
    "protocol": "tcp"
  }'
```

---

### Use Case 2: "Why is traffic blocked?"

**Question**: Users report they can't access a server. What's blocking them?

**How to Check**:
1. Run Traffic Flow Analysis with the failing flow
2. If result shows "blocked", note the blocking rule
3. Check if there's a more specific allow rule that's shadowed
4. Check rule ordering (higher rules match first)

**Common Causes**:
- Deny rule matching before expected allow rule
- Missing allow rule
- Wrong zone assignment
- Object contains wrong IP

---

### Use Case 3: "Create a new firewall rule"

**How to Create**:
1. Navigate to Automation > Bulk Import
2. Upload spreadsheet or enter manually
3. Fill in:
   - Rule name
   - Source zone and addresses
   - Destination zone and addresses
   - Services/ports
   - Action (allow/deny)
4. Select device group and placement
5. Preview and deploy

**Best Practices**:
- Use descriptive rule names (e.g., "Allow-WebApp-to-DB-MySQL")
- Enable logging
- Attach security profiles
- Add tags for categorization

---

### Use Case 4: "Find and fix compliance issues"

**How to Check**:
1. Navigate to Compliance > [Framework]
2. Select device groups in scope
3. Run scan
4. Review failed checks
5. Use Mass Edit to fix common issues (e.g., enable logging)
6. Re-run scan to verify

**Common Fixes**:
- Enable logging on all allow rules
- Attach security profiles
- Remove any-service rules
- Replace deprecated protocols

---

### Use Case 5: "Clean up duplicate objects"

**How to Check**:
1. Navigate to Analysis > Deduplication
2. Run scan for address objects
3. Review clusters of duplicates
4. Select canonical (primary) object
5. Preview reference updates
6. Execute deduplication

**Impact**:
- Reduced object count
- Easier object management
- Smaller configuration size
- Faster commits

---

## Troubleshooting Guide

### Problem: Topology Collection Fails

**Symptoms**:
- Collection stuck at a percentage
- Timeout errors
- Empty topology data

**Diagnosis**:
1. Check Panorama connectivity:
   ```bash
   curl -k "https://<panorama>/api/?type=op&cmd=<show><system><info></info></system></show>&key=<API_KEY>"
   ```
2. Check backend logs for errors
3. Check Celery worker status

**Solutions**:
| Cause | Solution |
|-------|----------|
| Timeout | Increase `TOPOLOGY_TIMEOUT` |
| API key invalid | Generate new API key in Panorama |
| Network latency | Check connectivity to Panorama |
| Large config | Increase memory for workers |

---

### Problem: Traffic Analysis Returns No Results

**Symptoms**:
- Analysis completes but shows no matching rules
- Unexpected "blocked" result

**Diagnosis**:
1. Check if topology is current (not stale)
2. Verify zone detection is correct
3. Check if device group has rules

**Solutions**:
| Cause | Solution |
|-------|----------|
| Stale topology | Trigger new collection |
| Wrong zones | Check interface-to-zone mapping |
| No rules in DG | Check parent device groups |
| Missing objects | Verify source/dest objects exist |

---

### Problem: Batch Deploy Fails

**Symptoms**:
- Deployment error message
- Partial rule creation
- Commit fails

**Diagnosis**:
1. Check error message details
2. Verify objects exist
3. Check for name conflicts
4. Review Panorama commit status

**Solutions**:
| Cause | Solution |
|-------|----------|
| Object not found | Create missing objects first |
| Name conflict | Use unique rule name |
| Validation error | Fix field format issues |
| Commit conflict | Wait for other commits, retry |

---

### Problem: ServiceNow Webhook Not Working

**Symptoms**:
- No tickets appearing in dashboard
- Webhook errors in ServiceNow

**Diagnosis**:
1. Check webhook secret matches
2. Verify FireWeave endpoint is reachable from ServiceNow
3. Check backend logs for incoming requests

**Solutions**:
| Cause | Solution |
|-------|----------|
| Secret mismatch | Update `SNOW_WEBHOOK_SECRET` |
| Firewall blocking | Allow ServiceNow IPs |
| SSL issues | Use valid certificate |
| Parse errors | Check FCR attachment format |

---

### Problem: Slow Analysis Performance

**Symptoms**:
- Analysis pages take >30 seconds
- Browser appears frozen

**Diagnosis**:
1. Check Pre-Computed Analysis status
2. Check if analysis is running fresh each time
3. Check database query performance

**Solutions**:
| Cause | Solution |
|-------|----------|
| No pre-computed results | Enable analysis scheduling |
| Stale results | Trigger refresh |
| Large dataset | Add pagination/filters |
| Database slow | Check PostgreSQL performance |

---

## Configuration Reference

### Environment Variables

**Required**:
```bash
# Panorama Connection
PANORAMA_IP=192.168.1.10
PANORAMA_API_KEY=your_api_key_here

# Authentication
AUTH_JWT_SECRET=CHANGE_ME_32_CHARS_MIN

# Database
DATABASE_URL=postgresql://user:pass@localhost:5432/fireweave

# Redis
REDIS_URL=redis://localhost:6379/4
```

**Optional**:
```bash
# Server
PORT=8000
HOST=0.0.0.0

# Topology
TOPOLOGY_TIMEOUT=300
TOPOLOGY_PROGRESS=true

# ServiceNow
SNOW_INSTANCE_URL=https://your-instance.service-now.com
SNOW_WEBHOOK_SECRET=your-secret

# LDAP
LDAP_URL=ldaps://ad.corp.example.com:636
LDAP_BIND_DN=cn=svc_fireweave,ou=service,dc=corp,dc=com
LDAP_BIND_PASSWORD=your-password

# Cloud
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=your-secret
AZURE_TENANT_ID=your-tenant
GCP_SERVICE_ACCOUNT_KEY=/path/to/key.json
```

### Ports

| Service | Port | Description |
|---------|------|-------------|
| FastAPI Backend | 8000 | Main API server |
| React Frontend | 5173 | Development server |
| AI Chat Orchestrator | 8081 | Chat microservice |
| Flower | 5555 | Celery monitoring |
| PostgreSQL | 5432 | Database |
| Redis | 6379 | Cache/Queue |

---

## Version History

| Version | Date | Major Changes |
|---------|------|---------------|
| 2.9.0 | 2025-01-18 | Object Consolidation, Jira Integration, Additional Features docs |
| 2.8.1 | 2025-12-30 | Batch Deploy profile fix |
| 2.8.0 | 2025-12-28 | AI Chat Orchestrator with workflow engine |
| 2.7.0 | 2025-12-15 | Pre-Computed Analysis Architecture |
| 2.6.0 | 2025-12-15 | GCP Cloud Integration |
| 2.5.0 | 2025-12-13 | Topology Data Architecture Modernization (TDAM) |
| 2.4.0 | 2025-12-12 | Single-fetch topology collection (15x faster) |
| 2.3.0 | 2025-12-05 | Template Stack, Mass Edit, Multi-Tenancy |
| 2.2.0 | 2025-12-04 | Device Group Hierarchy |
| 2.1.0 | 2025-12-01 | AWS Security Visualization |
| 2.0.0 | 2025-11-28 | Celery production, Breakglass admin |
| 1.8.0 | 2025-11-20 | VPN Automation, Database repositories |
| 1.7.0 | 2025-11-18 | ServiceNow integration, Compliance automation |

---

**Last Updated**: 2025-01-18
**Document Version**: 1.0.0
**Purpose**: Complete FireWeave platform reference for AI training and user documentation
