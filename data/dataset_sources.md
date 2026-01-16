# Dataset Sources & Attribution

This file tracks the sources of training data for the Network Security Expert model.

## Synthetic Data Generation

### Generated with AI Models
- **Tool Used**: OpenAI GPT-4 / Anthropic Claude
- **Generation Script**: `scripts/generate_synthetic_data.py`
- **Topics Covered**:
  - Cisco firewall and router configuration
  - Palo Alto Networks firewall management
  - AWS cloud security (VPC, Security Groups, IAM)
  - Azure security (NSG, Azure Firewall)
  - IDS/IPS systems (Snort, Suricata)
  - SIEM and log analysis
  - Network troubleshooting

### Quality Assurance
- [ ] All commands verified against official documentation
- [ ] Technical accuracy reviewed by domain experts
- [ ] Security best practices validated
- [ ] No PII or sensitive information included

## Curated Data Sources

### Vendor Documentation
- **Cisco**: IOS Command Reference, ASA Configuration Guide
- **Palo Alto**: PAN-OS Administrator's Guide
- **AWS**: Security Best Practices Whitepapers
- **Azure**: Security Center Documentation

### Community Resources
- **Stack Overflow**: Questions tagged with network-security, cisco, aws-security
- **Reddit**: r/networking, r/netsec, r/sysadmin
- **Security Blogs**: Cloudflare, AWS Security Blog, Palo Alto Networks blog

### CTF & Security Writeups
- Capture The Flag solutions and explanations
- Security incident response case studies
- Vulnerability analysis reports

## Data Distribution

### By Domain (Target)
- Firewall & Network Devices: 35% (~1,000-1,750 examples)
- Cloud Security (AWS/Azure/GCP): 35% (~1,000-1,750 examples)
- Threat Detection & IR: 30% (~900-1,500 examples)

### By Format
- Single-turn Q&A: 70%
- Multi-turn conversations: 30%

### By Difficulty
- Beginner: 40%
- Intermediate: 40%
- Advanced: 20%

## Licensing & Attribution

### Synthetic Data
- Generated specifically for this project
- No copyright restrictions
- Can be used freely for training

### Curated Data
- Stack Overflow content: CC BY-SA 4.0
- Reddit content: Check individual posts for licensing
- Vendor documentation: Fair use for educational purposes
- Blog posts: Used with proper attribution

## Quality Metrics

### Target Metrics
- [ ] Minimum 3,000 total examples
- [ ] Average answer length: 300-800 characters
- [ ] Technical accuracy: 95%+
- [ ] Includes code/commands: 80%+
- [ ] Has security warnings: 60%+

### Validation
- Validated using: `scripts/validate_dataset.py`
- Last validation date: [To be filled after dataset creation]
- Issues found: [To be documented]
- Issues resolved: [To be documented]

## Dataset Versions

### v1.0 (Initial)
- **Date**: [TBD]
- **Size**: [TBD] examples
- **Coverage**: Initial coverage of core topics
- **Notes**: First training run

### v1.1 (Planned)
- **Date**: [TBD]
- **Improvements**:
  - Additional vendor coverage (Fortinet, Check Point)
  - More troubleshooting scenarios
  - Enhanced multi-turn conversations
  - Expanded GCP coverage

## Notes for Future Improvements

### Areas Needing More Data
- [ ] Fortinet FortiOS configuration
- [ ] Check Point firewall management
- [ ] GCP security (currently underrepresented)
- [ ] Kubernetes network security
- [ ] Zero Trust architecture implementation
- [ ] Security automation and orchestration

### Common Issues to Address
- [ ] Ensure vendor-specific commands are version-aware
- [ ] Add more error scenarios and troubleshooting
- [ ] Include more compliance framework references
- [ ] Add disaster recovery and business continuity topics

---

**Important**: Always verify technical accuracy before using data for training. When in doubt, consult official vendor documentation.
