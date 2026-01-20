# Network Security Expert - Fine-Tuning Project

**Version**: 2.0.0
**Last Updated**: 2026-01-20
**Purpose**: Fine-tune Llama 3.1 8B to become a specialized Network Security expert integrated with FireWeave

---

## Project Overview

This project fine-tunes **Llama 3.1 8B Instruct** to create a specialized Network Security Expert AI that:
- Has deep knowledge of network security, firewalls, and cloud infrastructure
- Understands **FireWeave** platform features and can assist users
- Provides accurate CLI commands, configurations, and troubleshooting guidance
- Supports CISSP-level security knowledge and compliance frameworks
- Can perform function calling to trigger FireWeave actions

**Target Deployment**: Local inference via Ollama (GGUF format)

---

## What is FireWeave?

**FireWeave** is a network security policy management platform that helps organizations:

- **Analyze** traffic flows - Check if traffic between IPs/ports is allowed or blocked across firewalls
- **Manage** firewall rules - Bulk import, create, and deploy rules with approval workflows
- **Detect** policy issues - Find shadowed rules, unused rules, and duplicate objects
- **Ensure** compliance - Scan policies against PCI-DSS, SOC2, NIST, HIPAA frameworks
- **Integrate** with ITSM - Connect to ServiceNow/Jira for change management
- **Collect** topology - Automatically discover and version network device configurations

Supports multi-vendor environments (Palo Alto, Cisco, Fortinet, AWS, Azure, GCP) and provides a REST API for automation.

---

## Technologies & Techniques Used

### 1. Model Fine-Tuning

| Technology | Purpose |
|------------|---------|
| **Llama 3.1 8B Instruct** | Base model - Meta's open-weight LLM |
| **Unsloth** | Optimized fine-tuning library (2x faster, 50% less memory) |
| **QLoRA** | 4-bit quantization + Low-Rank Adaptation - enables training on consumer GPUs |
| **Google Colab** | Cloud GPU environment for training |

**Key Training Parameters:**
```python
# Model Configuration
max_seq_length = 2048
load_in_4bit = True

# LoRA Configuration
r = 16
lora_alpha = 16
lora_dropout = 0
target_modules = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]

# Training Configuration
num_train_epochs = 3
per_device_train_batch_size = 2
gradient_accumulation_steps = 4  # Effective batch size = 8
learning_rate = 2e-4
weight_decay = 0.01
warmup_steps = 10
```

### 2. Synthetic Data Generation

| Technology | Purpose |
|------------|---------|
| **OpenAI GPT-4o API** | Generate high-quality Q&A training pairs |
| **Python** | Data generation scripts |
| **JSONL/JSON** | Data storage format |
| **ShareGPT/ChatML** | Training data format for conversation fine-tuning |

**Data Generation Techniques:**
- Topic-based generation (40+ categories)
- Quality scoring (0-100) based on length, code blocks, technical depth
- MD5 hash deduplication to prevent memorization
- Batch processing with rate limit handling (30K TPM)

### 3. Model Quantization & Export

| Technology | Purpose |
|------------|---------|
| **GGUF** | Optimized model format for CPU/GPU inference |
| **llama.cpp** | Conversion and quantization tooling |
| **Ollama** | Local model serving with REST API |

**Quantization Levels:**
| Format | Size | Quality | Speed |
|--------|------|---------|-------|
| Q4_K_M | ~4.5GB | Good | Fastest |
| Q5_K_M | ~5.5GB | Better | Fast |
| Q8_0 | ~8GB | Best | Slower |

### 4. Key Techniques Summary

| Technique | Why Used |
|-----------|----------|
| **QLoRA** | Train 8B model on 16GB GPU |
| **Synthetic data generation** | Create domain-specific training data at scale |
| **Quality filtering** | Ensure training data meets standards |
| **Deduplication** | Prevent model memorization of duplicates |
| **GGUF quantization** | Enable local inference without cloud costs |
| **ShareGPT format** | Standard format for chat fine-tuning |
| **Function calling data** | Train model to trigger FireWeave actions |

---

## Final Dataset Statistics

| Metric | Value |
|--------|-------|
| **Total unique examples** | 9,930 |
| **High-quality filtered (score 50+)** | 2,031 |
| **File size** | 7.4 MB |
| **Source files** | 43 |
| **Format** | ShareGPT/ChatML |

### Dataset Files

| File | Examples | Description |
|------|----------|-------------|
| `data/processed/all_training_data.json` | 9,930 | Complete training dataset |
| `data/processed/high_quality_new.json` | 2,031 | Quality-filtered subset |

### Quality Distribution

```
Score Distribution:
  10-19:    56
  20-29:   619 ######
  30-39:  4402 ############################################
  40-49:  2100 #####################
  50-59:   710 #######
  60-69:   888 ########
  70-79:   665 ######
  80-89:   440 ####
  90-99:    52
```

### Top Topics by Quality Pass Rate

| Topic | Passed/Total | Rate |
|-------|--------------|------|
| fireweave_disambiguation | 74/74 | 100% |
| cissp-domains | 138/161 | 86% |
| fireweave-function-calling | 115/146 | 79% |
| azure-security | 215/300 | 72% |
| network-automation | 210/298 | 70% |
| cisco-firewall | 287/419 | 68% |
| aws-networking | 70/111 | 63% |

---

## Project Structure

```
Finetuning/
├── CLAUDE.md                          # THIS FILE - Complete project documentation
├── README.md                          # User-facing documentation
├── requirements.txt                   # Python dependencies
├── .gitignore                         # Git ignore rules
│
├── scripts/
│   ├── generate_synthetic_data.py     # Main data generation (40+ topics)
│   ├── generate_hq_data.py            # High-quality sequential generation
│   ├── filter_high_quality.py         # Quality scoring and filtering
│   └── validate_dataset.py            # Data validation and merging
│
├── data/
│   ├── raw/                           # Original source data
│   ├── processed/
│   │   ├── all_training_data.json     # Final dataset (9,930 examples)
│   │   └── high_quality_new.json      # Quality filtered (2,031 examples)
│   └── synthetic/                     # Generated training data (43 files)
│       ├── fireweave-features_openai.json
│       ├── fireweave-api_openai.json
│       ├── fireweave-troubleshooting_openai.json
│       ├── fireweave-function-calling_openai.json
│       ├── fireweave-disambiguation_openai.json
│       ├── palo-alto-complete_openai.json
│       ├── aws-networking_openai.json
│       ├── ... (40+ topic files)
│       └── cissp-domains_openai.json
│
├── notebooks/
│   └── train_llama3_network_security.ipynb  # Unsloth training notebook
│
├── models/
│   ├── Modelfile                      # Ollama configuration
│   └── gguf/
│       └── Llama-3.1-8B-Instruct.Q4_K_M.gguf  # Quantized model
│
├── configs/                           # Training configurations
└── outputs/                           # Training logs and checkpoints
```

---

## Training Data Topics

### Topic Categories (40+ topics)

| Category | Topics | Examples |
|----------|--------|----------|
| **FireWeave** | features, troubleshooting, api, function-calling, disambiguation | ~690 |
| **Palo Alto** | palo-alto, palo-alto-complete, palo-alto-administration | ~620 |
| **Cisco** | cisco-firewall | ~419 |
| **Cloud Networking** | aws-networking, azure-networking, gcp-networking | ~789 |
| **Cloud Security** | aws-security, azure-security | ~600 |
| **Networking Fundamentals** | osi-model, routing-switching, dns-fundamentals, advanced-routing | ~1,112 |
| **Security Operations** | soc-operations, security-monitoring, threat-hunting | ~900 |
| **Compliance** | cissp-domains, infosec-policies | ~561 |
| **Threat Detection** | ids-ips, siem-logs, incident-response | ~670 |
| **Automation** | network-automation, soar-automation | ~597 |
| **Modern Infrastructure** | sdn-nfv, service-mesh, microservices-networking, api-gateway | ~1,098 |
| **Other** | load-balancing, vulnerability-management, zero-trust-security, datacenter-networking | ~1,459 |

### FireWeave-Specific Topics (Priority 0)

**fireweave-features** (150 examples):
- Traffic flow analysis and NAT checking
- Bulk import from Excel/CSV/DOCX
- Shadowed/unused rule detection
- Object deduplication and consolidation
- Compliance scanning (PCI-DSS, SOC2, NIST, HIPAA)
- ServiceNow/Jira integration
- Topology collection and versioning
- Mass edit with approval workflows

**fireweave-troubleshooting** (70 examples):
- Topology collection stuck/timeout issues
- Stale data warnings
- Integration failures (ServiceNow, cloud connectors)
- API errors and validation issues
- Worker/job queue problems

**fireweave-api** (75 examples):
- REST API endpoint usage
- Authentication (JWT tokens)
- Traffic analysis API
- Rule creation/batch deploy API
- Job status and monitoring

**fireweave-function-calling** (173 examples):
- Structured tool calls for traffic checks
- Rule creation with parameters
- Compliance scan triggers
- Multi-step workflow execution

**fireweave-disambiguation** (222 examples):
- Clarifying ambiguous user requests
- Determining intent from context
- Asking follow-up questions

---

## Data Generation Scripts

### generate_synthetic_data.py

**Location**: `scripts/generate_synthetic_data.py`

**Providers Supported**:
- OpenAI (GPT-4o) - `OPENAI_API_KEY`
- Anthropic (Claude) - `ANTHROPIC_API_KEY`
- Kimi (Moonshot) - `KIMI_API_KEY`
- Mock (testing, no API)

**Commands**:
```bash
# List all topics
python scripts/generate_synthetic_data.py --list-topics

# Generate specific topic
python scripts/generate_synthetic_data.py --provider openai --topic fireweave-features --count 100

# Generate all topics
python scripts/generate_synthetic_data.py --all --count 5000 --provider openai

# Test without API calls
python scripts/generate_synthetic_data.py --provider mock --topic osi-model --count 10
```

### filter_high_quality.py

**Location**: `scripts/filter_high_quality.py`

**Quality Scoring Criteria (0-100)**:
- Answer length (longer = higher score)
- Code blocks present (+points)
- Technical depth indicators
- Markdown formatting

**Commands**:
```bash
# Filter with default threshold (50)
python scripts/filter_high_quality.py data/synthetic/ --output data/processed/high_quality.json

# Custom threshold
python scripts/filter_high_quality.py data/synthetic/ --threshold 60 --output data/processed/premium.json
```

### validate_dataset.py

**Location**: `scripts/validate_dataset.py`

**Validation Checks**:
- JSON format validity
- Required fields (question, answer)
- Minimum content length
- Placeholder text detection
- Duplicate detection (MD5 hash)

**Commands**:
```bash
# Validate and show stats
python scripts/validate_dataset.py data/synthetic/ --stats

# Merge into training dataset
python scripts/validate_dataset.py data/synthetic/ --merge --output data/processed/all_training_data.json --format sharegpt
```

---

## Training Pipeline

### Data Pipeline

```
GPT-4o API → JSONL files → Quality Filter → Deduplication → ShareGPT JSON → Unsloth Training
```

### Training Steps

1. **Upload notebook to Google Colab**
   ```
   notebooks/train_llama3_network_security.ipynb
   ```

2. **Upload training data**
   ```
   data/processed/all_training_data.json
   ```

3. **Run training** (approximately 2-3 hours on T4 GPU)

4. **Export to GGUF**
   ```python
   # Merge LoRA with base model
   model.save_pretrained_merged("models/merged-16bit", tokenizer, save_method="merged_16bit")

   # Convert to GGUF
   model.save_pretrained_gguf("models/gguf", tokenizer,
       quantization_method=["q4_k_m", "q5_k_m", "q8_0"])
   ```

5. **Download GGUF file**
   ```python
   from google.colab import files
   files.download('/models/gguf/Llama-3.1-8B-Instruct.Q4_K_M.gguf')
   ```

   Or upload to Hugging Face:
   ```python
   from huggingface_hub import HfApi, create_repo, login

   login()  # Enter your HF token

   HF_USERNAME = "YOUR_USERNAME"
   REPO_NAME = "network-security-expert-gguf"
   repo_id = f"{HF_USERNAME}/{REPO_NAME}"

   create_repo(repo_id, repo_type="model", exist_ok=True)

   api = HfApi()
   api.upload_folder(
       folder_path="/models/gguf",
       repo_id=repo_id,
       repo_type="model",
       commit_message="Upload fine-tuned Llama 3.1 8B Network Security Expert GGUF"
   )
   ```

---

## Deployment

### Local Deployment with Ollama

1. **Place GGUF file**:
   ```
   models/gguf/Llama-3.1-8B-Instruct.Q4_K_M.gguf
   ```

2. **Create Ollama model**:
   ```bash
   cd models
   ollama create network-security-expert -f Modelfile
   ```

3. **Run model**:
   ```bash
   ollama run network-security-expert
   ```

### Modelfile Configuration

```dockerfile
FROM ./gguf/Llama-3.1-8B-Instruct.Q4_K_M.gguf

TEMPLATE """{{ if .System }}<|begin_of_text|><|start_header_id|>system<|end_header_id|>

{{ .System }}<|eot_id|>{{ end }}{{ if .Prompt }}<|start_header_id|>user<|end_header_id|>

{{ .Prompt }}<|eot_id|>{{ end }}<|start_header_id|>assistant<|end_header_id|>

{{ .Response }}<|eot_id|>"""

PARAMETER stop "<|start_header_id|>"
PARAMETER stop "<|end_header_id|>"
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|reserved_special_token"

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER repeat_penalty 1.1

SYSTEM """You are a Network Security Expert with deep expertise in:
- Firewall & Network Devices: Cisco, Palo Alto, Fortinet
- Cloud Security: AWS, Azure, GCP
- Threat Detection: IDS/IPS, SIEM, Incident Response
- FireWeave platform features and API

Provide accurate, detailed technical guidance with specific commands and configurations."""
```

---

## Integration with FireWeave

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                     FireWeave Frontend                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Policy UI   │  │ Traffic UI  │  │    AI Chat Panel    │  │
│  └─────────────┘  └─────────────┘  └──────────┬──────────┘  │
└───────────────────────────────────────────────┼─────────────┘
                                                │ WebSocket/REST
┌───────────────────────────────────────────────▼─────────────┐
│                    FireWeave Backend (FastAPI)               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ /api/ai/chat │  │ Session Mgr  │  │ Context Injector │   │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘   │
└─────────┼─────────────────┼───────────────────┼─────────────┘
          │                 │                   │
          ▼                 ▼                   ▼
   ┌────────────┐    ┌────────────┐     ┌─────────────────┐
   │   Ollama   │    │   Redis    │     │ FireWeave DB    │
   │  (Model)   │    │ (Sessions) │     │ (Policies/Rules)│
   └────────────┘    └────────────┘     └─────────────────┘
```

### Technology Stack for Integration

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Inference Server** | Ollama | Serves GGUF model with REST API |
| **API Framework** | FastAPI (Python) | Async endpoints for chat |
| **Session Store** | Redis | Store chat history per user |
| **Queue** | Celery + Redis | Handle long-running inference |
| **Auth** | JWT | Tie sessions to authenticated users |
| **Chat UI** | React + WebSocket | Real-time streaming responses |
| **Markdown** | react-markdown | Render code blocks, tables |

### Basic Integration Code

**Chat with History (Python)**:
```python
import httpx

class NetworkSecurityChat:
    def __init__(self, model="network-security-expert"):
        self.model = model
        self.history = []
        self.base_url = "http://localhost:11434/api"

    def chat(self, message: str) -> str:
        self.history.append({"role": "user", "content": message})

        response = httpx.post(
            f"{self.base_url}/chat",
            json={
                "model": self.model,
                "messages": self.history,
                "stream": False
            },
            timeout=120
        )

        assistant_message = response.json()["message"]["content"]
        self.history.append({"role": "assistant", "content": assistant_message})

        return assistant_message

    def clear_history(self):
        self.history = []

# Usage
chat = NetworkSecurityChat()
print(chat.chat("How do I check traffic flows in FireWeave?"))
print(chat.chat("What if it shows the traffic is blocked?"))
```

**FastAPI Endpoint**:
```python
from fastapi import FastAPI
from pydantic import BaseModel
import httpx
import uuid

app = FastAPI()
sessions = {}

class ChatRequest(BaseModel):
    session_id: str | None = None
    message: str

@app.post("/api/ai/chat")
async def chat(request: ChatRequest):
    session_id = request.session_id or str(uuid.uuid4())
    if session_id not in sessions:
        sessions[session_id] = []

    history = sessions[session_id]
    history.append({"role": "user", "content": request.message})

    async with httpx.AsyncClient() as client:
        response = await client.post(
            "http://localhost:11434/api/chat",
            json={"model": "network-security-expert", "messages": history, "stream": False},
            timeout=120
        )

    assistant_msg = response.json()["message"]["content"]
    history.append({"role": "assistant", "content": assistant_msg})

    return {"session_id": session_id, "response": assistant_msg}
```

**Streaming Responses**:
```python
from fastapi.responses import StreamingResponse

@app.post("/api/ai/chat/stream")
async def chat_stream(request: ChatRequest):
    async def generate():
        async with httpx.AsyncClient() as client:
            async with client.stream(
                "POST",
                "http://localhost:11434/api/chat",
                json={"model": "network-security-expert", "messages": messages, "stream": True}
            ) as response:
                async for line in response.aiter_lines():
                    yield f"data: {line}\n\n"

    return StreamingResponse(generate(), media_type="text/event-stream")
```

### Function Calling Integration

The model is trained to output structured tool calls:
```python
TOOLS = [
    {
        "name": "check_traffic_flow",
        "description": "Check if traffic is allowed between source and destination",
        "parameters": {"source": "str", "destination": "str", "port": "int"}
    },
    {
        "name": "create_firewall_rule",
        "description": "Create a new firewall rule",
        "parameters": {"source": "str", "destination": "str", "action": "str"}
    },
    {
        "name": "run_compliance_scan",
        "description": "Run compliance scan against a framework",
        "parameters": {"framework": "str", "firewall": "str"}
    }
]
```

---

## Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| GPU VRAM | 12GB | 16-24GB |
| System RAM | 16GB | 32GB |
| Storage | 50GB | 100GB |
| OS | WSL2/Linux | WSL2/Linux |

**For Inference Only (Ollama)**:
- CPU: 8+ cores
- RAM: 16GB
- GPU (optional): 8GB+ VRAM for acceleration

---

## Troubleshooting

### Data Generation Issues

**API Rate Limits (429 Error)**:
```bash
# Use smaller batch size and longer delays
python scripts/generate_synthetic_data.py --batch-size 5 --delay 10
```

**JSON Parse Errors**:
```bash
python scripts/validate_dataset.py data/synthetic/ --verbose
```

### Training Issues

**CUDA Out of Memory**:
```python
per_device_train_batch_size = 1
gradient_accumulation_steps = 8
# Or reduce max_seq_length to 1024
```

**Loss Not Decreasing**:
- Check data format matches ShareGPT/ChatML
- Reduce learning rate to 1e-4
- Increase warmup steps

### Ollama Issues

**Model Won't Load**:
- Verify GGUF file path in Modelfile
- Try Q4_K_M format first (most compatible)
- Check stop tokens match Llama 3 format

**Slow Inference**:
- Use GPU acceleration: `OLLAMA_GPU_LAYERS=35`
- Use Q4_K_M quantization
- Reduce context length if possible

---

## Version History

### v2.0.0 (2026-01-20)
- Training completed successfully
- Final dataset: 9,930 examples
- High-quality filtered: 2,031 examples
- GGUF export completed (Q4_K_M, Q5_K_M, Q8_0)
- Added integration documentation
- Added function calling training data
- Added disambiguation training data

### v1.0.0 (2025-01-18)
- Initial project setup
- 20 training topics defined
- 3 FireWeave-specific topics added
- Sample data created (22 examples)
- Training notebook with Unsloth
- Ollama deployment configuration

---

## Files Reference

| File | Purpose |
|------|---------|
| `scripts/generate_synthetic_data.py` | Multi-topic data generation |
| `scripts/generate_hq_data.py` | High-quality sequential generation |
| `scripts/filter_high_quality.py` | Quality scoring and filtering |
| `scripts/validate_dataset.py` | Validation and merging |
| `notebooks/train_llama3_network_security.ipynb` | Unsloth training notebook |
| `models/Modelfile` | Ollama configuration |
| `data/processed/all_training_data.json` | Final training dataset |
| `data/processed/high_quality_new.json` | Quality-filtered subset |

---

**Last Updated**: 2026-01-20
