# Network Security Expert - Llama 3 8B Fine-tuned

A specialized fine-tuned version of Llama 3 8B Instruct trained on network security, cloud infrastructure, and threat detection topics.

## Overview

This project fine-tunes Llama 3 8B to become an expert in:
- **Firewall & Network Device Configuration** - Cisco, Palo Alto, Fortinet
- **Cloud Security** - AWS, Azure, GCP (VPC, Security Groups, IAM, etc.)
- **Threat Detection & Incident Response** - IDS/IPS, SIEM, log analysis

**Training Method:** QLoRA (4-bit quantization) using [Unsloth](https://github.com/unslothai/unsloth)
**Deployment:** Local inference via Ollama (GGUF format)
**Training Environment:** Windows/WSL with local GPU

## Project Structure

```
Finetuning/
├── notebooks/
│   └── train_llama3_network_security.ipynb    # Main training notebook
├── data/
│   ├── raw/                                    # Original data sources
│   ├── processed/                              # Cleaned & formatted datasets
│   └── synthetic/                              # Generated training data
├── scripts/
│   ├── generate_synthetic_data.py              # Create synthetic Q&A pairs
│   ├── validate_dataset.py                     # Dataset quality checker
│   ├── convert_to_gguf.py                      # LoRA → GGUF conversion
│   └── curate_stackoverflow.py                 # Parse online resources
├── models/
│   ├── network-security-lora/                  # Trained LoRA adapter
│   ├── merged-16bit/                           # Merged full model
│   ├── gguf/                                   # GGUF quantizations
│   └── Modelfile                               # Ollama configuration
├── outputs/                                     # Training logs
├── requirements.txt                             # Python dependencies
└── README.md                                    # This file
```

## Quick Start

### 1. Prerequisites

**Hardware:**
- GPU: 12GB+ VRAM (RTX 3060, 4060 Ti, 4070, 4080, 4090)
- RAM: 16GB+ system memory
- Storage: 50GB+ free space

**Software:**
- Windows 10/11 with WSL2 (Ubuntu 20.04+)
- Python 3.10+
- CUDA 11.8+ (installed in WSL)
- Git

### 2. Installation

**Install WSL2 (if not already installed):**
```bash
# In Windows PowerShell (as Administrator)
wsl --install
wsl --set-default-version 2
```

**Inside WSL, install dependencies:**
```bash
# Clone/navigate to this directory
cd Finetuning

# Install Python packages
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
pip install --no-deps "xformers<0.0.27" "trl<0.9.0" peft accelerate bitsandbytes
pip install -r requirements.txt

# Verify GPU is accessible
nvidia-smi
```

### 3. Generate Training Data

**Option A: Synthetic Data Generation (Recommended)**

Create a `.env` file with your API keys:
```bash
OPENAI_API_KEY=your-key-here
# OR
ANTHROPIC_API_KEY=your-key-here
```

Generate data for each topic:
```bash
# Firewall & Network Devices
python scripts/generate_synthetic_data.py --provider openai --topic cisco-firewall --count 200
python scripts/generate_synthetic_data.py --provider openai --topic palo-alto --count 150

# Cloud Security
python scripts/generate_synthetic_data.py --provider openai --topic aws-security --count 200
python scripts/generate_synthetic_data.py --provider openai --topic azure-security --count 150

# Threat Detection
python scripts/generate_synthetic_data.py --provider openai --topic ids-ips --count 150
python scripts/generate_synthetic_data.py --provider openai --topic siem-logs --count 150

# Troubleshooting
python scripts/generate_synthetic_data.py --provider openai --topic network-troubleshooting --count 150
```

**Option B: Manual Dataset Creation**

Create `data/processed/network_security_qa.json` in ChatML format:
```json
[
  {
    "conversations": [
      {
        "from": "human",
        "value": "How do I configure port security on a Cisco switch?"
      },
      {
        "from": "gpt",
        "value": "To configure port security on a Cisco switch...[detailed answer]"
      }
    ]
  }
]
```

**Merge and validate:**
```bash
# Combine all topic files into one dataset
cat data/synthetic/*.json > data/processed/network_security_qa.json

# Validate dataset
python scripts/validate_dataset.py data/processed/network_security_qa.json --stats
```

### 4. Train the Model

**Start Jupyter in WSL:**
```bash
jupyter notebook --no-browser --port=8888
```

Then access the notebook from Windows browser and open `notebooks/train_llama3_network_security.ipynb`.

**Run all cells in order:**
1. Install dependencies (if needed)
2. Load Llama 3.1 8B Instruct (4-bit)
3. Configure LoRA adapters
4. Load your dataset
5. Apply chat template
6. Configure training parameters
7. Initialize trainer
8. **Start training** (this takes 3-7 hours depending on dataset size)
9. Test the model
10. Save LoRA adapter
11. Export to GGUF for Ollama

**Monitor training:**
- Watch for decreasing loss values (target: 0.5-1.0)
- Training loss appears as numbers during training
- If loss doesn't decrease, reduce learning rate

### 5. Deploy to Ollama

**Install Ollama on Windows:**
- Download from [ollama.ai/download](https://ollama.ai/download)
- Install on Windows (not in WSL)

**Import your model:**
```bash
# In Windows terminal or WSL
cd models
ollama create network-security-expert -f Modelfile
```

**Test your model:**
```bash
ollama run network-security-expert
```

Try these test prompts:
- "How do I configure port security on a Cisco switch?"
- "Explain AWS Security Groups vs Network ACLs"
- "What Snort rules would detect SQL injection?"
- "My VPN tunnel keeps dropping. How do I troubleshoot?"

### 6. Use Your Model

**Via CLI:**
```bash
ollama run network-security-expert
```

**Via API:**
```bash
curl http://localhost:11434/api/generate -d '{
  "model": "network-security-expert",
  "prompt": "How do I secure an AWS S3 bucket?"
}'
```

**With Open WebUI (Optional):**
- Install Open WebUI for a ChatGPT-like interface
- Access at http://localhost:3000
- Select your network-security-expert model

## Training Details

### Hyperparameters

```python
Model: unsloth/llama-3.1-8b-Instruct-bnb-4bit
Method: QLoRA (4-bit quantization)
LoRA rank: 16
Batch size: 2 (effective: 8 with gradient accumulation)
Learning rate: 2e-4
Epochs: 3
Max sequence length: 2048
```

### Dataset Requirements

**Minimum:** 1,000 examples for basic specialization
**Recommended:** 3,000-5,000 examples for strong performance
**Optimal:** 10,000+ examples for expert-level capabilities

**Format:** ChatML/ShareGPT with conversational Q&A pairs
**Balance:** 70% single-turn, 30% multi-turn conversations
**Topics:**
- Firewall & Network Devices: ~35%
- Cloud Security: ~35%
- Threat Detection & IR: ~30%

### Training Time

On RTX 4090:
- 3,000 examples, 3 epochs: ~3-4 hours
- 5,000 examples, 3 epochs: ~5-7 hours

On RTX 3060 12GB:
- 3,000 examples, 3 epochs: ~6-8 hours
- 5,000 examples, 3 epochs: ~10-14 hours

## Quantization Options

The GGUF conversion creates three versions:

| Quantization | File Size | VRAM Required | Quality | Speed | Recommended For |
|--------------|-----------|---------------|---------|-------|-----------------|
| Q4_K_M       | ~4.5GB    | 6GB           | Good    | Fast  | Quick testing   |
| Q5_K_M       | ~5.5GB    | 8GB           | Better  | Med   | **Production**  |
| Q8_0         | ~8GB      | 10GB          | Best    | Slow  | Highest quality |

To use a different quantization, edit `models/Modelfile`:
```
FROM ./gguf/unsloth.Q4_K_M.gguf  # Change to Q4_K_M or Q8_0
```

## Troubleshooting

### Training Issues

**CUDA Out of Memory (OOM)**
```python
# Reduce batch size in training notebook
per_device_train_batch_size = 1
gradient_accumulation_steps = 8
```

**Loss not decreasing**
```python
# Try lower learning rate
learning_rate = 1e-4  # or 5e-5
```

**Overfitting (loss near 0)**
```python
# Reduce epochs
num_train_epochs = 1  # or 2
```

### Ollama Issues

**Model won't load**
- Check GGUF file path in Modelfile is correct
- Try Q4_K_M first (most compatible)
- Verify file isn't corrupted (should be 4-8GB)

**Poor quality responses**
- Ensure you loaded the fine-tuned model, not base Llama
- Check training loss was < 1.0
- Increase dataset size and quality
- Train for more epochs

## Advanced Topics

### Merging Multiple Datasets

```python
import json

datasets = [
    "data/synthetic/cisco-firewall.json",
    "data/synthetic/aws-security.json",
    "data/synthetic/ids-ips.json"
]

combined = []
for file in datasets:
    with open(file) as f:
        combined.extend(json.load(f))

with open("data/processed/network_security_qa.json", "w") as f:
    json.dump(combined, f, indent=2)
```

### Continuous Improvement

1. Collect user feedback on responses
2. Identify weak areas or incorrect responses
3. Generate additional training data for those topics
4. Retrain with expanded dataset
5. A/B test new version vs old version

### RAG Enhancement (Optional)

Combine with Retrieval-Augmented Generation for:
- Latest CVE information
- Up-to-date vendor documentation
- Recent security advisories
- Dynamic threat intelligence

## Resources

- [Unsloth Documentation](https://github.com/unslothai/unsloth)
- [Ollama Documentation](https://github.com/ollama/ollama)
- [Fine-tuning Guide](https://unsloth.ai/blog/)
- [Project Plan](../.claude/plans/humble-zooming-bachman.md)

## License

This project uses:
- Llama 3 (Meta license)
- Unsloth (Apache 2.0)
- Training scripts (MIT)

Check individual licenses for commercial use restrictions.

## Acknowledgments

- [Unsloth](https://unsloth.ai) for efficient fine-tuning
- [Meta AI](https://ai.meta.com) for Llama 3
- [Ollama](https://ollama.ai) for local inference

## Support

For issues or questions:
1. Check troubleshooting section above
2. Review the comprehensive plan file
3. Validate dataset quality
4. Check Unsloth/Ollama documentation

---

**Built with:** Unsloth + Llama 3 + Ollama
**Training Method:** QLoRA (4-bit)
**Deployment:** Local Windows/WSL

Happy network securing! 🛡️🔒
