# Quick Start Guide - Network Security Expert Fine-tuning

Get started training your Network Security expert model in 5 steps.

## Prerequisites Checklist

- [ ] Windows 10/11 with WSL2 installed
- [ ] NVIDIA GPU with 12GB+ VRAM
- [ ] 50GB+ free disk space
- [ ] OpenAI or Anthropic API key

## Step 1: Environment Setup (15 minutes)

**Install WSL2 (if needed):**
```powershell
# In Windows PowerShell (Administrator)
wsl --install
# Restart your computer
```

**Inside WSL, install Python packages:**
```bash
cd /mnt/c/Users/dorsa/Finetuning

# Install Unsloth
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"
pip install --no-deps "xformers<0.0.27" "trl<0.9.0" peft accelerate bitsandbytes

# Install other dependencies
pip install -r requirements.txt

# Verify GPU
nvidia-smi  # Should show your GPU
```

## Step 2: Generate Training Data (2-8 hours)

**Create .env file with your API key:**
```bash
cp .env.example .env
nano .env  # Add your OPENAI_API_KEY or ANTHROPIC_API_KEY
```

**Generate data for each topic:**
```bash
# Cisco Firewall (200 examples) - ~10 minutes
python scripts/generate_synthetic_data.py --provider openai --topic cisco-firewall --count 200

# AWS Security (200 examples) - ~10 minutes
python scripts/generate_synthetic_data.py --provider openai --topic aws-security --count 200

# Palo Alto (150 examples) - ~8 minutes
python scripts/generate_synthetic_data.py --provider openai --topic palo-alto --count 150

# Azure Security (150 examples) - ~8 minutes
python scripts/generate_synthetic_data.py --provider openai --topic azure-security --count 150

# IDS/IPS (150 examples) - ~8 minutes
python scripts/generate_synthetic_data.py --provider openai --topic ids-ips --count 150

# SIEM (150 examples) - ~8 minutes
python scripts/generate_synthetic_data.py --provider openai --topic siem-logs --count 150

# Troubleshooting (150 examples) - ~8 minutes
python scripts/generate_synthetic_data.py --provider openai --topic network-troubleshooting --count 150
```

**Merge all datasets:**
```bash
# Combine into one file
python -c "
import json
import glob

all_data = []
for file in glob.glob('data/synthetic/*.json'):
    with open(file) as f:
        all_data.extend(json.load(f))

with open('data/processed/network_security_qa.json', 'w') as f:
    json.dump(all_data, f, indent=2)

print(f'Total examples: {len(all_data)}')
"
```

**Validate your dataset:**
```bash
python scripts/validate_dataset.py data/processed/network_security_qa.json --stats --sample 3
```

## Step 3: Train the Model (3-7 hours)

**Start Jupyter Notebook:**
```bash
jupyter notebook --no-browser --port=8888
```

**Copy the URL that appears (looks like: http://localhost:8888/?token=...)**

**Open in Windows browser and navigate to:**
```
notebooks/train_llama3_network_security.ipynb
```

**Run all cells in order:**
1. Skip cell 1 if packages already installed
2. Run cells 2-8 (setup and configuration)
3. Cell 9: **Start Training** - This takes 3-7 hours
   - Watch the loss decrease (target: 0.5-1.0)
   - Don't close the browser or stop WSL
4. Run cells 10-11 after training completes

**Training complete when you see:**
```
✅ TRAINING COMPLETE!
Final loss: 0.XXX
```

## Step 4: Export to Ollama (30 minutes)

**Continue in the same notebook, run cell 12:**
- Merges LoRA with base model
- Converts to GGUF format (Q4_K_M, Q5_K_M, Q8_0)
- Creates 3 quantized versions

**Install Ollama on Windows:**
- Download from [ollama.ai/download](https://ollama.ai/download)
- Run installer
- Ollama should start automatically

**Import your model (in Windows Command Prompt or WSL):**
```bash
cd C:\Users\dorsa\Finetuning\models
ollama create network-security-expert -f Modelfile
```

## Step 5: Test Your Model (5 minutes)

**Start a conversation:**
```bash
ollama run network-security-expert
```

**Try these prompts:**

1. "How do I configure port security on a Cisco switch to limit MAC addresses per port?"

2. "I'm seeing dropped packets on my AWS EC2 instances. Security groups were just updated. How do I troubleshoot this?"

3. "What Snort rules would I write to detect SQL injection attempts targeting a web application?"

4. "Explain the difference between AWS Security Groups and Network ACLs. When should I use each?"

5. "My site-to-site VPN tunnel keeps dropping every few hours. Walk me through systematic troubleshooting steps."

**Expected behavior:**
- Detailed technical responses with specific commands
- Step-by-step procedures with explanations
- Security warnings and best practices
- Vendor-specific syntax (Cisco IOS, AWS CLI, etc.)

## Troubleshooting Quick Fixes

### CUDA Out of Memory during training
**In notebook, change:**
```python
per_device_train_batch_size = 1  # Reduce from 2 to 1
gradient_accumulation_steps = 8   # Increase from 4 to 8
```

### Loss not decreasing
**In notebook, change:**
```python
learning_rate = 1e-4  # Reduce from 2e-4
```

### Ollama model won't load
```bash
# Try Q4_K_M instead (in models/Modelfile)
FROM ./gguf/unsloth.Q4_K_M.gguf
ollama create network-security-expert -f Modelfile
```

### Dataset validation fails
```bash
# Check for JSON formatting errors
python scripts/validate_dataset.py data/processed/network_security_qa.json
# Fix errors shown, then re-validate
```

## Next Steps After Successful Training

1. **Test extensively** with real network security scenarios
2. **Collect feedback** on response quality
3. **Generate more data** for weak areas
4. **Retrain** with expanded dataset (iterative improvement)
5. **Deploy in production** via Ollama API or Open WebUI
6. **Share your model** on Hugging Face (optional)

## Time Estimates

| Phase | Time | Can Skip? |
|-------|------|-----------|
| Environment Setup | 15 min | No |
| Data Generation | 2-8 hrs | Partially* |
| Training | 3-7 hrs | No |
| GGUF Export | 30 min | No |
| Testing | 5 min | No |
| **Total** | **6-16 hrs** | |

*Minimum 1,000 examples required, but 3,000-5,000 recommended

## Success Criteria

Your model is ready when it can:
- ✅ Provide accurate Cisco/Palo Alto commands
- ✅ Explain AWS security concepts clearly
- ✅ Offer step-by-step troubleshooting
- ✅ Include security warnings appropriately
- ✅ Maintain context in multi-turn conversations
- ✅ Reference best practices and compliance standards

## Getting Help

1. Check [README.md](README.md) for detailed documentation
2. Review the [comprehensive plan](../.claude/plans/humble-zooming-bachman.md)
3. Validate dataset quality if responses are poor
4. Check training loss - should be 0.5-1.0

---

**Ready to start?** Begin with Step 1! 🚀

**Questions?** Most issues are covered in the README troubleshooting section.
