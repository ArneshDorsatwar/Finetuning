#!/bin/bash
# Setup script for local fine-tuning environment
# For Ubuntu with RTX 3090

set -e

echo "========================================"
echo "FireWeave Fine-Tuning Environment Setup"
echo "========================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check Python version
echo -e "${YELLOW}Checking Python version...${NC}"
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d'.' -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d'.' -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo -e "${RED}Error: Python 3.10+ required. Found: $PYTHON_VERSION${NC}"
    echo "Install Python 3.10+ and try again."
    exit 1
fi
echo -e "${GREEN}Python $PYTHON_VERSION found${NC}"

# Check NVIDIA driver
echo ""
echo -e "${YELLOW}Checking NVIDIA driver...${NC}"
if ! command -v nvidia-smi &> /dev/null; then
    echo -e "${RED}Error: nvidia-smi not found. Install NVIDIA drivers first.${NC}"
    exit 1
fi

GPU_NAME=$(nvidia-smi --query-gpu=name --format=csv,noheader | head -n1)
GPU_MEMORY=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader | head -n1)
echo -e "${GREEN}GPU: $GPU_NAME ($GPU_MEMORY)${NC}"

# Create virtual environment
VENV_DIR="venv_training"
echo ""
echo -e "${YELLOW}Creating virtual environment: $VENV_DIR${NC}"

if [ -d "$VENV_DIR" ]; then
    echo "Virtual environment already exists. Skipping creation."
else
    python3 -m venv $VENV_DIR
    echo -e "${GREEN}Virtual environment created${NC}"
fi

# Activate virtual environment
echo ""
echo -e "${YELLOW}Activating virtual environment...${NC}"
source $VENV_DIR/bin/activate

# Upgrade pip
echo ""
echo -e "${YELLOW}Upgrading pip...${NC}"
pip install --upgrade pip

# Install PyTorch with CUDA
echo ""
echo -e "${YELLOW}Installing PyTorch with CUDA support...${NC}"
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu121

# Verify CUDA access
echo ""
echo -e "${YELLOW}Verifying CUDA access from PyTorch...${NC}"
python3 -c "import torch; print(f'CUDA available: {torch.cuda.is_available()}'); print(f'CUDA version: {torch.version.cuda}'); print(f'GPU: {torch.cuda.get_device_name(0) if torch.cuda.is_available() else \"N/A\"}')"

if ! python3 -c "import torch; assert torch.cuda.is_available()"; then
    echo -e "${RED}Error: CUDA not accessible from PyTorch${NC}"
    exit 1
fi
echo -e "${GREEN}CUDA verified${NC}"

# Install Unsloth
echo ""
echo -e "${YELLOW}Installing Unsloth (this may take a few minutes)...${NC}"
pip install "unsloth[colab-new] @ git+https://github.com/unslothai/unsloth.git"

# Install other dependencies
echo ""
echo -e "${YELLOW}Installing training dependencies...${NC}"
pip install --no-deps xformers "trl<0.9.0" peft accelerate bitsandbytes

# Install additional packages
echo ""
echo -e "${YELLOW}Installing additional packages...${NC}"
pip install datasets transformers sentencepiece protobuf

# Verify installation
echo ""
echo -e "${YELLOW}Verifying installation...${NC}"
python3 << 'EOF'
import sys
print("Checking imports...")

try:
    import torch
    print(f"  torch: {torch.__version__}")
except ImportError as e:
    print(f"  ERROR: torch - {e}")
    sys.exit(1)

try:
    from unsloth import FastLanguageModel
    print("  unsloth: OK")
except ImportError as e:
    print(f"  ERROR: unsloth - {e}")
    sys.exit(1)

try:
    from transformers import TrainingArguments
    import transformers
    print(f"  transformers: {transformers.__version__}")
except ImportError as e:
    print(f"  ERROR: transformers - {e}")
    sys.exit(1)

try:
    from trl import SFTTrainer
    import trl
    print(f"  trl: {trl.__version__}")
except ImportError as e:
    print(f"  ERROR: trl - {e}")
    sys.exit(1)

try:
    from datasets import load_dataset
    import datasets
    print(f"  datasets: {datasets.__version__}")
except ImportError as e:
    print(f"  ERROR: datasets - {e}")
    sys.exit(1)

try:
    from peft import LoraConfig
    import peft
    print(f"  peft: {peft.__version__}")
except ImportError as e:
    print(f"  ERROR: peft - {e}")
    sys.exit(1)

print("")
print("All dependencies verified successfully!")
EOF

echo ""
echo "========================================"
echo -e "${GREEN}Setup Complete!${NC}"
echo "========================================"
echo ""
echo "To activate the environment, run:"
echo "  source $VENV_DIR/bin/activate"
echo ""
echo "To start training, run:"
echo "  python scripts/train_local.py --help"
echo ""
echo "Example training command:"
echo "  python scripts/train_local.py \\"
echo "    --data-path data/processed/all_training_data.json \\"
echo "    --epochs 3 \\"
echo "    --save-gguf"
echo ""
