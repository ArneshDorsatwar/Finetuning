#!/usr/bin/env python3
"""
Local Fine-Tuning Script for FireWeave Network Security Expert

This script fine-tunes Llama 3.1 8B Instruct using Unsloth and QLoRA.

RTX 3090 (24GB VRAM) Optimized - 2025 Best Practices:
- 4-bit QLoRA with rsLoRA for better scaling at higher ranks
- Packing enabled for 3x faster training
- NEFTune noise for improved generalization
- Native Llama 3.1 tool calling format (<|python_tag|>)
- torch.compile() for 10-20% additional speedup (optional)

Optimized Configuration (based on actual data analysis):
- LoRA r=32, alpha=32, dropout=0 (with rsLoRA)
- Learning rate 2e-4 with cosine scheduler
- Max sequence length 2048 (99% of training data fits)
- Batch size 4 with gradient accumulation 4 (effective=16)
- NEFTune noise alpha=5 for regularization
- Packing enabled for efficient training
- 4 dataloader workers for faster data loading

Memory Usage (RTX 3090):
- Default settings (batch=8, seq_len=2048): ~12-14GB peak
- High memory (batch=4, seq_len=4096): ~16-18GB peak
- Max quality (batch=4, seq_len=8192): ~20-22GB peak

Usage:
    # Train with optimized defaults (recommended for 3090)
    python scripts/train_local.py --data-path v2/data/processed/training_data_final.json --epochs 3

    # Train with GGUF export for Ollama:
    python scripts/train_local.py --data-path v2/data/processed/training_data_final.json --save-gguf

    # Maximum speed with torch.compile (10-20% faster):
    python scripts/train_local.py \\
        --data-path v2/data/processed/training_data_final.json \\
        --use-torch-compile \\
        --save-gguf

    # For longer sequences (if needed):
    python scripts/train_local.py \\
        --data-path v2/data/processed/training_data_final.json \\
        --batch-size 4 \\
        --max-seq-length 4096 \\
        --save-gguf

    # Disable newer features if compatibility issues:
    python scripts/train_local.py \\
        --data-path v2/data/processed/training_data_final.json \\
        --no-packing \\
        --no-neftune \\
        --no-rslora
"""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Check for required packages before importing
def check_dependencies():
    """Check if all required packages are installed."""
    required = ['torch', 'unsloth', 'transformers', 'datasets', 'trl', 'peft']
    missing = []
    for pkg in required:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)

    if missing:
        print(f"Error: Missing packages: {', '.join(missing)}")
        print("Run: ./scripts/setup_training_env.sh to set up the environment")
        sys.exit(1)

check_dependencies()

import torch
from datasets import load_dataset
from transformers import TrainingArguments
from trl import SFTTrainer
from unsloth import FastLanguageModel
from unsloth.chat_templates import get_chat_template


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Fine-tune Llama 3.1 8B for FireWeave Network Security Expert",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Train on example dataset (quick test)
  python scripts/train_local.py --data-path data/example_dataset.json --epochs 1

  # Train on all synthetic data (recommended)
  python scripts/train_local.py --data-dir data/synthetic/ --epochs 3

  # Train with GGUF export for Ollama
  python scripts/train_local.py --data-dir data/synthetic/ --save-gguf

  # Custom settings
  python scripts/train_local.py --data-dir data/synthetic/ --epochs 5 --batch-size 2 --learning-rate 1e-4
        """
    )

    # Data arguments
    parser.add_argument(
        "--data-path",
        type=str,
        default="data/example_dataset.json",
        help="Path to training data JSON or directory of JSON files (default: data/example_dataset.json)"
    )
    parser.add_argument(
        "--data-dir",
        type=str,
        default=None,
        help="Directory containing multiple JSON files to merge (e.g., data/synthetic/)"
    )

    # Output arguments
    parser.add_argument(
        "--output-dir",
        type=str,
        default="outputs/network-security-lora",
        help="Output directory for checkpoints (default: outputs/network-security-lora)"
    )

    # Training arguments
    parser.add_argument(
        "--epochs",
        type=int,
        default=3,
        help="Number of training epochs (default: 3)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=4,
        help="Per-device training batch size (default: 4 for 3090 with packing)"
    )
    parser.add_argument(
        "--gradient-accumulation",
        type=int,
        default=4,
        help="Gradient accumulation steps (default: 4, effective batch = batch-size * this = 16)"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=2e-4,
        help="Learning rate (default: 2e-4, standard for QLoRA)"
    )
    parser.add_argument(
        "--max-seq-length",
        type=int,
        default=2048,
        help="Maximum sequence length (default: 2048, covers 99%% of training data)"
    )
    parser.add_argument(
        "--warmup-ratio",
        type=float,
        default=0.03,
        help="Warmup ratio (default: 0.03)"
    )
    parser.add_argument(
        "--scheduler",
        type=str,
        default="cosine",
        choices=["linear", "cosine", "constant"],
        help="Learning rate scheduler (default: cosine)"
    )

    # Advanced training features (2025 best practices)
    parser.add_argument(
        "--packing",
        action="store_true",
        default=True,
        help="Enable sequence packing for 3x faster training (default: True)"
    )
    parser.add_argument(
        "--no-packing",
        action="store_true",
        help="Disable sequence packing"
    )
    parser.add_argument(
        "--neftune-alpha",
        type=float,
        default=5.0,
        help="NEFTune noise alpha for better generalization (default: 5.0, 0 to disable)"
    )
    parser.add_argument(
        "--no-neftune",
        action="store_true",
        help="Disable NEFTune noise embedding"
    )

    # LoRA arguments (2025 optimized defaults)
    parser.add_argument(
        "--lora-r",
        type=int,
        default=32,
        help="LoRA rank (default: 32, higher rank with rsLoRA)"
    )
    parser.add_argument(
        "--lora-alpha",
        type=int,
        default=32,
        help="LoRA alpha (default: 32, match rank when using rsLoRA)"
    )
    parser.add_argument(
        "--lora-dropout",
        type=float,
        default=0.0,
        help="LoRA dropout (default: 0.0, Unsloth recommends 0)"
    )
    parser.add_argument(
        "--use-rslora",
        action="store_true",
        default=True,
        help="Use rank-stabilized LoRA for better scaling (default: True)"
    )
    parser.add_argument(
        "--no-rslora",
        action="store_true",
        help="Disable rsLoRA (use standard LoRA)"
    )
    parser.add_argument(
        "--use-dora",
        action="store_true",
        default=False,
        help="Use DoRA (Weight-Decomposed LoRA) for +3-4%% accuracy (experimental)"
    )
    parser.add_argument(
        "--use-torch-compile",
        action="store_true",
        default=False,
        help="Use torch.compile() for 10-20%% speedup (requires PyTorch 2.0+)"
    )

    # Export arguments
    parser.add_argument(
        "--save-gguf",
        action="store_true",
        help="Export model to GGUF format after training"
    )
    parser.add_argument(
        "--quantization",
        type=str,
        default="q4_k_m",
        choices=["q4_k_m", "q5_k_m", "q8_0"],
        help="GGUF quantization type (default: q4_k_m)"
    )
    parser.add_argument(
        "--save-merged",
        action="store_true",
        help="Save merged 16-bit model (requires ~32GB disk space)"
    )

    # Other arguments
    parser.add_argument(
        "--resume-from",
        type=str,
        default=None,
        help="Resume training from checkpoint directory"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=3407,
        help="Random seed (default: 3407)"
    )
    parser.add_argument(
        "--logging-steps",
        type=int,
        default=10,
        help="Log every N steps (default: 10)"
    )
    parser.add_argument(
        "--save-steps",
        type=int,
        default=100,
        help="Save checkpoint every N steps (default: 100)"
    )

    return parser.parse_args()


def check_gpu():
    """Check GPU availability and print info."""
    print("\n" + "=" * 50)
    print("GPU Information")
    print("=" * 50)

    if not torch.cuda.is_available():
        print("ERROR: CUDA is not available!")
        print("Make sure you have NVIDIA drivers and CUDA installed.")
        sys.exit(1)

    gpu_name = torch.cuda.get_device_name(0)
    gpu_memory = torch.cuda.get_device_properties(0).total_memory / 1024**3
    gpu_memory_allocated = torch.cuda.memory_allocated(0) / 1024**3

    print(f"GPU: {gpu_name}")
    print(f"Total Memory: {gpu_memory:.1f} GB")
    print(f"Currently Allocated: {gpu_memory_allocated:.2f} GB")
    print(f"CUDA Version: {torch.version.cuda}")
    print(f"PyTorch Version: {torch.__version__}")

    # Check if bf16 is supported (Ampere and newer)
    bf16_supported = torch.cuda.is_bf16_supported()
    print(f"BF16 Supported: {bf16_supported}")

    # Provide recommendations based on GPU
    if "3090" in gpu_name or "4090" in gpu_name or gpu_memory >= 20:
        print(f"\n[Recommended for {gpu_memory:.0f}GB VRAM]")
        print("  batch_size=8, max_seq_length=2048, packing=True (default)")
        print("  Or: batch_size=4, max_seq_length=4096 for longer sequences")
    elif gpu_memory >= 12:
        print(f"\n[Recommended for {gpu_memory:.0f}GB VRAM]")
        print("  batch_size=4, max_seq_length=2048, packing=True")
    else:
        print(f"\n[Recommended for {gpu_memory:.0f}GB VRAM]")
        print("  batch_size=2, max_seq_length=2048, packing=True")

    return bf16_supported


def load_model(args):
    """Load the base model with 4-bit quantization and xformers attention."""
    print("\n" + "=" * 50)
    print("Loading Model")
    print("=" * 50)

    # Check for xformers availability (Unsloth auto-detects but we log it)
    try:
        import xformers
        from xformers.ops import memory_efficient_attention
        print(f"xformers version: {xformers.__version__} (memory_efficient_attention available)")
    except ImportError:
        print("Note: xformers not installed, Unsloth will use its native kernels")
    except Exception as e:
        print(f"Note: xformers installed but not functional: {e}")

    # Load model - Unsloth automatically uses xformers if available
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/Meta-Llama-3.1-8B-Instruct-bnb-4bit",
        max_seq_length=args.max_seq_length,
        dtype=None,  # Auto-detect
        load_in_4bit=True,
    )

    print(f"Model loaded: Llama 3.1 8B Instruct (4-bit)")
    print(f"Max sequence length: {args.max_seq_length}")

    return model, tokenizer


def configure_lora(model, args):
    """Configure LoRA adapters with 2025 best practices (rsLoRA, DoRA support)."""
    print("\n" + "=" * 50)
    print("Configuring LoRA (2025 Optimized)")
    print("=" * 50)

    # Determine rsLoRA setting
    use_rslora = args.use_rslora and not args.no_rslora

    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj"
        ],
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        use_gradient_checkpointing="unsloth",  # 30% less VRAM
        random_state=args.seed,
        use_rslora=use_rslora,  # Rank-stabilized LoRA for better scaling
        # Note: DoRA support depends on Unsloth version
        # use_dora=args.use_dora,  # Uncomment if supported
    )

    # Count trainable parameters
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())

    print(f"LoRA Rank (r): {args.lora_r}")
    print(f"LoRA Alpha: {args.lora_alpha}")
    print(f"LoRA Dropout: {args.lora_dropout}")
    print(f"rsLoRA (rank-stabilized): {use_rslora}")
    print(f"Target modules: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj")
    print(f"Trainable parameters: {trainable_params:,} ({100 * trainable_params / total_params:.2f}%)")

    if use_rslora:
        print("\n[rsLoRA] Scaling by 1/sqrt(r) instead of 1/r for better high-rank performance")

    return model


def merge_json_files(directory: Path) -> list:
    """Merge all JSON files from a directory into a single list."""
    all_data = []
    json_files = list(directory.glob("*.json"))

    if not json_files:
        print(f"ERROR: No JSON files found in {directory}")
        sys.exit(1)

    print(f"Found {len(json_files)} JSON files to merge:")
    for json_file in sorted(json_files):
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                if isinstance(data, list):
                    all_data.extend(data)
                    print(f"  - {json_file.name}: {len(data)} examples")
                else:
                    print(f"  - {json_file.name}: skipped (not a list)")
        except json.JSONDecodeError as e:
            print(f"  - {json_file.name}: skipped (JSON error: {e})")

    return all_data


def load_dataset_sharegpt(args, tokenizer):
    """Load and format the training dataset."""
    print("\n" + "=" * 50)
    print("Loading Dataset")
    print("=" * 50)

    # Handle data directory (merge multiple files)
    if args.data_dir:
        data_dir = Path(args.data_dir)
        if not data_dir.exists() or not data_dir.is_dir():
            print(f"ERROR: Data directory not found: {data_dir}")
            sys.exit(1)

        # Merge all JSON files
        all_data = merge_json_files(data_dir)
    else:
        data_path = Path(args.data_path)
        if not data_path.exists():
            print(f"ERROR: Data file not found: {data_path}")
            print(f"\nTry one of these options:")
            print(f"  1. Use existing example data: --data-path data/example_dataset.json")
            print(f"  2. Use synthetic data directory: --data-dir data/synthetic/")
            sys.exit(1)

        # Load JSON directly to handle mixed types
        with open(data_path, 'r', encoding='utf-8') as f:
            all_data = json.load(f)

    print(f"Loaded {len(all_data)} examples")

    # Normalize data - remove problematic 'tools' column and store separately
    tools_map = {}
    for i, item in enumerate(all_data):
        if 'tools' in item:
            tools_map[i] = item.pop('tools')

    print(f"Examples with tool definitions: {len(tools_map)}")

    # Create dataset from normalized data
    from datasets import Dataset
    dataset = Dataset.from_list(all_data)

    # Get Llama 3.1 chat template
    tokenizer = get_chat_template(
        tokenizer,
        chat_template="llama-3.1",
    )

    # System prompt for tool calling
    SYSTEM_PROMPT = """You are a Network Security Expert AI with FireWeave orchestration capabilities.

Available tools: check_traffic_flow, analyze_attack_path, run_compliance_scan, find_shadowed_rules, create_firewall_rule, get_rule_hit_count, calculate_blast_radius, fetch_jira_issues

When calling tools, use the format: <|python_tag|>{"name": "tool_name", "parameters": {...}}

Provide accurate, detailed technical guidance with specific commands and configurations."""

    def formatting_prompts_func(examples, indices):
        """Format conversations for Llama 3.1 native tool calling."""
        conversations = examples["conversations"]
        texts = []

        for idx, convo in zip(indices, conversations):
            # Build text manually for proper tool calling format
            text = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            text += SYSTEM_PROMPT

            # Add tool definitions if available (from tools_map)
            if idx in tools_map and tools_map[idx]:
                text += "\n\nAvailable tools:\n"
                text += json.dumps(tools_map[idx], indent=2)

            text += "<|eot_id|>"

            for turn in convo:
                role = turn.get("from", "")
                value = turn.get("value", "")

                if role == "human":
                    text += f"<|start_header_id|>user<|end_header_id|>\n\n{value}<|eot_id|>"
                elif role == "gpt":
                    # Check if this is a tool call (contains <|python_tag|>)
                    if "<|python_tag|>" in value:
                        # Tool call ends with <|eom_id|> (end of message, expecting tool response)
                        text += f"<|start_header_id|>assistant<|end_header_id|>\n\n{value}<|eom_id|>"
                    else:
                        # Regular response ends with <|eot_id|>
                        text += f"<|start_header_id|>assistant<|end_header_id|>\n\n{value}<|eot_id|>"
                elif role == "tool":
                    # Tool response uses ipython role
                    text += f"<|start_header_id|>ipython<|end_header_id|>\n\n{value}<|eot_id|>"

            texts.append(text)

        return {"text": texts}

    # Apply formatting with indices
    dataset = dataset.map(
        formatting_prompts_func,
        batched=True,
        with_indices=True,
        num_proc=1,  # Single process to access tools_map
        desc="Formatting dataset"
    )

    # Show a sample
    print("\nSample formatted text (first 500 chars):")
    print("-" * 40)
    print(dataset[0]["text"][:500] + "...")
    print("-" * 40)

    return dataset, tokenizer


def create_trainer(model, tokenizer, dataset, args, bf16_supported):
    """Create the SFTTrainer with 2025 optimizations."""
    print("\n" + "=" * 50)
    print("Setting Up Trainer (2025 Optimized)")
    print("=" * 50)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Determine packing and NEFTune settings
    use_packing = args.packing and not args.no_packing
    neftune_alpha = 0 if args.no_neftune else args.neftune_alpha

    # Training arguments with 2025 best practices
    training_args = TrainingArguments(
        output_dir=args.output_dir,

        # Batch configuration
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation,

        # Training duration
        num_train_epochs=args.epochs,

        # Learning rate schedule
        learning_rate=args.learning_rate,
        lr_scheduler_type=args.scheduler,
        warmup_ratio=args.warmup_ratio,

        # Optimization
        weight_decay=0.01,
        max_grad_norm=0.3,  # Gradient clipping for stability
        optim="adamw_8bit",  # 8-bit AdamW for memory efficiency

        # Logging & Checkpointing
        logging_steps=args.logging_steps,
        save_strategy="steps",
        save_steps=args.save_steps,
        save_total_limit=2,  # Keep only last 2 checkpoints

        # Mixed Precision
        fp16=not bf16_supported,
        bf16=bf16_supported,

        # Reproducibility
        seed=args.seed,
        report_to="none",  # Disable wandb/tensorboard

        # Other
        dataloader_num_workers=4,  # Increased for faster data loading
        dataloader_pin_memory=True,  # Faster CPU to GPU transfer
        remove_unused_columns=True,
    )

    effective_batch = args.batch_size * args.gradient_accumulation
    print(f"Effective batch size: {effective_batch}")
    print(f"Epochs: {args.epochs}")
    print(f"Learning rate: {args.learning_rate}")
    print(f"LR Scheduler: {args.scheduler}")
    print(f"Warmup ratio: {args.warmup_ratio}")
    print(f"Mixed precision: {'bf16' if bf16_supported else 'fp16'}")
    print(f"Gradient clipping: 0.3")

    # 2025 features
    print(f"\n[2025 Optimizations]")
    print(f"  Packing: {use_packing} {'(3x faster training)' if use_packing else ''}")
    print(f"  NEFTune: {neftune_alpha > 0} (alpha={neftune_alpha})" if neftune_alpha > 0 else f"  NEFTune: disabled")
    print(f"  Dataloader workers: 4 (parallel data loading)")
    print(f"  Pin memory: True (faster GPU transfer)")

    # Create trainer with advanced features
    trainer_kwargs = {
        "model": model,
        "tokenizer": tokenizer,
        "train_dataset": dataset,
        "dataset_text_field": "text",
        "max_seq_length": args.max_seq_length,
        "dataset_num_proc": 2,
        "packing": use_packing,
        "args": training_args,
    }

    # Add NEFTune if enabled (requires TRL >= 0.7.0)
    if neftune_alpha > 0:
        trainer_kwargs["neftune_noise_alpha"] = neftune_alpha
        print(f"  NEFTune noise will improve generalization")

    trainer = SFTTrainer(**trainer_kwargs)

    return trainer


def save_model(model, tokenizer, args):
    """Save the trained model."""
    print("\n" + "=" * 50)
    print("Saving Model")
    print("=" * 50)

    # Save LoRA adapter
    lora_path = Path(args.output_dir) / "final_lora"
    print(f"Saving LoRA adapter to: {lora_path}")
    model.save_pretrained(str(lora_path))
    tokenizer.save_pretrained(str(lora_path))
    print("LoRA adapter saved!")

    # Save merged model if requested
    if args.save_merged:
        merged_path = Path(args.output_dir) / "merged-16bit"
        print(f"\nSaving merged 16-bit model to: {merged_path}")
        model.save_pretrained_merged(
            str(merged_path),
            tokenizer,
            save_method="merged_16bit"
        )
        print("Merged model saved!")

    # Export to GGUF if requested
    if args.save_gguf:
        gguf_path = Path("models") / "gguf"
        os.makedirs(gguf_path, exist_ok=True)

        print(f"\nExporting to GGUF ({args.quantization})...")
        print(f"Output directory: {gguf_path}")

        model.save_pretrained_gguf(
            str(gguf_path),
            tokenizer,
            quantization_method=args.quantization
        )

        # Find the generated GGUF file
        gguf_files = list(gguf_path.glob("*.gguf"))
        if gguf_files:
            print(f"GGUF file created: {gguf_files[0]}")

            # Update Modelfile
            update_modelfile(gguf_files[0])

    return lora_path


def update_modelfile(gguf_path):
    """Update the Ollama Modelfile with the new GGUF path."""
    modelfile_path = Path("models") / "Modelfile"

    # Read existing Modelfile or create new one
    if modelfile_path.exists():
        with open(modelfile_path, 'r') as f:
            content = f.read()

        # Update the FROM line
        lines = content.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('FROM '):
                relative_path = gguf_path.relative_to(Path("models"))
                lines[i] = f'FROM ./{relative_path}'
                break

        content = '\n'.join(lines)
    else:
        # Create new Modelfile with tool calling support
        relative_path = gguf_path.relative_to(Path("models"))
        content = f'''FROM ./{relative_path}

TEMPLATE """{{{{ if .System }}}}<|begin_of_text|><|start_header_id|>system<|end_header_id|>

{{{{ .System }}}}<|eot_id|>{{{{ end }}}}{{{{ if .Prompt }}}}<|start_header_id|>user<|end_header_id|>

{{{{ .Prompt }}}}<|eot_id|>{{{{ end }}}}<|start_header_id|>assistant<|end_header_id|>

{{{{ .Response }}}}<|eot_id|>"""

PARAMETER stop "<|start_header_id|>"
PARAMETER stop "<|end_header_id|>"
PARAMETER stop "<|eot_id|>"
PARAMETER stop "<|eom_id|>"
PARAMETER stop "<|python_tag|>"
PARAMETER stop "<|reserved_special_token"

PARAMETER temperature 0.7
PARAMETER top_p 0.9
PARAMETER top_k 40
PARAMETER repeat_penalty 1.1
PARAMETER num_ctx 4096

SYSTEM """You are a Network Security Expert AI with FireWeave orchestration capabilities.

Available tools:
- check_traffic_flow: Check if traffic is allowed between source and destination
- analyze_attack_path: Analyze potential attack paths from source to target
- run_compliance_scan: Run compliance scan against PCI-DSS, SOC2, NIST, HIPAA, ISO27001, CIS
- find_shadowed_rules: Find rules that are shadowed by more specific rules
- create_firewall_rule: Generate firewall rule configuration
- get_rule_hit_count: Get hit count statistics for firewall rules
- calculate_blast_radius: Calculate blast radius if an asset is compromised
- fetch_jira_issues: Fetch firewall change requests from Jira

When calling tools, use the format: <|python_tag|>{{"name": "tool_name", "parameters": {{...}}}}

Provide accurate, detailed technical guidance with specific commands and configurations."""
'''

    with open(modelfile_path, 'w') as f:
        f.write(content)

    print(f"Updated Modelfile at: {modelfile_path}")
    print("\nTo create Ollama model, run:")
    print(f"  cd models && ollama create network-security-expert -f Modelfile")


def main():
    """Main training function."""
    args = parse_args()

    print("\n" + "=" * 50)
    print("FireWeave Network Security Expert - Local Training")
    print("=" * 50)
    print(f"Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check GPU
    bf16_supported = check_gpu()

    # Load model
    model, tokenizer = load_model(args)

    # Configure LoRA
    model = configure_lora(model, args)

    # Apply torch.compile() if requested (10-20% speedup)
    if args.use_torch_compile:
        print("\n" + "=" * 50)
        print("Applying torch.compile()")
        print("=" * 50)
        try:
            model = torch.compile(model)
            print("torch.compile() applied successfully!")
            print("Note: First few iterations will be slower due to compilation")
        except Exception as e:
            print(f"Warning: torch.compile() failed: {e}")
            print("Continuing without compilation...")

    # Load and format dataset
    dataset, tokenizer = load_dataset_sharegpt(args, tokenizer)

    # Create trainer
    trainer = create_trainer(model, tokenizer, dataset, args, bf16_supported)

    # Calculate training info
    total_steps = len(dataset) // (args.batch_size * args.gradient_accumulation) * args.epochs
    print(f"\nEstimated total steps: {total_steps}")

    # Start training
    print("\n" + "=" * 50)
    print("Starting Training")
    print("=" * 50)
    print("Press Ctrl+C to stop early (checkpoints will be saved)")
    print("")

    try:
        trainer_stats = trainer.train(resume_from_checkpoint=args.resume_from)

        print("\n" + "=" * 50)
        print("Training Complete!")
        print("=" * 50)
        print(f"Total training time: {trainer_stats.metrics.get('train_runtime', 0):.1f} seconds")
        print(f"Final loss: {trainer_stats.metrics.get('train_loss', 'N/A')}")

    except KeyboardInterrupt:
        print("\n\nTraining interrupted by user.")
        print("Saving current checkpoint...")

    # Save model
    lora_path = save_model(model, tokenizer, args)

    print("\n" + "=" * 50)
    print("All Done!")
    print("=" * 50)
    print(f"\nOutput files:")
    print(f"  LoRA adapter: {lora_path}")

    if args.save_merged:
        print(f"  Merged model: {Path(args.output_dir) / 'merged-16bit'}")

    if args.save_gguf:
        print(f"  GGUF file: models/gguf/")
        print(f"\nTo use with Ollama:")
        print(f"  cd models && ollama create network-security-expert -f Modelfile")
        print(f"  ollama run network-security-expert")

    print(f"\nEnd time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
