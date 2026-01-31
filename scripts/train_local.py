#!/usr/bin/env python3
"""
Local Fine-Tuning Script for FireWeave Network Security Expert

This script fine-tunes Llama 3.1 8B Instruct using Unsloth and QLoRA.

RTX 3090 (24GB VRAM) Compatible:
- 4-bit QLoRA uses ~5-6GB for model
- Default settings (batch=2, seq_len=4096): ~18-20GB peak
- Fallback settings (batch=1, seq_len=2048): ~12-14GB peak

Optimized for tool calling with:
- LoRA r=16, alpha=32, dropout=0.05
- Learning rate 3e-4 with cosine scheduler
- Max sequence length 4096 for multi-turn conversations
- Native Llama 3.1 tool calling format (<|python_tag|>)

Usage:
    # Train on prepared tool calling data (recommended for 3090)
    python scripts/train_local.py --data v2/data/processed/training_data_final.json --epochs 3

    # Train with GGUF export for Ollama:
    python scripts/train_local.py --data v2/data/processed/training_data_final.json --save-gguf

    # If you get OOM errors on 3090, reduce batch size:
    python scripts/train_local.py \\
        --data v2/data/processed/training_data_final.json \\
        --epochs 3 \\
        --batch-size 1 \\
        --gradient-accumulation 8 \\
        --max-seq-length 2048 \\
        --save-gguf
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
        help="Per-device training batch size (default: 4 for 3090)"
    )
    parser.add_argument(
        "--gradient-accumulation",
        type=int,
        default=4,
        help="Gradient accumulation steps (default: 4, effective batch = batch-size * this)"
    )
    parser.add_argument(
        "--learning-rate",
        type=float,
        default=3e-4,
        help="Learning rate (default: 3e-4, optimized for tool calling)"
    )
    parser.add_argument(
        "--max-seq-length",
        type=int,
        default=4096,
        help="Maximum sequence length (default: 4096 for multi-turn tool calling)"
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

    # LoRA arguments
    parser.add_argument(
        "--lora-r",
        type=int,
        default=16,
        help="LoRA rank (default: 16)"
    )
    parser.add_argument(
        "--lora-alpha",
        type=int,
        default=32,
        help="LoRA alpha (default: 32, 2x rank for better learning)"
    )
    parser.add_argument(
        "--lora-dropout",
        type=float,
        default=0.05,
        help="LoRA dropout for regularization (default: 0.05)"
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

    print(f"GPU: {gpu_name}")
    print(f"Total Memory: {gpu_memory:.1f} GB")
    print(f"CUDA Version: {torch.version.cuda}")
    print(f"PyTorch Version: {torch.__version__}")

    # Check if bf16 is supported (Ampere and newer)
    bf16_supported = torch.cuda.is_bf16_supported()
    print(f"BF16 Supported: {bf16_supported}")

    return bf16_supported


def load_model(args):
    """Load the base model with 4-bit quantization."""
    print("\n" + "=" * 50)
    print("Loading Model")
    print("=" * 50)

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/llama-3.1-8b-Instruct-bnb-4bit",
        max_seq_length=args.max_seq_length,
        dtype=None,  # Auto-detect
        load_in_4bit=True,
    )

    print(f"Model loaded: Llama 3.1 8B Instruct (4-bit)")
    print(f"Max sequence length: {args.max_seq_length}")

    return model, tokenizer


def configure_lora(model, args):
    """Configure LoRA adapters optimized for tool calling."""
    print("\n" + "=" * 50)
    print("Configuring LoRA (Optimized for Tool Calling)")
    print("=" * 50)

    model = FastLanguageModel.get_peft_model(
        model,
        r=args.lora_r,
        target_modules=[
            "q_proj", "k_proj", "v_proj", "o_proj",
            "gate_proj", "up_proj", "down_proj"
        ],
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,  # Regularization for tool calling
        bias="none",
        use_gradient_checkpointing="unsloth",  # Memory efficient
        random_state=args.seed,
    )

    # Count trainable parameters
    trainable_params = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total_params = sum(p.numel() for p in model.parameters())

    print(f"LoRA Rank (r): {args.lora_r}")
    print(f"LoRA Alpha: {args.lora_alpha}")
    print(f"LoRA Dropout: {args.lora_dropout}")
    print(f"Target modules: q_proj, k_proj, v_proj, o_proj, gate_proj, up_proj, down_proj")
    print(f"Trainable parameters: {trainable_params:,} ({100 * trainable_params / total_params:.2f}%)")

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

        # Save merged data to temp file for dataset loading
        temp_path = Path(args.output_dir) / "merged_training_data.json"
        os.makedirs(args.output_dir, exist_ok=True)
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(all_data, f)

        print(f"\nTotal: {len(all_data)} examples merged")
        data_path = temp_path
    else:
        data_path = Path(args.data_path)
        if not data_path.exists():
            print(f"ERROR: Data file not found: {data_path}")
            print(f"\nTry one of these options:")
            print(f"  1. Use existing example data: --data-path data/example_dataset.json")
            print(f"  2. Use synthetic data directory: --data-dir data/synthetic/")
            sys.exit(1)

    # Load dataset
    dataset = load_dataset("json", data_files=str(data_path), split="train")
    print(f"Loaded {len(dataset)} examples from {data_path}")

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

    def formatting_prompts_func(examples):
        """Format conversations for Llama 3.1 native tool calling."""
        conversations = examples["conversations"]
        tools_list = examples.get("tools", [None] * len(conversations))
        texts = []

        for convo, tools in zip(conversations, tools_list):
            # Build text manually for proper tool calling format
            text = "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            text += SYSTEM_PROMPT

            # Add tool definitions if available
            if tools:
                text += "\n\nAvailable tools:\n"
                text += json.dumps(tools, indent=2)

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

    # Apply formatting
    dataset = dataset.map(
        formatting_prompts_func,
        batched=True,
        num_proc=2,
        desc="Formatting dataset"
    )

    # Show a sample
    print("\nSample formatted text (first 500 chars):")
    print("-" * 40)
    print(dataset[0]["text"][:500] + "...")
    print("-" * 40)

    return dataset, tokenizer


def create_trainer(model, tokenizer, dataset, args, bf16_supported):
    """Create the SFTTrainer."""
    print("\n" + "=" * 50)
    print("Setting Up Trainer")
    print("=" * 50)

    # Create output directory
    os.makedirs(args.output_dir, exist_ok=True)

    # Training arguments optimized for tool calling
    training_args = TrainingArguments(
        output_dir=args.output_dir,

        # Batch configuration
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation,

        # Training duration
        num_train_epochs=args.epochs,

        # Learning rate schedule (optimized for tool calling)
        learning_rate=args.learning_rate,
        lr_scheduler_type=args.scheduler,
        warmup_ratio=args.warmup_ratio,

        # Optimization
        weight_decay=0.01,
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
        dataloader_num_workers=2,
        remove_unused_columns=True,
    )

    effective_batch = args.batch_size * args.gradient_accumulation
    print(f"Effective batch size: {effective_batch}")
    print(f"Epochs: {args.epochs}")
    print(f"Learning rate: {args.learning_rate}")
    print(f"LR Scheduler: {args.scheduler}")
    print(f"Warmup ratio: {args.warmup_ratio}")
    print(f"Mixed precision: {'bf16' if bf16_supported else 'fp16'}")

    # Create trainer
    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=args.max_seq_length,
        dataset_num_proc=2,
        packing=False,  # Set True for faster training on short sequences
        args=training_args,
    )

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
