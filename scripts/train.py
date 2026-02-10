#!/usr/bin/env python3
"""
Fine-tune Llama 3.1 8B Instruct for Network Security Expert (Ember/FireWeave).

Usage:
    python scripts/train.py
    python scripts/train.py --dataset data/processed/combined_train_formatted.json
    python scripts/train.py --epochs 3 --batch-size 2
    python scripts/train.py --skip-tests        # skip post-training tests
    python scripts/train.py --skip-gguf          # skip GGUF export
    python scripts/train.py --test-only          # load saved LoRA and test (no training)
"""

import os
import sys
import json
import shutil
import argparse
from pathlib import Path

# ---------------------------------------------------------------------------
# 0. Environment setup (must happen before torch/unsloth imports)
# ---------------------------------------------------------------------------
os.environ["TRITON_CACHE_MANAGER"] = "unsloth.triton_cache:TritonCacheManager"
os.environ["CUDA_LAUNCH_BLOCKING"] = "0"

# Fix torchao 0.15.0 + PyTorch 2.5.x compatibility:
# torchao expects torch.int1/int2/... dtypes that only exist in newer PyTorch.
# We patch them as None so the import doesn't crash. QLoRA uses bitsandbytes
# for quantization so torchao dtypes are never actually used.
import torch as _torch
for _attr in ("int1", "int2", "int3", "int4", "int5", "int6", "int7"):
    if not hasattr(_torch, _attr):
        setattr(_torch, _attr, None)

# Clear stale Triton cache
triton_cache = Path.home() / ".triton" / "cache"
if triton_cache.exists():
    shutil.rmtree(triton_cache, ignore_errors=True)
    print("Cleared stale Triton cache")


def parse_args():
    p = argparse.ArgumentParser(description="Train Llama 3.1 8B Network Security Expert")
    p.add_argument("--dataset", default=None,
                   help="Path to combined_train_formatted.json (auto-detected if omitted)")
    p.add_argument("--epochs", type=int, default=3, help="Number of training epochs")
    p.add_argument("--batch-size", type=int, default=2, help="Per-device batch size")
    p.add_argument("--grad-accum", type=int, default=4, help="Gradient accumulation steps")
    p.add_argument("--lr", type=float, default=2e-4, help="Learning rate")
    p.add_argument("--max-seq-length", type=int, default=2048, help="Max sequence length")
    p.add_argument("--lora-rank", type=int, default=32, help="LoRA rank")
    p.add_argument("--output-dir", default="outputs/network-security-v2", help="Training output dir")
    p.add_argument("--skip-tests", action="store_true", help="Skip post-training tests")
    p.add_argument("--skip-gguf", action="store_true", help="Skip GGUF export")
    p.add_argument("--test-only", action="store_true", help="Load saved LoRA and run tests only")
    p.add_argument("--gguf-methods", default="q4_k_m,q5_k_m,q8_0",
                   help="Comma-separated GGUF quantization methods")
    return p.parse_args()


def find_dataset(explicit_path):
    """Find the training dataset, trying multiple locations."""
    candidates = [
        explicit_path,
        os.path.expanduser("~/finetuning/Finetuning/data/processed/combined_train_formatted.json"),
        os.path.expanduser("~/finetuning/data/processed/combined_train_formatted.json"),
        "data/processed/combined_train_formatted.json",
        "../data/processed/combined_train_formatted.json",
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    print("ERROR: Dataset not found! Searched:")
    for c in candidates:
        if c:
            print(f"  - {c}")
    print("\nGenerate it with: python scripts/prepare_for_training.py")
    sys.exit(1)


def load_model(max_seq_length):
    """Load Llama 3.1 8B Instruct with 4-bit quantization."""
    from unsloth import FastLanguageModel
    import torch

    print("\n" + "=" * 60)
    print("STEP 1: Loading Model")
    print("=" * 60)

    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name="unsloth/llama-3.1-8b-Instruct-bnb-4bit",
        max_seq_length=max_seq_length,
        dtype=None,
        load_in_4bit=True,
    )

    print(f"  Model: Llama 3.1 8B Instruct (4-bit)")
    print(f"  Max seq length: {max_seq_length}")

    if torch.cuda.is_available():
        gpu_mem = torch.cuda.get_device_properties(0).total_memory / 1024**3
        gpu_used = torch.cuda.memory_allocated(0) / 1024**3
        print(f"  GPU: {torch.cuda.get_device_name(0)} ({gpu_mem:.1f} GB total, {gpu_used:.1f} GB used)")

    return model, tokenizer


def configure_lora(model, rank):
    """Add LoRA adapters with rsLoRA."""
    from unsloth import FastLanguageModel

    print("\n" + "=" * 60)
    print("STEP 2: Configuring LoRA")
    print("=" * 60)

    model = FastLanguageModel.get_peft_model(
        model,
        r=rank,
        target_modules=["q_proj", "k_proj", "v_proj", "o_proj",
                         "gate_proj", "up_proj", "down_proj"],
        lora_alpha=rank,
        lora_dropout=0,
        bias="none",
        use_gradient_checkpointing="unsloth",
        random_state=3407,
        use_rslora=True,
        loftq_config=None,
    )

    trainable = sum(p.numel() for p in model.parameters() if p.requires_grad)
    total = sum(p.numel() for p in model.parameters())
    print(f"  Rank: {rank} with rsLoRA")
    print(f"  Trainable: ~{trainable / 1e6:.1f}M ({100 * trainable / total:.2f}%)")

    return model


def load_dataset_and_verify(dataset_path, tokenizer):
    """Load dataset and verify format."""
    from datasets import load_dataset as hf_load_dataset
    from unsloth.chat_templates import get_chat_template

    print("\n" + "=" * 60)
    print("STEP 3: Loading & Verifying Dataset")
    print("=" * 60)

    # Apply Llama 3.1 chat template
    tokenizer = get_chat_template(tokenizer, chat_template="llama-3.1")

    # Verify special tokens
    special_tokens = {
        "<|begin_of_text|>": 128000,
        "<|end_of_text|>": 128001,
        "<|start_header_id|>": 128006,
        "<|end_header_id|>": 128007,
        "<|eot_id|>": 128009,
        "<|python_tag|>": 128010,
    }

    all_ok = True
    for token_str, expected_id in special_tokens.items():
        actual_id = tokenizer.convert_tokens_to_ids(token_str)
        if actual_id != expected_id:
            all_ok = False
            print(f"  WARNING: {token_str}: got {actual_id}, expected {expected_id}")

    if all_ok:
        print("  Special tokens: all verified")
    else:
        print("  WARNING: Token ID mismatches detected!")

    # Load dataset
    dataset = hf_load_dataset("json", data_files=dataset_path, split="train")
    print(f"  Loaded: {len(dataset)} examples from {dataset_path}")

    tool_count = sum(1 for ex in dataset if "<|python_tag|>" in str(ex.get("text", "")))
    print(f"  Tool calling: {tool_count} ({100 * tool_count / len(dataset):.1f}%)")
    print(f"  Knowledge: {len(dataset) - tool_count}")

    # Validate a sample
    sample = dataset[0]["text"]
    checks = [
        ("Starts with <|begin_of_text|>", sample.startswith("<|begin_of_text|>")),
        ("Has system header", "<|start_header_id|>system<|end_header_id|>" in sample),
        ("Ends with <|end_of_text|>", sample.endswith("<|end_of_text|>")),
        ("No <|eom_id|>", "<|eom_id|>" not in sample),
    ]
    for desc, passed in checks:
        if not passed:
            print(f"  FAIL: {desc}")
            sys.exit(1)
    print("  Format checks: all passed")

    return dataset, tokenizer


def train(model, tokenizer, dataset, args):
    """Run training."""
    import torch
    from trl import SFTTrainer
    from transformers import TrainingArguments

    print("\n" + "=" * 60)
    print("STEP 4: Training")
    print("=" * 60)

    os.makedirs(args.output_dir, exist_ok=True)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.grad_accum,
        num_train_epochs=args.epochs,
        learning_rate=args.lr,
        lr_scheduler_type="cosine",
        warmup_ratio=0.03,
        weight_decay=0.01,
        max_grad_norm=0.3,
        optim="adamw_8bit",
        logging_steps=10,
        save_strategy="steps",
        save_steps=500,
        save_total_limit=2,
        fp16=not torch.cuda.is_bf16_supported(),
        bf16=torch.cuda.is_bf16_supported(),
        seed=3407,
        report_to="none",
        dataloader_num_workers=2,
    )

    eff_batch = args.batch_size * args.grad_accum
    steps_per_epoch = len(dataset) // eff_batch
    print(f"  Epochs: {args.epochs}")
    print(f"  Batch size: {args.batch_size} x {args.grad_accum} = {eff_batch} effective")
    print(f"  Steps/epoch: ~{steps_per_epoch}")
    print(f"  Total steps: ~{steps_per_epoch * args.epochs}")
    print(f"  LR: {args.lr} (cosine)")
    print(f"  Precision: {'BF16' if training_args.bf16 else 'FP16'}")

    trainer = SFTTrainer(
        model=model,
        tokenizer=tokenizer,
        train_dataset=dataset,
        dataset_text_field="text",
        max_seq_length=args.max_seq_length,
        dataset_num_proc=1,
        packing=False,
        neftune_noise_alpha=5.0,
        args=training_args,
    )

    # Clear Triton cache again right before training
    if triton_cache.exists():
        shutil.rmtree(triton_cache, ignore_errors=True)

    print(f"\n  Starting training on {len(dataset)} examples...")
    print("  " + "-" * 50)

    stats = trainer.train()

    print("  " + "-" * 50)
    print(f"  Training complete!")
    print(f"  Final loss: {stats.training_loss:.4f}")
    print(f"  Time: {stats.metrics['train_runtime'] / 3600:.2f} hours")

    return stats


def run_tests(model, tokenizer):
    """Run post-training tests."""
    from unsloth import FastLanguageModel

    print("\n" + "=" * 60)
    print("STEP 5: Testing")
    print("=" * 60)

    FastLanguageModel.for_inference(model)

    # Test 1: Tool calling
    print("\n  Test 1: Tool Calling (should produce <|python_tag|>)")
    print("  " + "-" * 50)

    tool_prompt = (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- Don't narrate your process. Present results directly.\n\n"
        "Environment: ipython\n\n"
        '{"name": "search_objects", "description": "Search for address and service objects", '
        '"parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}'
        "<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
        "find 10.0.0.1<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
    )

    inputs = tokenizer(tool_prompt, return_tensors="pt").to("cuda")
    outputs = model.generate(**inputs, max_new_tokens=100, temperature=0.1)
    generated = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:])
    print(f"  Generated: {generated}")

    if "<|python_tag|>" in generated:
        json_part = generated.split("<|python_tag|>")[1].split("<|eot_id|>")[0].strip()
        try:
            tc = json.loads(json_part)
            print(f"  [{'PASS' if 'name' in tc else 'FAIL'}] Has 'name' field")
            print(f"  [{'PASS' if 'parameters' in tc else 'FAIL'}] Has 'parameters' field")
            print(f"  [{'PASS' if 'function' not in tc else 'FAIL'}] Not OpenAI format")
        except json.JSONDecodeError:
            print(f"  [FAIL] Invalid JSON: {json_part}")
    else:
        print("  [FAIL] No <|python_tag|> in output")

    # Test 2: Knowledge question (should NOT call tools)
    print("\n  Test 2: Knowledge Question (should NOT call tools)")
    print("  " + "-" * 50)

    knowledge_prompt = (
        "<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "Environment: ipython\n\n"
        '{"name": "search_objects", "description": "Search objects", '
        '"parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}}'
        "<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
        "what is a shadowed rule?<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
    )

    inputs = tokenizer(knowledge_prompt, return_tensors="pt").to("cuda")
    outputs = model.generate(**inputs, max_new_tokens=256, temperature=0.7, top_p=0.9)
    generated = tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:], skip_special_tokens=True)
    print(f"  Generated: {generated[:300]}...")
    has_tool = "<|python_tag|>" in tokenizer.decode(outputs[0][inputs.input_ids.shape[1]:])
    print(f"  [{'PASS' if not has_tool else 'FAIL'}] No tool call for knowledge question")

    # Test 3: General security question
    print("\n  Test 3: General Security Question")
    print("  " + "-" * 50)

    messages = [{"role": "user", "content": "How do I configure port security on a Cisco switch?"}]
    inputs = tokenizer.apply_chat_template(
        messages, tokenize=True, add_generation_prompt=True, return_tensors="pt"
    ).to("cuda")
    outputs = model.generate(input_ids=inputs, max_new_tokens=512, temperature=0.7, top_p=0.9, do_sample=True)
    response = tokenizer.batch_decode(outputs, skip_special_tokens=True)[0]
    response = response.split("assistant\n\n")[-1] if "assistant" in response else response
    print(f"  Answer: {response[:300]}...")

    print("\n  Testing complete!")


def save_lora(model, tokenizer):
    """Save the LoRA adapter."""
    print("\n" + "=" * 60)
    print("STEP 6: Saving LoRA Adapter")
    print("=" * 60)

    os.makedirs("models/network-security-lora", exist_ok=True)
    model.save_pretrained("models/network-security-lora")
    tokenizer.save_pretrained("models/network-security-lora")
    print("  Saved to: models/network-security-lora")


def export_gguf(model, tokenizer, methods):
    """Merge and export to GGUF."""
    print("\n" + "=" * 60)
    print("STEP 7: Exporting to GGUF")
    print("=" * 60)

    os.makedirs("models/merged-16bit", exist_ok=True)
    os.makedirs("models/gguf", exist_ok=True)

    print("  Merging LoRA with base model...")
    model.save_pretrained_merged(
        "models/merged-16bit",
        tokenizer,
        save_method="merged_16bit",
    )
    print("  Merged model saved")

    method_list = [m.strip() for m in methods.split(",")]
    print(f"  Converting to GGUF: {method_list}")
    print("  This takes 10-30 minutes...")

    model.save_pretrained_gguf(
        "models/gguf",
        tokenizer,
        quantization_method=method_list,
    )

    print("\n  GGUF files created in models/gguf/:")
    for m in method_list:
        print(f"    - unsloth.{m.upper()}.gguf")

    print("\n  Next steps:")
    print("    mv models/gguf/unsloth.Q4_K_M.gguf models/gguf/network-security-expert.Q4_K_M.gguf")
    print("    cd models && ollama create network-security-expert -f Modelfile")
    print("    ollama run network-security-expert")


def main():
    args = parse_args()

    print("=" * 60)
    print("Llama 3.1 8B - Network Security Expert Training")
    print("=" * 60)

    # Find dataset
    dataset_path = find_dataset(args.dataset)

    # Load model
    model, tokenizer = load_model(args.max_seq_length)

    # Configure LoRA
    model = configure_lora(model, args.lora_rank)

    # Load and verify dataset
    dataset, tokenizer = load_dataset_and_verify(dataset_path, tokenizer)

    if not args.test_only:
        # Train
        train(model, tokenizer, dataset, args)

        # Save LoRA
        save_lora(model, tokenizer)

    # Tests
    if not args.skip_tests:
        run_tests(model, tokenizer)

    # GGUF export
    if not args.skip_gguf and not args.test_only:
        export_gguf(model, tokenizer, args.gguf_methods)

    print("\n" + "=" * 60)
    print("ALL DONE")
    print("=" * 60)


if __name__ == "__main__":
    main()
