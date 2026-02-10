#!/usr/bin/env python3
"""
Export LoRA adapter to GGUF format.

Bypasses unsloth's bundled llama.cpp converter (which has a KIMI_LINEAR bug)
and uses standalone llama.cpp instead.

Steps:
  1. Load base model + LoRA adapter
  2. Merge into full 16-bit model
  3. Convert to GGUF via llama.cpp's convert_hf_to_gguf.py
  4. Quantize to Q4_K_M (and optionally Q8_0)

Usage:
    python scripts/export_gguf.py
    python scripts/export_gguf.py --lora-path models/network-security-lora
    python scripts/export_gguf.py --quantize q4_k_m,q8_0
"""

import os
import sys
import argparse
import subprocess

# ---------------------------------------------------------------------------
# torchao compatibility patch (same as train.py)
# ---------------------------------------------------------------------------
import torch as _torch
for _attr in ("int1", "int2", "int3", "int4", "int5", "int6", "int7"):
    if not hasattr(_torch, _attr):
        setattr(_torch, _attr, None)


def parse_args():
    p = argparse.ArgumentParser(description="Export LoRA to GGUF")
    p.add_argument("--lora-path", default="models/network-security-lora",
                   help="Path to saved LoRA adapter")
    p.add_argument("--merged-path", default="models/merged-16bit",
                   help="Where to save merged 16-bit model")
    p.add_argument("--gguf-path", default="models/gguf",
                   help="Where to save GGUF files")
    p.add_argument("--quantize", default="q4_k_m",
                   help="Comma-separated quantization methods (q4_k_m, q5_k_m, q8_0)")
    p.add_argument("--llama-cpp-path", default=None,
                   help="Path to llama.cpp repo (auto-cloned if not provided)")
    p.add_argument("--skip-merge", action="store_true",
                   help="Skip merging (use existing merged model)")
    return p.parse_args()


def merge_lora(lora_path, merged_path):
    """Load base model + LoRA and merge into full 16-bit weights."""
    print("\n" + "=" * 60)
    print("STEP 1: Merging LoRA with Base Model")
    print("=" * 60)

    from unsloth import FastLanguageModel

    print(f"  Loading base model + LoRA from: {lora_path}")
    model, tokenizer = FastLanguageModel.from_pretrained(
        model_name=lora_path,
        max_seq_length=2048,
        load_in_4bit=True,
    )

    os.makedirs(merged_path, exist_ok=True)

    print(f"  Merging and saving to: {merged_path}")
    print("  This takes 5-10 minutes...")
    model.save_pretrained_merged(
        merged_path,
        tokenizer,
        save_method="merged_16bit",
    )
    print("  Merge complete!")
    return merged_path


def setup_llama_cpp(llama_cpp_path):
    """Clone llama.cpp if not present, install requirements."""
    if llama_cpp_path and os.path.isdir(llama_cpp_path):
        print(f"  Using existing llama.cpp at: {llama_cpp_path}")
        return llama_cpp_path

    default_path = "llama.cpp"
    if os.path.isdir(default_path):
        print(f"  Using existing llama.cpp at: {default_path}")
        return default_path

    print("\n" + "=" * 60)
    print("STEP 2a: Cloning llama.cpp")
    print("=" * 60)

    subprocess.run(
        ["git", "clone", "--depth", "1", "https://github.com/ggerganov/llama.cpp.git"],
        check=True,
    )

    # Install Python requirements for the converter
    req_file = os.path.join("llama.cpp", "requirements", "requirements-convert_hf_to_gguf.txt")
    if os.path.exists(req_file):
        print("  Installing converter requirements...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "-r", req_file],
            check=True,
        )
    else:
        # Older llama.cpp versions have requirements.txt at root
        req_file_alt = os.path.join("llama.cpp", "requirements.txt")
        if os.path.exists(req_file_alt):
            subprocess.run(
                [sys.executable, "-m", "pip", "install", "-r", req_file_alt],
                check=True,
            )

    return "llama.cpp"


def convert_to_gguf(merged_path, gguf_path, llama_cpp_path):
    """Convert HF model to F16 GGUF using llama.cpp's converter."""
    print("\n" + "=" * 60)
    print("STEP 2: Converting to GGUF (F16)")
    print("=" * 60)

    os.makedirs(gguf_path, exist_ok=True)
    f16_gguf = os.path.join(gguf_path, "network-security-expert.F16.gguf")

    convert_script = os.path.join(llama_cpp_path, "convert_hf_to_gguf.py")
    if not os.path.exists(convert_script):
        print(f"  ERROR: {convert_script} not found!")
        print("  Make sure llama.cpp is cloned correctly.")
        sys.exit(1)

    print(f"  Input:  {merged_path}")
    print(f"  Output: {f16_gguf}")
    print("  This takes 5-15 minutes...")

    subprocess.run(
        [sys.executable, convert_script, merged_path,
         "--outfile", f16_gguf, "--outtype", "f16"],
        check=True,
    )
    print(f"  F16 GGUF saved: {f16_gguf}")
    return f16_gguf


def quantize_gguf(f16_gguf, gguf_path, llama_cpp_path, methods):
    """Quantize F16 GGUF to smaller formats using llama-quantize."""
    print("\n" + "=" * 60)
    print("STEP 3: Quantizing GGUF")
    print("=" * 60)

    # Find the quantize binary
    quantize_bin = None
    for candidate in [
        os.path.join(llama_cpp_path, "build", "bin", "llama-quantize"),
        os.path.join(llama_cpp_path, "build", "bin", "quantize"),
        os.path.join(llama_cpp_path, "llama-quantize"),
        os.path.join(llama_cpp_path, "quantize"),
    ]:
        if os.path.exists(candidate):
            quantize_bin = candidate
            break

    if not quantize_bin:
        print("  WARNING: llama-quantize binary not found!")
        print("  You need to build llama.cpp first:")
        print(f"    cd {llama_cpp_path}")
        print("    cmake -B build")
        print("    cmake --build build --config Release -j$(nproc)")
        print("")
        print("  Then re-run this script with --skip-merge")
        print(f"  Or quantize manually:")
        for method in methods:
            out_name = f"network-security-expert.{method.upper()}.gguf"
            print(f"    llama-quantize {f16_gguf} {os.path.join(gguf_path, out_name)} {method}")
        return []

    output_files = []
    for method in methods:
        out_name = f"network-security-expert.{method.upper()}.gguf"
        out_path = os.path.join(gguf_path, out_name)
        print(f"\n  Quantizing to {method.upper()}...")
        subprocess.run(
            [quantize_bin, f16_gguf, out_path, method],
            check=True,
        )
        # Get file size
        size_gb = os.path.getsize(out_path) / (1024**3)
        print(f"  Saved: {out_path} ({size_gb:.1f} GB)")
        output_files.append(out_path)

    return output_files


def main():
    args = parse_args()

    print("=" * 60)
    print("GGUF Export - Network Security Expert")
    print("=" * 60)

    # Step 1: Merge LoRA
    if not args.skip_merge:
        merge_lora(args.lora_path, args.merged_path)
    else:
        print(f"\n  Skipping merge, using existing: {args.merged_path}")

    # Step 2a: Setup llama.cpp
    llama_cpp_path = setup_llama_cpp(args.llama_cpp_path)

    # Step 2b: Convert to F16 GGUF
    f16_gguf = convert_to_gguf(args.merged_path, args.gguf_path, llama_cpp_path)

    # Step 3: Quantize
    methods = [m.strip() for m in args.quantize.split(",")]
    output_files = quantize_gguf(f16_gguf, args.gguf_path, llama_cpp_path, methods)

    # Summary
    print("\n" + "=" * 60)
    print("EXPORT COMPLETE")
    print("=" * 60)
    print(f"\n  F16 GGUF: {f16_gguf}")
    for f in output_files:
        print(f"  Quantized: {f}")

    print("\n  Next steps:")
    print("  1. Update models/Modelfile to point to the new GGUF:")
    print(f"     FROM ./gguf/network-security-expert.{methods[0].upper()}.gguf")
    print("  2. Create Ollama model:")
    print("     cd models && ollama create network-security-expert -f Modelfile")
    print("  3. Test:")
    print("     ollama run network-security-expert")

    # Optional: clean up F16 (it's large, ~16GB)
    f16_size = os.path.getsize(f16_gguf) / (1024**3)
    print(f"\n  Note: F16 file is {f16_size:.1f} GB. Delete it after quantizing to save space:")
    print(f"    rm {f16_gguf}")


if __name__ == "__main__":
    main()
