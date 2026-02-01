#!/usr/bin/env python3
"""
Pre-flight check for GPU training.
Run this before starting training to ensure GPU is ready.

Usage:
    python scripts/preflight_check.py
    python scripts/preflight_check.py --clear  # Kill GPU processes and clear cache
    python scripts/preflight_check.py --clear-triton  # Also clear Triton cache

Fixes for "Triton Error: the launch timed out":
1. Reduce batch size (--batch-size 1)
2. Reduce sequence length (--max-seq-length 2048)
3. Disable packing (--no-packing)
4. Clear Triton cache (--clear-triton)
"""

import subprocess
import sys
import argparse
import shutil
from pathlib import Path


def get_gpu_processes():
    """Get list of processes using GPU memory."""
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-compute-apps=pid,process_name,used_memory', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True
        )
        processes = []
        for line in result.stdout.strip().split('\n'):
            if line.strip():
                parts = line.split(', ')
                if len(parts) >= 3:
                    processes.append({
                        'pid': int(parts[0]),
                        'name': parts[1],
                        'memory_mb': int(parts[2])
                    })
        return processes
    except Exception as e:
        print(f"Error querying GPU: {e}")
        return []


def get_gpu_info():
    """Get GPU memory info."""
    try:
        result = subprocess.run(
            ['nvidia-smi', '--query-gpu=name,memory.total,memory.used,memory.free', '--format=csv,noheader,nounits'],
            capture_output=True, text=True, check=True
        )
        line = result.stdout.strip()
        parts = line.split(', ')
        return {
            'name': parts[0],
            'total_mb': int(parts[1]),
            'used_mb': int(parts[2]),
            'free_mb': int(parts[3])
        }
    except Exception as e:
        print(f"Error querying GPU: {e}")
        return None


def kill_gpu_processes(exclude_pids=None):
    """Kill all GPU compute processes except excluded ones."""
    import os
    exclude_pids = exclude_pids or []
    processes = get_gpu_processes()

    for proc in processes:
        if proc['pid'] not in exclude_pids:
            print(f"  Killing PID {proc['pid']} ({proc['name']}) - {proc['memory_mb']}MB")
            try:
                os.kill(proc['pid'], 9)
            except ProcessLookupError:
                pass
            except PermissionError:
                print(f"    Permission denied - try running with sudo")


def clear_cuda_cache():
    """Clear PyTorch CUDA cache if available."""
    try:
        import torch
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            torch.cuda.synchronize()
            print("  PyTorch CUDA cache cleared")
    except ImportError:
        pass


def clear_triton_cache():
    """Clear Triton compilation cache to fix timeout issues."""
    triton_cache = Path.home() / ".triton" / "cache"
    unsloth_cache = Path.cwd() / "unsloth_compiled_cache"

    cleared = False

    if triton_cache.exists():
        size_mb = sum(f.stat().st_size for f in triton_cache.rglob('*') if f.is_file()) / 1024 / 1024
        shutil.rmtree(triton_cache, ignore_errors=True)
        print(f"  Cleared Triton cache ({size_mb:.1f}MB): {triton_cache}")
        cleared = True

    if unsloth_cache.exists():
        size_mb = sum(f.stat().st_size for f in unsloth_cache.rglob('*') if f.is_file()) / 1024 / 1024
        shutil.rmtree(unsloth_cache, ignore_errors=True)
        print(f"  Cleared Unsloth cache ({size_mb:.1f}MB): {unsloth_cache}")
        cleared = True

    if not cleared:
        print("  No Triton/Unsloth cache found")

    return cleared


def check_triton_cache():
    """Check Triton cache size and age."""
    triton_cache = Path.home() / ".triton" / "cache"

    if not triton_cache.exists():
        return None

    # Get size and file count
    files = list(triton_cache.rglob('*'))
    file_count = len([f for f in files if f.is_file()])
    size_mb = sum(f.stat().st_size for f in files if f.is_file()) / 1024 / 1024

    # Get oldest file age
    import time
    oldest_age_days = 0
    for f in files:
        if f.is_file():
            age_days = (time.time() - f.stat().st_mtime) / 86400
            oldest_age_days = max(oldest_age_days, age_days)

    return {
        'path': triton_cache,
        'files': file_count,
        'size_mb': size_mb,
        'oldest_days': oldest_age_days
    }


def main():
    parser = argparse.ArgumentParser(description="Pre-flight GPU check for training")
    parser.add_argument('--clear', action='store_true', help='Kill GPU processes and clear CUDA cache')
    parser.add_argument('--clear-triton', action='store_true', help='Also clear Triton compilation cache')
    parser.add_argument('--min-free-gb', type=float, default=20.0, help='Minimum free GPU memory required (GB)')
    args = parser.parse_args()

    print("=" * 60)
    print("GPU Pre-flight Check for Training")
    print("=" * 60)

    # Get GPU info
    gpu = get_gpu_info()
    if not gpu:
        print("\n❌ ERROR: Could not query GPU. Is nvidia-smi available?")
        sys.exit(1)

    print(f"\nGPU: {gpu['name']}")
    print(f"Memory: {gpu['used_mb']:,}MB / {gpu['total_mb']:,}MB used ({gpu['free_mb']:,}MB free)")

    # Get processes
    processes = get_gpu_processes()
    if processes:
        print(f"\nGPU Processes ({len(processes)}):")
        for proc in processes:
            print(f"  PID {proc['pid']}: {proc['name']} - {proc['memory_mb']}MB")
    else:
        print("\nNo GPU compute processes running ✓")

    # Check Triton cache
    triton = check_triton_cache()
    if triton:
        print(f"\nTriton Cache:")
        print(f"  Path: {triton['path']}")
        print(f"  Size: {triton['size_mb']:.1f}MB ({triton['files']} files)")
        print(f"  Age: {triton['oldest_days']:.1f} days old")
        if triton['oldest_days'] > 7 or triton['size_mb'] > 500:
            print("  ⚠️  Consider clearing with --clear-triton (may fix timeout issues)")
    else:
        print("\nTriton Cache: Not present ✓")

    # Clear if requested
    if args.clear:
        if processes:
            print("\nClearing GPU processes...")
            kill_gpu_processes()
        clear_cuda_cache()

        # Re-check
        import time
        time.sleep(2)
        gpu = get_gpu_info()
        print(f"\nAfter clearing: {gpu['used_mb']:,}MB / {gpu['total_mb']:,}MB used")

    # Clear Triton cache if requested
    if args.clear_triton:
        print("\nClearing Triton cache...")
        clear_triton_cache()

    # Check if enough memory
    free_gb = gpu['free_mb'] / 1024
    min_required = args.min_free_gb

    print("\n" + "=" * 60)
    if free_gb >= min_required:
        print(f"✅ READY: {free_gb:.1f}GB free (need {min_required:.1f}GB)")
        print("=" * 60)
        print("\nRecommended training settings for stability:")
        print("  --batch-size 1 --gradient-accumulation 8 --max-seq-length 2048 --no-packing")
        sys.exit(0)
    else:
        print(f"❌ NOT READY: Only {free_gb:.1f}GB free (need {min_required:.1f}GB)")
        print("\nRun with --clear to kill GPU processes:")
        print("  python scripts/preflight_check.py --clear --clear-triton")
        print("=" * 60)
        sys.exit(1)


if __name__ == "__main__":
    main()
