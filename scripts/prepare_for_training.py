#!/usr/bin/env python3
"""
Convert combined_train.json (ShareGPT format) -> training-ready Llama 3.1 text format.

This script produces a JSON file where each example has a pre-formatted "text" field
containing the exact Llama 3.1 chat template with proper special tokens. The training
notebook simply loads this and trains directly — no formatting bugs possible.

Llama 3.1 Tool Calling Format (from ember-v2-training-reference.md):

    <|begin_of_text|><|start_header_id|>system<|end_header_id|>

    {system message}<|eot_id|><|start_header_id|>user<|end_header_id|>

    {user message}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

    <|python_tag|>{"name": "tool", "parameters": {...}}<|eot_id|><|start_header_id|>ipython<|end_header_id|>

    {tool result}<|eot_id|><|start_header_id|>assistant<|end_header_id|>

    {presentation}<|eot_id|><|end_of_text|>

Role mapping (ShareGPT -> Llama 3.1):
    system  -> system
    human   -> user
    gpt     -> assistant
    ipython -> ipython

Usage:
    python scripts/prepare_for_training.py
    python scripts/prepare_for_training.py --input data/processed/combined_train.json
    python scripts/prepare_for_training.py --validate-only
"""

import json
import argparse
import sys
from pathlib import Path
from collections import Counter


# ShareGPT role -> Llama 3.1 role
ROLE_MAP = {
    "system": "system",
    "human": "user",
    "gpt": "assistant",
    "ipython": "ipython",
    "tool": "ipython",  # Fallback if anyone used "tool" role
}


def format_example(conversations: list) -> str:
    """Convert a ShareGPT conversation to Llama 3.1 chat template text.

    Returns the full formatted text string with special tokens.
    """
    text = "<|begin_of_text|>"

    for i, turn in enumerate(conversations):
        role = ROLE_MAP.get(turn["from"], turn["from"])
        value = turn["value"]

        # Role header
        text += f"<|start_header_id|>{role}<|end_header_id|>\n\n"

        # Content
        text += value

        # End token — always <|eot_id|> (NOT <|eom_id|>)
        # Per Llama 3.1 protocol: <|python_tag|> signals tool call,
        # Ollama intercepts the token. <|eot_id|> ends every turn.
        text += "<|eot_id|>"

    # End of sequence
    text += "<|end_of_text|>"

    return text


def validate_formatted(text: str) -> list[str]:
    """Validate a formatted training example."""
    issues = []

    if not text.startswith("<|begin_of_text|>"):
        issues.append("Missing <|begin_of_text|>")

    if not text.endswith("<|end_of_text|>"):
        issues.append("Missing <|end_of_text|>")

    if "<|start_header_id|>system<|end_header_id|>" not in text:
        issues.append("Missing system header")

    # Check that tool calls use <|python_tag|> not literal text
    if "<|python_tag|>" in text:
        # Tool call present — check it's in an assistant turn
        parts = text.split("<|python_tag|>")
        for i in range(1, len(parts)):
            # The text before <|python_tag|> should end with assistant header
            before = parts[i-1]
            if "<|start_header_id|>assistant<|end_header_id|>" not in before.split("<|eot_id|>")[-1]:
                issues.append("Tool call <|python_tag|> not in assistant turn")

        # Check that ipython turn follows tool call
        if "<|start_header_id|>ipython<|end_header_id|>" not in text:
            # Only an issue if there's a tool call AND result expected
            # (some examples might be tool-call-only without result)
            pass

    # Check no <|eom_id|> (wrong token)
    if "<|eom_id|>" in text:
        issues.append("Contains <|eom_id|> — should use <|eot_id|>")

    # Check no double headers
    if "<|start_header_id|><|start_header_id|>" in text:
        issues.append("Double header detected")

    return issues


def main():
    parser = argparse.ArgumentParser(description="Convert training data to Llama 3.1 text format")
    parser.add_argument("--input", default="data/processed/combined_train.json",
                        help="Input combined dataset (ShareGPT format)")
    parser.add_argument("--output", default="data/processed/combined_train_formatted.json",
                        help="Output training-ready dataset")
    parser.add_argument("--validate-only", action="store_true",
                        help="Just validate, don't write output")
    args = parser.parse_args()

    # -------------------------------------------------------------------------
    # Load
    # -------------------------------------------------------------------------
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"ERROR: Input not found: {input_path}")
        sys.exit(1)

    data = json.loads(input_path.read_text(encoding="utf-8"))
    print(f"Loaded {len(data)} examples from {input_path}")

    # -------------------------------------------------------------------------
    # Convert and validate
    # -------------------------------------------------------------------------
    formatted = []
    issue_count = 0
    role_counts = Counter()
    has_tool_call = 0
    has_ipython = 0
    token_lengths = []

    for i, example in enumerate(data):
        convs = example.get("conversations", [])

        # Count roles
        for c in convs:
            role_counts[c["from"]] += 1

        # Format
        text = format_example(convs)

        # Validate
        issues = validate_formatted(text)
        if issues:
            issue_count += 1
            if issue_count <= 5:
                human = next((c["value"][:50] for c in convs if c["from"] == "human"), "?")
                print(f"  Issue in example {i}: {human}...")
                for iss in issues:
                    print(f"    - {iss}")

        # Stats
        if "<|python_tag|>" in text:
            has_tool_call += 1
        if "<|start_header_id|>ipython<|end_header_id|>" in text:
            has_ipython += 1

        # Rough token estimate (chars / 4)
        token_lengths.append(len(text) // 4)

        formatted.append({"text": text})

    # -------------------------------------------------------------------------
    # Report
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("CONVERSION REPORT")
    print("=" * 60)
    print(f"  Total examples: {len(formatted)}")
    print(f"  Validation issues: {issue_count}")
    print(f"\n  Role counts in source data:")
    for role, count in sorted(role_counts.items()):
        mapped = ROLE_MAP.get(role, role)
        print(f"    {role} -> {mapped}: {count}")

    print(f"\n  Content stats:")
    print(f"    With tool calls (<|python_tag|>): {has_tool_call}")
    print(f"    With ipython turns: {has_ipython}")
    print(f"    Pure text (no tools): {len(formatted) - has_tool_call}")

    if token_lengths:
        avg_tokens = sum(token_lengths) / len(token_lengths)
        max_tokens = max(token_lengths)
        over_2048 = sum(1 for t in token_lengths if t > 2048)
        print(f"\n  Token estimates (chars/4):")
        print(f"    Average: {avg_tokens:.0f}")
        print(f"    Max: {max_tokens}")
        print(f"    Over 2048 (will be truncated): {over_2048} ({over_2048/len(formatted)*100:.1f}%)")

    # -------------------------------------------------------------------------
    # Sample output
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("SAMPLE FORMATTED OUTPUT")
    print("=" * 60)

    # Show one tool calling example
    for ex in formatted:
        if "<|python_tag|>" in ex["text"] and "<|start_header_id|>ipython<|end_header_id|>" in ex["text"]:
            print("\n[Tool Calling Example]")
            # Show first 600 chars
            print(ex["text"][:600])
            print("..." if len(ex["text"]) > 600 else "")
            break

    # Show one knowledge example
    for ex in formatted:
        if "<|python_tag|>" not in ex["text"]:
            print("\n[Knowledge Example]")
            print(ex["text"][:500])
            print("..." if len(ex["text"]) > 500 else "")
            break

    # -------------------------------------------------------------------------
    # Write output
    # -------------------------------------------------------------------------
    if args.validate_only:
        print(f"\n{'=' * 60}")
        print("VALIDATE ONLY — no file written")
        print("=" * 60)
    else:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(formatted, f, indent=2, ensure_ascii=False)

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"\n{'=' * 60}")
        print("OUTPUT WRITTEN")
        print("=" * 60)
        print(f"  Path: {output_path}")
        print(f"  Size: {size_mb:.1f} MB")
        print(f"  Examples: {len(formatted)}")
        print(f"  Format: Each example has 'text' field with pre-formatted Llama 3.1 chat template")

    if issue_count > 0:
        print(f"\nWARNING: {issue_count} examples had validation issues")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
