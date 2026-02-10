#!/usr/bin/env python3
"""
Combine tool calling data + high-quality knowledge data into final training dataset.

Fixes HQ data per ember-v2-training-reference.md:
1. Adds Ember system message to ALL examples
2. For ~20% of examples: includes Environment: ipython + tool schemas
   (teaches model to NOT call tools even when visible — Section 10)
3. Fixes 36 dict-type gpt values (extracts 'response' key)
4. Removes empty/broken answers
5. Validates combined dataset against spec criteria

Usage:
    python scripts/combine_datasets.py
    python scripts/combine_datasets.py --dry-run          # Preview without writing
    python scripts/combine_datasets.py --output path.json  # Custom output path
"""

import json
import hashlib
import random
import argparse
import sys
from pathlib import Path
from collections import Counter

# ---------------------------------------------------------------------------
# Constants from the reference doc / generation script
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS = [
    (
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- For optional parameters like device_group, leave them null unless the user specified one.\n"
        "- After a tool returns data, present findings concisely using markdown tables.\n"
        "- Don't narrate your process. Present results directly."
    ),
    (
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- For optional parameters like device_group, leave them null unless the user specified one.\n"
        "- After a tool returns data, present findings concisely using markdown tables."
    ),
    (
        "You are Ember, a senior network security analyst embedded in the FireWeave platform.\n\n"
        "RULES:\n"
        "- NEVER fabricate data. Only present data from tool results.\n"
        "- Don't narrate your process. Present results directly."
    ),
]

# Compact single-line tool schemas (same as generate_tool_calling_data.py)
TOOL_SCHEMAS = {
    "search_objects": '{"name": "search_objects", "description": "Search for address and service objects across all Panoramas", "parameters": {"type": "object", "properties": {"query": {"type": "string", "description": "IP address, subnet, or object name"}, "object_type": {"type": "string", "description": "Optional: ip, address-group, service-group, tag"}, "device_group": {"type": "string", "description": "Optional device group filter"}}, "required": ["query"]}}',
    "find_unused_rules": '{"name": "find_unused_rules", "description": "Find security rules with zero hit count", "parameters": {"type": "object", "properties": {"days": {"type": "integer", "description": "Days to check (default 90)"}}}}',
    "list_unused_objects": '{"name": "list_unused_objects", "description": "List objects not referenced by any rule", "parameters": {"type": "object", "properties": {"object_type": {"type": "string", "description": "Type: address-group, service-group, tag"}, "device_group": {"type": "string"}}}}',
    "find_shadowed_rules": '{"name": "find_shadowed_rules", "description": "Find rules overshadowed by higher-priority rules", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}}}}',
    "search_rules": '{"name": "search_rules", "description": "Search security rules by criteria", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}, "source_zone": {"type": "string"}, "destination_zone": {"type": "string"}, "action": {"type": "string", "description": "allow, deny, or drop"}, "has_logging": {"type": "boolean"}}}}',
    "nat_check": '{"name": "nat_check", "description": "Test NAT policy matching for traffic flows", "parameters": {"type": "object", "properties": {"src_ip": {"type": "string"}, "dst_ip": {"type": "string"}, "src_zone": {"type": "string"}, "dst_zone": {"type": "string"}}, "required": ["src_ip", "dst_ip"]}}',
    "get_rule_statistics": '{"name": "get_rule_statistics", "description": "Get aggregate rule counts and security posture", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}}}}',
    "get_rule_hit_count": '{"name": "get_rule_hit_count", "description": "Get hit count for a specific rule", "parameters": {"type": "object", "properties": {"rule_id": {"type": "string"}, "time_range": {"type": "string", "description": "7d, 30d, or 90d"}}, "required": ["rule_id"]}}',
    "check_traffic_flow": '{"name": "check_traffic_flow", "description": "Check if traffic can flow between source and destination", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}, "port": {"type": "integer"}, "protocol": {"type": "string"}}, "required": ["source", "destination"]}}',
    "run_compliance_scan": '{"name": "run_compliance_scan", "description": "Run compliance check against a framework", "parameters": {"type": "object", "properties": {"framework": {"type": "string", "description": "pci-dss, soc2, nist, hipaa, or cis"}, "firewall": {"type": "string", "description": "Device group (optional)"}}, "required": ["framework"]}}',
    "get_dnat_exposure": '{"name": "get_dnat_exposure", "description": "Find services exposed via DNAT", "parameters": {"type": "object", "properties": {"device_group": {"type": "string"}}}}',
    "check_access": '{"name": "check_access", "description": "Verify if traffic is allowed by expanded rules", "parameters": {"type": "object", "properties": {"source_ip": {"type": "string"}, "destination_ip": {"type": "string"}, "protocol": {"type": "string"}, "port": {"type": "integer"}, "device_group": {"type": "string"}}, "required": ["source_ip", "destination_ip"]}}',
    "query_audit_logs": '{"name": "query_audit_logs", "description": "Search audit/config/system logs", "parameters": {"type": "object", "properties": {"log_type": {"type": "string", "description": "audit, config, or system"}, "search": {"type": "string"}, "admin": {"type": "string"}, "limit": {"type": "integer"}}}}',
    "get_audit_diff": '{"name": "get_audit_diff", "description": "Get before/after diff for a change event", "parameters": {"type": "object", "properties": {"event_id": {"type": "string"}}, "required": ["event_id"]}}',
    "compare_configs": '{"name": "compare_configs", "description": "Compare running vs candidate config", "parameters": {"type": "object", "properties": {"source_a_type": {"type": "string"}, "source_b_type": {"type": "string"}, "scope": {"type": "string"}, "device_group": {"type": "string"}}}}',
    "get_critical_findings": '{"name": "get_critical_findings", "description": "Get critical security findings", "parameters": {"type": "object", "properties": {"provider": {"type": "string", "description": "aws, azure, gcp, or all"}}}}',
    "get_snow_changes": '{"name": "get_snow_changes", "description": "Get open ServiceNow change requests", "parameters": {"type": "object", "properties": {}}}',
    "get_vpn_health": '{"name": "get_vpn_health", "description": "Get VPN tunnel health status", "parameters": {"type": "object", "properties": {}}}',
    "get_jira_issues": '{"name": "get_jira_issues", "description": "Get open Jira firewall change issues", "parameters": {"type": "object", "properties": {}}}',
    "find_duplicate_objects": '{"name": "find_duplicate_objects", "description": "Find duplicate address/service objects", "parameters": {"type": "object", "properties": {"object_type": {"type": "string", "description": "address, service, address-group, service-group"}}}}',
    "create_firewall_rule": '{"name": "create_firewall_rule", "description": "Create a firewall security rule", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "destination": {"type": "string"}, "port": {"type": "string"}, "action": {"type": "string"}}, "required": ["source", "destination", "action"]}}',
    "analyze_attack_path": '{"name": "analyze_attack_path", "description": "Analyze potential attack paths from source to target", "parameters": {"type": "object", "properties": {"source": {"type": "string"}, "target": {"type": "string"}}, "required": ["source", "target"]}}',
}

# Tool sets to pick from when adding tools to knowledge examples (Section 10)
TOOL_SETS_FOR_KNOWLEDGE = [
    ["search_objects", "find_unused_rules", "find_shadowed_rules", "search_rules"],
    ["check_traffic_flow", "check_access", "nat_check", "search_objects"],
    ["run_compliance_scan", "search_rules", "get_rule_statistics"],
    ["query_audit_logs", "get_audit_diff", "compare_configs"],
    ["get_rule_statistics", "get_dnat_exposure", "get_critical_findings", "find_unused_rules"],
    ["get_snow_changes", "get_jira_issues", "search_objects"],
    ["search_objects"],
    ["search_objects", "find_unused_rules"],
    ["run_compliance_scan", "find_unused_rules", "search_objects"],
    ["check_traffic_flow", "nat_check"],
]


def load_json(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def content_hash(text: str) -> str:
    return hashlib.md5(text.strip().lower().encode()).hexdigest()


def fix_hq_example(example: dict, add_tools: bool, rng: random.Random) -> dict | None:
    """Fix a single HQ example per the reference doc spec.

    Returns None if example should be dropped (broken/empty).
    """
    convs = example.get("conversations", [])
    if len(convs) < 2:
        return None

    # Extract human/gpt turns
    human_turn = None
    gpt_turn = None
    for turn in convs:
        if turn["from"] == "human":
            human_turn = turn
        elif turn["from"] == "gpt":
            gpt_turn = turn

    if not human_turn or not gpt_turn:
        return None

    # Fix dict-type gpt values (disambiguation examples with classification/intent/response)
    gpt_value = gpt_turn["value"]
    if isinstance(gpt_value, dict):
        # Extract the 'response' key if it exists
        if "response" in gpt_value and isinstance(gpt_value["response"], str):
            gpt_value = gpt_value["response"]
        else:
            # Try to build a string from the dict
            parts = []
            for k, v in gpt_value.items():
                if isinstance(v, str) and v.strip():
                    parts.append(v)
            gpt_value = "\n\n".join(parts) if parts else ""

    # Drop empty answers
    if not isinstance(gpt_value, str) or len(gpt_value.strip()) < 20:
        return None

    # Build system message
    system_prompt = rng.choice(SYSTEM_PROMPTS)

    if add_tools:
        # Section 10: Add tool schemas so model learns NOT to call tools for knowledge questions
        tool_set = rng.choice(TOOL_SETS_FOR_KNOWLEDGE)
        schemas = "\n".join(TOOL_SCHEMAS[t] for t in tool_set if t in TOOL_SCHEMAS)
        system_value = f"{system_prompt}\n\nEnvironment: ipython\n\n{schemas}"
    else:
        # Pure knowledge — no tools visible (Section 14: 15% "Pure knowledge (no tools)")
        system_value = system_prompt

    # Build fixed conversation
    new_convs = [
        {"from": "system", "value": system_value},
        {"from": "human", "value": human_turn["value"]},
        {"from": "gpt", "value": gpt_value},
    ]

    return {"conversations": new_convs}


def validate_tool_calling_example(example: dict) -> list[str]:
    """Validate a tool calling example against anti-patterns."""
    issues = []
    convs = example.get("conversations", [])

    if not convs:
        issues.append("Empty conversations")
        return issues

    # Must have system message
    if convs[0]["from"] != "system":
        issues.append("Missing system message")

    # System message must have Environment: ipython
    if convs[0]["from"] == "system" and "Environment: ipython" not in convs[0]["value"]:
        issues.append("Missing 'Environment: ipython' in system message")

    for turn in convs:
        val = turn.get("value", "")
        if not isinstance(val, str):
            issues.append(f"Non-string value in {turn['from']} turn")
            continue

        if turn["from"] == "gpt" and "<|python_tag|>" in val:
            # Check for narration before tool call
            tag_pos = val.find("<|python_tag|>")
            prefix = val[:tag_pos].strip()
            if prefix:
                issues.append(f"Text before <|python_tag|>: '{prefix[:50]}...'")

            # Check JSON format
            json_str = val[tag_pos + len("<|python_tag|>"):]
            try:
                tc = json.loads(json_str)
                if isinstance(tc, list):
                    issues.append("Tool call wrapped in array")
                if "type" in tc and tc.get("type") == "function":
                    issues.append("OpenAI format detected")
                if "name" not in tc:
                    issues.append("Tool call missing 'name'")
                if "parameters" not in tc:
                    issues.append("Tool call missing 'parameters'")
            except json.JSONDecodeError:
                issues.append("Invalid JSON in tool call")

    return issues


def validate_knowledge_example(example: dict) -> list[str]:
    """Validate a knowledge/conversational example."""
    issues = []
    convs = example.get("conversations", [])

    if not convs:
        issues.append("Empty conversations")
        return issues

    if convs[0]["from"] != "system":
        issues.append("Missing system message")

    # Knowledge examples must NOT have ipython role or <|python_tag|>
    for turn in convs:
        val = turn.get("value", "")
        if not isinstance(val, str):
            issues.append(f"Non-string value in {turn['from']} turn")
            continue

        if turn["from"] == "ipython":
            issues.append("Knowledge example should not have ipython turn")
        if turn["from"] == "gpt" and "<|python_tag|>" in val:
            issues.append("Knowledge example should not have tool call")

    return issues


def compute_ratios(tool_calling: list, knowledge: list) -> dict:
    """Compute category ratios for the combined dataset."""
    total = len(tool_calling) + len(knowledge)

    # Categorize tool calling examples
    tc_categories = Counter()
    for ex in tool_calling:
        convs = ex.get("conversations", [])
        roles = [c["from"] for c in convs]
        has_tool_call = any(
            "<|python_tag|>" in c.get("value", "")
            for c in convs if c["from"] == "gpt"
        )
        has_ipython = "ipython" in roles
        has_error = any(
            '"status": "error"' in c.get("value", "")
            for c in convs if c["from"] == "ipython"
        )
        turn_count = sum(1 for r in roles if r in ("human", "gpt"))

        # Check confirmation BEFORE multi-turn (confirmation flows have 5+ turns too)
        human_msgs = [c["value"] for c in convs if c["from"] == "human"]
        is_confirm = has_tool_call and has_ipython and len(human_msgs) >= 2 and any(
            m.lower().strip() in ("yes", "go ahead", "do it", "ok", "proceed", "yes, do it",
                                   "yes please", "yes, go ahead", "sure", "confirmed",
                                   "yes go ahead", "sure, go ahead")
            or m.lower().strip().startswith("yes")
            for m in human_msgs[1:]
        )

        if has_error:
            tc_categories["error"] += 1
        elif is_confirm:
            tc_categories["confirmation"] += 1
        elif turn_count > 4 and not is_confirm:
            tc_categories["multi_turn"] += 1
        elif has_tool_call and has_ipython:
            tc_categories["tool_call"] += 1
        elif not has_tool_call and not has_ipython:
            tc_categories["conversational_tools"] += 1
        else:
            tc_categories["tool_call"] += 1

    # Knowledge examples
    knowledge_with_tools = 0
    knowledge_pure = 0
    for ex in knowledge:
        convs = ex.get("conversations", [])
        if convs and "Environment: ipython" in convs[0].get("value", ""):
            knowledge_with_tools += 1
        else:
            knowledge_pure += 1

    return {
        "total": total,
        "tool_call": tc_categories.get("tool_call", 0),
        "confirmation": tc_categories.get("confirmation", 0),
        "conversational_tools": tc_categories.get("conversational_tools", 0) + knowledge_with_tools,
        "knowledge_pure": knowledge_pure,
        "multi_turn": tc_categories.get("multi_turn", 0),
        "error": tc_categories.get("error", 0),
    }


def main():
    parser = argparse.ArgumentParser(description="Combine training datasets")
    parser.add_argument("--tool-calling", default="data/processed/tool_calling_train.json",
                        help="Path to tool calling training data")
    parser.add_argument("--hq-data", default="data/processed/high_quality_new.json",
                        help="Path to high-quality knowledge data")
    parser.add_argument("--output", default="data/processed/combined_train.json",
                        help="Output path for combined dataset")
    parser.add_argument("--tools-visible-pct", type=float, default=0.20,
                        help="Fraction of knowledge examples with tool schemas visible (default 0.20)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--dry-run", action="store_true", help="Preview without writing output")
    args = parser.parse_args()

    rng = random.Random(args.seed)

    # -------------------------------------------------------------------------
    # Step 1: Load datasets
    # -------------------------------------------------------------------------
    print("=" * 60)
    print("STEP 1: Load datasets")
    print("=" * 60)

    tc_path = Path(args.tool_calling)
    hq_path = Path(args.hq_data)

    if not tc_path.exists():
        print(f"ERROR: Tool calling data not found: {tc_path}")
        sys.exit(1)
    if not hq_path.exists():
        print(f"ERROR: HQ data not found: {hq_path}")
        sys.exit(1)

    tool_calling = load_json(str(tc_path))
    hq_raw = load_json(str(hq_path))

    print(f"  Tool calling examples: {len(tool_calling)}")
    print(f"  HQ knowledge examples: {len(hq_raw)}")

    # -------------------------------------------------------------------------
    # Step 2: Fix HQ data
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 2: Fix HQ knowledge data")
    print("=" * 60)

    # Decide which examples get tools visible
    indices = list(range(len(hq_raw)))
    rng.shuffle(indices)
    tools_visible_count = int(len(hq_raw) * args.tools_visible_pct)
    tools_visible_set = set(indices[:tools_visible_count])

    fixed_hq = []
    dropped = {"dict_fixed": 0, "empty_dropped": 0, "short_dropped": 0}

    for i, example in enumerate(hq_raw):
        add_tools = i in tools_visible_set

        # Track dict fixes
        gpt_turn = next((t for t in example.get("conversations", []) if t["from"] == "gpt"), None)
        if gpt_turn and isinstance(gpt_turn.get("value"), dict):
            dropped["dict_fixed"] += 1

        fixed = fix_hq_example(example, add_tools=add_tools, rng=rng)
        if fixed is None:
            dropped["empty_dropped"] += 1
        else:
            fixed_hq.append(fixed)

    tools_with = sum(
        1 for ex in fixed_hq
        if "Environment: ipython" in ex["conversations"][0]["value"]
    )
    tools_without = len(fixed_hq) - tools_with

    print(f"  Fixed examples: {len(fixed_hq)}")
    print(f"  Dict values fixed: {dropped['dict_fixed']}")
    print(f"  Dropped (empty/short): {dropped['empty_dropped']}")
    print(f"  With tool schemas visible: {tools_with} ({tools_with/len(fixed_hq)*100:.1f}%)")
    print(f"  Pure knowledge (no tools): {tools_without} ({tools_without/len(fixed_hq)*100:.1f}%)")

    # -------------------------------------------------------------------------
    # Step 3: Deduplicate across both datasets
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 3: Deduplicate combined dataset")
    print("=" * 60)

    seen_hashes = set()
    combined = []
    dupe_count = 0

    # Tool calling first (higher priority)
    for ex in tool_calling:
        convs = ex.get("conversations", [])
        human_turns = " ".join(c["value"] for c in convs if c["from"] == "human" and isinstance(c["value"], str))
        h = content_hash(human_turns)
        if h not in seen_hashes:
            seen_hashes.add(h)
            combined.append(ex)
        else:
            dupe_count += 1

    # Then knowledge
    for ex in fixed_hq:
        convs = ex.get("conversations", [])
        human_turns = " ".join(c["value"] for c in convs if c["from"] == "human" and isinstance(c["value"], str))
        h = content_hash(human_turns)
        if h not in seen_hashes:
            seen_hashes.add(h)
            combined.append(ex)
        else:
            dupe_count += 1

    print(f"  Duplicates removed: {dupe_count}")
    print(f"  Combined total: {len(combined)}")

    # Shuffle
    rng.shuffle(combined)

    # -------------------------------------------------------------------------
    # Step 4: Validate
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 4: Validate combined dataset")
    print("=" * 60)

    tc_count = 0
    kn_count = 0
    tc_issues_total = 0
    kn_issues_total = 0
    issue_examples = []

    for ex in combined:
        convs = ex.get("conversations", [])
        has_ipython = any(c["from"] == "ipython" for c in convs)
        has_tool_call = any(
            "<|python_tag|>" in c.get("value", "")
            for c in convs if c["from"] == "gpt" and isinstance(c.get("value"), str)
        )

        if has_ipython or has_tool_call:
            tc_count += 1
            issues = validate_tool_calling_example(ex)
            if issues:
                tc_issues_total += 1
                if len(issue_examples) < 5:
                    issue_examples.append(("tool_call", issues, convs[1]["value"][:60] if len(convs) > 1 else "?"))
        else:
            kn_count += 1
            issues = validate_knowledge_example(ex)
            if issues:
                kn_issues_total += 1
                if len(issue_examples) < 5:
                    issue_examples.append(("knowledge", issues, convs[1]["value"][:60] if len(convs) > 1 else "?"))

    print(f"  Tool calling examples: {tc_count}")
    print(f"  Knowledge examples: {kn_count}")
    print(f"  Tool calling issues: {tc_issues_total}")
    print(f"  Knowledge issues: {kn_issues_total}")

    if issue_examples:
        print(f"\n  Sample issues:")
        for cat, issues, query in issue_examples:
            print(f"    [{cat}] '{query}...'")
            for iss in issues:
                print(f"      - {iss}")

    # -------------------------------------------------------------------------
    # Step 5: Ratio analysis
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("STEP 5: Training ratio analysis")
    print("=" * 60)

    # Separate back out for ratio calc
    tc_examples = [ex for ex in combined if any(
        c["from"] == "ipython" for c in ex.get("conversations", [])
    ) or any(
        "<|python_tag|>" in c.get("value", "")
        for c in ex.get("conversations", []) if c["from"] == "gpt" and isinstance(c.get("value"), str)
    )]
    kn_examples = [ex for ex in combined if ex not in tc_examples]

    ratios = compute_ratios(tc_examples, kn_examples)
    total = ratios["total"]

    print(f"\n  Category breakdown:")
    target_ratios = {
        "tool_call": ("IP-triggered tool calls", 30),
        "confirmation": ("Confirmation tool calls", 15),
        "conversational_tools": ("Conversational with tools", 20),
        "knowledge_pure": ("Pure knowledge (no tools)", 15),
        "multi_turn": ("Multi-turn with follow-ups", 10),
        "error": ("Error handling", 10),
    }

    print(f"  {'Category':<35} {'Count':>6} {'Actual%':>8} {'Target%':>8} {'Status'}")
    print(f"  {'-'*35} {'-'*6} {'-'*8} {'-'*8} {'-'*10}")
    for key, (label, target) in target_ratios.items():
        count = ratios.get(key, 0)
        pct = count / total * 100 if total else 0
        # Allow ±10 absolute percentage points tolerance
        status = "OK" if abs(pct - target) <= 12 else "WARN"
        print(f"  {label:<35} {count:>6} {pct:>7.1f}% {target:>7}% {status}")

    print(f"\n  Total: {total}")

    # -------------------------------------------------------------------------
    # Step 6: Write output
    # -------------------------------------------------------------------------
    if args.dry_run:
        print(f"\n{'=' * 60}")
        print("DRY RUN — no file written")
        print("=" * 60)
    else:
        print(f"\n{'=' * 60}")
        print("STEP 6: Write combined dataset")
        print("=" * 60)

        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(combined, f, indent=2, ensure_ascii=False)

        size_mb = output_path.stat().st_size / (1024 * 1024)
        print(f"  Written to: {output_path}")
        print(f"  File size: {size_mb:.1f} MB")
        print(f"  Total examples: {len(combined)}")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print(f"\n{'=' * 60}")
    print("SUMMARY")
    print("=" * 60)
    print(f"  Tool calling examples: {tc_count} ({tc_count/len(combined)*100:.1f}%)")
    print(f"  Knowledge examples:    {kn_count} ({kn_count/len(combined)*100:.1f}%)")
    print(f"  Total:                 {len(combined)}")
    print(f"  Validation issues:     {tc_issues_total + kn_issues_total}")

    ref_checks = []
    # Section 17: minimum 2000-5000
    if len(combined) >= 2000:
        ref_checks.append(("Minimum 2,000 examples (Section 17)", "PASS"))
    else:
        ref_checks.append(("Minimum 2,000 examples (Section 17)", "FAIL"))

    # All examples must have system message
    all_have_system = all(
        ex["conversations"][0]["from"] == "system"
        for ex in combined if ex.get("conversations")
    )
    ref_checks.append(("All examples have system message", "PASS" if all_have_system else "FAIL"))

    # No human/gpt-only examples (must have system)
    no_bare = all(
        len(ex["conversations"]) >= 3  # system + human + gpt minimum
        for ex in combined if ex.get("conversations")
    )
    ref_checks.append(("No bare human/gpt examples", "PASS" if no_bare else "FAIL"))

    # Tool call examples have Environment: ipython
    tc_have_env = all(
        "Environment: ipython" in ex["conversations"][0]["value"]
        for ex in tc_examples
    )
    ref_checks.append(("Tool examples have Environment: ipython", "PASS" if tc_have_env else "FAIL"))

    # No validation issues
    ref_checks.append(("Zero validation issues", "PASS" if (tc_issues_total + kn_issues_total) == 0 else "FAIL"))

    print(f"\n  Reference doc compliance:")
    for check, status in ref_checks:
        marker = "PASS" if status == "PASS" else "FAIL"
        print(f"    [{marker}] {check}")

    # Return exit code
    total_issues = tc_issues_total + kn_issues_total
    if total_issues > 0:
        print(f"\nWARNING: {total_issues} validation issues found")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
