#!/usr/bin/env python3
"""
Test tool calling with the fine-tuned model via Ollama API.

The model produces Llama 3.1 native tool calls using <|python_tag|> followed
by JSON.  Ollama's CLI strips special tokens, so we use the /api/chat endpoint
with raw mode to see the full output.

This script also demonstrates how FireWeave would integrate with the model:
  1. Send user query → model returns <|python_tag|>{tool call JSON}
  2. Parse the tool call
  3. Execute it (simulated here)
  4. Feed the result back as an ipython role message
  5. Model produces a human-readable summary

Usage:
    python scripts/test_tool_calling.py
    python scripts/test_tool_calling.py --base-url http://192.168.1.100:11434
    python scripts/test_tool_calling.py --model kirito
"""

import argparse
import json
import re
import sys

import requests

# ── Default configuration ──────────────────────────────────────────────────
DEFAULT_MODEL = "kirito"
DEFAULT_BASE_URL = "http://localhost:11434"

SYSTEM_PROMPT = """\
You are Ember, a Network Security Expert AI integrated with FireWeave. You have deep expertise in firewall configuration (Cisco, Palo Alto, Fortinet), cloud security (AWS, Azure, GCP), threat detection, compliance frameworks (PCI-DSS, SOC2, NIST, HIPAA), and network automation.

When users request actions like checking traffic, creating rules, running scans, or analyzing policies, use the available tools to fulfill their request. Provide accurate, detailed technical guidance with specific commands and configurations.

Environment: ipython

{"name": "check_traffic_flow", "description": "Check if traffic is allowed between source and destination across firewalls", "parameters": {"source": {"type": "string", "description": "Source IP address"}, "destination": {"type": "string", "description": "Destination IP address"}, "port": {"type": "integer", "description": "Destination port number"}, "protocol": {"type": "string", "description": "Protocol (tcp or udp)"}}}
{"name": "create_firewall_rule", "description": "Create a new firewall rule", "parameters": {"source": {"type": "string", "description": "Source IP or subnet"}, "destination": {"type": "string", "description": "Destination IP or subnet"}, "port": {"type": "integer", "description": "Destination port"}, "action": {"type": "string", "description": "allow or deny"}}}
{"name": "run_compliance_scan", "description": "Run a compliance scan against a security framework", "parameters": {"firewall": {"type": "string", "description": "Firewall device name"}, "framework": {"type": "string", "description": "Compliance framework (PCI-DSS, SOC2, NIST, HIPAA)"}}}
{"name": "find_shadowed_rules", "description": "Find rules that are shadowed by other rules and never match traffic", "parameters": {"firewall": {"type": "string", "description": "Firewall device name"}}}
{"name": "get_rule_hit_count", "description": "Get hit count statistics for firewall rules", "parameters": {"firewall": {"type": "string", "description": "Firewall device name"}, "rule_id": {"type": "string", "description": "Rule ID to check"}}}
{"name": "analyze_attack_path", "description": "Analyze potential attack paths between source and target", "parameters": {"source": {"type": "string", "description": "Source IP"}, "target": {"type": "string", "description": "Target IP"}}}"""

# ── Simulated tool results ─────────────────────────────────────────────────
MOCK_TOOL_RESULTS = {
    "check_traffic_flow": lambda p: json.dumps({
        "status": "allowed",
        "path": [
            {"device": "fw-edge-01", "rule": "ACL-1042", "action": "permit"},
            {"device": "fw-core-02", "rule": "POL-3391", "action": "permit"},
        ],
        "source": p.get("source", "?"),
        "destination": p.get("destination", "?"),
        "port": p.get("port", "?"),
        "protocol": p.get("protocol", "tcp"),
        "nat_translations": [],
    }),
    "create_firewall_rule": lambda p: json.dumps({
        "status": "pending_approval",
        "rule_id": "RULE-20260210-001",
        "message": "Rule created and submitted for approval workflow.",
    }),
    "run_compliance_scan": lambda p: json.dumps({
        "status": "completed",
        "framework": p.get("framework", "?"),
        "firewall": p.get("firewall", "?"),
        "score": 87,
        "findings": [
            {"severity": "high", "rule": "4.1.2", "description": "Default admin credentials detected"},
            {"severity": "medium", "rule": "6.3.1", "description": "Logging not enabled on 3 interfaces"},
        ],
    }),
    "find_shadowed_rules": lambda p: json.dumps({
        "firewall": p.get("firewall", "?"),
        "shadowed_rules": [
            {"rule_id": "ACL-204", "shadowed_by": "ACL-198", "reason": "Broader source range in ACL-198"},
            {"rule_id": "ACL-312", "shadowed_by": "ACL-100", "reason": "Any-any deny before specific permit"},
        ],
    }),
    "get_rule_hit_count": lambda p: json.dumps({
        "firewall": p.get("firewall", "?"),
        "rule_id": p.get("rule_id", "?"),
        "hit_count": 14823,
        "last_hit": "2026-02-09T14:32:11Z",
        "period": "last 30 days",
    }),
    "analyze_attack_path": lambda p: json.dumps({
        "source": p.get("source", "?"),
        "target": p.get("target", "?"),
        "paths_found": 2,
        "critical_path": {
            "hops": [
                {"device": "fw-dmz-01", "vulnerability": "CVE-2025-1234"},
                {"device": "sw-core-01", "vulnerability": None},
                {"device": "fw-internal-01", "vulnerability": "overly permissive rule ACL-999"},
            ],
            "risk_score": 7.8,
        },
    }),
}


def parse_args():
    p = argparse.ArgumentParser(description="Test tool calling with fine-tuned model")
    p.add_argument("--model", default=DEFAULT_MODEL, help="Ollama model name")
    p.add_argument("--base-url", default=DEFAULT_BASE_URL, help="Ollama API base URL")
    p.add_argument("--interactive", action="store_true", help="Interactive chat mode")
    return p.parse_args()


def repair_json(text: str) -> str:
    """Attempt to fix minor JSON issues from model output."""
    # Fix missing opening quotes before key names:  port": 22 → "port": 22
    text = re.sub(r'(?<=[\{,])\s*(\w+)":', r' "\1":', text)
    # Remove extra trailing braces
    # Count opening vs closing braces and trim excess
    opens = text.count("{")
    closes = text.count("}")
    if closes > opens:
        for _ in range(closes - opens):
            idx = text.rfind("}")
            text = text[:idx] + text[idx + 1:]
    return text


def parse_tool_call(raw_response: str):
    """Parse <|python_tag|>{...} into (tool_name, parameters) or None."""
    # Strip the <|python_tag|> prefix if present
    text = raw_response.strip()
    if "<|python_tag|>" in text:
        text = text.split("<|python_tag|>", 1)[1].strip()

    # Remove trailing special tokens
    for tok in ("<|eot_id|>", "<|end_of_text|>"):
        text = text.replace(tok, "")
    text = text.strip()

    if not text.startswith("{"):
        return None  # Not a tool call

    text = repair_json(text)

    try:
        obj = json.loads(text)
    except json.JSONDecodeError as e:
        print(f"  [!] JSON parse error: {e}")
        print(f"  [!] Raw text: {text}")
        return None

    name = obj.get("name")
    params = obj.get("parameters", {})
    return (name, params)


def call_ollama_raw(base_url: str, model: str, messages: list) -> str:
    """
    Send a prompt to Ollama using raw mode so we get <|python_tag|> in output.

    We build the Llama 3.1 chat template manually and send with raw=true.
    """
    # Build the full prompt with Llama 3.1 chat template tokens
    prompt_parts = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if role == "system":
            prompt_parts.append(
                f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
                f"{content}<|eot_id|>"
            )
        elif role == "user":
            prompt_parts.append(
                f"<|start_header_id|>user<|end_header_id|>\n\n"
                f"{content}<|eot_id|>"
            )
        elif role == "assistant":
            prompt_parts.append(
                f"<|start_header_id|>assistant<|end_header_id|>\n\n"
                f"{content}<|eot_id|>"
            )
        elif role == "ipython":
            prompt_parts.append(
                f"<|start_header_id|>ipython<|end_header_id|>\n\n"
                f"{content}<|eot_id|>"
            )

    # Add assistant header for the model to continue from
    prompt_parts.append("<|start_header_id|>assistant<|end_header_id|>\n\n")

    full_prompt = "".join(prompt_parts)

    resp = requests.post(
        f"{base_url}/api/generate",
        json={
            "model": model,
            "prompt": full_prompt,
            "raw": True,
            "stream": False,
            "options": {
                "temperature": 0.6,
                "top_p": 0.9,
                "stop": [
                    "<|start_header_id|>",
                    "<|end_header_id|>",
                    "<|eot_id|>",
                ],
            },
        },
        timeout=120,
    )
    resp.raise_for_status()
    return resp.json().get("response", "")


def execute_tool(name: str, params: dict) -> str:
    """Simulate executing a FireWeave tool and return the result."""
    handler = MOCK_TOOL_RESULTS.get(name)
    if handler:
        return handler(params)
    return json.dumps({"error": f"Unknown tool: {name}"})


def run_single_query(base_url: str, model: str, user_query: str):
    """Run one query through the full tool-calling loop."""
    print(f"\n{'='*60}")
    print(f"USER: {user_query}")
    print(f"{'='*60}")

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_query},
    ]

    # Step 1: Get model response
    print("\n[Step 1] Sending to model...")
    raw = call_ollama_raw(base_url, model, messages)
    print(f"  Raw output: {raw[:200]}{'...' if len(raw) > 200 else ''}")

    # Step 2: Parse tool call
    tool_call = parse_tool_call(raw)

    if tool_call is None:
        # Model responded with text, not a tool call
        print(f"\n[Result] Model responded with text (no tool call):")
        # Clean up any special tokens for display
        clean = raw.replace("<|python_tag|>", "").replace("<|eot_id|>", "").strip()
        print(f"  {clean}")
        return

    name, params = tool_call
    print(f"\n[Step 2] Parsed tool call:")
    print(f"  Tool:   {name}")
    print(f"  Params: {json.dumps(params, indent=2)}")

    # Step 3: Execute tool (simulated)
    print(f"\n[Step 3] Executing {name}...")
    result = execute_tool(name, params)
    print(f"  Result: {result[:150]}{'...' if len(result) > 150 else ''}")

    # Step 4: Feed result back to model for human-readable summary
    messages.append({"role": "assistant", "content": f"<|python_tag|>{json.dumps({'name': name, 'parameters': params})}"})
    messages.append({"role": "ipython", "content": result})

    print(f"\n[Step 4] Getting model summary...")
    summary = call_ollama_raw(base_url, model, messages)
    # Clean up special tokens
    summary = summary.replace("<|python_tag|>", "").replace("<|eot_id|>", "").strip()
    print(f"\n[EMBER]: {summary}")


def run_tests(base_url: str, model: str):
    """Run a battery of test queries."""
    test_queries = [
        # Tool calling tests
        "Check if traffic from 10.1.1.50 to 172.16.0.10 on port 443 TCP is allowed",
        "Run a PCI-DSS compliance scan on firewall fw-edge-01",
        "Find shadowed rules on fw-core-02",
        "Create a firewall rule to allow 10.0.0.0/24 to 192.168.1.100 on port 8080",
        "Analyze attack paths from 203.0.113.50 to 10.10.10.5",

        # Knowledge tests (should respond with text, not tool calls)
        "What is the difference between stateful and stateless firewalls?",
        "Explain the PCI-DSS requirement for network segmentation",
    ]

    print("=" * 60)
    print(f"  TOOL CALLING TEST SUITE")
    print(f"  Model: {model}")
    print(f"  URL:   {base_url}")
    print("=" * 60)

    results = {"tool_call": 0, "text": 0, "error": 0}

    for query in test_queries:
        try:
            run_single_query(base_url, model, query)
            # Simple heuristic: if the query mentions specific IPs/firewalls, expect tool call
            results["tool_call" if any(w in query.lower() for w in ["check", "run a", "find shadowed", "create a firewall", "analyze attack"]) else "text"] += 1
        except Exception as e:
            print(f"\n  [ERROR] {e}")
            results["error"] += 1

    print(f"\n\n{'='*60}")
    print("TEST SUMMARY")
    print(f"{'='*60}")
    print(f"  Tool calls detected: {results['tool_call']}")
    print(f"  Text responses:      {results['text']}")
    print(f"  Errors:              {results['error']}")


def interactive_mode(base_url: str, model: str):
    """Interactive chat with tool calling support."""
    print("=" * 60)
    print("  EMBER - Interactive Mode (tool calling enabled)")
    print(f"  Model: {model}")
    print("  Type 'quit' to exit, 'clear' to reset history")
    print("=" * 60)

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]

    while True:
        try:
            user_input = input("\nYou: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if not user_input:
            continue
        if user_input.lower() == "quit":
            break
        if user_input.lower() == "clear":
            messages = [{"role": "system", "content": SYSTEM_PROMPT}]
            print("  [History cleared]")
            continue

        messages.append({"role": "user", "content": user_input})

        raw = call_ollama_raw(base_url, model, messages)
        tool_call = parse_tool_call(raw)

        if tool_call:
            name, params = tool_call
            print(f"  [Tool Call] {name}({json.dumps(params)})")

            result = execute_tool(name, params)
            print(f"  [Tool Result] {result[:100]}...")

            # Add to history
            messages.append({"role": "assistant", "content": f"<|python_tag|>{json.dumps({'name': name, 'parameters': params})}"})
            messages.append({"role": "ipython", "content": result})

            # Get summary
            summary = call_ollama_raw(base_url, model, messages)
            summary = summary.replace("<|python_tag|>", "").replace("<|eot_id|>", "").strip()
            messages.append({"role": "assistant", "content": summary})
            print(f"\nEmber: {summary}")
        else:
            clean = raw.replace("<|python_tag|>", "").replace("<|eot_id|>", "").strip()
            messages.append({"role": "assistant", "content": clean})
            print(f"\nEmber: {clean}")


def main():
    args = parse_args()

    # Quick connectivity check
    try:
        r = requests.get(f"{args.base_url}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        if not any(args.model in m for m in models):
            print(f"WARNING: Model '{args.model}' not found in Ollama.")
            print(f"  Available: {', '.join(models)}")
            print(f"  Continuing anyway...\n")
    except requests.ConnectionError:
        print(f"ERROR: Cannot connect to Ollama at {args.base_url}")
        print("  Make sure Ollama is running: ollama serve")
        sys.exit(1)

    if args.interactive:
        interactive_mode(args.base_url, args.model)
    else:
        run_tests(args.base_url, args.model)


if __name__ == "__main__":
    main()
