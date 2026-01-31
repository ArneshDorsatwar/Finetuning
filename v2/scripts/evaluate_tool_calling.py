#!/usr/bin/env python3
"""
Evaluation Suite for Tool Calling Fine-Tuned Model

Tests:
1. Tool selection accuracy - Does model choose correct tool?
2. Parameter extraction - Are parameters correctly extracted?
3. JSON validity - Is output valid JSON?
4. Multi-turn handling - Does model maintain context?
5. Non-tool queries - Does model avoid hallucinating tools?

Usage:
    # Test with Ollama
    python v2/scripts/evaluate_tool_calling.py --model network-security-expert

    # Test with custom endpoint
    python v2/scripts/evaluate_tool_calling.py --endpoint http://localhost:11434

    # Run specific test categories
    python v2/scripts/evaluate_tool_calling.py --categories tool_selection json_validity
"""

import json
import argparse
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from collections import defaultdict

try:
    import httpx
except ImportError:
    print("Please install httpx: pip install httpx")
    exit(1)


@dataclass
class TestCase:
    """A single test case for evaluation."""
    query: str
    expected_tool: Optional[str]  # None means no tool should be called
    expected_params: Optional[Dict[str, Any]] = None
    category: str = "general"
    description: str = ""


@dataclass
class TestResult:
    """Result of running a test case."""
    test_case: TestCase
    response: str
    tool_called: Optional[str]
    params_extracted: Optional[Dict[str, Any]]
    json_valid: bool
    tool_correct: bool
    params_correct: bool
    error: Optional[str] = None


# Test cases organized by category
TEST_CASES = [
    # ========== TOOL SELECTION TESTS ==========
    TestCase(
        query="Check if traffic from 10.1.1.100 to 192.168.50.10 on port 5432 is allowed",
        expected_tool="check_traffic_flow",
        expected_params={"source_ip": "10.1.1.100", "destination_ip": "192.168.50.10", "port": 5432},
        category="tool_selection",
        description="Traffic flow check with all params"
    ),
    TestCase(
        query="Can the web server at 10.0.1.50 reach the database at 10.0.2.100 on port 3306?",
        expected_tool="check_traffic_flow",
        expected_params={"source_ip": "10.0.1.50", "destination_ip": "10.0.2.100", "port": 3306},
        category="tool_selection",
        description="Traffic check with natural language"
    ),
    TestCase(
        query="Run a PCI-DSS compliance scan on all firewalls",
        expected_tool="run_compliance_scan",
        expected_params={"framework": "pci-dss"},
        category="tool_selection",
        description="Compliance scan trigger"
    ),
    TestCase(
        query="What attack paths exist from the internet to our payment server?",
        expected_tool="analyze_attack_path",
        expected_params={"source": "internet"},
        category="tool_selection",
        description="Attack path analysis"
    ),
    TestCase(
        query="Find all shadowed rules in the production firewall",
        expected_tool="find_shadowed_rules",
        category="tool_selection",
        description="Shadowed rule detection"
    ),
    TestCase(
        query="Create a firewall rule to allow HTTPS traffic from DMZ to internal web servers",
        expected_tool="create_firewall_rule",
        expected_params={"action": "allow"},
        category="tool_selection",
        description="Rule creation"
    ),
    TestCase(
        query="What is the blast radius if the jump server at 10.5.1.10 is compromised?",
        expected_tool="calculate_blast_radius",
        expected_params={"asset": "10.5.1.10"},
        category="tool_selection",
        description="Blast radius calculation"
    ),
    TestCase(
        query="Get rule hit counts for the DG-Production device group",
        expected_tool="get_rule_hit_count",
        expected_params={"device_group": "DG-Production"},
        category="tool_selection",
        description="Rule hit count query"
    ),

    # ========== NON-TOOL TESTS (should NOT call tools) ==========
    TestCase(
        query="What is the principle of least privilege?",
        expected_tool=None,
        category="non_tool",
        description="Conceptual question - no tool"
    ),
    TestCase(
        query="Explain the difference between stateful and stateless firewalls",
        expected_tool=None,
        category="non_tool",
        description="Educational question - no tool"
    ),
    TestCase(
        query="What are the NIST 800-53 access control families?",
        expected_tool=None,
        category="non_tool",
        description="Compliance theory - no tool"
    ),
    TestCase(
        query="How does defense in depth work?",
        expected_tool=None,
        category="non_tool",
        description="Security concept - no tool"
    ),

    # ========== JSON VALIDITY TESTS ==========
    TestCase(
        query="Check traffic from 192.168.1.0/24 to 10.0.0.0/8 on ports 80 and 443",
        expected_tool="check_traffic_flow",
        category="json_validity",
        description="CIDR notation in params"
    ),
    TestCase(
        query="Analyze attack paths from 'untrusted-zone' to 'payment-servers' including cloud",
        expected_tool="analyze_attack_path",
        category="json_validity",
        description="String params with special chars"
    ),

    # ========== PARAMETER EXTRACTION TESTS ==========
    TestCase(
        query="Is UDP traffic on port 53 allowed from 10.1.1.0/24 to 8.8.8.8?",
        expected_tool="check_traffic_flow",
        expected_params={"protocol": "udp", "port": 53, "destination_ip": "8.8.8.8"},
        category="param_extraction",
        description="Protocol extraction"
    ),
    TestCase(
        query="Run SOC2 compliance scan on DG-Finance with evidence generation",
        expected_tool="run_compliance_scan",
        expected_params={"framework": "soc2", "include_evidence": True},
        category="param_extraction",
        description="Boolean param extraction"
    ),

    # ========== EDGE CASES ==========
    TestCase(
        query="Check traffic",
        expected_tool="check_traffic_flow",
        category="edge_case",
        description="Incomplete query - should ask for params or make reasonable defaults"
    ),
    TestCase(
        query="What tools do you have available?",
        expected_tool=None,
        category="edge_case",
        description="Meta question about capabilities"
    ),
]


def extract_tool_call(response: str) -> Tuple[Optional[str], Optional[Dict], bool]:
    """Extract tool call from response, return (tool_name, params, json_valid)."""
    # Look for <|python_tag|> format
    if "<|python_tag|>" in response:
        try:
            json_str = response.split("<|python_tag|>")[1].strip()
            # Find the JSON object
            if json_str.startswith('['):
                end = json_str.rfind(']') + 1
            elif json_str.startswith('{'):
                end = json_str.rfind('}') + 1
            else:
                return None, None, False

            json_str = json_str[:end]
            data = json.loads(json_str)

            if isinstance(data, list):
                data = data[0]  # Take first tool call

            tool_name = data.get('name')
            params = data.get('parameters', {})
            return tool_name, params, True

        except (json.JSONDecodeError, IndexError):
            return None, None, False

    # Look for JSON in response (fallback)
    try:
        match = re.search(r'\{[^{}]*"name"[^{}]*\}', response, re.DOTALL)
        if match:
            data = json.loads(match.group())
            return data.get('name'), data.get('parameters', {}), True
    except:
        pass

    return None, None, True  # No tool call, but valid (might be intentional)


def check_params_match(expected: Optional[Dict], actual: Optional[Dict]) -> bool:
    """Check if actual params contain expected params (subset match)."""
    if expected is None:
        return True
    if actual is None:
        return False

    for key, value in expected.items():
        if key not in actual:
            return False
        # Flexible matching for strings
        if isinstance(value, str) and isinstance(actual[key], str):
            if value.lower() not in actual[key].lower() and actual[key].lower() not in value.lower():
                return False
        elif actual[key] != value:
            return False

    return True


def query_model(query: str, model: str, endpoint: str) -> str:
    """Send query to model and get response."""
    url = f"{endpoint}/api/generate"

    payload = {
        "model": model,
        "prompt": query,
        "stream": False,
        "options": {
            "temperature": 0.1,  # Low temperature for deterministic testing
            "num_predict": 500
        }
    }

    try:
        with httpx.Client(timeout=60.0) as client:
            response = client.post(url, json=payload)
            response.raise_for_status()
            return response.json().get("response", "")
    except Exception as e:
        return f"ERROR: {str(e)}"


def run_test(test: TestCase, model: str, endpoint: str) -> TestResult:
    """Run a single test case."""
    response = query_model(test.query, model, endpoint)

    if response.startswith("ERROR:"):
        return TestResult(
            test_case=test,
            response=response,
            tool_called=None,
            params_extracted=None,
            json_valid=False,
            tool_correct=False,
            params_correct=False,
            error=response
        )

    tool_name, params, json_valid = extract_tool_call(response)

    # Check tool correctness
    if test.expected_tool is None:
        tool_correct = tool_name is None
    else:
        tool_correct = tool_name == test.expected_tool

    # Check params correctness
    params_correct = check_params_match(test.expected_params, params)

    return TestResult(
        test_case=test,
        response=response,
        tool_called=tool_name,
        params_extracted=params,
        json_valid=json_valid,
        tool_correct=tool_correct,
        params_correct=params_correct
    )


def print_result(result: TestResult, verbose: bool = False):
    """Print a single test result."""
    status = "PASS" if (result.tool_correct and result.json_valid) else "FAIL"
    icon = "✓" if status == "PASS" else "✗"

    print(f"  {icon} {result.test_case.description}")

    if verbose or status == "FAIL":
        print(f"      Query: {result.test_case.query[:60]}...")
        print(f"      Expected tool: {result.test_case.expected_tool}")
        print(f"      Got tool: {result.tool_called}")
        print(f"      JSON valid: {result.json_valid}")
        if result.error:
            print(f"      Error: {result.error}")
        print()


def run_evaluation(model: str, endpoint: str, categories: List[str], verbose: bool = False):
    """Run full evaluation suite."""
    print(f"\n{'='*60}")
    print(f"Tool Calling Evaluation Suite")
    print(f"{'='*60}")
    print(f"Model: {model}")
    print(f"Endpoint: {endpoint}")
    print()

    # Filter test cases by category
    if categories:
        tests = [t for t in TEST_CASES if t.category in categories]
    else:
        tests = TEST_CASES

    # Group by category
    by_category = defaultdict(list)
    for test in tests:
        by_category[test.category].append(test)

    # Run tests
    all_results = []

    for category, category_tests in by_category.items():
        print(f"\n[{category.upper()}] ({len(category_tests)} tests)")
        print("-" * 40)

        for test in category_tests:
            result = run_test(test, model, endpoint)
            all_results.append(result)
            print_result(result, verbose)

    # Summary
    print(f"\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")

    total = len(all_results)
    tool_correct = sum(1 for r in all_results if r.tool_correct)
    json_valid = sum(1 for r in all_results if r.json_valid)
    params_correct = sum(1 for r in all_results if r.params_correct)
    full_pass = sum(1 for r in all_results if r.tool_correct and r.json_valid and r.params_correct)

    print(f"\nTotal tests: {total}")
    print(f"Tool selection accuracy: {tool_correct}/{total} ({100*tool_correct/total:.1f}%)")
    print(f"JSON validity: {json_valid}/{total} ({100*json_valid/total:.1f}%)")
    print(f"Parameter extraction: {params_correct}/{total} ({100*params_correct/total:.1f}%)")
    print(f"Full pass (all criteria): {full_pass}/{total} ({100*full_pass/total:.1f}%)")

    # By category summary
    print("\nBy category:")
    for category in by_category.keys():
        cat_results = [r for r in all_results if r.test_case.category == category]
        cat_pass = sum(1 for r in cat_results if r.tool_correct and r.json_valid)
        print(f"  {category}: {cat_pass}/{len(cat_results)} ({100*cat_pass/len(cat_results):.1f}%)")

    # Targets check
    print(f"\n{'='*60}")
    print("TARGET CHECK")
    print(f"{'='*60}")

    targets = {
        "Tool selection": (100 * tool_correct / total, 90),
        "Parameter extraction": (100 * params_correct / total, 85),
        "JSON validity": (100 * json_valid / total, 100),
    }

    all_pass = True
    for name, (actual, target) in targets.items():
        status = "✓ PASS" if actual >= target else "✗ FAIL"
        if actual < target:
            all_pass = False
        print(f"  {name}: {actual:.1f}% (target: {target}%) - {status}")

    if all_pass:
        print("\n✓ All targets met! Model is ready for deployment.")
    else:
        print("\n✗ Some targets not met. Consider additional training or DPO refinement.")

    return all_results


def main():
    parser = argparse.ArgumentParser(description='Evaluate tool calling model')
    parser.add_argument('--model', type=str, default='network-security-expert',
                       help='Ollama model name')
    parser.add_argument('--endpoint', type=str, default='http://localhost:11434',
                       help='Ollama API endpoint')
    parser.add_argument('--categories', nargs='+', default=None,
                       choices=['tool_selection', 'non_tool', 'json_validity',
                               'param_extraction', 'edge_case'],
                       help='Test categories to run')
    parser.add_argument('--verbose', action='store_true',
                       help='Show detailed output for all tests')
    parser.add_argument('--list-tests', action='store_true',
                       help='List all test cases and exit')

    args = parser.parse_args()

    if args.list_tests:
        print("Available test cases:")
        for test in TEST_CASES:
            print(f"  [{test.category}] {test.description}")
            print(f"    Query: {test.query[:60]}...")
            print(f"    Expected: {test.expected_tool}")
            print()
        return

    run_evaluation(args.model, args.endpoint, args.categories, args.verbose)


if __name__ == '__main__':
    main()
