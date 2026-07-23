#!/usr/bin/env python
"""Test script for the scan_evtx tool.

Calls scan_evtx directly against sample EVTX files to verify the implementation.
"""

from pathlib import Path
import json
import sys

import server


def main():
    """Run scan_evtx against a sample EVTX file and display results."""
    samples_dir = Path(__file__).parent / "samples"

    if not samples_dir.exists():
        print("Error: samples/ directory not found. Run this script from the repo root.", file=sys.stderr)
        return 1

    # Find a test file (pick one with a known detection)
    test_files = sorted(samples_dir.glob("**/*.evtx"))
    if not test_files:
        print("Error: no .evtx files found in samples/", file=sys.stderr)
        return 1

    test_file = test_files[0]
    print(f"Testing with: {test_file.relative_to(samples_dir.parent)}")
    print()

    # Test 1: Scan with default severity (informational)
    print("=== Test 1: Scan with min_severity='informational' (summary format) ===")
    result = server.scan_evtx(str(test_file), min_severity="informational")
    print(json.dumps(result, indent=2))
    print()

    if result["status"] != "ok":
        print(f"Scan failed: {result.get('detail', 'unknown error')}")
        return 1

    print(f"Found {result['count']} detections (summary format)")
    print()

    # Test 2: Scan with higher severity threshold
    print("=== Test 2: Scan with min_severity='high' ===")
    result = server.scan_evtx(str(test_file), min_severity="high")
    print(f"Found {result['count']} high+ detections")
    print()

    # Test 3: Scan a directory
    print("=== Test 3: Scan entire samples/ directory ===")
    result = server.scan_evtx(str(samples_dir), min_severity="medium")
    if result["status"] == "ok":
        print(f"Found {result['count']} medium+ detections across all EVTX files")
    else:
        print(f"Scan failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 4: Test error handling (invalid severity)
    print("=== Test 4: Invalid severity (should error gracefully) ===")
    result = server.scan_evtx(str(test_file), min_severity="urgent")
    print(f"Status: {result['status']}")
    print(f"Error: {result.get('error', 'N/A')}")
    print(f"Detail: {result.get('detail', 'N/A')}")
    print()

    # Test 5: Test error handling (file not found)
    print("=== Test 5: File not found (should error gracefully) ===")
    result = server.scan_evtx("/no/such/file.evtx")
    print(f"Status: {result['status']}")
    print(f"Error: {result.get('error', 'N/A')}")
    print()

    # Test 6: Test new parameter - rule_filter
    print("=== Test 6: Rule filter (filter='mimikatz') ===")
    result = server.scan_evtx(str(samples_dir), min_severity="informational", rule_filter="mimikatz")
    if result["status"] == "ok":
        print(f"Found {result['count']} detections matching 'mimikatz'")
        print(f"Total matching before limit: {result.get('total_matching', result['count'])}")
        if "sample_detections" in result and result["sample_detections"]:
            print(f"Sample detection rule: {result['sample_detections'][0].get('RuleTitle', 'N/A')}")
    else:
        print(f"Scan failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 7: Test new parameter - output_format="full"
    print("=== Test 7: Output format='full' (first detection only) ===")
    result = server.scan_evtx(str(test_file), min_severity="informational", output_format="full", max_results=1)
    if result["status"] == "ok":
        print(f"Format: full | Count: {result['count']} | Total matching: {result.get('total_matching', 'N/A')}")
        if result["detections"]:
            print(f"First detection keys: {list(result['detections'][0].keys())}")
    else:
        print(f"Scan failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 8: Test new parameter - output_format="summary"
    print("=== Test 8: Output format='summary' (aggregated results) ===")
    result = server.scan_evtx(str(samples_dir), min_severity="high", output_format="summary", max_results=50)
    if result["status"] == "ok":
        print(f"Format: summary | Count: {result['count']} | Total matching: {result.get('total_matching', 'N/A')}")
        print(f"Severity breakdown: {result.get('severity_breakdown', {})}")
        print(f"Top 3 rules: {dict(list(result.get('top_rules', {}).items())[:3])}")
        print(f"Affected computers: {dict(list(result.get('affected_computers', {}).items())[:3])}")
    else:
        print(f"Scan failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 9: Test invalid output_format
    print("=== Test 9: Invalid output_format (should error) ===")
    result = server.scan_evtx(str(test_file), output_format="invalid")
    print(f"Status: {result['status']}")
    print(f"Error: {result.get('error', 'N/A')}")
    print()

    # Test 10: Test invalid max_results
    print("=== Test 10: Invalid max_results (should error) ===")
    result = server.scan_evtx(str(test_file), max_results=-5)
    print(f"Status: {result['status']}")
    print(f"Error: {result.get('error', 'N/A')}")
    print()

    print("All tests completed.")
    return 0


def test_get_rules():
    """Test the get_hayabusa_rules tool."""
    print("\n" + "="*80)
    print("Testing get_hayabusa_rules tool")
    print("="*80 + "\n")

    # Test 1: Get all rules
    print("=== Test 1: Get all available rules ===")
    result = server.get_hayabusa_rules()
    if result["status"] == "ok":
        print(f"Total available rules: {result['total_available']}")
        print(f"Returned rules: {result['count']}")
        if result["rules"]:
            sample = result["rules"][0]
            print(f"\nSample rule keys: {list(sample.keys())}")
            print(f"Sample rule: {sample.get('title')} (Level: {sample.get('level')})")
    else:
        print(f"Failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 2: Filter by keyword (mimikatz)
    print("=== Test 2: Filter by keyword 'mimikatz' ===")
    result = server.get_hayabusa_rules(keyword="mimikatz")
    if result["status"] == "ok":
        print(f"Found {result['count']} rules matching 'mimikatz'")
        if result["rules"]:
            for rule in result["rules"][:3]:
                print(f"  - {rule.get('title')} (by {rule.get('author')})")
    else:
        print(f"Failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 3: Filter by keyword (powershell)
    print("=== Test 3: Filter by keyword 'powershell' ===")
    result = server.get_hayabusa_rules(keyword="powershell")
    if result["status"] == "ok":
        print(f"Found {result['count']} rules matching 'powershell'")
        if result["rules"]:
            for rule in result["rules"][:3]:
                print(f"  - {rule.get('title')}")
    else:
        print(f"Failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 4: Filter by level
    print("=== Test 4: Filter by level 'critical' ===")
    result = server.get_hayabusa_rules(level_filter="critical")
    if result["status"] == "ok":
        print(f"Found {result['count']} critical-level rules")
        if result["rules"]:
            for rule in result["rules"][:5]:
                print(f"  - {rule.get('title')} (ID: {rule.get('id')})")
    else:
        print(f"Failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 5: Combined filter (keyword + level)
    print("=== Test 5: Filter by keyword 'lateral' AND level 'high' ===")
    result = server.get_hayabusa_rules(keyword="lateral", level_filter="high")
    if result["status"] == "ok":
        print(f"Found {result['count']} rules matching 'lateral' with high severity")
        if result["rules"]:
            for rule in result["rules"][:3]:
                print(f"  - {rule.get('title')}")
    else:
        print(f"Failed: {result.get('detail', 'unknown error')}")
    print()

    # Test 6: Invalid level filter
    print("=== Test 6: Invalid level filter (should error) ===")
    result = server.get_hayabusa_rules(level_filter="urgent")
    print(f"Status: {result['status']}")
    print(f"Error: {result.get('error', 'N/A')}")
    print()

    # Test 7: Filter by tags (sysmon)
    print("=== Test 7: Filter by keyword 'sysmon' (tag search) ===")
    result = server.get_hayabusa_rules(keyword="sysmon")
    if result["status"] == "ok":
        print(f"Found {result['count']} rules with 'sysmon' tag")
        if result["rules"]:
            rule = result["rules"][0]
            print(f"Sample: {rule.get('title')}")
            print(f"Tags: {rule.get('tags', [])}")
    else:
        print(f"Failed: {result.get('detail', 'unknown error')}")
    print()

    print("get_hayabusa_rules tests completed.")


if __name__ == "__main__":
    test_get_rules()
    sys.exit(main())
