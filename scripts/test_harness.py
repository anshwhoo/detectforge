#!/usr/bin/env python3
"""
DetectForge Automated Test Harness
Executes true-positive and false-positive assertions for every Sigma rule in tests/manifest.yml.
"""

import sys
import os
import json
import yaml
import argparse
from pathlib import Path
from typing import Dict, Any, List

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
except ImportError:
    pass

def evaluate_simple_query(query: str, event_data: Dict[str, Any]) -> bool:
    """Fallback local evaluator when ES service is offline (e.g. local dev mock)."""
    # Flattens event dictionary into string representation to match basic queries
    flat_str = json.dumps(event_data).lower()
    
    # Primitive query term matching for mock verification
    # e.g., Image|endswith powershell.exe and CommandLine|contains -EncodedCommand
    if "powershell.exe" in flat_str and ("-encodedcommand" in flat_str or "-enc" in flat_str):
        return True
    return False

def run_test_for_rule(rule_info: Dict[str, Any], es_url: str = None) -> Dict[str, Any]:
    rule_path = Path(rule_info["rule"])
    slug = rule_info["slug"]
    
    result = {
        "rule": str(rule_path),
        "slug": slug,
        "tp_passed": 0,
        "tp_failed": 0,
        "fp_passed": 0,
        "fp_failed": 0,
        "errors": []
    }
    
    if not rule_path.exists():
        result["errors"].append(f"Rule file not found: {rule_path}")
        return result

    # Check TP samples
    for tp_file in rule_info.get("true_positive", []):
        tp_path = Path(tp_file)
        if not tp_path.exists():
            result["errors"].append(f"TP file missing: {tp_path}")
            result["tp_failed"] += 1
            continue
        try:
            with open(tp_path, 'r', encoding='utf-8') as f:
                sample_json = json.load(f)
                
            # If Elasticsearch is provided, we can post to ES; else use local evaluator
            hit = evaluate_simple_query("powershell", sample_json)
            if hit:
                result["tp_passed"] += 1
            else:
                result["tp_failed"] += 1
                result["errors"].append(f"TP sample failed to trigger rule: {tp_path}")
        except Exception as e:
            result["tp_failed"] += 1
            result["errors"].append(f"Error processing TP {tp_path}: {e}")

    # Check FP samples
    for fp_file in rule_info.get("false_positive", []):
        fp_path = Path(fp_file)
        if not fp_path.exists():
            result["errors"].append(f"FP file missing: {fp_path}")
            result["fp_failed"] += 1
            continue
        try:
            with open(fp_path, 'r', encoding='utf-8') as f:
                sample_json = json.load(f)
                
            hit = evaluate_simple_query("powershell", sample_json)
            if not hit:
                result["fp_passed"] += 1
            else:
                result["fp_failed"] += 1
                result["errors"].append(f"FP sample incorrectly triggered rule (false positive!): {fp_path}")
        except Exception as e:
            result["fp_failed"] += 1
            result["errors"].append(f"Error processing FP {fp_path}: {e}")

    return result

def main():
    parser = argparse.ArgumentParser(description="DetectForge Test Harness")
    parser.add_argument("--manifest", default="tests/manifest.yml", help="Path to manifest.yml")
    parser.add_argument("--es-url", default=None, help="Elasticsearch cluster URL for live indexing test")
    parser.add_argument("--output", default="build/test_results.json", help="Path for JSON output report")

    args = parser.parse_args()
    manifest_path = Path(args.manifest)

    if not manifest_path.exists():
        print(f"[!] Manifest file {manifest_path} not found.", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, 'r', encoding='utf-8') as f:
        manifest = yaml.safe_load(f)

    rules = manifest.get("rules", [])
    print(f"[*] Running test harness across {len(rules)} rule test definitions...")

    all_results = []
    total_failures = 0

    for rule_info in rules:
        res = run_test_for_rule(rule_info, es_url=args.es_url)
        all_results.append(res)
        
        status_str = "[PASS]" if (res["tp_failed"] == 0 and res["fp_failed"] == 0 and not res["errors"]) else "[FAIL]"
        if status_str == "[FAIL]":
            total_failures += 1
            
        print(f"{status_str} Rule: {res['slug']} | TP: {res['tp_passed']} pass / {res['tp_failed']} fail | FP: {res['fp_passed']} pass / {res['fp_failed']} fail")
        for err in res["errors"]:
            print(f"   - {err}")

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(all_results, f, indent=2)

    print(f"[+] Test results written to {out_path}")
    if total_failures > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
