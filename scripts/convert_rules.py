#!/usr/bin/env python3
"""
DetectForge Rule Conversion Engine
Converts Sigma YAML rules to Lucene / Elasticsearch queries using pySigma for CI test harness.
"""

import sys
import os
import json
from pathlib import Path
from typing import Dict, Any

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
except ImportError as e:
    print(f"[!] Required pySigma module not installed: {e}", file=sys.stderr)
    print("    Run 'pip install -r requirements.txt'", file=sys.stderr)
    sys.exit(1)

def convert_rule_file(rule_path: Path) -> Dict[str, Any]:
    """Convert a single Sigma YAML file into Elasticsearch Lucene query string."""
    try:
        rule_collection = SigmaCollection.from_yaml(rule_path.read_text(encoding='utf-8'))
        backend = LuceneBackend()
        queries = backend.convert(rule_collection)
        return {
            "status": "success",
            "rule_file": str(rule_path),
            "queries": queries
        }
    except Exception as e:
        return {
            "status": "error",
            "rule_file": str(rule_path),
            "error": str(e)
        }

def main():
    rules_dir = Path("rules")
    out_dir = Path("build/converted")
    out_dir.mkdir(parents=True, exist_ok=True)

    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    rule_files = [f for f in rule_files if not f.name.startswith(".")]

    print(f"[*] Converting {len(rule_files)} Sigma rule(s) to Elasticsearch Lucene queries...")

    converted_results = []
    has_errors = False

    for rule_file in rule_files:
        result = convert_rule_file(rule_file)
        converted_results.append(result)
        if result["status"] == "success":
            print(f"[PASS] {rule_file} -> {result['queries']}")
        else:
            has_errors = True
            print(f"[FAIL] {rule_file}: {result['error']}", file=sys.stderr)

    summary_file = out_dir / "converted_rules.json"
    with open(summary_file, 'w', encoding='utf-8') as f:
        json.dump(converted_results, f, indent=2)

    if has_errors:
        print(f"\n[!] Conversion failed for 1 or more rules.", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"\n[+] All rules successfully converted! Output written to {summary_file}")
        sys.exit(0)

if __name__ == "__main__":
    main()
