#!/usr/bin/env python3
"""
DetectForge Rule Linter
Validates Sigma rule YAML syntax, required metadata fields, and mandatory MITRE ATT&CK tags.
"""

import os
import sys
import re
import yaml
from pathlib import Path

# Ensure UTF-8 output encoding on Windows consoles
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

REQUIRED_FIELDS = ['title', 'id', 'status', 'description', 'logsource', 'detection', 'tags']
ATTACK_TAG_REGEX = re.compile(r'^attack\.t\d{4}(\.\d{3})?$', re.IGNORECASE)
UUID_REGEX = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)

def lint_file(file_path: Path) -> list[str]:
    errors = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"YAML Syntax Error: {e}"]
    except Exception as e:
        return [f"File Read Error: {e}"]

    if not isinstance(data, dict):
        return ["Root structure must be a YAML mapping/dictionary"]

    # Required fields check
    for field in REQUIRED_FIELDS:
        if field not in data or data[field] is None:
            errors.append(f"Missing required field: '{field}'")

    # UUID format check
    rule_id = str(data.get('id', ''))
    if rule_id and not UUID_REGEX.match(rule_id):
        errors.append(f"Field 'id' must be a valid UUID (got: '{rule_id}')")

    # ATT&CK tag enforcement
    tags = data.get('tags', [])
    if not isinstance(tags, list):
        errors.append("Field 'tags' must be a list")
    else:
        attack_technique_tags = [t for t in tags if isinstance(t, str) and ATTACK_TAG_REGEX.match(t)]
        if not attack_technique_tags:
            errors.append("Must carry at least one valid ATT&CK technique tag (e.g. 'attack.t1059.001')")

    return errors

def main():
    rules_dir = Path("rules")
    if not rules_dir.exists():
        print("[!] Rules directory 'rules/' not found.", file=sys.stderr)
        sys.exit(1)

    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    rule_files = [f for f in rule_files if not f.name.startswith(".")]

    if not rule_files:
        print("[!] No rule files found in rules/.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Linting {len(rule_files)} Sigma rule(s)...")
    total_errors = 0

    for rule_file in rule_files:
        errors = lint_file(rule_file)
        if errors:
            total_errors += len(errors)
            print(f"[FAIL] {rule_file}:")
            for err in errors:
                print(f"   - {err}")
        else:
            print(f"[PASS] {rule_file}")

    if total_errors > 0:
        print(f"\n[!] Linting failed with {total_errors} total error(s).", file=sys.stderr)
        sys.exit(1)
    else:
        print("\n[+] All Sigma rules passed lint checks!")
        sys.exit(0)

if __name__ == "__main__":
    main()
