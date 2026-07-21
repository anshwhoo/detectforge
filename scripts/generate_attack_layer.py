#!/usr/bin/env python3
"""
DetectForge ATT&CK Coverage Layer Generator
Scans all rules under rules/, extracts attack.t#### tags, and builds a MITRE ATT&CK
Navigator layer JSON file (schema v4.5) stored in config/attack_coverage_layer.json.
"""

import sys
import os
import re
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

ATTACK_TAG_REGEX = re.compile(r'^attack\.t(\d{4}(?:\.\d{3})?)$', re.IGNORECASE)

def parse_attack_techniques_from_rules(rules_dir: Path) -> Dict[str, List[str]]:
    technique_to_rules = {}
    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    
    for rf in rule_files:
        if rf.name.startswith("."):
            continue
        try:
            with open(rf, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                if not isinstance(data, dict):
                    continue
                title = data.get("title", rf.name)
                tags = data.get("tags", [])
                for tag in tags:
                    if not isinstance(tag, str):
                        continue
                    m = ATTACK_TAG_REGEX.match(tag.strip())
                    if m:
                        tech_id = f"T{m.group(1)}".upper()
                        technique_to_rules.setdefault(tech_id, []).append(title)
        except Exception as e:
            print(f"[!] Warning: Error reading {rf}: {e}", file=sys.stderr)

    return technique_to_rules

def main():
    template_file = Path("config/attack_layer_template.json")
    rules_dir = Path("rules")
    output_file = Path("config/attack_coverage_layer.json")

    base_layer = {
        "name": "DetectForge Deployed Detection Layer",
        "versions": {
            "attack": "14",
            "navigator": "5.0.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Live MITRE ATT&CK coverage map automatically generated from deployed DetectForge Sigma rules.",
        "filters": {
            "platforms": ["Windows", "Linux", "macOS"]
        },
        "sorting": 0,
        "layout": {
            "layout": "side-by-side",
            "showID": True,
            "showName": True,
            "showAggregateScores": True,
            "countUnscored": False
        },
        "gradient": {
            "colors": ["#ffe6e6", "#66ff66", "#00b300"],
            "minValue": 0,
            "maxValue": 5
        },
        "legendItems": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False
    }

    if template_file.exists():
        try:
            with open(template_file, 'r', encoding='utf-8') as f:
                override = json.load(f)
                base_layer.update(override)
        except Exception as e:
            print(f"[!] Could not load template {template_file}: {e}", file=sys.stderr)

    tech_map = parse_attack_techniques_from_rules(rules_dir)
    print(f"[*] Extracted coverage for {len(tech_map)} MITRE ATT&CK technique(s)...")

    techniques_layer = []
    for tech_id, rule_titles in tech_map.items():
        score = len(rule_titles)
        comment = f"Detected by {score} rule(s): " + ", ".join(rule_titles)
        techniques_layer.append({
            "techniqueID": tech_id,
            "score": score,
            "color": "#66ff66" if score >= 1 else "#ffffff",
            "comment": comment,
            "enabled": True,
            "metadata": []
        })

    base_layer["techniques"] = techniques_layer

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(base_layer, f, indent=2)

    print(f"[+] Successfully generated ATT&CK coverage layer at {output_file}")

if __name__ == "__main__":
    main()
