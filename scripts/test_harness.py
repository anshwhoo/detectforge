#!/usr/bin/env python3
"""
DetectForge Automated Test Harness
Executes true-positive and false-positive assertions for every Sigma rule in tests/manifest.yml
by indexing each sample event into a live Elasticsearch/OpenSearch cluster and running that
rule's actual compiled Lucene query (from build/converted/converted_rules.json) against it.
"""

import sys
import os
import json
import yaml
import argparse
from pathlib import Path
from typing import Dict, Any, List, Optional

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # self-signed cert on the local Wazuh Indexer
except ImportError:
    print("[!] The 'requests' package is required. Run 'pip install -r requirements.txt'", file=sys.stderr)
    sys.exit(1)

TEST_INDEX = "detectforge-test-harness"

# Every string field gets mapped as an unanalyzed, lowercased keyword instead of the
# default dynamic "text" mapping. This matters a lot: the standard text analyzer splits
# on backslashes/colons (so "C:\Windows\System32\schtasks.exe" tokenizes into
# ["c", "windows", "system32", "schtasks.exe"], destroying the literal path structure a
# Sigma wildcard query like Image:*\schtasks.exe needs to match against). The lowercase
# normalizer matches Sigma's case-insensitive-by-default matching semantics, and is
# applied to both indexed values and query terms automatically by query_string.
INDEX_MAPPING = {
    "settings": {
        "analysis": {
            "normalizer": {
                "lowercase_normalizer": {"type": "custom", "filter": ["lowercase"]}
            }
        }
    },
    "mappings": {
        "dynamic_templates": [
            {
                "strings_as_keyword": {
                    "match_mapping_type": "string",
                    "mapping": {"type": "keyword", "normalizer": "lowercase_normalizer"}
                }
            }
        ]
    }
}


def build_es_session(es_url: str) -> requests.Session:
    session = requests.Session()
    session.verify = False
    if es_url.startswith("https"):
        token = os.environ.get("SIEM_API_TOKEN", "admin:SecretPassword")
        user, _, password = token.partition(":")
        session.auth = (user, password)
    return session


def load_converted_queries(converted_path: Path) -> Dict[str, str]:
    """Maps a normalized rule file path to its compiled Lucene query string."""
    if not converted_path.exists():
        return {}
    with open(converted_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    queries = {}
    for entry in data:
        if entry.get("status") == "success" and entry.get("queries"):
            norm_path = str(Path(entry["rule_file"])).replace("\\", "/")
            queries[norm_path] = entry["queries"][0]
    return queries


def flatten_event(sample: Dict[str, Any]) -> Dict[str, Any]:
    """Merges the event's top-level fields with its nested EventData block, since Sigma
    rules reference fields like Image/CommandLine flatly, not nested under EventData."""
    event = sample.get("event", {})
    flat = {k: v for k, v in event.items() if k != "EventData"}
    flat.update(event.get("EventData", {}))
    return flat


def query_matches(session: requests.Session, es_url: str, doc_id: str, query: str) -> Optional[bool]:
    body = {
        "query": {
            "bool": {
                "filter": [{"ids": {"values": [doc_id]}}],
                "must": [{"query_string": {"query": query, "analyze_wildcard": True}}]
            }
        }
    }
    r = session.post(f"{es_url}/{TEST_INDEX}/_search", json=body, timeout=10)
    r.raise_for_status()
    return r.json()["hits"]["total"]["value"] > 0


def run_test_for_rule(rule_info: Dict[str, Any], session: requests.Session, es_url: str,
                       queries_by_rule: Dict[str, str]) -> Dict[str, Any]:
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

    query = queries_by_rule.get(str(rule_path).replace("\\", "/"))
    if not query:
        result["errors"].append(
            f"No compiled query found for {rule_path} in build/converted/converted_rules.json - "
            f"run convert_rules.py first"
        )
        result["tp_failed"] = len(rule_info.get("true_positive", []))
        result["fp_failed"] = 0
        return result

    def evaluate(samples: List[str], expect_hit: bool, pass_key: str, fail_key: str, kind: str):
        for i, sample_file in enumerate(samples):
            sample_path = Path(sample_file)
            if not sample_path.exists():
                result["errors"].append(f"{kind} file missing: {sample_path}")
                result[fail_key] += 1
                continue
            try:
                with open(sample_path, "r", encoding="utf-8") as f:
                    sample_json = json.load(f)
                doc = flatten_event(sample_json)
                doc_id = f"{slug}-{kind.lower()}-{i}"
                r = session.put(f"{es_url}/{TEST_INDEX}/_doc/{doc_id}", params={"refresh": "true"},
                                 json=doc, timeout=10)
                r.raise_for_status()
                hit = query_matches(session, es_url, doc_id, query)
                session.delete(f"{es_url}/{TEST_INDEX}/_doc/{doc_id}", timeout=10)

                if hit == expect_hit:
                    result[pass_key] += 1
                else:
                    result[fail_key] += 1
                    if kind == "TP":
                        result["errors"].append(f"TP sample failed to trigger rule: {sample_path}")
                    else:
                        result["errors"].append(f"FP sample incorrectly triggered rule (false positive!): {sample_path}")
            except requests.RequestException as e:
                result[fail_key] += 1
                result["errors"].append(f"Elasticsearch error processing {kind} {sample_path}: {e}")
            except Exception as e:
                result[fail_key] += 1
                result["errors"].append(f"Error processing {kind} {sample_path}: {e}")

    evaluate(rule_info.get("true_positive", []), True, "tp_passed", "tp_failed", "TP")
    evaluate(rule_info.get("false_positive", []), False, "fp_passed", "fp_failed", "FP")

    return result


def main():
    parser = argparse.ArgumentParser(description="DetectForge Test Harness")
    parser.add_argument("--manifest", default="tests/manifest.yml", help="Path to manifest.yml")
    parser.add_argument("--converted", default="build/converted/converted_rules.json",
                         help="Path to compiled queries from convert_rules.py")
    parser.add_argument("--es-url", required=True,
                         help="Elasticsearch/OpenSearch cluster URL to run live queries against (required - "
                              "there is no offline fallback, since a fake local evaluator that doesn't check "
                              "the actual rule logic is worse than no test at all)")
    parser.add_argument("--output", default="build/test_results.json", help="Path for JSON output report")

    args = parser.parse_args()
    manifest_path = Path(args.manifest)

    if not manifest_path.exists():
        print(f"[!] Manifest file {manifest_path} not found.", file=sys.stderr)
        sys.exit(1)

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = yaml.safe_load(f)

    rules = manifest.get("rules", [])
    es_url = args.es_url.rstrip("/")
    session = build_es_session(es_url)

    try:
        session.get(es_url, timeout=5).raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Cannot reach Elasticsearch/OpenSearch at {es_url}: {e}", file=sys.stderr)
        sys.exit(1)

    queries_by_rule = load_converted_queries(Path(args.converted))
    if not queries_by_rule:
        print(f"[!] No compiled queries found at {args.converted}. Run convert_rules.py first.", file=sys.stderr)
        sys.exit(1)

    session.delete(f"{es_url}/{TEST_INDEX}", timeout=10)
    r = session.put(f"{es_url}/{TEST_INDEX}", json=INDEX_MAPPING, timeout=10)
    if not r.ok:
        print(f"[!] Failed to create test index: {r.text}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Running test harness across {len(rules)} rule test definitions against {es_url}...")

    all_results = []
    total_failures = 0

    for rule_info in rules:
        res = run_test_for_rule(rule_info, session, es_url, queries_by_rule)
        all_results.append(res)

        status_str = "[PASS]" if (res["tp_failed"] == 0 and res["fp_failed"] == 0 and not res["errors"]) else "[FAIL]"
        if status_str == "[FAIL]":
            total_failures += 1

        print(f"{status_str} Rule: {res['slug']} | TP: {res['tp_passed']} pass / {res['tp_failed']} fail | FP: {res['fp_passed']} pass / {res['fp_failed']} fail")
        for err in res["errors"]:
            print(f"   - {err}")

    session.delete(f"{es_url}/{TEST_INDEX}", timeout=10)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)

    print(f"[+] Test results written to {out_path}")
    if total_failures > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
