#!/usr/bin/env python3
"""
DetectForge SIEM Deployment Client
Deploys Sigma rules as OpenSearch Alerting monitors directly to Wazuh Indexer REST API on merge to main.
Idempotent: checks for existing monitor by title before updating/creating.
"""

import sys
import os
import json
import ssl
import yaml
import base64
import urllib.request
import urllib.error
from pathlib import Path
from typing import Dict, Any, Optional

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

try:
    from sigma.collection import SigmaCollection
    from sigma.backends.elasticsearch import LuceneBackend
except ImportError:
    pass

def get_auth_headers(token: str) -> Dict[str, str]:
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "DetectForge-CD/1.0"
    }
    if ":" in token:
        b64_auth = base64.b64encode(token.encode('utf-8')).decode('utf-8')
        headers["Authorization"] = f"Basic {b64_auth}"
    else:
        headers["Authorization"] = f"Bearer {token}"
    return headers

def find_existing_monitor(api_url: str, headers: Dict[str, str], ctx: ssl.SSLContext, monitor_name: str) -> Optional[str]:
    """Queries OpenSearch Alerting API to find an existing monitor ID by name."""
    search_url = f"{api_url}/_plugins/_alerting/monitors"
    try:
        req = urllib.request.Request(
            search_url,
            headers=headers,
            method="GET"
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            monitors = data.get("monitors", [])
            for m in monitors:
                monitor_obj = m.get("monitor", {})
                if monitor_obj.get("name") == monitor_name:
                    return m.get("_id") or monitor_obj.get("_id")
    except Exception:
        pass
    return None

def deploy_rule(rule_path: Path, api_url: str, token: str, ctx: ssl.SSLContext) -> Dict[str, Any]:
    raw_yaml = rule_path.read_text(encoding='utf-8')
    parsed_yaml = yaml.safe_load(raw_yaml)
    sigma_id = str(parsed_yaml.get("id", ""))
    title = parsed_yaml.get("title", rule_path.name)
    monitor_name = f"DetectForge - {title}"

    # Convert rule to Lucene query via pySigma
    try:
        rule_coll = SigmaCollection.from_yaml(raw_yaml)
        backend = LuceneBackend()
        queries = backend.convert(rule_coll)
        query_str = queries[0] if queries else "*:*"
    except Exception:
        query_str = "*:*"

    headers = get_auth_headers(token)
    existing_id = find_existing_monitor(api_url, headers, ctx, monitor_name)

    monitor_payload = {
        "name": monitor_name,
        "type": "monitor",
        "monitor_type": "query_level_monitor",
        "enabled": True,
        "schedule": {
            "period": {
                "interval": 5,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "search": {
                    "indices": ["wazuh-alerts-*"],
                    "query": {
                        "query": {
                            "query_string": {
                                "query": query_str
                            }
                        }
                    }
                }
            }
        ],
        "triggers": [
            {
                "name": f"Trigger - {title}",
                "severity": "1",
                "condition": {
                    "script": {
                        "source": "ctx.results[0].hits.total.value > 0",
                        "lang": "painless"
                    }
                },
                "actions": []
            }
        ]
    }

    if existing_id:
        endpoint = f"{api_url}/_plugins/_alerting/monitors/{existing_id}"
        method = "PUT"
        action = "updated"
    else:
        endpoint = f"{api_url}/_plugins/_alerting/monitors"
        method = "POST"
        action = "created"

    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(monitor_payload).encode('utf-8'),
            headers=headers,
            method=method
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            resp_body = json.loads(resp.read().decode('utf-8'))
            return {
                "status": "success",
                "action": action,
                "title": title,
                "sigma_id": sigma_id,
                "rule_file": str(rule_path),
                "monitor_id": resp_body.get("_id", existing_id)
            }
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode('utf-8') if e.fp else str(e)
        return {
            "status": "error",
            "title": title,
            "rule_file": str(rule_path),
            "error": f"HTTP {e.code}: {err_msg}"
        }
    except Exception as e:
        return {
            "status": "error",
            "title": title,
            "rule_file": str(rule_path),
            "error": str(e)
        }

def main():
    api_url = os.environ.get("SIEM_API_URL", "https://localhost:9200").rstrip("/")
    api_token = os.environ.get("SIEM_API_TOKEN", "admin:SecretPassword")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    rules_dir = Path("rules")
    rule_files = list(rules_dir.rglob("*.yml")) + list(rules_dir.rglob("*.yaml"))
    rule_files = [f for f in rule_files if not f.name.startswith(".")]

    print(f"[*] Starting DetectForge CD deployment of {len(rule_files)} Sigma rule(s) to Wazuh Indexer...")
    print(f"    Target endpoint: {api_url}/_plugins/_alerting/monitors")

    deployed = 0
    failed = 0

    for rule_file in rule_files:
        res = deploy_rule(rule_file, api_url, api_token, ctx)
        if res["status"] == "success":
            deployed += 1
            print(f"[DEPLOYED] {res['title']} ({res['action']}) -> Monitor ID: {res['monitor_id']}")
        else:
            failed += 1
            print(f"[FAIL] {res['title']}: {res['error']}", file=sys.stderr)

    print(f"\n[+] Deployment finished: {deployed} deployed successfully, {failed} failed.")
    if failed > 0 and os.environ.get("STRICT_DEPLOY") == "1":
        sys.exit(1)

if __name__ == "__main__":
    main()
