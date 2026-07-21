#!/usr/bin/env python3
"""
DetectForge SIEM Deployment Client
Pushes raw Sigma YAML rules directly to OpenSearch Security Analytics API on merge to main.
Idempotent: checks for existing rule by Sigma UUID before updating/creating.
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

def find_existing_rule(api_url: str, headers: Dict[str, str], ctx: ssl.SSLContext, sigma_id: str) -> Optional[str]:
    """Queries Security Analytics rules API to check if a rule with sigma_id already exists."""
    search_url = f"{api_url}/_plugins/_security_analytics/rules/_search"
    query_payload = {
        "query": {
            "match": {
                "rule": sigma_id
            }
        }
    }
    try:
        req = urllib.request.Request(
            search_url,
            data=json.dumps(query_payload).encode('utf-8'),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            hits = data.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]["_id"]
    except Exception:
        pass
    return None

def deploy_rule_yaml(rule_path: Path, api_url: str, token: str, ctx: ssl.SSLContext) -> Dict[str, Any]:
    raw_yaml = rule_path.read_text(encoding='utf-8')
    parsed_yaml = yaml.safe_load(raw_yaml)
    sigma_id = str(parsed_yaml.get("id", ""))
    title = parsed_yaml.get("title", rule_path.name)

    headers = get_auth_headers(token)
    existing_rule_id = find_existing_rule(api_url, headers, ctx, sigma_id)

    payload = {
        "category": "windows",
        "type": "raw",
        "rule": raw_yaml
    }

    if existing_rule_id:
        endpoint = f"{api_url}/_plugins/_security_analytics/rules/{existing_rule_id}"
        method = "PUT"
        action = "updated"
    else:
        endpoint = f"{api_url}/_plugins/_security_analytics/rules"
        method = "POST"
        action = "created"

    try:
        req = urllib.request.Request(
            endpoint,
            data=json.dumps(payload).encode('utf-8'),
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
                "opensearch_id": resp_body.get("_id", existing_rule_id)
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

    print(f"[*] Starting DetectForge CD deployment of {len(rule_files)} raw Sigma rule(s) to SIEM...")
    print(f"    Target endpoint: {api_url}/_plugins/_security_analytics/rules")

    deployed = 0
    failed = 0

    for rule_file in rule_files:
        res = deploy_rule_yaml(rule_file, api_url, api_token, ctx)
        if res["status"] == "success":
            deployed += 1
            print(f"[DEPLOYED] {res['title']} ({res['action']}) -> ID: {res['opensearch_id']}")
        else:
            failed += 1
            print(f"[FAIL] {res['title']}: {res['error']}", file=sys.stderr)

    print(f"\n[+] Deployment finished: {deployed} deployed successfully, {failed} failed.")
    if failed > 0 and os.environ.get("STRICT_DEPLOY") == "1":
        sys.exit(1)

if __name__ == "__main__":
    main()
