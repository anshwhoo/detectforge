#!/usr/bin/env python3
"""
DetectForge Rollback Mechanism
Removes a specified detection rule from the live SIEM by Sigma UUID or OpenSearch Rule ID
and updates the ATT&CK coverage map accordingly.
"""

import sys
import os
import json
import ssl
import base64
import urllib.request
import argparse
from pathlib import Path

if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')

def rollback_rule(rule_id: str, api_url: str, token: str, ctx: ssl.SSLContext) -> bool:
    headers = {"User-Agent": "DetectForge-Rollback/1.0"}
    if ":" in token:
        b64_auth = base64.b64encode(token.encode('utf-8')).decode('utf-8')
        headers["Authorization"] = f"Basic {b64_auth}"
    else:
        headers["Authorization"] = f"Bearer {token}"

    endpoint = f"{api_url}/_plugins/_security_analytics/rules/{rule_id}"
    print(f"[*] Sending DELETE request for rule ID '{rule_id}' to {endpoint}...")

    try:
        req = urllib.request.Request(endpoint, headers=headers, method="DELETE")
        with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
            if resp.status in (200, 204):
                print(f"[+] Successfully deleted rule '{rule_id}' from SIEM.")
                return True
            else:
                print(f"[!] SIEM API returned status {resp.status}")
                return False
    except Exception as e:
        print(f"[!] Rollback API call failed: {e}", file=sys.stderr)
        return False

def main():
    parser = argparse.ArgumentParser(description="DetectForge Rule Rollback Script")
    parser.add_argument("--rule-id", required=True, help="OpenSearch Rule ID or Sigma UUID to remove")
    args = parser.parse_args()

    api_url = os.environ.get("SIEM_API_URL", "https://localhost:9200").rstrip("/")
    api_token = os.environ.get("SIEM_API_TOKEN", "admin:SecretPassword")

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    success = rollback_rule(args.rule_id, api_url, api_token, ctx)
    if success:
        print("[*] Re-generating MITRE ATT&CK coverage layer post-rollback...")
        os.system(f"{sys.executable} scripts/generate_attack_layer.py")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
