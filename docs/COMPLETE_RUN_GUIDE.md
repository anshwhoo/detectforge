# DetectForge — Complete Run & Verification Guide

Everything you need to start the project from scratch, run every stage,
verify each step actually worked, add new detection rules, and confirm
live deployment inside Wazuh. No step is skipped or assumed.

---

## Prerequisites Checklist

Before running anything, confirm the following tools are installed:

| Tool | Required Version | Check Command |
|:---|:---|:---|
| Docker Desktop | Latest | `docker --version` |
| Python | 3.10+ | `python --version` |
| Git | Any | `git --version` |
| Node.js | 18+ | `node --version` |
| npm | 9+ | `npm --version` |
| GitHub CLI | 2.x | `gh --version` |

Confirm GitHub CLI is authenticated:
```powershell
gh auth status
```
Expected: `Logged in to github.com as anshwhoo`

---

## Part 1 — Starting the Local Wazuh SIEM Lab (Docker)

### 1.1 Start the Stack

```powershell
cd "c:\Users\ANSHUMAN ROY\Desktop\Minor Project 2\detectforge"
docker compose -f lab/docker-compose.yml up -d
```

This starts three containers:

| Container | Role | Port |
|:---|:---|:---|
| `lab-wazuh.indexer-1` | OpenSearch / Alert storage and REST API | `9200` |
| `lab-wazuh.manager-1` | Wazuh Manager / log decoder | `55000`, `1514` |
| `lab-wazuh.dashboard-1` | Wazuh Dashboard UI | `443` |

### 1.2 Verify Docker is Healthy

```powershell
docker ps
```

Expected: all three containers show `Up` in the STATUS column.

### 1.3 Verify Wazuh Indexer API is Responding

```powershell
python -c "
import urllib.request, ssl
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://localhost:9200', headers={'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ='})
resp = urllib.request.urlopen(req, context=ctx)
print('Indexer status:', resp.status)
"
```

Expected output: `Indexer status: 200`

### 1.4 Open Wazuh Dashboard in Browser

Navigate to: **https://localhost:443**
- **Username**: `admin`
- **Password**: `SecretPassword`
- Accept the self-signed certificate warning.

> **What you will see**: The Wazuh Dashboard. The Alerting section
> (under OpenSearch Plugins > Alerting) is where deployed DetectForge
> rules appear as Monitors.

---

## Part 2 — Setting Up the Python Environment

### 2.1 Create and Activate Virtual Environment

```powershell
cd "c:\Users\ANSHUMAN ROY\Desktop\Minor Project 2\detectforge"
python -m venv venv
.\venv\Scripts\activate
```

### 2.2 Install All Python Dependencies

```powershell
pip install -r requirements.txt
```

Full dependency list from `requirements.txt`:
```
pysigma>=0.11.0                    # Core Sigma rule parsing
pysigma-backend-elasticsearch>=1.1.0  # Sigma to Lucene/ES query translation
pysigma-pipeline-sysmon>=1.0.0     # Sysmon field mappings
pysigma-pipeline-windows>=1.2.0    # Windows ECS field mappings
sigma-cli>=1.0.0                   # Sigma CLI tooling
pyyaml>=6.0                        # YAML parsing
requests>=2.31.0                   # HTTP client for SIEM API calls
jsonschema>=4.20.0                 # JSON schema validation
pytest>=7.4.0                      # Test framework
urllib3>=2.0.0                     # HTTP library
python-evtx>=0.7.4                 # Parse Windows EVTX event log files
```

### 2.3 Verify Installation

```powershell
python -c "import sigma; print('pySigma OK')"
python -c "import yaml; print('PyYAML OK')"
python -c "import requests; print('Requests OK')"
```

---

## Part 3 — Starting the Self-Hosted GitHub Actions Runner

The CD pipeline runs on your Windows machine via a local self-hosted runner.
It must be running before CD can execute.

### 3.1 Start the Runner

Open a **separate PowerShell window** (keep it open):

```powershell
cd C:\actions-runner
.\run.cmd
```

Expected output:
```
Connected to GitHub
Current runner version: '2.336.0'
Listening for Jobs
```

### 3.2 Verify Runner is Online

In a different terminal:

```powershell
gh api repos/anshwhoo/detectforge/actions/runners
```

Look for `"status": "online"` in the output.

> **If offline**: Go back and run `.\run.cmd` in `C:\actions-runner`.

---

## Part 4 — About the Datasets (Test Telemetry)

### 4.1 Existing Dataset for the Deployed Rule

**True-Positive Sample**
File: `tests/true_positive/powershell_encoded_command/t1059_001_sample_1.json`

Source: Normalized from **OTRF Security Datasets (Mordor)** — a curated
collection of real adversary technique recordings from a controlled lab.

Key fields that trigger the rule:
```json
{
  "EventData": {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -NoProfile -EncodedCommand JABzAD0A..."
  }
}
```

**False-Positive Sample**
File: `tests/false_positive/powershell_encoded_command/legitimate_admin_script.json`

Source: Hand-crafted SCCM health check. No `-EncodedCommand` flag, so
the rule must return zero hits.

```json
{
  "EventData": {
    "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\ProgramData\\SCCM\\scripts\\healthcheck.ps1"
  }
}
```

### 4.2 Where to Get Datasets for New Rules

| Source | URL | Format |
|:---|:---|:---|
| OTRF Security Datasets (Mordor) | https://github.com/OTRF/Security-Datasets | JSON / EVTX |
| EVTX-ATTACK-SAMPLES | https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES | .evtx files |
| Atomic Red Team | https://github.com/redcanaryco/atomic-red-team | Simulation scripts |

Convert `.evtx` to JSON with `python-evtx` (already installed):
```powershell
python -c "import Evtx.Evtx as evtx; import json; ..."
```

### 4.3 Auto-Fetch a Dataset for a New Technique

```powershell
python scripts/fetch_reference_samples.py --technique T1053.005 --rule-slug scheduled_task
```

Creates:
- `tests/true_positive/scheduled_task/t1053_005_sample_1.json`
- `tests/false_positive/scheduled_task/legitimate_schtask.json`

---

## Part 5 — Running the CI Pipeline Locally

Run all three steps before opening a PR.

### 5.1 Lint the Sigma Rules

```powershell
python scripts/lint_rules.py
```

Checks: YAML syntax, required fields (id, title, description, author,
date, logsource, detection, level, tags), valid UUID, attack.t#### tag.

Expected output:
```
[*] Linting 1 rule file(s)...
[+] PASS: rules/windows/process_creation/proc_creation_win_powershell_encoded_command.yml
[*] Lint complete: 1 passed, 0 failed.
```

### 5.2 Convert Sigma to Lucene

```powershell
python scripts/convert_rules.py
```

Translates each Sigma YAML to an Elasticsearch Lucene query via pySigma.

Expected output:
```
[*] Converting 1 rule(s) via pySigma...
[+] CONVERTED: proc_creation_win_powershell_encoded_command
    Query: (Image:(*\\powershell.exe OR *\\pwsh.exe)) AND (CommandLine:(*\ \-EncodedCommand\ * ...))
[*] Conversion complete: 1 passed, 0 failed.
```

### 5.3 Run the TP/FP Test Harness

Requires Wazuh Indexer running (Part 1).

```powershell
python scripts/test_harness.py
```

Expected output:
```
[*] Running test harness for 1 rule(s)...

Rule: proc_creation_win_powershell_encoded_command
  TP sample: t1059_001_sample_1.json
    Result: 1 hit(s)   PASS (expected >= 1)
  FP sample: legitimate_admin_script.json
    Result: 0 hit(s)   PASS (expected 0)

[*] All tests passed: 1/1 rules clean.
```

If TP returns 0: query is too narrow, check field mappings in `pipelines/sysmon_to_ecs.yml`.
If FP returns >= 1: rule is too broad, tighten the detection condition.

---

## Part 6 — Triggering the GitHub CI Pipeline (Pull Request)

### 6.1 Create a Feature Branch and Push

```powershell
git checkout -b feature/verify-ci-run
git add -A
git commit -m "test: trigger CI verification run"
git push -u origin feature/verify-ci-run
```

### 6.2 Open a Pull Request

```powershell
gh pr create --title "Test CI run verification" --body "Triggering CI pipeline." --base main
```

### 6.3 Watch the CI Workflow Run

```powershell
gh run list --limit 5
# Stream live:
gh run watch
```

Look for: `DetectForge CI - Lint, Convert & Test Rules`

### 6.4 Check the PR Comment Bot

```powershell
gh pr view --comments
```

Expected: A Markdown table from `github-actions[bot]` showing PASS
for both TP and FP assertions.

---

## Part 7 — Triggering the CD Pipeline (Deploying to Wazuh)

### 7.1 Merge the PR

```powershell
gh pr merge --squash --delete-branch
```

This triggers `.github/workflows/cd-deploy-rules.yml` on
`detectforge-local-runner` immediately.

### 7.2 Watch the CD Workflow

```powershell
gh run list --limit 5
$runId = gh run list --limit 1 --json databaseId --jq '.[0].databaseId'
gh run watch $runId
```

Look for: `DetectForge CD - Deploy Rules to SIEM`

### 7.3 Verify Rule Deployed — REST API

```powershell
python -c "
import urllib.request, ssl, json
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request(
    'https://localhost:9200/_plugins/_alerting/monitors?size=10',
    headers={'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ='}
)
data = json.loads(urllib.request.urlopen(req, context=ctx).read())
for m in data.get('monitors', []):
    print('Monitor:', m['name'], '| Enabled:', m['enabled'])
"
```

Expected:
```
Monitor: DetectForge - Suspicious PowerShell Encoded Command Execution | Enabled: True
```

### 7.4 Verify Rule Deployed — Dashboard UI

1. Open **https://localhost:443**
2. Hamburger menu > **OpenSearch Plugins** > **Alerting** > **Monitors**
3. You should see the rule listed with schedule: Every 5 minutes

---

## Part 8 — Live Trigger Test (Rule Fires in Wazuh)

> WARNING: Run only in your lab, never on a production machine.

### 8.1 Simulate Encoded PowerShell Activity

This decodes to `Write-Host "DetectForge Test"` — completely harmless:

```powershell
powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIARABlAHQAZQBjAHQARgBvAHIAZwBlACAAVABlAHMAdAAi
```

Expected: terminal prints `DetectForge Test`.

### 8.2 Wait for Monitor Execution (up to 5 minutes)

The monitor polls `wazuh-alerts-*` every 5 minutes.

### 8.3 Check for Alert in Wazuh Dashboard

1. **https://localhost:443** > OpenSearch Plugins > Alerting > **Alerts**
2. Filter by: `DetectForge - Suspicious PowerShell Encoded Command Execution`
3. Alert record appears with trigger fired status.

### 8.4 Manual Event Injection (No Agent Required)

If no Wazuh agent is installed, inject a synthetic event directly:

```powershell
python scripts/test_harness.py --inject-live
```

Or manually via Python:
```powershell
python -c "
import urllib.request, ssl, json
from datetime import datetime
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
idx = 'wazuh-alerts-4.x-' + datetime.now().strftime('%Y.%m.%d')
event = {
    'timestamp': datetime.utcnow().isoformat() + 'Z',
    'rule': {'description': 'DetectForge live inject', 'level': 10},
    'agent': {'name': 'test-workstation'},
    'data': {
        'win': {
            'eventdata': {
                'image': 'C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe',
                'commandLine': 'powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdA=='
            }
        }
    }
}
body = json.dumps(event).encode('utf-8')
req = urllib.request.Request(
    f'https://localhost:9200/{idx}/_doc',
    data=body,
    headers={'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ=', 'Content-Type': 'application/json'},
    method='POST'
)
resp = urllib.request.urlopen(req, context=ctx)
print('Injected:', json.loads(resp.read())['result'])
"
```

---

## Part 9 — Running the Web Dashboard

### 9.1 Generate Fresh Data Files

```powershell
python scripts/generate_rules_index.py
```

Expected:
```
[+] Generated dashboard/public/data/rules_index.json (1 rules)
[+] Copied attack_coverage_layer.json
[+] Generated pipeline_runs.json (2 runs)
[+] Generated system_health.json: Indexer online, Runner online
```

### 9.2 Start Dev Server

```powershell
cd dashboard
npm run dev
```

Open: **http://localhost:5173**

### 9.3 Dashboard Verification Checklist

| Tab | What to Verify |
|:---|:---|
| Overview | Rule count = 1, coverage line chart shows 4 snapshots, all 10 build phases green |
| Rules | PowerShell rule appears, HIGH badge, `attack.t1059.001` tag, chevron expands details |
| ATT&CK Coverage | Execution column T1059.001 highlighted green, tactic bar chart shows 1 |
| Pipeline Activity | Pass rate gauge = 100%, 2 runs in history list |
| Monitoring | "Coming Soon" placeholder visible |

---

## Part 10 — Adding a New Rule (Full Lifecycle Example)

### Example: T1136.001 — New Local Account via net.exe

```powershell
git checkout -b feature/add-t1136-create-account
```

Create `rules/windows/process_creation/proc_creation_win_net_user_add.yml`:
```yaml
title: New Local User Account Created via Net.exe
id: <run: python -c "import uuid; print(uuid.uuid4())">
status: experimental
description: Detects creation of new local user account via net.exe, used for persistence.
author: DetectForge Team
date: 2026/07/22
references:
  - https://attack.mitre.org/techniques/T1136/001/
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\net.exe'
      - '\net1.exe'
    CommandLine|contains|all:
      - 'user'
      - '/add'
  condition: selection
falsepositives:
  - Legitimate IT provisioning scripts
level: medium
tags:
  - attack.persistence
  - attack.t1136.001
```

Create `tests/true_positive/net_user_add/t1136_001_sample_1.json`:
```json
{
  "metadata": { "source": "Hand-crafted", "technique_id": "T1136.001" },
  "event": {
    "EventData": {
      "Image": "C:\\Windows\\System32\\net.exe",
      "CommandLine": "net user backdoor P@ssw0rd123! /add"
    }
  }
}
```

Create `tests/false_positive/net_user_add/legitimate_it_provisioning.json`:
```json
{
  "metadata": { "source": "Hand-crafted" },
  "event": {
    "EventData": {
      "Image": "C:\\Windows\\System32\\net.exe",
      "CommandLine": "net user /domain query adminuser"
    }
  }
}
```

Append to `tests/manifest.yml`:
```yaml
  - rule: rules/windows/process_creation/proc_creation_win_net_user_add.yml
    slug: net_user_add
    true_positive:
      - tests/true_positive/net_user_add/t1136_001_sample_1.json
    false_positive:
      - tests/false_positive/net_user_add/legitimate_it_provisioning.json
```

Run local CI:
```powershell
python scripts/lint_rules.py
python scripts/convert_rules.py
python scripts/test_harness.py
```

Push, create PR, merge:
```powershell
git add -A
git commit -m "feat(rules): add T1136.001 net user /add detection"
git push -u origin feature/add-t1136-create-account
gh pr create --title "feat: T1136.001 persistence via net user" --body "Adds new local account creation detection." --base main
# After CI passes:
gh pr merge --squash --delete-branch
```

After CD completes, verify both monitors are deployed:
```powershell
python -c "
import urllib.request, ssl, json
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://localhost:9200/_plugins/_alerting/monitors?size=10', headers={'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ='})
data = json.loads(urllib.request.urlopen(req, context=ctx).read())
[print(m['name']) for m in data.get('monitors', [])]
"
```

---

## Part 11 — Rolling Back a Deployed Rule

```powershell
# By UUID from the YAML id field:
python scripts/rollback_rule.py --rule-id c8b31a89-2917-4d92-93d3-0570b5550a18

# Or via Git revert (CD re-runs and removes the rule):
git revert HEAD~1 --no-edit
git push origin main
```

---

## Quick Reference — All Commands in Order

```powershell
# STARTUP
docker compose -f lab/docker-compose.yml up -d
python -m venv venv && .\venv\Scripts\activate && pip install -r requirements.txt
# In a separate terminal:
cd C:\actions-runner && .\run.cmd

# VERIFY ENVIRONMENT
docker ps
gh api repos/anshwhoo/detectforge/actions/runners

# LOCAL CI
python scripts/lint_rules.py
python scripts/convert_rules.py
python scripts/test_harness.py

# DASHBOARD
python scripts/generate_rules_index.py
cd dashboard && npm run dev
# Open http://localhost:5173

# VERIFY DEPLOYED RULES IN WAZUH
python -c "
import urllib.request, ssl, json
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
req = urllib.request.Request('https://localhost:9200/_plugins/_alerting/monitors?size=10', headers={'Authorization': 'Basic YWRtaW46U2VjcmV0UGFzc3dvcmQ='})
data = json.loads(urllib.request.urlopen(req, context=ctx).read())
[print(m['name']) for m in data.get('monitors', [])]
"
```
