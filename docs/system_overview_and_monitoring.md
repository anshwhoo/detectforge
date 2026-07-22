# DetectForge — System Architecture & Live Monitoring Roadmap

A complete technical specification of the **DetectForge** Detection-as-Code pipeline, its end-to-end workflow, and the execution blueprint for the **Live Monitoring & Alert Analytics Feature** in the next development stage.

---

## 1. Executive Summary & Core Philosophy

**DetectForge** bridges the gap between software engineering discipline and security operations (SOC). In traditional environments, detection logic is manually edited inside SIEM UIs without version control, automated testing, or automated rollback paths.

DetectForge implements **Detection-as-Code (DaC)**:
- **Rules as Code**: Sigma YAML detection rules versioned in Git.
- **Continuous Integration (CI)**: Automated schema linting, `pySigma` translation, and True Positive (TP) / False Positive (FP) assertion testing on every Pull Request.
- **Continuous Deployment (CD)**: Idempotent REST API deployment to a live Wazuh SIEM on merge to `main`.
- **Automated ATT&CK Mapping**: Dynamic MITRE ATT&CK Navigator coverage layer derived from deployed rule tags.
- **Analytics Control Center**: A static React + Tailwind web dashboard deployed to GitHub Pages.

---

## 2. End-to-End Project Workflow

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             DetectForge Workflow                                 │
│                                                                                  │
│  [1. Authoring]               [2. CI Testing Gate]           [3. CD Deployment]  │
│  Sigma Rule (YAML)  ────────►  GitHub Actions (CI)       ───►  Self-Hosted       │
│  + Test Samples                ├─ lint_rules.py               Runner             │
│  (OTRF / EVTX)                 ├─ convert_rules.py            │                  │
│                                ├─ test_harness.py             ▼                  │
│                                └─ post_pr_comment.py        Wazuh Indexer REST   │
│                                                               (OpenSearch)       │
│                                                                 │                │
│                                                                 ▼                │
│                                                      [4. Dashboard Analytics]    │
│                                                      React + Tailwind            │
│                                                      GitHub Pages Dashboard      │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Stage 1: Rule Authoring & Telemetry Curation
1. Detection engineers author vendor-neutral Sigma rules under `rules/windows/` or `rules/linux/`.
2. True-positive security events are curated from **OTRF Security Datasets (Mordor)** or **EVTX-ATTACK-SAMPLES** via `scripts/fetch_reference_samples.py`.
3. Benign false-positive events are hand-crafted to simulate legitimate administrative background noise.
4. Mappings are registered in `tests/manifest.yml`.

### Stage 2: CI Regression Testing Gate (GitHub Actions Cloud)
1. Opening a Pull Request triggers `.github/workflows/ci-test-rules.yml`.
2. `lint_rules.py` verifies YAML syntax, UUID uniqueness, and mandatory `attack.t####` tags.
3. `convert_rules.py` translates Sigma YAML to Elasticsearch Lucene queries via `pySigma`.
4. `test_harness.py` indexes test events into an ephemeral Elasticsearch container, asserting $\ge 1$ hit for TP and $0$ hits for FP.
5. `post_pr_comment.py` formats and posts a pass/fail matrix table directly as a PR comment.

### Stage 3: Idempotent CD Deployment (Self-Hosted Runner)
1. Merging a PR into `main` triggers `.github/workflows/cd-deploy-rules.yml` on the local self-hosted runner (`detectforge-local-runner`).
2. `deploy_rules.py` converts rules to Lucene and pushes them to the local Wazuh Indexer API (`https://localhost:9200/_plugins/_alerting/monitors`) as OpenSearch Alerting Monitors.
3. `generate_attack_layer.py` updates the MITRE ATT&CK coverage layer JSON (`config/attack_coverage_layer.json`) and appends snapshots to `coverage_history.json`.

### Stage 4: Dashboard Build & Deployment
1. `.github/workflows/deploy-dashboard.yml` runs `generate_rules_index.py` and `generate_system_health.py`.
2. Builds the React + Tailwind frontend (`dashboard/`).
3. Deploys static build artifacts to **GitHub Pages** (`https://anshwhoo.github.io/detectforge/`).

---

## 3. Live Monitoring Feature Specification (Next Stage Blueprint)

### 🎯 Objective of Live Monitoring
While the current dashboard provides **static pipeline state, rule inventory, and ATT&CK coverage**, the **Live Monitoring Feature** will bring real-time operational visibility into how deployed rules perform against live SIEM log streams.

Key operational metrics provided by Live Monitoring:
1. **Rule Fires Per Day / Hour**: Tracks alert frequency to identify active threats or noisy rules.
2. **False-Positive Rate Tracking**: Measures analyst FP tagging feedback to inform rule tuning.
3. **Detection Health & Latency**: Monitors SIEM ingestion lag and query evaluation times.
4. **Top Triggered Rules**: Identifies high-volume detections requiring SOC attention.

---

### 🛡️ Architecture: Zero-Credential Browser Security

To maintain the project's security architecture (**never expose SIEM credentials in the browser**), Live Monitoring will follow the established snapshot pattern:

```
┌─────────────────────────┐          ┌───────────────────────────┐          ┌─────────────────────────┐
│ Wazuh SIEM REST API     │          │ Server-Side Polling       │          │ GitHub Pages Dashboard  │
│ https://localhost:9200  │ ───────► │ scripts/                  │ ───────► │ dashboard/public/data/  │
│ wazuh-alerts-* Indices  │          │ generate_monitoring.py    │          │ monitoring_data.json    │
└─────────────────────────┘          └───────────────────────────┘          └─────────────────────────┘
                                                                                         │ (30s Polling)
                                                                                         ▼
                                                                            React Recharts Monitoring Tab
```

1. **Server-Side Snapshot Collector (`scripts/generate_monitoring_snapshot.py`)**:
   - Runs locally or via a scheduled GitHub Actions workflow step.
   - Queries the local Wazuh Indexer API (`https://localhost:9200/wazuh-alerts-*/_search`) using standard credentials (`admin:SecretPassword`).
   - Aggregates alert count by rule ID over time (24h histogram) and calculates trigger rates.
   - Outputs a sanitized JSON file to `dashboard/public/data/monitoring_data.json`.

2. **Frontend Integration (`MonitoringTab.jsx`)**:
   - Fetches `monitoring_data.json` every 30 seconds alongside existing JSON data files.
   - Renders interactive Recharts visualizations:
     - **Rule Fires Per Day (Line / Area Chart)**: Select any rule from a dropdown to view its 24-hour fire trend.
     - **Top Triggered Detections (Bar Chart)**: Ranks rules by total alert count.
     - **FP vs TP Ratio Gauge**: Displays real-time detection fidelity metrics.
     - **Triage Shortcut**: Direct links to open alert logs in Wazuh Dashboard (`https://localhost:443`).

---

## 4. Implementation Roadmap for Stage 2 Execution

| Step | Action Item | Deliverable File | Status |
|:---:|:---|:---|:---:|
| **1** | Build server-side snapshot script | `scripts/generate_monitoring_snapshot.py` | ⏳ Next Stage |
| **2** | Create sample monitoring JSON data | `dashboard/public/data/monitoring_data.json` | ⏳ Next Stage |
| **3** | Replace placeholder in React frontend | `dashboard/src/components/MonitoringTab.jsx` | ⏳ Next Stage |
| **4** | Add monitoring snapshot task to data pipeline | `scripts/generate_rules_index.py` | ⏳ Next Stage |
| **5** | Deploy updated dashboard with Live Monitoring | `gh-pages` build | ⏳ Next Stage |

---

## 5. Summary of System Assets & URLs

- **GitHub Repository**: [github.com/anshwhoo/detectforge](https://github.com/anshwhoo/detectforge)
- **Live Web Dashboard**: [anshwhoo.github.io/detectforge](https://anshwhoo.github.io/detectforge/)
- **Local Wazuh Dashboard**: `https://localhost:443` (`admin` / `SecretPassword`)
- **Local Wazuh Indexer API**: `https://localhost:9200` (`admin` / `SecretPassword`)
- **Self-Hosted Actions Runner**: `detectforge-local-runner` (Active on Windows Host)
