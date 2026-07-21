<p align="center">
  <h1 align="center">🔍 DetectForge</h1>
  <p align="center">
    <strong>Detection-as-Code CI/CD Pipeline</strong><br/>
    Sigma rules · Automated testing · Wazuh SIEM deployment · MITRE ATT&CK coverage mapping
  </p>
</p>

<p align="center">
  <a href="https://github.com/anshwhoo/detectforge/actions/workflows/ci-test-rules.yml">
    <img src="https://github.com/anshwhoo/detectforge/actions/workflows/ci-test-rules.yml/badge.svg" alt="CI Status"/>
  </a>
  <a href="https://github.com/anshwhoo/detectforge/actions/workflows/cd-deploy-rules.yml">
    <img src="https://github.com/anshwhoo/detectforge/actions/workflows/cd-deploy-rules.yml/badge.svg" alt="CD Status"/>
  </a>
</p>

---

## What is DetectForge?

**DetectForge** applies real software CI/CD discipline to SIEM detection logic. Instead of deploying detection rules straight into a SIEM's UI with no automated testing, no peer review, no version history, and no rollback path — DetectForge version-controls Sigma rules in Git, automatically lints and regression-tests them on every pull request, and deploys them to a live Wazuh SIEM on every merge.

A live **MITRE ATT&CK coverage map** is generated from what's actually deployed — not maintained by hand.

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        DetectForge Pipeline                          │
│                                                                      │
│  ┌─────────────┐    ┌──────────────────────┐    ┌─────────────────┐  │
│  │  AUTHOR      │    │  CI (on every PR)     │    │  CD (on merge)  │  │
│  │             │    │                      │    │                 │  │
│  │ Sigma YAML  │───▶│ 1. Lint (schema +    │───▶│ 1. Deploy rules │  │
│  │ rules in    │    │    ATT&CK tags)      │    │    to Wazuh     │  │
│  │ Git         │    │ 2. Convert (pySigma  │    │    Indexer      │  │
│  │             │    │    → Elasticsearch)   │    │ 2. Generate     │  │
│  │ Test data   │    │ 3. Test (TP/FP       │    │    ATT&CK       │  │
│  │ (OTRF +     │    │    assertions on     │    │    coverage     │  │
│  │  crafted)   │    │    ephemeral index)  │    │    layer        │  │
│  │             │    │ 4. PR comment bot    │    │ 3. Tag release  │  │
│  └─────────────┘    └──────────────────────┘    └─────────────────┘  │
│                                                         │            │
│                                                         ▼            │
│                                              ┌─────────────────┐    │
│                                              │  Wazuh SIEM     │    │
│                                              │  (OpenSearch     │    │
│                                              │   Security       │    │
│                                              │   Analytics)     │    │
│                                              └─────────────────┘    │
└──────────────────────────────────────────────────────────────────────┘
```

## Repository Structure

```
detectforge/
├── .github/workflows/          # CI/CD GitHub Actions workflows
│   ├── ci-test-rules.yml       #   Lint, convert, test on every PR
│   ├── cd-deploy-rules.yml     #   Deploy to Wazuh on merge to main
│   └── policy-check.yml        #   OPA policy gate (stretch goal)
├── rules/                      # Sigma detection rules (one file per rule)
│   ├── windows/                #   Windows event categories
│   │   ├── process_creation/
│   │   ├── registry/
│   │   └── network_connection/
│   └── linux/
│       └── process_creation/
├── tests/                      # TP/FP test corpus
│   ├── manifest.yml            #   Maps rules → test samples
│   ├── true_positive/          #   Sourced from OTRF / EVTX-ATTACK-SAMPLES
│   └── false_positive/         #   Hand-crafted legitimate activity
├── pipelines/                  # Sigma processing pipelines
│   └── sysmon_to_ecs.yml       #   Sysmon field → ECS mapping
├── scripts/                    # All automation scripts
│   ├── lint_rules.py           #   Sigma schema + metadata validation
│   ├── convert_rules.py        #   Sigma → Elasticsearch via pySigma
│   ├── test_harness.py         #   TP/FP assertions against ephemeral ES
│   ├── post_pr_comment.py      #   Bot that posts results to PR
│   ├── deploy_rules.py         #   Push Sigma YAML to Wazuh Indexer
│   ├── setup_detector.py       #   One-time detector/log-type setup
│   ├── generate_attack_layer.py#   Build ATT&CK Navigator layer JSON
│   ├── rollback_rule.py        #   Remove a rule from the SIEM
│   ├── fetch_reference_samples.py # Pull samples from OTRF/EVTX repos
│   └── policy/
│       └── rule_quality.rego   #   OPA policy (stretch goal)
├── lab/                        # Local development environment
│   └── docker-compose.yml      #   Wazuh single-node stack
├── dashboards/
│   └── rule_health_dashboard.ndjson
├── config/
│   ├── siem.config.yml         #   SIEM connection defaults
│   └── attack_layer_template.json
├── docs/
│   ├── architecture.md
│   └── runbook.md
├── .gitignore
├── requirements.txt
└── README.md
```

## Quickstart

### Prerequisites

- Python 3.11+
- Docker & Docker Compose v2
- Git

### 1. Clone & set up

```bash
git clone https://github.com/anshwhoo/detectforge.git
cd detectforge
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Stand up the lab SIEM

```bash
cd lab
docker compose up -d
# Dashboard: https://localhost (admin / SecretPassword)
# Indexer API: https://localhost:9200
```

### 3. Write a rule

Create a Sigma YAML file under `rules/`, add test samples under `tests/`, and update `tests/manifest.yml`.

### 4. Open a PR

```bash
git checkout -b feature/my-new-rule
git add .
git commit -m "feat: add detection for T1059.001"
git push -u origin feature/my-new-rule
```

CI automatically lints, converts, and tests your rule. Results are posted as a PR comment.

### 5. Merge → auto-deploy

Once CI passes and a reviewer approves, merge to `main`. CD automatically deploys the rule to the Wazuh Indexer and updates the ATT&CK coverage map.

## Key Design Decisions

| Decision | Choice | Rationale |
|:---|:---|:---|
| Rule language | Sigma | Industry standard, portable, well-tooled |
| SIEM backend | Wazuh (OpenSearch Indexer) | REST API, Security Analytics supports Sigma natively |
| Deployment path | Raw Sigma YAML → Security Analytics API | Avoids lossy XML conversion; full Sigma fidelity preserved |
| CI test backend | pySigma → Elasticsearch | Converts to Lucene/ES query for ephemeral test index assertions |
| Test data source | OTRF Security Datasets + EVTX-ATTACK-SAMPLES | Real-world telemetry mapped to ATT&CK, not fabricated |
| ATT&CK coverage | Auto-generated Navigator layer JSON | Derived from deployed rules' tags, not manually maintained |

## License

This project is for educational and internal SOC use. See individual rule attributions where applicable.
