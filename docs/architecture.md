# DetectForge Architecture

DetectForge is an end-to-end **Detection-as-Code (DaC)** CI/CD pipeline built around modern software engineering principles.

```mermaid
flowchart TB
    subgraph LayerA["Layer A — Source & Authoring"]
        R["Sigma YAML Rules\n(rules/*)"]
        T["Test Corpus & Manifest\n(tests/*)"]
        P["Field Pipelines\n(pipelines/*)"]
        F["Reference Sample Fetcher\n(scripts/fetch_reference_samples.py)"]
    end

    subgraph LayerB["Layer B — Continuous Integration (GitHub Actions)"]
        L["Rule Linter\n(lint_rules.py)"]
        C["pySigma Conversion Engine\n(convert_rules.py)"]
        H["Test Harness\n(test_harness.py)"]
        B["PR Comment Bot\n(post_pr_comment.py)"]
    end

    subgraph LayerC["Layer C — Continuous Deployment"]
        D["SIEM Deploy Client\n(deploy_rules.py)"]
        A["ATT&CK Coverage Generator\n(generate_attack_layer.py)"]
        M["ATT&CK Navigator JSON\n(config/attack_coverage_layer.json)"]
    end

    subgraph LayerD["Layer D — Operations"]
        W["Wazuh / OpenSearch\nSecurity Analytics"]
        RB["Rollback Script\n(rollback_rule.py)"]
        DB["Rule Health Dashboard\n(rule_health_dashboard.ndjson)"]
    end

    R --> L
    T --> H
    L --> C --> H --> B
    LayerB -- Merge to main --> D
    D --> W
    D --> A --> M
    W --> DB
    W -. Rollback .-> RB
```

## Key Components

1. **Source & Authoring**: Detection rules written in vendor-neutral Sigma format. True-positive telemetry curated from OTRF Security Datasets (Mordor) & EVTX-ATTACK-SAMPLES.
2. **Continuous Integration**: On every PR, automated scripts lint rule YAML, validate UUIDs and mandatory `attack.t####` tags, convert rules via pySigma, and execute TP/FP assertions.
3. **Continuous Deployment**: On merge to `main`, raw Sigma YAML rules are pushed via REST API directly to OpenSearch Security Analytics (Wazuh Indexer), avoiding lossy XML translation.
4. **Operations & Monitoring**: Automated release tagging, ATT&CK Navigator coverage layer generation, and programmatic rollback.
