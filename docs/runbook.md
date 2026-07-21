# DetectForge Operational Runbook

This runbook guides SOC engineers on common tasks in DetectForge.

---

## 1. How to Add a New Detection Rule

1. **Create a new branch**:
   ```bash
   git checkout -b feature/t1059-001-powershell-rule
   ```
2. **Fetch or prepare reference telemetry**:
   ```bash
   python scripts/fetch_reference_samples.py --technique T1059.001 --rule-slug my_new_rule
   ```
3. **Write the Sigma YAML rule** under `rules/windows/...` or `rules/linux/...`:
   - Must include `id: <valid-uuid>`
   - Must include `tags: [attack.t####]`
4. **Update `tests/manifest.yml`** to map the rule to its TP and FP test JSON files.
5. **Run local CI validation**:
   ```bash
   python scripts/lint_rules.py
   python scripts/convert_rules.py
   python scripts/test_harness.py
   ```
6. **Open Pull Request**: Push to GitHub and create a PR.

---

## 2. How to Roll Back a Deployed Rule

If a rule causes excessive false positives in production:

1. **Option A: Git Revert (Recommended)**:
   Revert the PR commit on `main`. The CD workflow will run and remove/update the rule.

2. **Option B: Programmatic CLI Rollback**:
   ```bash
   python scripts/rollback_rule.py --rule-id <rule-id-or-uuid>
   ```

---

## 3. Environment Variables for CI/CD

| Variable | Description |
|:---|:---|
| `SIEM_API_URL` | Base URL of Wazuh Indexer API (e.g. `https://localhost:9200`) |
| `SIEM_API_TOKEN` | Credentials formatted as `admin:password` or JWT token |
| `GITHUB_TOKEN` | Automatically supplied by GitHub Actions for PR bot comments |
