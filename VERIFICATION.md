# FIREWATCH v5.0.0 Verification Record

Release target: `FIREWATCH-WebSec-Agent-v5.0.0`

## Executed checks

From the repository root:

```bash
python -m compileall -q backend/app backend/tests demo_target
cd backend
PYTHONPATH=. pytest tests -q --cov=app --cov-report=term-missing --cov-report=json:../coverage.json --cov-fail-under=65
cd ..
node --check frontend/static/app.js
bash -n scripts/publish_to_github.sh
python scripts/repo_hygiene.py
python scripts/export_assessment_plan.py
python -c "import yaml; yaml.safe_load(open('docker-compose.yml', encoding='utf-8')); print('Compose YAML OK')"
```

Results recorded for this release build:

- **400 / 400 automated tests passed**.
- **80.39% statement coverage** across `backend/app` (Python 3.13.5 build environment).
- Python compilation passed for the application and tests.
- Dashboard JavaScript syntax check passed.
- Bash publishing helper syntax check passed.
- Repository hygiene check passed.
- Docker Compose YAML parsing passed. This checks YAML syntax only; it is not a container build.
- The assessment plan exporter generated a 79-case catalog in JSON, CSV and Markdown. Counts: 22 automated passive, 13 automated review candidates, 38 manual/test-account required, 6 specialist-tool required.
- Integration test starts a local deliberately vulnerable demo, runs the CLI scanner, and verifies completed status plus HTML, JSON, CSV, Markdown and SARIF output.

## Test suite inventory

The exact module counts and each suite's purpose are documented in [`docs/TEST_MATRIX_V5.md`](docs/TEST_MATRIX_V5.md). The key cases include scope/DNS/url rules, credential isolation, structured redaction, report escaping, CSV formula mitigation, API validation, role-comparison policy, schema handling, asset/finding de-duplication, worker claim transitions, safe ZAP plan serialization and local end-to-end report generation.

## Not executed / external verification required

- PyPI package installation was not repeated here because outbound package-network access was unavailable. The currently installed environment was used for the local test run.
- Docker Compose was parsed but Docker images/containers were not built because Docker Engine/CLI was unavailable.
- Bandit and pip-audit were added to CI but were not run locally because those executables are not installed in this environment. CI results are not claimed until a hosted GitHub run is completed.
- Chromium browser automation, real ZAP active/passive scan execution, GitHub-hosted CodeQL, production PostgreSQL concurrency/load, and public GitHub publishing were not claimed as completed by this local verification.

## Interpretation and constraints

Software test coverage is not security coverage and does not imply a percent of vulnerabilities detected. The 79-case catalog labels manual/tool-required cases honestly; the built-in scanner does not execute all entries. Scope policy should be combined with network egress controls in deployments because DNS checks alone are not a complete DNS-rebinding or network-isolation defense. See [`docs/SECURITY_COVERAGE.md`](docs/SECURITY_COVERAGE.md) and [`SECURITY.md`](SECURITY.md).
