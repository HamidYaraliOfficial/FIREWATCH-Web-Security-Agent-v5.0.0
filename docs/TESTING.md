# Testing Guide — FIREWATCH v5.0.0

## Automated tests

The v5 release suite contains **400 collected tests** and all passed in the local release test run. `pytest-cov` reported **80.39% statement coverage** in that build environment. CI enforces a 65% minimum; this metric reflects exercised Python statements, not percentage of vulnerabilities that will be detected.

```bash
python -m pip install -r backend/requirements-dev.txt
cd backend
PYTHONPATH=. python -m pytest tests -q -rA --cov=app --cov-report=term-missing --cov-report=xml:../coverage.xml --cov-fail-under=65
```

The full inventory is in [`TEST_MATRIX_V5.md`](TEST_MATRIX_V5.md). It covers API/readiness, a local demo end-to-end scan, URL/host/port policy, secret redaction, schema parsing, risk-score edges, cookie/header/CSP/API checks, report escaping and CSV formula safety, worker queue, planner behavior, authorization review candidates, and safe ZAP plan output.

## Assessment-plan export

The separate 79-case coverage plan distinguishes 22 automated passive checks, 13 review candidates, 38 manual/test-account cases and 6 specialist-tool cases. Regenerate its JSON/CSV/Markdown forms after catalog changes:

```bash
python scripts/export_assessment_plan.py
```

The API serves the same plan at `GET /api/v1/assessment-plan`. Manual or tool-required entries are not run automatically by the built-in safe scanner.

## Static checks

From the project root:

```bash
python -m compileall -q backend/app backend/tests demo_target
node --check frontend/static/app.js
bash -n scripts/publish_to_github.sh
python scripts/repo_hygiene.py
python -c "import yaml; yaml.safe_load(open('docker-compose.yml', encoding='utf-8')); print('Compose YAML OK')"
```

GitHub Actions additionally runs a Python 3.11/3.12/3.13 matrix, coverage reporting, high-severity/high-confidence Bandit checks and `pip-audit`. CodeQL runs separately in GitHub Actions. These hosted checks should be treated as verified only after their actual workflow runs complete.

## Manual browser / deployment tests

Install Playwright's Chromium binary if using browser discovery; then start the demo target on loopback and launch the API. Confirm the browser inventory stays in scope, forms are not submitted, downloads are not accepted, configured credentials are not sent to other origins or public HTTP, and test secrets never appear in report evidence. Check Docker image build, PostgreSQL deployments, external worker processing and ZAP reachability separately; these were not all run in the local release environment.

## Demo result interpretation

The included target is intentionally weak to exercise detector paths. Expected finding count can change as rules evolve. Tests should assert rule behavior, evidence sanitization and pipeline completion rather than assume a finding count guarantees full coverage.
