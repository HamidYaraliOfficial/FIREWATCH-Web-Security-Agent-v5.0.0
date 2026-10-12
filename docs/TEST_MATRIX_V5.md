# FIREWATCH v5 — Automated Test Matrix

Release: `5.0.0`  
Collection baseline: **400 automated tests**  
Last local full run: **400 passed**  
Coverage command result: **80.39% statement coverage** on the build environment used for this release.

> These are software tests. Test count and source-code coverage must not be interpreted as a percentage of vulnerabilities found or as proof that a target is secure.

## Suite inventory

| Test module | Collected tests | Focus |
|---|---:|---|
| `test_api.py` | 6 | API health/readiness, security headers, coverage, reports and bundles |
| `test_checks.py` | 1 | Security rule registry smoke test |
| `test_integration.py` | 1 | Local demo end-to-end CLI scan and report generation |
| `test_scope.py` | 2 | Basic target scope policy |
| `test_security_regressions.py` | 14 | Security regressions, URL/request boundaries and secrets |
| `test_v4_security.py` | 6 | Credential isolation, path exclusions and transport guards retained from v4 |
| `test_v5_api_extended.py` | 8 | API contract, filtering, version/coverage and response handling |
| `test_v5_authz_matrix.py` | 14 | Role-comparison matrices and authorization response-difference cases |
| `test_v5_authz_policy.py` | 17 | Role profiles, authorization comparison candidates and policy edge cases |
| `test_v5_browser_mock.py` | 3 | Browser discovery behavior using mocked browser objects |
| `test_v5_cli.py` | 7 | CLI arguments, invocation and report-flow behavior |
| `test_v5_discovery_components.py` | 18 | Crawler, API discovery and bounded parameter-probe behavior |
| `test_v5_misc_invariants.py` | 7 | Cross-module invariants and edge-case regressions |
| `test_v5_redaction_matrix.py` | 70 | Parameterized redaction tests for tokens, credentials, headers and structured data |
| `test_v5_risk_catalog.py` | 35 | Risk score boundaries, malformed numbers and assessment-catalog integrity |
| `test_v5_schema_matrix.py` | 39 | Schema parsing, validation and malformed input matrix |
| `test_v5_scope_matrix.py` | 44 | URL, host, port, control-character, exclusion and scope edge cases |
| `test_v5_security_checks.py` | 44 | Cookie, headers/CSP, API security and static rule behavior |
| `test_v5_tls_matrix.py` | 9 | TLS/transport parsing and certificate/posture edge cases |
| `test_v5_transport_report.py` | 34 | TLS/transport logic, HTML escaping, CSV formula safety, report output |
| `test_v5_worker_planner_zap.py` | 21 | Worker queue transitions, planner modes, finding/asset persistence, ZAP URL and YAML safety |
| **Total** | **400** | |

The table reflects the current local collection count; use pytest's collection output as the source of truth after adding tests.

> These are software tests. Test count and source-code coverage must not be interpreted as a percentage of vulnerabilities found or as proof that a target is secure.

## Local regression command

Run from the repository root after installing the development requirements:

```bash
python -m pip install -r backend/requirements-dev.txt
python -m compileall -q backend/app backend/tests demo_target
cd backend
PYTHONPATH=. python -m pytest tests -q -rA --cov=app --cov-report=term-missing --cov-report=xml:../coverage.xml --cov-fail-under=65
```

Additional checks from the root:

```bash
node --check frontend/static/app.js
bash -n scripts/publish_to_github.sh
python scripts/repo_hygiene.py
python scripts/export_assessment_plan.py
python -c "import yaml; yaml.safe_load(open('docker-compose.yml', encoding='utf-8')); print('Compose YAML OK')"
```

CI additionally runs the high-severity/high-confidence Bandit checks, `pip-audit`, CodeQL on GitHub, and the Python 3.11/3.12/3.13 regression matrix. Hosted Bandit/pip-audit/CodeQL results must be read from the actual GitHub Actions run; they are not claimed as locally executed in this artifact build.

## Separate target assessment catalog

FIREWATCH also ships a **79-case assessment catalog**; this is separate from the 400 software regression tests:

- 22 automated passive/low-impact observations
- 13 automated review candidates requiring validation
- 38 manual or test-account/workflow cases
- 6 cases requiring optional specialist tooling

See [`ASSESSMENT_CATALOG.md`](ASSESSMENT_CATALOG.md), [`assessment-plan-v5.json`](assessment-plan-v5.json), and [`assessment-plan-v5.csv`](assessment-plan-v5.csv). The built-in scanner does not execute the manual/tool-required entries automatically.
