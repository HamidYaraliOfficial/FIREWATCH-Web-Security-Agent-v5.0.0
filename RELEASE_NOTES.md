# FIREWATCH Web Security Agent v5.0.0

FIREWATCH v5 is a security-assessment and test-quality release. It increases regression coverage, adds a transparent assessment catalog, and fixes concrete correctness and report-handling issues discovered through the enlarged tests.

## Release highlights

- **400 automated tests** across unit tests, parameterized edge-case matrices, API/worker/report tests and a full local demo scan.
- **80.39% statement coverage** in the local build environment; CI sets a 65% minimum. Coverage is not a percentage of vulnerabilities detected.
- **79-item assessment plan**, served by `/api/v1/assessment-plan` and included as JSON, CSV and Markdown. Its entries explicitly distinguish passive automatic checks, review candidates, manual/test-account cases and specialist-tool cases.
- Stronger redaction, URL/port boundaries, OpenAPI security review, cookie-prefix/SameSite checks, CSP checks, HTML autoescaping, CSV formula neutralization, ZAP plan URL validation and YAML-safe serialization.
- Asset de-duplication fix for sessions running with SQLAlchemy `autoflush=False`.
- CI matrix on Python 3.11, 3.12 and 3.13 with coverage, JavaScript syntax, repository hygiene, YAML parsing, Bandit high-severity/high-confidence scan and dependency audit.

## Validation actually performed locally

- `PYTHONPATH=backend pytest -q backend/tests`: **400 passed**.
- `cd backend && PYTHONPATH=. pytest tests -q --cov=app --cov-report=term-missing --cov-report=json:../coverage.json --cov-fail-under=65`: **400 passed; 80.39% statement coverage**.
- Python app/test compile, JavaScript syntax, repository hygiene, shell syntax, Docker Compose YAML parsing and assessment-plan export are release checks.
- The local end-to-end test starts the deliberately vulnerable demo application on loopback, runs the CLI scan, and validates completed status plus HTML/JSON/CSV/Markdown/SARIF report artifacts.

## Not claimed as locally verified

The build environment did not re-install pinned packages from PyPI and does not have Docker Engine, Bandit or pip-audit installed. Thus dependency audit, Docker image build, browser automation with a real Chromium binary, GitHub-hosted CodeQL and actual hosted CI results must be verified after pushing the repository. The GitHub publish helper was not run against an authenticated account from this build environment.

## Safe-use boundary

This project is for systems for which the operator has explicit authorization. The scanner remains bounded and non-destructive by default; it does not run brute force, destructive writes/deletes, exploit chains or arbitrary injection payloads. A clean report is not proof that the application is secure. Business logic, IDOR/BOLA, injection exploitability and several authentication workflows require application-specific test identities and validation.
