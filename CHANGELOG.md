# Changelog

All notable release changes are recorded here.

## 5.0.0 — 2026-10-09

### Assessment coverage and transparency
- Added a 79-case assessment plan mapped to OWASP Top 10:2025, OWASP ASVS 5.0.0, WSTG v4.2 stable and OWASP API Security Top 10:2023.
- Added `/api/v1/assessment-plan` and export formats JSON, CSV, and Markdown.
- Clearly separated built-in passive observations, automated review candidates, manual/test-account workflows, and specialist-tool-only tests.

### Security and correctness
- Expanded secret redaction for URLs, structured evidence, Authorization, cookies and credential-like values.
- Corrected URL rejection for control characters/backslashes and invalid port values.
- Corrected OpenAPI operation-level `security: []` review behavior.
- Added precise cookie attribute, SameSite=None/Secure, `__Host-` and `__Secure-` policy checks.
- Added CSP `object-src`/`base-uri`, cross-origin isolation and header-value review checks.
- Enabled Jinja HTML autoescaping for generated findings reports.
- Neutralized spreadsheet formula injection in CSV findings exports.
- Safely serialized optional ZAP automation YAML and validated ZAP base URLs.
- Fixed same-transaction asset de-duplication with SQLAlchemy sessions configured with `autoflush=False`.
- Hardened risk score handling for NaN, infinity and malformed confidence values.

### Test quality and GitHub automation
- Expanded the automated suite to 400 unit, matrix, regression and local end-to-end tests.
- Measured 80.39% statement coverage in the local build environment and added a 65% CI coverage threshold.
- Added Python 3.11/3.12/3.13 CI matrix, high-severity/high-confidence Bandit checks and `pip-audit` dependency review.
- Added test inventory, generated assessment catalog, v5 verification record and release notes.
- Updated publishing helpers and package metadata to v5.0.0.

### Boundaries
- Manual and specialist tests are not represented as automatically executed. FIREWATCH does not perform brute-force login attempts, destructive workflows, exploit chains, or arbitrary write/delete operations by default.

## 4.0.0 — 2026-10-09
- Isolated credentials to the root hostname and scheme; refused credential-like query strings.
- Added cancellation checkpoints, strict scope behavior, report bundle APIs and GitHub publishing helpers.

## 3.0.0
- Improved scope validation, credential encryption/redaction, API discovery, coverage catalog, multiple report outputs, and security tests.

## 2.0.0
- Added browser/API discovery and a broader low-impact rule catalog.

## 1.0.0
- Initial working assessment pipeline, queue, dashboard, findings, and HTML/JSON reports.
