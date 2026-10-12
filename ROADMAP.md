# Roadmap

## v5.0.0 — current

- Root-host/root-scheme credential isolation across HTTP and browser traffic.
- Credential-like query URL protection and stronger path exclusion normalization.
- Cooperative cancellation and atomic job finalization.
- Redacted evidence endpoint, scan-level coverage endpoint, filtered pagination, and ZIP report bundle.
- Readiness/security headers and inline/external worker separation.
- GitHub release automation, CodeQL, Dependabot, contributor templates and repository hygiene checks.

## v4.x — next

- Database schema migrations and explicit scan retention/purge policy.
- Egress proxy integration with DNS/IP pinning and auditable resolved-address policy.
- Authenticated Playwright login journeys using a declarative, non-secret workflow file and secret injection at run time.
- Rule test harness with precision/recall fixtures and a regression corpus of synthetic applications.
- More API authorization workflow support using designated test objects and per-route expected-role assertions.
- SARIF baseline integration and machine-readable risk acceptance workflow.
- External queue backend and multi-worker load/concurrency tests.

## Later major versions

- Optional LLM-assisted planning with deterministic policy enforcement and typed tool calls.
- CI/CD gate policies and scan-result trend analytics.
- Additional protocol-specific adapters for API gateways and supported DAST tools.
- Tenant isolation only after a dedicated threat model, authentication/authorization model, migration design and security review.

## Non-goals for default profiles

Unbounded scanning, password guessing, destructive business workflows, arbitrary write methods, exploit payload automation, weaponized SSRF and silent scope expansion remain out of scope for defaults.
