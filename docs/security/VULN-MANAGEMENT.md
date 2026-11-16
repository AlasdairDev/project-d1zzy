# Vulnerability management

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Review | Weekly dependency check, monthly policy review |

This is how I find, rank, fix and close findings. It also records the advisories I
knowingly accept, so they are not silently ignored.

## 1. Sources

| Source | What it covers | How it runs |
|--------|----------------|-------------|
| pip-audit and OSV | Python dependencies | `just security`, CI weekly |
| Bandit | Python SAST, high severity is fatal | `just security`, CI |
| Ruff | Lint, including undefined names and unused code | `just security`, CI |
| gitleaks | Secrets in the working tree and git history | `just security`, CI |
| Semgrep | Pattern SAST | `just security --strict` with `SECURITY_SEMGREP=1`, CI |
| GitHub security advisories | Private reports | Manual triage |
| User reports | Anything in scope in `.github/SECURITY.md` | Manual triage |
| Container image scanning | Base images and OS packages | Planned, Trivy |
| CodeQL | Data-flow analysis | Planned, free for public repositories |

## 2. Severity and SLAs

| Severity | Example | Triage | Fix or documented mitigation |
|----------|---------|--------|------------------------------|
| Critical | Remote code execution without authentication, key leak, payment forgery | Same day | 7 days |
| High | Authentication bypass, stored XSS, signature bypass | 2 business days | 30 days |
| Medium | CSRF gap, information disclosure, reachable dependency advisory | 5 business days | 90 days |
| Low | Hygiene, hardening, non-reachable advisory | 10 business days | Next cycle |
| Info | Accepted design trade-off or documented limitation | n/a | Reviewed at release |

If a fix is not possible, the finding stays open with a written compensating control and an
owner. It is never marked "won't fix" without an entry here.

## 3. Triage questions

1. Is the affected code reachable in this application?
2. Does the attack need authentication, a privileged role, a malicious peer or a local
   position?
3. What is the worst realistic impact on confidentiality, integrity, availability or funds?
4. Is there a compensating control already in place?
5. Can the dependency be upgraded without breaking the test suite?

## 4. Current accepted advisories

These are open as of 2026-11-16. They are also in `SECURITY-ASSESSMENT.md`.

| Package | Version | Issue | Why it is open | Compensating control |
|---------|---------|-------|----------------|----------------------|
| `fastapi-users` | 14.0.2 | `PYSEC-2026-1363`, fixed in 15.0.2 | Upgrade is planned but not done | Short JWT lifetime, strong secret, email verification |
| `pyjwt` | 2.10.1 | Multiple advisories, fixed in 2.12 to 2.15 | `fastapi-users` 14.0.2 exact-pins it | HS256 only, explicit algorithm allowlist, audience separation, 15-minute access tokens |
| `python-multipart` | 0.0.20 | Multiple advisories, fixed in 0.0.22 to 0.0.31 | `fastapi-users` 14.0.2 exact-pins it | 5 MB request cap, authenticated uploads, no arbitrary file writes |
| `starlette` | 0.46.2 | Multiple advisories, fixed in 0.47.2 and later | FastAPI 0.115.14 requires `<0.47` | No exploit demonstrated. Plan a FastAPI major upgrade |

The honest summary: the upgrade path is blocked by an upstream exact pin. The fix is to move
`fastapi-users` to 15.0.2 or later, then upgrade FastAPI and Starlette together.

## 5. Exception and VEX process

For an accepted advisory, record:

- the package and advisory ID,
- the affected code path and whether it is reachable,
- the compensating controls,
- the owner and review date,
- the condition that closes the exception.

Keep the record in this file. Do not add a scanner ignore rule unless the reason is written
down here first.

## 6. Patch cadence

- Dependencies: checked weekly by CI. Upgrade in the next working window when a fix exists.
- Base images: reviewed monthly. Pin by digest once the image set is stable.
- Application code: fixes follow the SLAs above.
- OS and container runtime: operator responsibility, documented in `.github/SECURITY.md`.

## 7. Metrics

| Metric | Target | Current |
|--------|--------|---------|
| High or critical findings open | 0 | 0 high and 0 critical by Bandit. pip-audit advisories are medium and tracked |
| Findings older than 90 days | 0 | 4 packages, all blocked upstream |
| Mean time to fix a critical | 7 days | No production incidents yet |
| Secret leaks in the tree | 0 | 0 |
| High-severity SAST findings | 0 | 0 |

These are definitions, not a dashboard. See `METRICS.md` for the full set.

## 8. Closing a finding

A finding is closed when:

1. the fix is merged,
2. a test or scan proves the fix,
3. the entry in this file or `SECURITY-ASSESSMENT.md` is updated, and
4. the change is noted in `docs/CHANGELOG.md` if it affects users.
