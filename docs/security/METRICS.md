# Security and assurance metrics

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Purpose | Define the numbers that show whether the controls work |

This is a definition list, not a live dashboard. Values are updated when a scan or test run
changes them. "Not measured" is an honest value and a gap.

I keep these numbers so I cannot pretend the controls work. A metric with no measurement is
a gap, not a zero.

## 1. Product and code

| Metric | Definition | Target | Current |
|--------|------------|--------|---------|
| Test functions | Collected by pytest | Growing | 95 |
| Security regression tests | Tests under `tests/security/` | Every control has one | 27 |
| Lint findings | Ruff errors and warnings | 0 | 0 |
| Format drift | `ruff format --check` | 0 files | 0 |
| Bandit high severity | `bandit -lll` | 0 | 0 |
| Bandit medium severity | `bandit -lll` excludes medium | Reviewed | 0 known |
| Secret leaks | gitleaks `--no-git` | 0 | 0 |
| Type errors | mypy or pyright | Not configured | Not measured |

## 2. Dependencies

| Metric | Definition | Target | Current |
|--------|------------|--------|---------|
| Known advisories | pip-audit packages and IDs | 0 | 4 packages |
| Advisories older than 90 days | Age of the oldest open advisory | 0 | Blocked upstream |
| High or critical advisories | CVSS 7.0 or later | 0 | 0 |
| Fix SLA compliance | Fixed within the policy window | 100% | Not measured |
| SBOM published | CycloneDX artifact per release | Every release | Not yet |
| Images pinned by digest | Compose and quadlet references | All | 0 |

## 3. Operations

| Metric | Definition | Target | Current |
|--------|------------|--------|---------|
| Backup success rate | Scheduled dumps that complete | 100% | Not measured |
| Restore drill | Last successful restore test | Quarterly | Never run |
| `MARKET_KEY` rotation drill | Last successful rotation | Yearly | Never run |
| Mean time to detect | Report to triage | 3 business days | No production data |
| Mean time to fix critical | Triage to fix | 7 days | No production data |
| Vulnerability disclosure SLA | First reply | 3 business days | Policy only |
| Alert coverage | Auth and CSRF denial bursts | Alerted | Not implemented |

## 4. Privacy

| Metric | Definition | Target | Current |
|--------|------------|--------|---------|
| IP addresses in logs | Fields matching an IP pattern | 0 | 0 by design |
| Third-party origins in CSP | External hosts in `default-src` | 0 | 0 |
| Plaintext messages at rest | Ratchet messages stored in clear | 0 | 0 |
| Retention jobs | Automated deletion jobs | All categories | None |
| Data subject requests | Open requests past 30 days | 0 | No production data |

## 5. How to refresh

```bash
just lint
just test-fast
just security
just security --strict   # expected to fail on the tracked advisories
```

Record the date and the output in the table. Do not round a failure up to a pass.
