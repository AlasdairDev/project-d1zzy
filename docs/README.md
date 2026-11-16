# Documentation

The code shows what the system does. These documents show what it is supposed to do, how
it is assessed, and what happens when something goes wrong.

I wrote these while building D1zzy. Some of them are more honest than a launch page would
be. That is intentional.

## Guides

| Document | Audience | What it covers |
|----------|----------|----------------|
| [`guides/USER-SECURITY-GUIDE.md`](guides/USER-SECURITY-GUIDE.md) | Users | Verifying the onion address, comparing safety numbers, spotting scams, protecting keys |

## Screenshots

[`screenshots/`](screenshots/) holds the UI screenshots used in the README, captured from the
seeded demo data.

## Policy

| Document | What it covers |
|----------|----------------|
| [`policy/TRUST-AND-SAFETY.md`](policy/TRUST-AND-SAFETY.md) | Prohibited content, abuse taxonomy, enforcement and appeals |
| [`policy/TRANSPARENCY-REPORT-TEMPLATE.md`](policy/TRANSPARENCY-REPORT-TEMPLATE.md) | The template for publishing moderation and disclosure statistics |

## Security

Start with the threat model, then read the assessment. The remaining documents are the
operational and assurance material behind them.

| Document | What it covers |
|----------|----------------|
| [`security/THREAT-MODEL.md`](security/THREAT-MODEL.md) | Assets, adversaries, trust boundaries, STRIDE, attack trees, privacy analysis and accepted risks |
| [`security/SECURITY-ASSESSMENT.md`](security/SECURITY-ASSESSMENT.md) | Review findings, fixes, open items and reproduction steps |
| [`security/CONTROLS-MATRIX.md`](security/CONTROLS-MATRIX.md) | OWASP ASVS 4.0.3 L2, NIST CSF 2.0 and ISO 27001:2022 Annex A evidence, plus the gap register |
| [`security/CASE-STUDY.md`](security/CASE-STUDY.md) | The short version: why the project exists and what the assessment taught |
| [`security/IR-PLAN.md`](security/IR-PLAN.md) | Severity levels, incident playbooks and the tabletop exercise |
| [`security/KEY-MANAGEMENT.md`](security/KEY-MANAGEMENT.md) | Key inventory, rotation, backup and destruction |
| [`security/VULN-MANAGEMENT.md`](security/VULN-MANAGEMENT.md) | Triage SLAs, accepted advisories and the exception process |
| [`security/SUPPLIER-REGISTER.md`](security/SUPPLIER-REGISTER.md) | What Tor, IPFS, payments and base images see, and how to exit |
| [`security/BIA.md`](security/BIA.md) | Recovery targets, the backup plan and the restore drill |
| [`security/PRIVACY.md`](security/PRIVACY.md) | Data map, retention schedule, DPIA-lite and data subject requests |
| [`security/METRICS.md`](security/METRICS.md) | The numbers behind the assurance claims |

## Project policies

| Document | What it covers |
|----------|----------------|
| [`SECURITY.md`](../.github/SECURITY.md) | Disclosure policy, scope, safe harbour and operator hardening |
| [`CONTRIBUTING.md`](../.github/CONTRIBUTING.md) | Development setup, checks and pull request expectations |
| [`CODE_OF_CONDUCT.md`](../.github/CODE_OF_CONDUCT.md) | Community expectations |
| [`CHANGELOG.md`](CHANGELOG.md) | Release history |
