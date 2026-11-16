# Privacy assessment and retention

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Type | Lightweight DPIA and records of processing |
| Review | Before adding a data field, integration or retention change |

D1zzy is built to collect as little as possible. This is what it still holds, why, for how
long, and what a user can ask for.

The privacy work is easy to describe and harder to prove. This document is the part I can
point at when someone asks what the server can actually see.

## 1. Data map

| Data | Why | Where | Visible to | Retention |
|------|-----|-------|------------|-----------|
| Email address | Login, verification, password reset | PostgreSQL, plaintext | Server operator, moderators with database access | Until account deletion |
| Password hash | Authentication | PostgreSQL, Argon2id or bcrypt | Nobody | Until account deletion |
| Handle | Public pseudonym | PostgreSQL, public pages | Everyone | Until account deletion |
| Role and flags | Access control | PostgreSQL | Server operator | Until account deletion |
| Public keys | Signature and key verification | PostgreSQL, public on profile | Everyone | Until account deletion |
| Listing plaintext | Marketplace content | PostgreSQL, sealed with `MARKET_KEY` | Anyone who can reach the site (listings are public) | Until deletion or account removal |
| Offer plaintext | Price and terms | PostgreSQL, sealed | Buyer, seller, server operator | Until offer expiry plus retention |
| Rating plaintext | Reputation | PostgreSQL, sealed | Everyone | Until deletion |
| Messages, ratchet mode | Chat | PostgreSQL, ciphertext only | The two participants. Server cannot read | Until conversation deletion |
| Messages, server mode | No-JS fallback | PostgreSQL, sealed with `MARKET_KEY` | Participants and server operator | Until conversation deletion |
| Reported messages | Moderation | PostgreSQL, plaintext copy after report | Moderators | 12 months, then review |
| Reports | Trust and safety | PostgreSQL | Moderators | 12 months |
| Moderation audit | Accountability | PostgreSQL, append-only | Moderators, operator | 24 months |
| Listing views | Basic analytics | PostgreSQL, `ip_hash` optional | Operator | 90 days |
| Payment ids and amounts | Payment reconciliation | PostgreSQL and provider | Operator, provider | 7 years if tax law requires |
| Logs | Operations and security | stdout, no IPs or query strings | Operator | 30 days |

## 2. What is not collected

- No IP address in application logs.
- No third-party analytics, fonts or scripts.
- No device fingerprint.
- No precise location. `location_approx` is user supplied.
- No plaintext chat in ratchet mode.
- No card data. Stripe Checkout hosts the payment page.

## 3. Purposes and basis

The service processes data to provide the marketplace, to keep it safe and to meet payment
and tax obligations. In GDPR terms, the bases are contract performance for account and
transaction data, legitimate interests for security and abuse prevention, and legal
obligation for payment records. This is a portfolio project, not legal advice.

## 4. User rights

| Right | How to exercise it | Current state |
|-------|--------------------|---------------|
| Access and export | Request by email from the account address | Manual. No self-service export yet |
| Correction | Edit the profile | Implemented |
| Deletion | Request account deletion | Manual. No automated workflow yet |
| Restriction | Ask the operator to suspend the account | Manual |
| Objection | Ask the operator to stop a processing activity | Manual |
| Complaint | Contact the operator, then a supervisory authority | Not applicable to the demo |

Because accounts are pseudonymous, the operator may ask for a signature or another proof
before acting on a request. Do not ask for more identity data than needed.

## 5. Retention schedule

| Category | Retention | Trigger |
|----------|-----------|---------|
| Active account data | Until deletion request | User request |
| Closed account data | 30 days, then delete | Account closure |
| Reports and reported content | 12 months | Report closure |
| Moderation audit | 24 months | Action date |
| Payment records | 7 years | Transaction date |
| Application logs | 30 days | Log rotation |
| Listing views | 90 days | View date |
| Backups | 30 daily, 12 monthly | Backup date |

The audit log is append-only, so deletion requests cannot remove moderation records before
their retention period. That limitation is disclosed.

## 6. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Email links a pseudonym to a real person | Medium | Medium | Email is not shown publicly. Optional email is a product change, not built |
| Payment provider links identity to a purchase | High | Medium | Documented. Crypto methods reduce the link. No card data on the server |
| Metadata in a database dump | Medium | Medium | Content is sealed. Handles, timestamps and audit rows remain |
| Reported message plaintext stays after resolution | Medium | Medium | Retained 12 months, then reviewed. Access limited to moderators |
| No automated deletion | High | Medium | Manual runbook today. Tracked as gap G8 |
| Backup contains data past retention | Medium | Medium | Backup retention matches the schedule. Old backups must be destroyed |
| IP hash can be brute forced | Low | Low | Salted hash, optional, 90-day retention |

## 7. Data subject request runbook

1. Verify the request came from the account email.
2. Identify the account by handle, not by asking for more identity data.
3. Export the account row, listings, offers, ratings and messages if access is requested.
4. For deletion, remove or anonymise content, then delete the account row.
5. Keep the audit row and payment records for their retention period.
6. Reply within 30 days and record the request without storing extra data.

## 8. Gaps

- No automated export or deletion.
- No self-service privacy dashboard.
- No signed data processing agreements with payment providers.
- No formal records-of-processing register beyond this file.
