# Incident response plan

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Scope | The application, its containers, the onion service and the data stores in this repository |
| Review | After every incident and at least twice a year |

This plan is for a single-maintainer portfolio project. It is deliberately short enough to
use, and it names the gaps instead of pretending there is a 24/7 team behind it.

An incident plan that only exists in my head is not a plan. This one is written down so I
can follow it when I am tired and something is on fire.

## 1. Roles

| Role | Who | Responsibility |
|------|-----|----------------|
| Incident commander | Maintainer | Owns the timeline, decisions and communication |
| Technical lead | Maintainer | Contains, eradicates and recovers |
| Scribe | Maintainer | Keeps the timeline and evidence log |
| Legal and privacy | External advice | Only when user data or law enforcement is involved |

One person fills every role today. That is a known limitation and a reason to keep the
playbooks short.

## 2. Severity

| Level | Examples | Target response | Target fix |
|-------|----------|-----------------|------------|
| SEV1 | `MARKET_KEY` or `SECRET_KEY` exposed, database exfiltration, admin takeover, payment keys leaked, onion private key leaked | Immediate | Contain first, fix within 24 hours |
| SEV2 | Authentication bypass, stored XSS, CSRF bypass, signature verification bypass, moderator account takeover | Within 4 hours | 7 days |
| SEV3 | Rate-limit bypass, information disclosure with limited impact, dependency advisory with a reachable path | Within 1 business day | 30 days |
| SEV4 | Hygiene issue, documentation error, low-impact scanner finding | Within 5 business days | 90 days |

## 3. Lifecycle

1. **Detect.** A report through `.github/SECURITY.md`, a CI failure, a dependency advisory, a user
   report or an anomaly in the logs.
2. **Triage.** Assign a severity, write down what is known, and decide whether to contain.
3. **Contain.** Stop the bleeding before finding the root cause. Rotate keys, disable a
   route, block a session, stop a container or take the service offline.
4. **Eradicate.** Fix the defect, add a regression test, and check for the same pattern
   elsewhere.
5. **Recover.** Restore from a known-good backup, verify integrity, and watch the logs.
6. **Review.** Write a post-incident note within five business days. Record what worked,
   what did not, and which control or document changes.

## 4. Evidence

- Preserve the relevant logs and the container state before restarting or deleting anything.
- The application does not log IP addresses or query strings, so network attribution will be
  limited. That is a privacy feature and an investigation cost.
- Record times in UTC. Keep the timeline in a private file, not in a public issue.
- Do not copy plaintext messages, keys or payment data into the incident record.

## 5. Playbooks

### 5.1 `MARKET_KEY` exposure

1. Treat every listing, offer and rating blob as readable. Assume image keys are readable
   too.
2. Take the service offline or disable reads that return ciphertext.
3. Generate a new `MARKET_KEY`.
4. Re-encrypt stored blobs. There is no automated rotation script yet, so this is a manual
   database operation with a tested backup. Until that exists, restoring from a backup taken
   before the exposure is the safer path.
5. Rotate `SERVER_SIGNING_SEED` if it was stored with the key.
6. Tell users what was exposed. Do not claim the content was safe.

### 5.2 Database or backup exfiltration

1. Confirm what was taken. Content is sealed, but handles, timestamps, payment identifiers
   and the audit log are not.
2. Rotate the database password and `SECRET_KEY`, and invalidate sessions.
3. Check for writes or logins you cannot explain.
4. If `MARKET_KEY` was in the same backup, follow 5.1.

### 5.3 Moderator or admin takeover

1. Disable the account and revoke its sessions.
2. Review `moderation_actions` for actions taken by that account. The table is append-only,
   so the record should be intact.
3. Check reports resolved by that account and restore any content that was hidden.
4. Require a fresh login and, if possible, a fresh device for the replacement account.

### 5.4 Payment webhook forgery

1. Disable the affected payment method by clearing its secret.
2. Compare provider dashboards with offer statuses.
3. Rotate the webhook secret.
4. Reconcile every offer touched in the window. Do not mark anything paid without a
   provider-side record.

### 5.5 Onion private key compromise

1. Assume the onion address is burned. Do not reuse it.
2. Generate a new hidden service key and publish the new address.
3. Keep the old service offline so users cannot be served by the attacker.
4. Tell users how to verify the new address.

## 6. Communication

- Security reports: reply within three business days, as stated in `.github/SECURITY.md`.
- Users: publish a short notice with what happened, what was exposed, what they should do,
  and what changed. No marketing language.
- Payment providers: follow their incident process if keys or transaction data are involved.
- Regulators or law enforcement: only with legal advice.

## 7. Tabletop exercise

Run one scenario per quarter and record the result here.

| Date | Scenario | What was learned | Change made |
|------|----------|------------------|-------------|
| Not run yet | `MARKET_KEY` exposure | No tested rotation path | Tracked as a gap |

Suggested first exercise: a leaked `MARKET_KEY` with no rotation script. It will expose the
missing tooling immediately.

## 8. Known gaps

- No on-call rotation, paging or 24/7 coverage.
- No automated `MARKET_KEY` rotation.
- No remote, immutable log sink.
- No pre-agreed legal or privacy advisor.
- No tested backup restore yet. See `BIA.md`.
