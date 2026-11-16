# Trust and safety policy

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Applies to | Every listing, offer, message, rating, report and profile |

D1zzy is a small moderated marketplace. It is pseudonymous and it does not perform identity
verification. That makes clear rules and a predictable enforcement process more important,
not less.

This is the policy I would want a moderator to follow on a bad day. It is deliberately
concrete: what is not allowed, what happens when someone reports it, and how a decision can
be reviewed.

## 1. Prohibited content and conduct

Do not use the service to trade, advertise or facilitate:

- illegal goods or services,
- child sexual abuse material, or any sexual content involving minors,
- stolen data, credentials, malware or exploit kits,
- weapons, explosives or instructions for making them,
- controlled drugs, precursor chemicals or drug paraphernalia,
- human trafficking, sexual services or exploitation,
- counterfeit documents, currency or financial instruments,
- personal data obtained without consent, doxxing or harassment,
- fraud, scams, phishing or payment manipulation,
- content that infringes copyright or trademarks,
- anything that violates applicable law in the operator's jurisdiction.

This list is not exhaustive. Moderators may remove content that creates a safety, legal or
fraud risk even if it is not listed here.

## 2. Abuse taxonomy

| Abuse | What it looks like | First response |
|-------|--------------------|----------------|
| Spam | Repeated listings, keyword stuffing, links to off-platform contact | Remove listings, warn |
| Scam | Fake item, fake payment proof, off-platform payment request | Remove, suspend, preserve evidence |
| Fake reviews | Ring of new accounts rating each other | Remove ratings, suspend accounts |
| Collusion or wash trading | Buyer and seller inflate reputation | Remove ratings, review both accounts |
| Sybil accounts | Many accounts from one operator | Rate limits, vendor review, suspend |
| Harassment | Abusive messages, threats, doxxing | Remove message, suspend |
| Prohibited item | Goods or services in section 1 | Remove, suspend, report where required |
| Payment fraud | Stolen card, chargeback abuse, fake webhook | Disable method, reconcile, suspend |
| Impersonation | Handle or profile that mimics another user | Remove profile, restore handle |
| Ban evasion | New account after suspension | Suspend, apply rate limits |

## 3. Enforcement ladder

1. **Warn.** A written warning with the rule and the required change.
2. **Remove content.** Hide the listing or delete the message.
3. **Restrict selling.** Remove the vendor role.
4. **Suspend.** The account cannot sign in.
5. **Ban.** Permanent removal, with the audit record retained.

Every action requires a reason and writes a row to `moderation_actions`. The table is
append-only at the database level, so an action cannot be quietly edited later.

## 4. Reporting

Users can report a listing, message, offer, rating or profile from the page itself. A report
goes to the moderation queue. The reporter sees a confirmation after the action is taken.

Reports should include the rule that was broken and enough detail to find the content. Do
not include more personal data than necessary.

## 5. Appeals

A suspended user can reply to the notice and ask for a review. The reviewer checks the audit
log, the reported content and the original report. The decision and reason are recorded. A
second review is best effort, not guaranteed.

## 6. Law enforcement

- Require a valid legal request before disclosing account data.
- Disclose the minimum necessary. Content may be sealed, so the operator may not be able to
  read it at all.
- Log the request internally.
- Notify the user unless a law or court order forbids it.
- Never disclose `MARKET_KEY` or user private keys. The server does not hold user private
  keys.

## 7. Child safety

If content appears to involve a minor, do not download, copy or redistribute it. Preserve
the minimum metadata, restrict access, and report to the relevant authority or child
protection hotline. This is a legal obligation in many jurisdictions, not a moderation
choice.

## 8. Transparency

Publish a yearly summary if the service is live: reports received, actions taken, appeals
upheld, law enforcement requests, and any data breaches. A template is in
`docs/policy/TRANSPARENCY-REPORT-TEMPLATE.md`.

## 9. Limits

- No identity verification, so age and jurisdiction checks are limited.
- No automated CSAM detection.
- No 24/7 moderation.
- No escrow for card payments, so disputes are handled by the payment provider.
