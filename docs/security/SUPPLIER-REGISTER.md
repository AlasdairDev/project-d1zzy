# Supplier and third-party register

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Review | Every new integration and twice a year |

D1zzy depends on infrastructure and payment providers outside this repository. This is the
list of what each one sees, how critical it is, and what happens if it fails or changes.

A dependency is still part of the system even when it is not in the repo. This register is
how I keep track of what leaves the project and what I would have to replace.

Criticality: **high** means the service stops or user data is exposed. **Medium** means a
feature degrades. **Low** means an optional convenience.

| Supplier | Service | Data shared | Criticality | Assurance | Exit |
|----------|---------|-------------|-------------|-----------|------|
| Tor network | Onion transport | Traffic metadata at the network layer. The app does not log IPs | High | Public protocol, widely reviewed. No contract or SLA | None. The design depends on it |
| Kubo IPFS | Encrypted blob store | Ciphertext, CIDs, sizes. No plaintext | High | Local container, offline mode. No external DHT | Export CIDs and re-add to another store |
| PostgreSQL | Primary database | Accounts, ciphertext, metadata, audit log | High | Local container, standard backups | `pg_dump` and restore |
| Redis | Queue, pub/sub, rate limits | Conversation ids and queue payloads. No plaintext messages | Medium | Local container, private network, no password | The app degrades to polling and fails open on limits |
| Stripe | Card payments | Email, amount, currency, offer metadata. No card data reaches the app | High | PCI DSS provider, hosted Checkout, signed webhooks | Disable Stripe, reconcile open sessions |
| BTCPay Server | Bitcoin and Lightning | Invoice id, amount, order metadata | Medium | Self-hosted, signed webhooks | Disable BTCPay, keep invoices in the dashboard |
| Monero daemon and wallet RPC | XMR payments | Addresses, amounts, subaddress index | Medium | Self-hosted regtest or node, no third party | Disable Monero, export the wallet |
| PayMongo | Local payment methods | Email, amount, payment intent metadata | Medium | Provider contract, signed webhooks | Disable PayMongo |
| SMTP provider (Mailpit locally) | Verification and notification email | Email address, message text | Medium | Local Mailpit in dev. Production provider not bundled | Disable email, verification becomes manual |
| PyPI and `uv` | Python packages | Package names and versions, no user data | High | Lockfile, hashes, pip-audit | Vendor the wheel set or use an internal mirror |
| Container base images | Runtime | None at build time | High | Official images, tags. Digest pinning is planned | Rebuild from a different base |
| GitHub Actions | CI | Source code, build logs. No production secrets | Medium | Pinned actions are planned. Least-privilege `GITHUB_TOKEN` | Run the same commands locally |
| ngrok (optional) | Clearnet tunnel for demos | Traffic if enabled. Off by default | Low | Disable in production. Documented as optional | Remove the container |
| CDN or fonts | None | The app self-hosts fonts and scripts | n/a | No third-party origin is allowed by CSP | n/a |

## Data processing notes

- The app does not send message plaintext, listing plaintext or user keys to any supplier.
- Payment providers see the identity and amount needed to process a payment. That is the
  main link between a pseudonymous account and a payment instrument.
- IPFS is kept offline. Joining the public DHT would announce the server's real IP address.
- No analytics, no third-party fonts, no CDN.

## Production requirements not met here

This is a portfolio project, so there are no signed data processing agreements, no vendor
security questionnaires and no right-to-audit clauses. A real deployment needs them for
every high-criticality supplier, especially payments and hosting.

## Review checklist

- Did the supplier change its data handling or subprocessors?
- Is the integration still using the least data necessary?
- Are webhook secrets rotated and signatures verified?
- Is there a tested exit path?
- Is the supplier in the threat model and the controls matrix?
