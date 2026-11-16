# Security policy

D1zzy Market is a portfolio project: a pseudonymous peer-to-peer marketplace built to run as
a Tor onion service. I want to hear about security problems, including problems with the
design (threat model, cryptography, privacy properties), not only exploitable bugs.

## Reporting a vulnerability

Report privately through GitHub's advisory form:

<https://github.com/AlasdairDev/project-d1zzy/security/advisories/new>

Please do not open a public issue, pull request or discussion for a suspected vulnerability.
If you run a fork, set `SECURITY_CONTACT` so `/.well-known/security.txt` points at your own
reporting channel.

Include what you can of the following:

1. What the issue is and which security property it breaks.
2. The affected component (`app/core/crypto.py`, the Tor sidecar, a payment webhook, an
   access-control dependency, and so on) plus the version or commit.
3. Steps to reproduce or a proof of concept. Use a throwaway account and demo data.
4. Impact: confidentiality, integrity, availability, anonymity or funds.
5. A suggested fix or mitigation if you have one.

## What to expect

| Stage | Target |
|-------|--------|
| Acknowledgement | within 3 business days |
| Triage and severity | within 10 business days |
| Fix or documented mitigation | critical within 7 days, high within 30, medium within 90 |
| Public disclosure | coordinated, usually 90 days after the fix or by agreement |

I will credit you in the release notes if you want credit. If you would rather stay
anonymous, say so and I will leave your name out.

## Scope

In scope:

* Authentication, session handling and the access model
  (`SUPERADMIN > ADMIN > MODERATOR > VENDOR > USER`).
* The crypto design and its implementations: Ed25519 signatures, X25519 key agreement,
  XChaCha20-Poly1305 sealing, Argon2id passphrase derivation, and the Double Ratchet in
  `app/static/js/ratchet.js` and `app/core/ratchet.py`.
* Signature verification bypass, ciphertext tampering, key substitution.
* CSRF, XSS, CSP bypass, clickjacking, request smuggling, path traversal.
* Payment-flow integrity (Stripe, BTCPay, Monero regtest, PayMongo) and webhook forgery.
* Moderation-authority abuse or gaps in the audit log.
* Anonymity leaks: IP addresses or identifying metadata in logs, the database, IPFS or
  outbound requests.
* Container and Tor configuration in `deploy/docker/`, `deploy/quadlet/` and `deploy/compose/`.

Out of scope:

* Volumetric denial of service, or DoS that ignores the documented rate limits.
* Attacks that need a compromised user device, a malicious browser extension, or a
  compromised Tor guard or exit that goes beyond the documented Tor threat model.
* Social engineering of the maintainer.
* Findings against third-party services (Stripe, BTCPay, Monero, PayMongo, Kubo) that this
  project's integration did not cause.
* The demo accounts and demo passwords shipped for local development. They are not
  credentials for a real deployment.
* Missing hardening headers on a local HTTP dev server. Production behaviour is in
  `../docs/security/CONTROLS-MATRIX.md`.
* Scanner output with no demonstrated impact.

## Safe harbour

I will not pursue legal action for good-faith research that:

* stays inside the scope above,
* uses only accounts and data you own or are authorised to use,
* does not access, change, exfiltrate or keep other people's data,
* does not degrade the service for others, and
* gives me reasonable time to fix the issue before public disclosure.

## Hardening guidance for operators

If you run a deployment based on this project:

* Generate fresh `SECRET_KEY`, `MARKET_KEY` and `SERVER_SIGNING_SEED`. Do not reuse the
  development values. Back up `MARKET_KEY` separately from the database.
* Run `just init-env` on a new deployment. It now rotates the database password as well as
  the application secrets. The app refuses to start in production with the defaults.
* Set `MODE=production` and `COOKIE_SECURE=true` behind HTTPS. Keep the app reachable only
  through the Tor sidecar or a properly terminated TLS proxy.
* Keep IPFS in `--offline` mode. An onion service that joins the public IPFS DHT announces
  its real IP address.
* Use test-mode payment keys until you have done a payment security review. Payouts are
  manual. Stripe Connect is not built.
* Run `just security` and the test suite before deploying, and read
  `../docs/security/SECURITY-ASSESSMENT.md` for the risks I know about and accept.
* Read `../docs/security/IR-PLAN.md` before you need it, and run the restore drill in
  `../docs/security/BIA.md`. A backup you have never restored is a guess.
