# Security controls matrix: D1zzy Market

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-15 |
| Frameworks | OWASP ASVS 4.0.3 (Level 2), NIST Cybersecurity Framework 2.0, ISO/IEC 27001:2022 Annex A |
| Scope | The application in this repository, its containers and its documented deployment |
| Companion | [Threat model](THREAT-MODEL.md), [Security assessment](SECURITY-ASSESSMENT.md) |

Status legend: **implemented**, **partial or compensating**, **planned or accepted**, **N/A**
(not applicable to this design).

This is a self-assessment, and it records gaps on purpose. A controls matrix that claims
100% is a warning sign, not a result worth showing off.

I used this matrix as a gap finder, not a badge. The partial and missing rows are the useful
ones. They show where I had been avoiding work.

---

## 1. OWASP ASVS 4.0.3 (Level 2, selected requirements)

### V1: Architecture, design and threat modelling

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 1.1.1 | Secure SDLC applied | Partial | Threat model, self-assessment, SAST and secret scanning, regression tests. No formal sign-off process |
| 1.1.2 | Threat modelling for each design change | Partial | `docs/security/THREAT-MODEL.md`. Review cadence is documented but not automated |
| 1.2.1 | Unique low-privilege components | Implemented | Separate app, worker, Tor, DB, Redis and IPFS containers (`deploy/compose/podman-compose.yml`, `deploy/quadlet/`) |
| 1.4.1 | Trust boundaries documented | Implemented | `THREAT-MODEL.md` section 4 (TB1 to TB7) |
| 1.5.1 | Input and output separation | Implemented | Jinja autoescaping, no `safe` filter on user data, parameterised ORM |
| 1.5.3 | SSRF protections | Implemented | Outbound destinations are fixed configuration (payment, IPFS, SMTP), not user-controlled |
| 1.9.1 | Communications encryption | Partial | Onion transport plus end-to-end payload crypto. Clearnet is opt-in with HSTS |
| 1.14.1 | Segmented architecture | Partial | Container separation, but a flat Podman network with no service mesh |

### V2: Authentication

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 2.1.1 | Passwords at least 12 characters | Partial | 10 characters enforced in `UserManager.validate_password`. Raise to 12 for strict Level 2 |
| 2.1.2 | Allow long passwords | Implemented | No upper bound. Rejects a password containing the email local part |
| 2.1.7 | Breached-password check | Planned | Not implemented. Needs an offline k-anonymity lookup, which is a privacy trade-off |
| 2.2.1 | Anti-automation controls | Implemented | Auth endpoints limited to 5/min, registration 5/min, reset 3/min (`RateLimitMiddleware`) |
| 2.2.2 | Weak authenticator notice | Planned | No password strength meter |
| 2.3.1 | Reset uses a secure token | Implemented | fastapi-users signed tokens with `SECRET_KEY`, one hour expiry |
| 2.5.1 | Password change requires current password | Implemented | fastapi-users reset and change flows |
| 2.7.1 | Authenticator binding | Implemented | JWT audience `fastapi-users:auth`. Refresh uses a separate audience |
| 2.8.1 | Time-based OTP | N/A | No MFA. This is a pseudonymous marketplace |

### V3: Session management

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 3.1.1 | No session token in URL | Implemented | Tokens only in cookies |
| 3.2.1 | Tokens from a CSPRNG | Implemented | `secrets` and PyJWT HS256 with `SECRET_KEY`. CSRF uses `secrets.token_urlsafe` |
| 3.3.1 | Logout invalidates the session | Implemented | Access and refresh cookies cleared (`RefreshingCookieTransport.get_logout_response`) |
| 3.3.2 | Session timeout | Implemented | Access 15 minutes, refresh 7 days, silent refresh (`RefreshMiddleware`) |
| 3.3.3 | Idle and absolute timeout | Partial | Absolute timeouts exist. No configurable idle timeout |
| 3.4.1 | Cookie attributes | Implemented | HttpOnly, SameSite=Lax, `Secure` when `COOKIE_SECURE=true` |
| 3.5.1 | Stateless tokens use a signature | Implemented | HS256, `jwt.decode` with an explicit algorithm allowlist |
| 3.5.3 | Token revocation | Partial | No server-side denylist. Short access lifetime limits exposure. `OLD_JWT_SECRET` and `ADDITIONAL_JWT_SECRETS` support rotation |
| 3.7.1 | Defensive session handling | Implemented | Refresh only when access is absent or invalid. Activity is re-checked by fastapi-users |

### V4: Access control

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 4.1.1 | Least privilege | Implemented | SUPERADMIN > ADMIN > MODERATOR > VENDOR > USER. `is_admin` is strictly ADMIN |
| 4.1.2 | Centralised access control | Implemented | All checks flow through `app/api/deps.py` dependencies |
| 4.1.3 | Server-side enforcement | Implemented | Dependencies run on the server. Nothing relies on the client |
| 4.2.1 | CSRF protection | Implemented | Signed double-submit cookie, header or form field, `csrf_protect` on every state-changing route |
| 4.2.2 | CSRF tokens are per-session and validated | Implemented | HMAC-signed nonce and timestamp, `hmac.compare_digest`, max age |
| 4.3.1 | Admin interface requires admin | Implemented | `current_admin` and `current_superadmin`. Admin CRUD is SUPERADMIN-only |
| 4.3.2 | Directory browsing disabled | Implemented | No static directory listing. Starlette `StaticFiles` only |
| 4.3.3 | Sensitive functionality uses MFA | Planned | Not implemented |

### V5: Validation, sanitisation and encoding

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 5.1.1 | Positive input validation | Implemented | Pydantic schemas with length and format constraints |
| 5.1.3 | Validation at the trust boundary | Implemented | API schemas and route dependencies |
| 5.1.4 | Structured data is strongly typed | Implemented | Typed payloads. Sealed blobs are base64 with strict decoding (`crypto.b64d`) |
| 5.2.1 | Sanitisation on output | Implemented | Jinja autoescaping. CSP blocks inline script |
| 5.3.3 | ORM and parameterised queries | Implemented | SQLAlchemy async. No string-built SQL |
| 5.3.4 | Parameterised queries | Implemented | Same |
| 5.4.1 | Object-level authorisation | Implemented | Ownership checks on listings, offers, messages and saved items |
| 5.5.1 | Safe deserialisation | Implemented | JSON only. No pickle, YAML or eval. Sealed JSON is AEAD-authenticated |
| 5.5.2 | No eval or dynamic code | Implemented | CSP forbids `unsafe-eval`. Alpine CSP build. No `eval` in `app/static/js` |

### V6: Stored cryptography

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 6.1.1 | Documented cryptographic inventory | Implemented | `README.md` security model, `app/core/crypto.py` docstring, `THREAT-MODEL.md` section 2 |
| 6.2.1 | Approved algorithms | Implemented | Ed25519, X25519, XChaCha20-Poly1305, Argon2id, BLAKE2b, SHA-256 HMAC |
| 6.2.2 | Approved modes and parameters | Implemented | AEAD only. 24-byte random nonce. Argon2id interactive limits |
| 6.2.3 | Unique IV or nonce | Implemented | `os.urandom(24)` per seal |
| 6.2.4 | CSPRNG | Implemented | `os.urandom` and `secrets`. No `random` for security values |
| 6.3.1 | Random values are unpredictable | Implemented | Same |
| 6.4.1 | Keys generated securely | Implemented | Client Ed25519 from an Argon2id-derived seed. Server keys from env or `openssl rand` |
| 6.4.2 | Key storage | Partial | Client keys never leave the browser. `MARKET_KEY` and `SERVER_SIGNING_SEED` live in env. No HSM or KMS |
| 6.4.3 | Key rotation | Partial | JWT rotation is supported. `MARKET_KEY` rotation requires re-encryption, documented in the README |

### V7: Error handling and logging

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 7.1.1 | No sensitive data in error responses | Implemented | Generic HTML error page, JSON `detail` for APIs, no stack traces |
| 7.1.2 | No sensitive data in logs | Implemented | No IPs, query strings, tokens or plaintext |
| 7.2.1 | No secrets in logs | Implemented | Security events log booleans, not values (`csrf_rejected`) |
| 7.3.1 | Security events logged | Partial | `csrf_rejected`, `authz_denied` and request logs. No SIEM or alerting pipeline |
| 7.3.3 | Audit log integrity | Partial | Moderation actions are append-only by convention. No WORM or remote log sink |
| 7.4.1 | Generic error messages | Implemented | Custom exception handlers |

### V8: Data protection

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 8.1.1 | Sensitive data inventory | Implemented | `THREAT-MODEL.md` section 2 (A1 to A11) |
| 8.1.2 | Data retention | Partial | Offers can expire. No automated retention or deletion policy for all data |
| 8.2.1 | No sensitive data in browser storage | Implemented | Keys and ratchet state are held in memory. The passphrase is never persisted |
| 8.3.1 | Sensitive data not in URLs | Implemented | No tokens in query strings |
| 8.3.4 | Data encrypted at rest | Implemented | Listings, offers, ratings and images are sealed. DB and disk encryption are operator controls |
| 8.3.7 | Data encrypted in transit | Partial | Onion transport. Clearnet requires HSTS and TLS termination |

### V9: Communication security

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 9.1.2 | Strong TLS for clearnet | Partial | HSTS in production. TLS is terminated by the operator's proxy and is not bundled |
| 9.1.3 | No mixed content | Implemented | CSP `default-src 'self'`. No third-party origins |
| 9.2.1 | Server-to-server encryption | Implemented | HTTPS to Stripe, BTCPay and PayMongo. Local containers share a private network |

### V10: Malicious code

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 10.1.1 | Code integrity | Partial | Vendored JS is version-pinned but not SRI-checked at runtime. Reproducible builds pending |
| 10.2.1 | Third-party libraries are current | Partial | `uv.lock` is pinned. pip-audit has open findings blocked upstream (see assessment) |
| 10.3.1 | Dependency inventory and SBOM | Partial | `uv.lock` is a complete lockfile. No CycloneDX artefact yet |

### V11: Business logic

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 11.1.1 | Business logic security | Implemented | Offer state machine, ownership checks, payment status only set by webhooks or the worker |
| 11.1.2 | Anti-automation | Implemented | Per-path rate limits |
| 11.1.4 | Sequential processing | Implemented | Offer transitions are validated. No double-pay path in the UI |

### V12: Files and resources

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 12.1.1 | File size limits | Implemented | 5 MB request and upload cap (`RequestSizeMiddleware`, `max_upload_bytes`) |
| 12.2.1 | Content-type validation | Implemented | `IMAGE_MIMES` allowlist in `app/schemas/listing.py` |
| 12.3.1 | User files not executed | Implemented | Images are served as decrypted media, not script. CSP `object-src 'none'` |
| 12.4.1 | File storage outside webroot | Implemented | Ciphertext lives in IPFS and is proxied by the app |
| 12.5.1 | Path traversal protection | Implemented | Uploads never use a client-supplied path. Data is sealed and addressed by CID, not filename |

### V13: API and web service

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 13.1.1 | Same controls on APIs | Implemented | Shared dependencies and middleware for HTML and JSON |
| 13.2.1 | JSON schema validation | Implemented | Pydantic models |
| 13.3.1 | Content-type enforcement | Implemented | FastAPI and Pydantic. Multipart is handled explicitly |
| 13.4.1 | Authorisation on every API route | Implemented | `current_user` and role dependencies, plus regression tests |

### V14: Configuration

| Req | Requirement | Status | Evidence and note |
|-----|-------------|--------|-------------------|
| 14.1.1 | Repeatable build | Implemented | `pyproject.toml` and `uv.lock`. `just dev` or podman-compose |
| 14.2.1 | Dependency management | Partial | Locked and audited. Open advisories upstream |
| 14.2.2 | Unused dependencies removed | Implemented | Ruff `F401` is clean after the assessment |
| 14.3.1 | Debug disabled in production | Implemented | OpenAPI and docs only when `MODE=development` |
| 14.3.2 | No default credentials | Partial | Demo seed accounts exist in dev. Production guidance says do not seed |
| 14.4.1 | Security headers | Implemented | CSP, HSTS in production, X-Frame-Options, nosniff, Referrer-Policy, COOP/CORP/COEP, Permissions-Policy |
| 14.5.1 | Allowed HTTP methods | Implemented | Routes declare methods. CSRF applies to state-changing verbs |
| 14.5.3 | CSP | Implemented | No `unsafe-inline` or `unsafe-eval`. `wasm-unsafe-eval` only for libsodium |

---

## 2. NIST Cybersecurity Framework 2.0

| Function | Category | How D1zzy addresses it | Evidence |
|----------|----------|------------------------|----------|
| GV: Govern | GV.OC, GV.RM, GV.PO | Security policy, disclosure policy, accepted-risk register | `.github/SECURITY.md`, `THREAT-MODEL.md` section 8 |
| | GV.RR, GV.OV | Self-assessment with owners and a review cadence | `SECURITY-ASSESSMENT.md` |
| | GV.SC | Supply chain: lockfile, pip-audit, gitleaks, pinned vendored JS | `uv.lock`, `scripts/security_scan.sh` |
| ID: Identify | ID.AM | Asset inventory, data-flow diagram, container inventory | `THREAT-MODEL.md` sections 1 and 2 |
| | ID.RA | Threat model, STRIDE, attack trees, risk register | `THREAT-MODEL.md` sections 5 to 8 |
| | ID.IM | Improvement through findings and a remediation roadmap | `SECURITY-ASSESSMENT.md` |
| PR: Protect | PR.AA | Authentication, least privilege, RBAC, session controls | `app/api/deps.py`, `app/core/security.py` |
| | PR.AT | Operator hardening guidance and demo warnings | `.github/SECURITY.md`, README |
| | PR.DS | Encryption in transit and at rest, data minimisation | `app/core/crypto.py`, IPFS offline |
| | PR.PS | Secure configuration, change management, dependency control | `pyproject.toml`, `deploy/compose/podman-compose.yml` |
| | PR.IR | Resilience: queues, health checks, restart policies | `deploy/compose/podman-compose.yml`, `justfile` |
| DE: Detect | DE.CM | Request logging, authorisation and CSRF denial events, health checks | `SecurityHeadersMiddleware`, `deps.audit_denied` |
| | DE.AE | Static and dynamic analysis, secret scanning, dependency audit | `just security`, CI workflow |
| RS: Respond | RS.MA | Vulnerability disclosure and triage | `.github/SECURITY.md` |
| | RS.AN | Severity model and evidence requirements | `SECURITY-ASSESSMENT.md` section 2 |
| | RS.MI | Fixes for every high-severity SAST and runtime bug found | `SECURITY-ASSESSMENT.md` section 3 |
| RC: Recover | RC.RP | Backups (documented `MARKET_KEY` backup), restart policies | README, `.github/SECURITY.md` |
| | RC.CO | Coordinated disclosure and credit | `.github/SECURITY.md` |

---

## 3. ISO/IEC 27001:2022 Annex A (applicable themes)

| Control | Theme | Status | Evidence and note |
|---------|-------|--------|-------------------|
| A.5.7 | Threat intelligence | Partial | Feed-based advisories through pip-audit and OSV. No formal threat-intel programme |
| A.5.9 | Inventory of assets | Implemented | `THREAT-MODEL.md` section 2 and `SUPPLIER-REGISTER.md` |
| A.5.12 | Classification of information | Implemented | Data map and retention schedule in `PRIVACY.md` |
| A.5.15 | Access control | Implemented | RBAC and server-side dependencies |
| A.5.24 | Incident management planning | Partial | `IR-PLAN.md` has severity levels and playbooks. No 24/7 team |
| A.5.25 | Assessment and decision on incidents | Partial | Severity model exists. No live incidents yet |
| A.5.26 | Response to incidents | Partial | Playbooks exist but have not been exercised |
| A.5.27 | Learning from incidents | Partial | Post-incident review is required. No completed review yet |
| A.5.28 | Collection of evidence | Partial | Evidence rules in `IR-PLAN.md`. No remote log sink |
| A.5.34 | Privacy and PII protection | Partial | `PRIVACY.md` and manual data subject process. Deletion is not automated |
| A.5.17 | Authentication information | Implemented | Argon2id and bcrypt hashes, no plaintext, reset tokens |
| A.5.23 | Cloud service security | Partial | Self-hosted containers. Operator responsibility is documented |
| A.5.29 | Disruption during an incident | Partial | Restart policies and queues. No formal business continuity plan |
| A.6.3 | Awareness and training | Partial | README and security docs. No formal training record |
| A.8.2 | Privileged access rights | Implemented | SUPERADMIN and ADMIN separation. Admin CRUD is guarded |
| A.8.3 | Information access restriction | Implemented | Object-level checks and role dependencies |
| A.8.5 | Secure authentication | Implemented | Password policy, JWT audiences, cookie flags |
| A.8.6 | Capacity management | Partial | Rate limits and queues. No autoscaling |
| A.8.7 | Protection against malware | Partial | No executable uploads. Vendored JS is pinned. CSP |
| A.8.8 | Technical vulnerability management | Implemented | pip-audit, Bandit, Semgrep, gitleaks, CI |
| A.8.9 | Configuration management | Implemented | Compose and quadlet plus env. `init-env` generates secrets |
| A.8.10 | Information deletion | Partial | Offer expiry and a manual runbook in `PRIVACY.md`. No automated deletion |
| A.8.11 | Data masking | Implemented | Public handles instead of email, ciphertext at rest |
| A.8.12 | Data leakage prevention | Partial | No IP logging, no third-party origins. No DLP tooling |
| A.8.13 | Information backup | Partial | Backup plan and RTO/RPO in `BIA.md`. Restore drill not run |
| A.8.15 | Logging | Implemented | Structured request and security logs without sensitive data |
| A.8.16 | Monitoring activities | Partial | Logs exist. No alerting or SIEM |
| A.8.20 | Network security | Implemented | Tor-first exposure, offline IPFS, container network |
| A.8.21 | Security of network services | Implemented | Payment APIs over HTTPS. No third-party web assets |
| A.8.23 | Web filtering | N/A | The server does not browse the web |
| A.8.24 | Use of cryptography | Implemented | Documented inventory and approved primitives |
| A.8.25 | Secure development lifecycle | Partial | Threat model, tests and scanning. No formal gate sign-off |
| A.8.26 | Application security requirements | Implemented | ASVS Level 2 matrix (this document) |
| A.8.28 | Secure coding | Implemented | Lint clean, code review, typed schemas |
| A.8.29 | Security testing in development | Implemented | 95 test functions, 27 of them security regressions |
| A.8.32 | Change management | Partial | No formal change board. CI checks run on pull requests |
| A.8.33 | Test information | Implemented | Ephemeral testcontainers and throwaway accounts |
| A.8.34 | Protection of systems during audit | N/A | Self-assessment. No external auditors |

---

## 4. Evidence index

| Artefact | Location |
|----------|----------|
| Threat model | `docs/security/THREAT-MODEL.md` |
| Security assessment | `docs/security/SECURITY-ASSESSMENT.md` |
| Incident response plan | `docs/security/IR-PLAN.md` |
| Key management | `docs/security/KEY-MANAGEMENT.md` |
| Vulnerability management | `docs/security/VULN-MANAGEMENT.md` |
| Supplier register | `docs/security/SUPPLIER-REGISTER.md` |
| Business impact and recovery | `docs/security/BIA.md` |
| Privacy assessment | `docs/security/PRIVACY.md` |
| Assurance metrics | `docs/security/METRICS.md` |
| Trust and safety policy | `docs/policy/TRUST-AND-SAFETY.md` |
| User security guide | `docs/guides/USER-SECURITY-GUIDE.md` |
| Disclosure policy | `.github/SECURITY.md` |
| Security regression tests | `tests/security/` |
| Static, dependency and secret scan | `scripts/security_scan.sh`, `just security` |
| CI security workflow | `.github/workflows/security.yml` |
| Secret-scanning rules | `.gitleaks.toml` |
| Full test suite | `tests/` (`just test-fast`) |
| Dependency lockfile | `uv.lock` |

---

## 5. Gap register and roadmap

| ID | Gap | Framework ref | Target |
|----|-----|---------------|--------|
| G1 | Upgrade `fastapi-users` to drop its exact pins on vulnerable `pyjwt` and `python-multipart` | ASVS 14.2.1, A.8.8 | Next dependency window |
| G2 | Upgrade FastAPI and Starlette past the current advisory window | ASVS 14.2.1 | Next major upgrade |
| G3 | Add a server-side JWT denylist or shorten access tokens to 5 minutes or less | ASVS 3.5.3 | Before any production use |
| G4 | Add a password breach check (offline k-anonymity) or a strength meter | ASVS 2.1.7, 2.2.2 | Nice to have |
| G5 | Generate a CycloneDX SBOM in CI | ASVS 10.3.1, A.8.8 | Next CI change |
| G6 | Add SRI or reproducible builds for vendored JS | ASVS 10.1.1 | Before production |
| G7 | Add alerting for bursts of `authz_denied` and `csrf_rejected` | CSF DE.CM, A.8.16 | Operations milestone |
| G8 | Formal data-retention and account-deletion workflow | ASVS 8.1.2, A.8.10 | Product milestone |
