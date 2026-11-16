# Security assessment: D1zzy Market

| | |
|---|---|
| Assessment ID | D1Z-SEC-2026-11 |
| Date | 2026-11-15 |
| Assessor | Project maintainer (self-assessment) |
| Type | Code review, threat modelling, SAST, dependency and secret audit, targeted exploit reasoning |
| Scope | `app/`, `tests/`, `scripts/`, `deploy/docker/`, `deploy/compose/`, `deploy/quadlet/`, configuration defaults |
| Out of scope | A live deployed instance, third-party payment providers, Tor network internals, physical security, social engineering |
| Classification | Public (portfolio artefact) |

> This is a self-assessment, not a third-party audit. It records what I found, what I fixed,
> and what I accepted. The point is evidence, not a clean-sheet claim.

---

## 1. Summary

D1zzy is a small marketplace I built. It does not ask users to trust the server with their
content. Listings, offers and ratings are sealed client-side, writes are signed with per-user
Ed25519 keys, and chat uses a Double Ratchet. During the assessment I checked that those
properties are enforced in code and covered by tests.

The review also found real defects, which was the useful part:

* two latent `NameError`s on security-relevant paths (vendor approval and PayMongo webhook
  verification),
* a high-severity SAST finding for MD5 use, which was not security-sensitive but should not
  have been there,
* a placeholder request-sanitisation middleware that did nothing while suggesting a control
  existed,
* duplicate imports and definitions, and a loop variable bug that made review harder.

All of those are fixed, and regression tests now cover the properties that matter. Dependency
advisories remain open because `fastapi-users` exact-pins vulnerable versions of `pyjwt` and
`python-multipart`. That risk is recorded with compensating controls instead of being hidden.

| Metric | Before | After |
|--------|--------|-------|
| Ruff findings | 163 | 0 |
| Bandit high severity | 1 (MD5) | 0 |
| Bandit medium severity | 1 (`/tmp` write) | 0 |
| Undefined names (`F821`) | 2 | 0 |
| Shadowed definitions (`F811`) | 19 | 0 |
| Unused variables (`F841`) | 4 | 0 |
| Security regression tests | 0 | 27 |
| Full test suite | 67 | 95 (94 run, 1 Monero skip) |
| Secrets detected | 2 (local `.env`, gitignored) | 0 under the documented policy |
| Dependency advisories | Multiple | Open and tracked (upstream pins) |

---

## 2. Method

1. Design review. I read the README security model, `app/core/crypto.py`,
   `app/core/security.py`, `app/api/deps.py`, `app/core/market.py`, the payment clients and
   the Tor and Podman configuration.
2. Threat modelling. STRIDE per trust boundary, an asset inventory, attack trees and a
   LINDDUN-style privacy pass. Output: [THREAT-MODEL.md](THREAT-MODEL.md).
3. Static analysis. Ruff, Bandit (high and medium), Semgrep (optional in `just security`).
4. Dependency and secret scanning. pip-audit against the exported production requirements,
   and gitleaks over the working tree with a reviewed allowlist.
5. Targeted verification. I wrote executable tests for each security claim: headers, CSRF,
   signatures, RBAC, cookies, JWT, AEAD, request size and base64 parsing.
6. Manual reasoning. I looked for reachable exploit paths and did not attempt live
   exploitation of third-party services.

### Tool versions

| Tool | Version |
|------|---------|
| Python | 3.12 |
| Ruff | as locked in `uv.lock` |
| Bandit | 1.9.4 |
| pip-audit | 2.10.1 |
| gitleaks | installed locally |
| pytest | 8.4.2 |

### Severity model

Severity combines likelihood and impact, with a CVSS v3.1 base score estimate where a
network-reachable defect exists. Critical means remote compromise without authentication.
High means significant impact on confidentiality, integrity or funds. Medium means limited
impact or a requirement for privileged access. Low means defence-in-depth or hygiene. Info
means a documented property or an accepted design trade-off.

---

## 3. Findings

### 3.1 Fixed during this assessment

#### DA-01: Undefined `UserRole` breaks vendor approval (Medium, fixed)

* Location: `app/api/routes/moderation.py`, `approve_vendor()`.
* Issue: `target.role = UserRole.VENDOR` used `UserRole` without importing it (Ruff `F821`).
  Any call to the approve-vendor endpoint would raise `NameError`, return a 500 and leave the
  application pending.
* Impact: the moderation workflow failed every time. This was not privilege escalation, but
  it was a reliable denial of a security-relevant function.
* Evidence: Ruff `F821 Undefined name 'UserRole'`.
* Fix: added `UserRole` to the import from `app.models`.
* Verification: the full suite passes, and the moderation tests exercise vendor approval.

#### DA-02: Undefined `json` breaks PayMongo webhook verification (Medium, fixed)

* Location: `app/core/paymongo.py`, webhook verification.
* Issue: the function called `json.loads(payload)` without `import json` (`F821`).
* Impact: PayMongo webhooks failed, so payment state could drift from the provider and orders
  could appear unpaid or paid when they were not.
* Fix: added `import json`.
* Verification: lint is clean, and the payment paths import successfully.

#### DA-03: Dead placeholder module had MD5 and an unbound variable (Low, fixed then removed)

* Location: `app/core/placeholder.py`.
* Issue: Bandit `B324` flagged MD5 in `_hash_to_int()`, and the `"concentric"` branch of
  `_build_pattern()` used `step` before assigning it. The hash only picked a colour and
  pattern, so MD5 was not a real cryptographic risk, but it did not belong in a security
  codebase.
* Fix: replaced MD5 with BLAKE2b and defined `step` in the branch. A later usage scan found
  that nothing imported the module, so I deleted it rather than keep dead code with tests.
* Verification: `bandit -lll` reports no high-severity findings.

#### DA-04: No-op sanitisation middleware gave false assurance (Low, fixed)

* Location: `app/core/security.py`, `app/main.py`.
* Issue: `RequestSanitizationMiddleware` claimed to sanitise form and JSON bodies but passed
  every request through unchanged. It also imported helpers that nothing used. One helper
  had an unbound `Any` annotation in its fallback path.
* Risk: reviewers and future maintainers could believe an injection control existed when it
  did not. A real regex sanitiser on every body would also corrupt the base64 ciphertext the
  marketplace stores.
* Fix: removed the middleware and its imports. Documented the layers that actually do the
  work: parameterised ORM queries, Jinja autoescaping, a strict CSP and Pydantic validation.
  Added regression tests for the properties that matter. The unused `app/core/sanitize.py`
  module went too, once nothing outside its own tests imported it.
* Verification: `tests/security/test_security.py::test_security_headers_are_strict` plus the CSRF and
  request-size tests.

#### DA-05: Duplicate `page_user` definition (Low, fixed)

* Location: `app/api/deps.py`.
* Issue: `page_user` was defined twice, and the second definition silently replaced the first
  (`F811`). No behaviour change at the time, but a maintenance hazard.
* Fix: removed the duplicate and added audit logging to the remaining guards.
* Verification: lint is clean and the auth tests pass.

#### DA-06: Shadowed imports, unused variables and a loop bug (Low, fixed)

* Location: `app/api/routes/discussions.py`, `listings.py`, `social.py`.
* Issue: 19 shadowed definitions (`F811`), 4 unused variables (`F841`), one loop variable
  overriding its iterable (`B020`) and a `raise` without `from` (`B904`). Two computed values
  (`user_vote`, `details_ct`) were calculated and then ignored.
* Fix: removed duplicate imports, used the computed values, renamed the loop variable and
  added `from None`. Using the computed values also removed a duplicate DB query and a
  duplicate AEAD seal.
* Verification: `ruff check app tests alembic` passes and the full suite passes.

#### DA-07: Security event logging was missing for denials (Low, fixed)

* Location: `app/api/deps.py`, `app/core/security.py`.
* Issue: CSRF rejections and authorisation denials were not recorded as security events,
  which made detection harder.
* Fix: added `csrf_rejected` and `authz_denied` structured logs. They record the path, rule
  and user id, and never tokens, query strings or IPs.
* Verification: code review. The events use the existing structlog pipeline.

### 3.2 Open or accepted

#### DA-08: `fastapi-users` pins vulnerable dependencies and has its own advisory (Medium, open, blocked upstream)

* Evidence: `importlib.metadata.requires("fastapi-users")` returns `pyjwt[crypto]==2.10.1`
  and `python-multipart==0.0.20` (exact pins), while the OSV feed reports advisories fixed in
  newer releases. pip-audit also reports `PYSEC-2026-1363` against `fastapi-users` 14.0.2
  itself, fixed in 15.0.2.
* Impact: depends on the advisory. The app uses HS256 JWTs with a strong secret and short
  access lifetimes, caps uploads at 5 MB, and stores ciphertext only.
* Compensating controls: JWT algorithm allowlist, separate audiences, 15-minute access tokens,
  5 MB request cap, CSRF on writes and no user-controlled file writes.
* Remediation: upgrade `fastapi-users` to 15.0.2 or later. That release should remove the
  exact pins as well. If it does not, add a reviewed `[tool.uv] override-dependencies` entry
  and re-run the full suite plus pip-audit.
* Tracking: gap G1 in the controls matrix.

#### DA-09: Starlette advisories blocked by FastAPI's `<0.47` constraint (Medium, open)

* Evidence: installed `fastapi 0.115.14` requires `starlette>=0.40.0,<0.47.0`. The advisories
  against `0.46.2` are fixed in the 1.x line.
* Impact: advisory-specific. I did not demonstrate an exploit in this app.
* Remediation: plan a FastAPI major upgrade, then re-run the full suite and the security scan.
  Tracked as gap G2.

#### DA-10: Rate limiting fails open if Redis is unavailable (Low, accepted)

* Location: `RateLimitMiddleware`.
* Rationale: availability wins, and auth endpoints can also be limited at the reverse proxy.
  Documented as R8 in the threat model.

#### DA-11: Anonymous Tor traffic shares a single rate-limit bucket (Low, accepted by design)

* Rationale: all anonymous requests appear to come from the Tor container. This is
  back-pressure, not a boundary. Authenticated users get per-user buckets.

#### DA-12: No server-side JWT denylist (Low, accepted for the demo)

* Rationale: access tokens last 15 minutes and refresh tokens 7 days. Logout clears the
  cookies, but a stolen token stays valid until it expires. Add a denylist or shorten access
  tokens before a real deployment (gap G3).

#### DA-13: The server sees no-JS message plaintext (Info, documented)

* Rationale: this is unavoidable in the no-JS fallback. The UI labels those messages as not
  end-to-end encrypted, and the threat model says so directly.

#### DA-14: No prekey server, so the first message lacks forward secrecy (Info, documented)

* Rationale: the first shared secret comes from static identity keys and the conversation id.
  Forward secrecy starts at the first DH ratchet step. A prekey server is future work.

#### DA-15: CSP allows `'wasm-unsafe-eval'` (Info, accepted)

* Rationale: libsodium's WebAssembly needs it. `'unsafe-eval'` and `'unsafe-inline'` stay
  forbidden, and Alpine uses its CSP build.

#### DA-16: Demo data is seeded by default (Low, accepted for development)

* Rationale: `SEED_DEMO_DATA=true` in the example environment, with `mod@d1zzy.local` and a
  known password. Production guidance says not to seed and to generate fresh secrets. A
  production deployment should fail closed when demo seeding is on. That is a future
  hardening item.

#### DA-17: `.env` contains locally generated secrets (Info, policy documented)

* Rationale: `.env` is gitignored. gitleaks scans the working tree with `--no-git`, and the
  local `.env` is allowlisted because a developer machine needs one. CI scans git history,
  where `.env` must never appear. The exception is deliberate and documented.

### 3.3 Hardening added after the assessment

The assessment is a point in time. A later pass closed several gaps that the review found
but did not fix immediately:

- **Chat safety numbers.** Both users can compare a 60-digit fingerprint of the two identity
  keys over another channel. This gives them a way to detect a key swap by the server.
- **Append-only audit log.** A database trigger rejects `UPDATE`, `DELETE` and `TRUNCATE` on
  `moderation_actions`. The old guarantee was a convention.
- **Production configuration guard.** The app refuses to start in production with
  `change-me`, an empty `MARKET_KEY`, the default database password, demo seeding or
  insecure cookies. `just init-env` now rotates the database password too.
- **Upload magic-byte checks.** The no-JS image path no longer trusts the browser's
  `Content-Type`.
- **`/.well-known/security.txt`.** A machine-readable disclosure contact.
- **Tor proof-of-work and stream limits.** The onion service now uses Tor's PoW defences and
  caps concurrent streams.
- **Container hardening.** The app and worker run with no new privileges, no capabilities, a
  read-only root filesystem, and PID and memory limits.
- **Assurance documents.** Incident response, key management, vulnerability management,
  supplier register, business impact, privacy, trust and safety, user guidance and metrics
  are now written down and linked from the README.
- **Repository hygiene.** License, contributing guide, code of conduct, changelog, issue
  templates and pull request template.

These changes are covered by `tests/security/` where they are testable.

---

## 4. What the review confirmed

* Content confidentiality does not trust the server. AEAD and signatures are checked in the
  browser and on write, and tampering is detectable
  (`test_aead_roundtrip_and_tamper_detection`, `test_ed25519_tamper_detection`).
* Browser hardening is strict. The CSP has no inline or eval, and the app sends
  `frame-ancestors 'none'`, `nosniff`, `no-referrer`, COOP/CORP/COEP, Permissions-Policy and
  HSTS in production (`test_security_headers_are_strict`).
* CSRF has real coverage. The token is a signed double-submit value with a constant-time
  comparison and an expiry, and it is accepted from a header or a form field (`test_csrf_*`).
* RBAC is centralised and tested. SUPERADMIN and ADMIN are separate, nobody can promote
  themselves to SUPERADMIN, and admin CRUD is guarded
  (`test_admin_management_requires_superadmin`, `test_cannot_promote_to_superadmin`).
* Privacy is built in. There is no IP logging, no third-party origin, IPFS runs offline,
  public handles replace emails, and search stays local when JS is on.
* Passwords are hashed, not stored. fastapi-users uses Argon2id or bcrypt, and a test checks
  the value at rest (`test_password_is_hashed_at_rest`).
* Moderation is accountable. Every action needs a reason and writes an audit row, which is
  part of the TB5 controls in the threat model.

---

## 5. Verification evidence

### 5.1 Test suite

```text
$ just test-fast
...
95 tests collected; 94 passed, 1 skipped (Monero, SKIP_MONERO_TESTS=1)
```

The security regression modules contribute 27 tests:

```text
tests/security/ ........................... (27 passed)
```

### 5.2 Lint and SAST

```text
$ ruff check app tests alembic
All checks passed!

$ bandit -q -r app -c pyproject.toml -lll
# no output, zero high-severity findings
```

### 5.3 Security scan

```text
$ just security
== Ruff (lint) ==                    PASS
== Bandit (SAST, high severity) ==   PASS (no high-severity findings)
== pip-audit (dependency CVEs) ==    SKIP advisories (open and tracked; pass with --strict)
== gitleaks (secret scan) ==         PASS (no leaks found)
== Summary ==
  result: PASS
```

`--strict` makes lint, dependency advisories and Semgrep findings fatal. Use it on release
branches once the upstream pins have been upgraded.

### 5.4 Reproduction

```bash
# Everything except the roughly 40 second Monero multisig test
just test-fast

# Lint, SAST, dependency audit and secret scan
just security

# The same, failing on advisories and Semgrep findings
just security --strict

# Full suite, including the real Monero regtest multisig test
just test
```

---

## 6. Limitations

* There was no live penetration test against a public deployment. The assessment is based on
  code and tests.
* I did not fuzz the parsers or the Double Ratchet.
* There was no independent cryptographic review.
* Dependency advisories are a point-in-time OSV snapshot. CI re-checks weekly.
* The Tor threat model is bounded by Tor. A global passive adversary is out of scope.
* Operational controls such as host patching, firewalling, secret management and backups are
  the operator's job. They are documented here, not implemented.

---

## 7. Remediation roadmap

| Priority | Item | Finding or gap | Target |
|----------|------|----------------|--------|
| 1 | Upgrade `fastapi-users` to a release that drops the exact pins | DA-08, G1 | Next dependency window |
| 2 | Upgrade FastAPI and Starlette | DA-09, G2 | Next major upgrade |
| 3 | Add a JWT denylist or 5-minute access tokens | DA-12, G3 | Before production |
| 4 | Fail closed if demo seeding is enabled in production | DA-16 | Before production |
| 5 | Alert on bursts of `authz_denied` and `csrf_rejected` | G7 | Operations milestone |
| 6 | CycloneDX SBOM and SRI for vendored JS | G5, G6 | Next CI change |
| 7 | Data-retention and account-deletion workflow | G8 | Product milestone |

---

## 8. Conclusion

The core security claims hold up under review and are now pinned by tests. The most useful
change was deleting a control that only pretended to exist, writing down the layers that
really protect the app, and recording the dependency risk instead of hiding it. The project
now has an assurance argument that someone else can check, which is more useful than a list
of features.
