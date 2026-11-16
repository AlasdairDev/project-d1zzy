# Case study: a marketplace that does not trust its own server

I built D1zzy Market to answer a question I kept running into in privacy and security work:
what does a marketplace look like if the operator cannot read what users post?

I care about information assurance because the hard part is not adding a control. It is
proving the control does what it says, and being honest when it does not.

The usual answer is "trust us, we encrypt at rest". That is useful against a stolen backup,
but it does nothing against the operator, a subpoena, or a server compromise. So I made the
server the wrong place to look.

## The design bet

Listings, offers and ratings are sealed in the browser with XChaCha20-Poly1305 under a
marketplace key. The key lives on the server so the app can render pages, but the database
never holds plaintext on its own. Every write carries an Ed25519 signature from the user's
identity key, and the browser checks those signatures when it reads content back. Chat uses a
Double Ratchet, so the server relays bytes it cannot open. Images are sealed with a per-image
key that lives inside the encrypted listing. IPFS runs offline, because an onion service that
joins the public DHT announces its real IP address.

No-JS users get a plain HTML fallback. It is encrypted at rest, signed by the server on the
user's behalf, and labelled "not end-to-end encrypted" in the UI. Pretending otherwise would
be worse than the fallback itself.

## What the review found

I treated the project as an assessment target instead of a demo. I wrote a threat model with
assets, adversaries and trust boundaries, mapped controls to OWASP ASVS 4.0.3 Level 2, NIST
CSF 2.0 and ISO 27001:2022 Annex A, and ran Ruff, Bandit, pip-audit and gitleaks over the
tree.

The code was in worse shape than the README suggested. Lint went from 163 findings to zero.
Bandit found MD5 in a placeholder generator and a world-writable temp path. Two security
paths had latent `NameError`s: vendor approval used `UserRole` without importing it, and
PayMongo webhook verification called `json.loads` without importing `json`. Both would have
failed at runtime, not at review time.

The most useful finding was a middleware called `RequestSanitizationMiddleware`. It claimed
to sanitise form and JSON bodies and passed every request through unchanged. That is worse
than having no middleware, because a reviewer sees the name and assumes a control exists. I
deleted it and wrote down the layers that actually do the work: parameterised SQLAlchemy
queries, Jinja autoescaping, a strict CSP, and Pydantic validation at the boundary. A regex
sanitiser over every request body would also have corrupted the base64 ciphertext the market
stores.

I also deleted three modules nothing imported, including a validation helper module that only
its own tests used. Dead code with tests looks like coverage until you check who calls it.

## Where it stands

The suite is 95 tests, 94 passing and one Monero regtest test skipped by default. Twenty-seven
of those are security regressions covering headers, CSRF, RBAC, Ed25519, AEAD, JWT handling
and the request-size cap. `just security` runs Ruff, Bandit, pip-audit and gitleaks; the CI
workflow runs the same checks plus Semgrep.

Some risks are still open. `fastapi-users` exact-pins `pyjwt==2.10.1` and
`python-multipart==0.0.20`, and FastAPI caps Starlette below 0.47, so pip-audit reports
advisories I cannot remove without an upstream release or a reviewed override. I documented
the compensating controls and put the upgrade in the gap register instead of quietly
suppressing the scanner. Rate limiting also fails open if Redis disappears, and there is no
JWT denylist yet. Those are written down as accepted risks with a target date, not as
footnotes.

## What I took from it

A security claim is only worth something if someone else can check it. That means a threat
model with named assets, controls with evidence, tests that fail when a property breaks, and
an honest list of what is still weak. Deleting a fake control was more valuable than adding
another one.

## Short version

I built D1zzy Market as a personal project: a small marketplace prototype where chat is
end-to-end encrypted, listings are signed in the browser, and images are encrypted before
they are stored. It is not a live service. Then I reviewed it the way I would review
someone else's code.

The review took Ruff from 163 findings to zero, removed a "sanitisation" middleware that did
nothing, and found two `NameError`s on security paths. I wrote a threat model, mapped the
controls to OWASP ASVS Level 2, NIST CSF 2.0 and ISO 27001, and added 27 security regression
tests. The login libraries still have a few open warnings. I documented them with the controls
I already had instead of hiding them.

The biggest lesson was that a control which only exists in a class name is worse than no
control at all.
