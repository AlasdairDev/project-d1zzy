# Changelog

All notable changes to this project are recorded here. The format follows Keep a Changelog,
and the project uses semantic versioning once it reaches 1.0.

## Unreleased

### Added

- Chat safety numbers so two users can compare key fingerprints out of band.
- Append-only database trigger for the moderation audit log.
- Magic-byte validation for no-JS image uploads.
- `/.well-known/security.txt`.
- Tor proof-of-work defences and stream limits on the onion service.
- Container hardening for the app and worker: no new privileges, no capabilities, read-only
  root, PID and memory limits.
- Production configuration guard that rejects development secrets and the default database
  password.
- Incident response, key management, vulnerability management, supplier register, business
  impact, privacy, trust and safety, and user security documents.
- Contributor guide, code of conduct, issue templates and pull request template.
- Screenshots of the main pages under `docs/screenshots/`, captured from the seeded demo data.

### Changed

- `just init-env` now rotates `POSTGRES_PASSWORD` and rewrites `DATABASE_URL`.
- Deployment files moved under `deploy/`, fonts under `scripts/assets/`, and tests under
  `tests/security/` and `tests/integration/`.
- Compose files grouped under `deploy/compose/`, the user guide moved to `docs/guides/`,
  and `docs/README.md` added as a documentation index.
- Community health files moved into `.github/` and the changelog into `docs/`, leaving the
  repository root with only project configuration, the README and the licence.
- Added `.dockerignore` so local secrets, virtualenvs and test data never enter the build
  context.
- Expanded `.gitignore` to cover env variants, private keys, certificates, local databases,
  backups, logs, editor files and local compose overrides.
- Replaced the placeholder security contact with GitHub private advisories and made the
  `security.txt` contact configurable via `SECURITY_CONTACT`.
- Clarified the public case-study summary so it matches the design: public content is signed
  and sealed at rest, while private chat is end-to-end encrypted.
- The demo and buyer flow are Philippines-only: prices in PHP, GCash, Maya, card or bank
  transfer through PayMongo, and cash on delivery as the default.
- Price formatting uses the peso sign in both server-rendered pages and client-side search
  results. The new-listing form defaults to PHP.
- Removed the last Stripe, Lightning and Monero copy from the home page and vendor
  dashboard; both now describe PayMongo and cash on delivery.

### Fixed

- Removed a sanitisation middleware that did nothing.
- Fixed two latent `NameError`s in vendor approval and PayMongo webhook verification.
- Removed unused modules and stale session notes.
- Chat now starts the ratchet after unlocking keys; the conversation config is read once in
  `init` instead of through a stale method binding.
- Signed forms fall back to a native POST when no keys are unlocked, so reporting, offers and
  listings still work with JavaScript on and no passphrase.
- Form field macros now close their wrapper elements, fixing the new-listing grid and other
  multi-column forms.
- Seed assigns the documented vendor and moderator roles, so `mod@d1zzy.local` can open the
  moderation queue.
- Rebuilt the icon subset after the payment settings gained GCash, Maya, card and delivery
  icons.

## 0.1.0

Initial portfolio release: Tor-first marketplace, client-side sealing and signatures, Double
Ratchet chat, payment integrations, moderation audit log and security documentation.
