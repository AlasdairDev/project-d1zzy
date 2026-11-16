# Key and secret management

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Applies to | The application, the worker, the Tor sidecar and local development |

The design puts user identity keys in the browser. The server keeps a smaller set of keys
for content sealing, JWT signing and the no-JS fallback. This is the key inventory. It says
what each key does, where it lives, how it is rotated and what happens if it leaks.

Keys are the part of the design I least wanted to get wrong. Most of the security model
falls apart if one of them is stored, logged or rotated in the wrong way.

## 1. Inventory

| Key | Purpose | Storage | Rotation | If it leaks |
|-----|---------|---------|----------|-------------|
| `SECRET_KEY` | Signs JWTs and CSRF tokens, and fastapi-users tokens | `.env`, container environment | Restart with a new value. Old tokens fail unless `OLD_JWT_SECRET` is set | Anyone can mint sessions. Rotate immediately and invalidate sessions |
| `OLD_JWT_SECRET` | Validates tokens during a JWT rotation window | `.env` | Remove after the refresh window (7 days) | Same as `SECRET_KEY` |
| `ADDITIONAL_JWT_SECRETS` | Comma-separated keys accepted during rotation | `.env` | Remove after the window | Same as `SECRET_KEY` |
| `MARKET_KEY` | Seals listing, offer and rating blobs at rest | `.env`, container environment | No automated rotation. Requires re-encryption | All sealed content can be read. Same for image keys inside listings |
| `SERVER_SIGNING_SEED` | Signs writes made through the no-JS fallback | `.env`, container environment | New seed changes the server public key. Old server-signed content will no longer verify as server-signed | Anyone can forge server-signed content |
| User signing and exchange keys | Author and decrypt user content | Browser only, derived from the passphrase with Argon2id | User generates a new identity in settings | The user's content can be forged or read. The server cannot revoke a browser key |
| Tor onion service key | The `.onion` address | Podman volume `torkeys` | Generate a new hidden service. The address changes | The attacker can impersonate the onion address |
| Database password | App to PostgreSQL | `.env` and `DATABASE_URL` | `just init-env` generates a random one. Change it manually on an existing deployment | Database access, limited by network exposure |
| Payment API and webhook secrets | Stripe, BTCPay, PayMongo | `.env` | Provider dashboard, then restart | Payment forgery or refund abuse |
| SMTP credentials | Verification and notification email | `.env` | Provider dashboard | Email abuse |
| Redis | Queue and pub/sub | No password, private container network | n/a | Queue manipulation if the network is reached |

## 2. Rules

- Never commit `.env`. It is gitignored and gitleaks scans the tree.
- Back up `MARKET_KEY` separately from the database. A database backup without the key is
  useless, and a key backup without the database is useless.
- Do not put keys in shell history. `just init-env` writes them straight to `.env`.
- Do not reuse development keys in production. `Settings.assert_production_safe()` refuses
  to start in production with the defaults.
- Keep the number of people with access to `.env` at one.

## 3. JWT rotation

1. Generate a new secret.
2. Move the current value to `OLD_JWT_SECRET`.
3. Set the new value as `SECRET_KEY`.
4. Restart the app and worker.
5. After the refresh token lifetime, remove `OLD_JWT_SECRET`.

`ADDITIONAL_JWT_SECRETS` exists for accepting several keys during a longer rollout. Remove
old values once the window closes.

## 4. `MARKET_KEY` rotation

There is no automated rotation script yet. This is a real gap, and it is tracked in
`IR-PLAN.md` and `SECURITY-ASSESSMENT.md`.

The safe manual procedure today:

1. Take a database backup and verify that it restores into a scratch database.
2. Take the service offline so no new blobs are written.
3. Generate a new key with `openssl rand -base64 32`.
4. Re-encrypt each blob from the old key to the new key in one transaction per table:
   `listings.listing_ct`, `offers.offer_ct`, `ratings` ciphertext, and any other sealed
   column.
5. Update `MARKET_KEY`, start the service, and verify one listing, one offer and one rating
   from each mode.
6. Keep the old key offline until the backup retention period ends.

Until this is scripted and tested, restoring a pre-exposure backup is safer than a manual
rewrite.

## 5. `SERVER_SIGNING_SEED`

The seed derives the server signing key. Rotating it changes the public key served at
`/api/market-key`. Content signed by the old server key will verify only as invalid unless
the old public key is retained, which the app does not do today.

If the seed leaks:

1. Generate a new seed.
2. Restart the app and worker.
3. Expect old no-JS content to show as invalid or unverified. That is the honest outcome.
4. Tell users that server-signed content from before the rotation cannot be trusted.

## 6. User keys

- The passphrase is stretched with Argon2id in the browser. The server sees only public
  keys.
- There is no key escrow and no recovery. A lost passphrase means a lost identity.
- The UI now shows safety numbers so two users can detect a key swap.
- A user who suspects key substitution should compare safety numbers over another channel
  and stop using the conversation until they match.

## 7. Backups and destruction

| Item | Backup | Retention | Destruction |
|------|--------|-----------|-------------|
| PostgreSQL | `pg_dump`, encrypted before it leaves the host | 30 days daily, 12 months monthly | Shred or delete per the retention schedule |
| `MARKET_KEY` | Separate sealed copy, offline | Life of the data | Destroy only after the last ciphertext is gone |
| Tor onion key | Encrypted copy | Life of the service | Destroy with the service |
| `.env` | Password manager or sealed archive | Rotate on staff change | Delete old copies |

Encrypt backups with `age` or GPG before storing them off the host. A database dump is
ciphertext for content but plaintext for handles, timestamps and payment identifiers.

## 8. Gaps

- No HSM or KMS. Keys live in environment variables.
- No automated `MARKET_KEY` rotation.
- No scripted backup and restore drill.
- No key ceremony or dual control. This is a single-maintainer project.
