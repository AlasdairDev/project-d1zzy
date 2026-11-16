# Business impact and recovery

| | |
|---|---|
| Version | 1.0 |
| Date | 2026-11-16 |
| Owner | Project maintainer |
| Review | Quarterly, and after any schema or infrastructure change |

This is the recovery plan for a small self-hosted deployment. It sets recovery targets and
explains how to restore the service. The targets are not a commercial SLA.

I wrote it because "restore from backup" is not a plan. The useful part is knowing what to
do first, and what has to be true before the site comes back.

## 1. Impact by asset

| Asset | Loss impact | RTO | RPO | Notes |
|-------|-------------|-----|-----|-------|
| Application and UI | Users cannot browse, trade or message | 1 hour | n/a | Stateless containers, rebuild from image |
| PostgreSQL | Accounts, listings, offers, ratings, messages, audit log | 2 hours | 24 hours | Daily `pg_dump` at minimum. Hourly is better |
| `MARKET_KEY` | All sealed content becomes unreadable | 0 | 0 | Must never be lost. Back up separately |
| Tor onion key | The `.onion` address changes | 4 hours | 24 hours | Users must learn the new address |
| IPFS blobs | Listing images disappear | 24 hours | 24 hours | Ciphertext only. Re-uploading requires users |
| Redis | Queues, pub/sub and rate limits fail | 15 minutes | n/a | The app degrades but stays up |
| Payment state | Orders show the wrong status | 4 hours | 1 hour | Reconcile from provider dashboards |
| Audit log | Loss of accountability evidence | 0 | 0 | Append-only trigger protects against edits, not disk loss |
| User identity keys | Users lose access to their identity | n/a | n/a | Browser only. No recovery by design |

## 2. Backup plan

| Item | Method | Frequency | Retention | Where |
|------|--------|-----------|-----------|-------|
| PostgreSQL | `pg_dump --format=custom` | Daily | 30 daily, 12 monthly | Encrypted, off host |
| `MARKET_KEY` and `SERVER_SIGNING_SEED` | Sealed archive in a password manager | On change | Life of the data | Separate from the database |
| Tor onion key | Copy of the `torkeys` volume, encrypted | On change | Life of the service | Off host |
| `.env` | Password manager | On change | Until rotation | Off host |
| IPFS | Rebuildable from the database and user uploads | n/a | n/a | Do not rely on it as a backup |

Encrypt every backup with `age` or GPG before it leaves the host. A database dump contains
ciphertext for content but plaintext for handles, timestamps, payment identifiers and the
audit log.

## 3. Restore procedure

1. Stop the app and worker so nothing writes during the restore.
2. Restore the database into a scratch instance first:
   `pg_restore --clean --if-exists --dbname="$DATABASE_URL" backup.dump`.
3. Check row counts for `users`, `listings`, `offers`, `messages` and `moderation_actions`.
4. Decrypt one listing, one offer and one message with the restored `MARKET_KEY`.
5. Point the app at the restored database, start it, and check `/healthz`.
6. Sign in as a test account, open a listing, send a message and load the moderation page.
7. Record the restore time and any data loss in the drill log below.

## 4. Drill log

| Date | What was tested | Restore time | Data loss | Follow-up |
|------|-----------------|--------------|-----------|-----------|
| Not run yet | Full database restore | n/a | n/a | This is a gap. Run it before claiming recovery readiness |

The first drill should use a copy of the development stack. Do not test on the only copy of
real data.

## 5. Degradation modes

| Failure | Behaviour | User impact |
|---------|-----------|-------------|
| Redis down | Queue and pub/sub unavailable. Rate limits fail open | Chat falls back to polling, background jobs stop |
| IPFS down | Image upload and media reads fail | Listings still work without images |
| Payment provider down | That method is disabled or errors | Other methods still work |
| Database down | The app returns errors | Full outage |
| Tor sidecar down | The onion address is unreachable | Clearnet only, if configured |
| `MARKET_KEY` missing | Sealed content cannot be opened | Full content outage |

## 6. Gaps

- No automated backup job in this repository. The operator must schedule it.
- No tested restore yet. This is the largest recovery gap.
- No off-site replication.
- No `MARKET_KEY` rotation or escrow tooling.
- Recovery targets are best effort, not contractual.
