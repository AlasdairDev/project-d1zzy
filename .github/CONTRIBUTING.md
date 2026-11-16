# Contributing

Thanks for taking a look. This is a portfolio project, but the same rules apply as any
security-sensitive codebase.

## Before you start

- Read `../README.md` and `../docs/security/THREAT-MODEL.md`. The design is unusual on purpose.
- For a suspected vulnerability, follow `SECURITY.md`. Do not open a public issue.
- For anything that changes a trust boundary, a key, a payment flow or an access check,
  open a discussion first.

## Development

```bash
just init-env
just sync
just dev
```

The stack runs on Podman. `just test-fast` skips the Monero regtest test; `just test` runs
everything.

## Checks

```bash
just lint
just fmt
just test-fast
just security
```

`just security --strict` is for release branches. It fails on dependency advisories and
Semgrep findings.

## Style

- Ruff handles formatting and lint. Do not fight it.
- Keep route handlers thin. Put shared domain logic in `app/core/` or a service module.
- Add a test for every security property you touch.
- Do not add comments that restate the code. Explain why, not what.
- No em dashes in comments or docs. Use a colon, a comma or a full stop.

## Pull requests

- One change per pull request.
- Describe the risk and how you verified the fix.
- Update the relevant document in `../docs/security/` if a control or risk changed.
- Never commit `.env`, keys, tokens or real user data.
