#!/usr/bin/env bash
# Security assurance scan: lint, SAST, dependency audit, secret scan, optional Semgrep.
#
#   scripts/security_scan.sh            # report; exit non-zero on high-severity findings
#   scripts/security_scan.sh --strict   # also fail on Semgrep findings and lint errors
#
# Tools are used from .venv, PATH, or uvx in that order. Missing optional tools are skipped
# with a clear message rather than silently passing.
set -uo pipefail
cd "$(dirname "$0")/.."

STRICT=0
[[ "${1:-}" == "--strict" ]] && STRICT=1

fail=0
ran=0
skipped=()

bold() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
ok() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=1; }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; skipped+=("$1"); }

have() { command -v "$1" >/dev/null 2>&1; }
venv_bin() { [[ -x ".venv/bin/$1" ]]; }

# --- Lint ---------------------------------------------------------------------------------
bold "Ruff (lint)"
if venv_bin ruff; then
  .venv/bin/ruff check app tests alembic && ok "ruff" || { [[ $STRICT -eq 1 ]] && bad "ruff" || skip "ruff findings (run with --strict to fail)"; }
elif have uv; then
  uv run --frozen ruff check app tests alembic && ok "ruff" || { [[ $STRICT -eq 1 ]] && bad "ruff" || skip "ruff findings"; }
else
  skip "ruff (not installed)"
fi

# --- Python SAST: Bandit -------------------------------------------------------------------
bold "Bandit (SAST, high severity)"
bandit_cmd=()
if venv_bin bandit; then bandit_cmd=(.venv/bin/bandit)
elif have bandit; then bandit_cmd=(bandit)
elif have uvx; then bandit_cmd=(uvx --from 'bandit[toml]' bandit)
fi
if [[ ${#bandit_cmd[@]} -gt 0 ]]; then
  ran=$((ran + 1))
  if "${bandit_cmd[@]}" -q -r app -c pyproject.toml -lll; then
    ok "bandit: no high-severity findings"
  else
    bad "bandit: high-severity findings"
  fi
else
  skip "bandit (run: uv sync --extra security)"
fi

# --- Dependency CVEs ------------------------------------------------------------------------
bold "pip-audit (dependency CVEs)"
audit_cmd=()
if venv_bin pip-audit; then audit_cmd=(.venv/bin/pip-audit)
elif have pip-audit; then audit_cmd=(pip-audit)
elif have uvx; then audit_cmd=(uvx pip-audit)
fi
if [[ ${#audit_cmd[@]} -gt 0 ]]; then
  ran=$((ran + 1))
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  audit_failed=0
  if have uv && uv export --frozen --no-dev --no-hashes --format requirements-txt -o "$tmp" >/dev/null 2>&1; then
    "${audit_cmd[@]}" -r "$tmp" --progress-spinner off || audit_failed=1
  else
    "${audit_cmd[@]}" --progress-spinner off || audit_failed=1
  fi
  if [[ $audit_failed -eq 0 ]]; then
    ok "pip-audit: no known vulnerabilities"
  elif [[ $STRICT -eq 1 ]]; then
    bad "pip-audit: known vulnerabilities (see docs/security/SECURITY-ASSESSMENT.md)"
  else
    skip "pip-audit advisories (non-strict; see docs/security/SECURITY-ASSESSMENT.md)"
  fi
else
  skip "pip-audit (run: uv sync --extra security)"
fi

# --- Secret scan ----------------------------------------------------------------------------
bold "gitleaks (secret scan)"
if have gitleaks; then
  ran=$((ran + 1))
  if gitleaks detect --source . --config .gitleaks.toml --no-git --redact --exit-code 1; then
    ok "gitleaks: no secrets found"
  else
    bad "gitleaks: potential secrets found"
  fi
else
  skip "gitleaks (brew install gitleaks)"
fi

# --- Semgrep (opt-in; downloads rules) ------------------------------------------------------
if [[ "${SECURITY_SEMGREP:-0}" == "1" ]]; then
  bold "Semgrep (pattern-based SAST)"
  semgrep_cmd=()
  if have semgrep; then semgrep_cmd=(semgrep)
  elif have uvx; then semgrep_cmd=(uvx semgrep)
  fi
  if [[ ${#semgrep_cmd[@]} -gt 0 ]]; then
    ran=$((ran + 1))
    if "${semgrep_cmd[@]}" --config p/python --config p/secrets --error --quiet app; then
      ok "semgrep"
    else
      [[ $STRICT -eq 1 ]] && bad "semgrep findings" || skip "semgrep findings (non-strict)"
    fi
  else
    skip "semgrep (pipx install semgrep)"
  fi
else
  skip "semgrep (set SECURITY_SEMGREP=1 to enable)"
fi

# --- Summary --------------------------------------------------------------------------------
bold "Summary"
echo "  tools that ran: $ran"
if [[ ${#skipped[@]} -gt 0 ]]; then printf '  skipped: %s\n' "${skipped[*]}"; fi
if [[ $fail -ne 0 ]]; then
  echo "  result: FAIL"
  exit 1
fi
echo "  result: PASS"
