# Project D1zzy Market. Run `just` to list recipes.
set shell := ["bash", "-euo", "pipefail", "-c"]

compose := "podman-compose -f deploy/compose/podman-compose.yml"
btcpay := "podman-compose -f deploy/compose/podman-compose.yml -f deploy/compose/btcpay.yml --profile btcpay"
podman_sock := "unix:///run/user/" + `id -u` + "/podman/podman.sock"

# List recipes
default:
    @just --list --unsorted

# --- Setup ------------------------------------------------------------------------------

# Create .env from .env.example with fresh random secrets (never overwrites an existing .env)
init-env:
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -f .env ]; then echo ".env exists, leaving it alone"; exit 0; fi
    cp .env.example .env
    sed -i "s|^SECRET_KEY=.*|SECRET_KEY=$(openssl rand -base64 32)|" .env
    sed -i "s|^MARKET_KEY=.*|MARKET_KEY=$(openssl rand -base64 32)|" .env
    sed -i "s|^SERVER_SIGNING_SEED=.*|SERVER_SIGNING_SEED=$(openssl rand -base64 32)|" .env
    db_password=$(openssl rand -hex 24)
    db_user=$(sed -n "s/^POSTGRES_USER=//p" .env | head -1)
    db_name=$(sed -n "s/^POSTGRES_DB=//p" .env | head -1)
    db_user=${db_user:-d1zzy}
    db_name=${db_name:-project_d1zzy_market}
    sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$db_password|" .env
    sed -i "s|^DATABASE_URL=.*|DATABASE_URL=postgresql+asyncpg://${db_user}:${db_password}@db:5432/${db_name}|" .env
    echo "wrote .env (back up MARKET_KEY: without it, stored listings cannot be decrypted)"

# Resolve and pin Python dependencies (uv.lock)
lock:
    uv lock

# Install Python deps (incl. dev) into .venv
sync:
    uv sync --extra dev

# Re-subset the Material Symbols icon font to the icons used in templates/JS (run after adding an icon)
icons:
    uv run python scripts/subset_icons.py

# Re-download vendored JS (HTMX, Alpine CSP build, Fuse) and rebuild the libsodium bundle (needs npm)
vendor:
    #!/usr/bin/env bash
    set -euo pipefail
    v=app/static/vendor; mkdir -p "$v"
    curl -fsSL -o $v/htmx.min.js "https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js"
    curl -fsSL -o $v/alpine.min.js "https://cdn.jsdelivr.net/npm/@alpinejs/csp@3.14.1/dist/cdn.min.js"
    curl -fsSL -o $v/fuse.min.js "https://cdn.jsdelivr.net/npm/fuse.js@7.0.0/dist/fuse.min.js"
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    (cd "$tmp" && npm init -y >/dev/null && npm i --silent --ignore-scripts libsodium-wrappers-sumo@0.7.15 esbuild@0.24.2 \
      && echo 'self.sodium = require("libsodium-wrappers-sumo");' > entry.js \
      && npx esbuild entry.js --bundle --minify --platform=browser --format=iife \
           --external:fs --external:path --external:crypto --outfile=sodium.js)
    cp "$tmp/sodium.js" $v/libsodium.wasm.js
    ls -la $v

# --- Stack ------------------------------------------------------------------------------

# Build images
build:
    {{compose}} build

# Start the core stack in the background
up:
    mkdir -p tor-data
    {{compose}} up -d

# init-env + build + up, then wait until the app is healthy
dev: init-env stop-old build up wait
    @echo "App:     http://localhost:8000"
    @echo "Mailpit: http://localhost:8025"
    @echo "Onion:   run 'just onion' in ~30s"

# Same as dev, plus Monero regtest daemon + wallet-rpc (set MONERO_RPC_URL in .env)
dev-crypto: init-env stop-old build
    mkdir -p tor-data
    {{compose}} --profile monero up -d
    just wait

# Add BTCPay Server (bitcoind regtest + NBXplorer) next to the running stack
btcpay-up:
    {{btcpay}} up -d bitcoind nbxplorer btcpay
    @echo "BTCPay: http://localhost:23000 (create a store, an API key and a webhook to /webhooks/btcpay)"

# Stop BTCPay services
btcpay-down:
    {{btcpay}} stop bitcoind nbxplorer btcpay

# Wait for /healthz (up to 3 minutes)
wait:
    #!/usr/bin/env bash
    for i in $(seq 1 90); do
      if curl -fs http://localhost:8000/healthz >/dev/null; then echo "healthy"; exit 0; fi
      sleep 2
    done
    echo "app did not become healthy; see 'just logs app'" >&2; exit 1

# Stop the stack (keeps volumes)
down:
    {{compose}} --profile monero down

# Stop containers left running by the previous Project D1zzy stack (does not delete them or their volumes)
stop-old:
    #!/usr/bin/env bash
    ids=$(podman ps -q --filter label=com.docker.compose.project=project-d1zzy)
    if [ -n "$ids" ]; then echo "stopping old project-d1zzy containers"; podman stop $ids >/dev/null; fi

# Restart one service (default: app)
restart svc="app":
    {{compose}} restart {{svc}}

# Follow logs (optionally for one service)
logs *svc:
    {{compose}} logs -f {{svc}}

# Show container status
ps:
    {{compose}} ps

# Shell inside the app container
shell:
    {{compose}} exec app bash

# psql inside the db container
psql:
    {{compose}} exec db psql -U d1zzy -d project_d1zzy_market

# redis-cli inside the redis container
redis-cli:
    {{compose}} exec redis redis-cli

# Health check
health:
    curl -fsS http://localhost:8000/healthz && echo

# Print the onion address
onion:
    #!/usr/bin/env bash
    for i in $(seq 1 60); do
      if [ -s tor-data/hostname ]; then echo "http://$(cat tor-data/hostname)"; exit 0; fi
      sleep 2
    done
    echo "no onion address yet; see 'just logs tor'" >&2; exit 1

# --- Database & data --------------------------------------------------------------------

# Apply migrations
migrate:
    {{compose}} exec app alembic upgrade head

# New autogenerated migration: just revision "add thing"
revision msg:
    {{compose}} exec app alembic revision --autogenerate -m "{{msg}}"

# Load demo vendors, buyer, moderator and listings (idempotent)
seed:
    {{compose}} exec app python -m app.cli seed

# Create or promote a moderator
create-moderator email password:
    {{compose}} exec app python -m app.cli create-moderator "{{email}}" "{{password}}"

# Create or promote a vendor
create-vendor email password:
    {{compose}} exec app python -m app.cli create-vendor "{{email}}" "{{password}}"

# Mine regtest Monero blocks to the market wallet (needs dev-crypto; 60+ to unlock coinbase)
xmr-mine blocks="70":
    {{compose}} exec app python -m app.cli xmr-mine {{blocks}}

# Forward Stripe test webhooks to the local app (needs the Stripe CLI)
stripe-listen:
    stripe listen --forward-to localhost:8000/webhooks/stripe

# Delete ALL stack data (database, IPFS, onion keys). Asks first.
[confirm("This deletes the database, IPFS blocks and the onion key. Continue?")]
nuke:
    {{compose}} --profile monero down -v
    rm -rf tor-data

# --- Quality ----------------------------------------------------------------------------

# Run the full test-suite: real Postgres/Redis/IPFS/Monero via testcontainers on rootless Podman
test *args:
    systemctl --user start podman.socket
    DOCKER_HOST={{podman_sock}} TESTCONTAINERS_RYUK_DISABLED=true uv run pytest {{args}}

# Tests without the ~40 s Monero regtest multisig test
test-fast *args:
    systemctl --user start podman.socket
    SKIP_MONERO_TESTS=1 DOCKER_HOST={{podman_sock}} TESTCONTAINERS_RYUK_DISABLED=true uv run pytest {{args}}

# Tests inside containers (throwaway Postgres/Redis/IPFS from deploy/compose/podman-compose.test.yml)
test-container:
    podman-compose -f deploy/compose/podman-compose.test.yml up --build --abort-on-container-exit --exit-code-from tests
    podman-compose -f deploy/compose/podman-compose.test.yml down -v

# Lint
lint:
    uv run ruff check app tests alembic

# Install the security assurance tooling (Bandit, pip-audit) into .venv
security-setup:
    uv sync --extra dev --extra security

# Security assurance scan: lint + Bandit + pip-audit + gitleaks (+ Semgrep with SECURITY_SEMGREP=1)
security *args:
    ./scripts/security_scan.sh {{args}}

# Format
fmt:
    uv run ruff format app tests alembic
    uv run ruff check --fix app tests alembic

# Lint + tests
check: lint test

# --- Quadlet (systemd user units) -------------------------------------------------------

quadlet_dir := env_var("HOME") + "/.config/containers/systemd"

# Install Quadlet units (production-style, no bind mounts) and reload systemd
quadlet-install: build
    mkdir -p {{quadlet_dir}}
    cp deploy/quadlet/* {{quadlet_dir}}/
    mkdir -p ~/.config/d1zzy && [ -f ~/.config/d1zzy/env ] || cp .env ~/.config/d1zzy/env
    systemctl --user daemon-reload
    @echo "installed; start with: just quadlet-start"

# Start all Quadlet services
quadlet-start:
    systemctl --user start d1zzy-app.service d1zzy-worker.service d1zzy-tor.service

# Stop all Quadlet services
quadlet-stop:
    systemctl --user stop d1zzy-tor.service d1zzy-worker.service d1zzy-app.service d1zzy-ipfs.service d1zzy-redis.service d1zzy-db.service

# Quadlet service status
quadlet-status:
    systemctl --user --no-pager status 'd1zzy-*'

# Remove Quadlet units (keeps volumes)
quadlet-uninstall:
    -just quadlet-stop
    rm -f {{quadlet_dir}}/d1zzy-*
    systemctl --user daemon-reload

# --- Browsers (Aurora DX / Flatpak) -----------------------------------------------------

# Open the shop in Zen Browser
zen:
    flatpak run app.zen_browser.zen http://localhost:8000

# Launch Tor Browser (paste the `just onion` address)
tor-browser:
    flatpak run org.torproject.torbrowser-launcher
