#!/bin/sh
# Writes torrc, fixes key-dir permissions (Tor refuses group/world-readable keys), starts
# Tor as the unprivileged `tor` user and copies the onion hostname to the shared export dir
# so the app can advertise it (Onion-Location header, footer) and `just onion` can print it.
set -eu
: "${TOR_TARGET_HOST:=app}"
: "${TOR_TARGET_PORT:=8000}"
HS_DIR=/var/lib/tor/hidden_service
DATA_DIR=/var/lib/tor/data
EXPORT_DIR=/run/tor-export

# HiddenServicePort needs an IP address, not a hostname.
target_ip=""
for _ in $(seq 1 60); do
  target_ip=$(getent hosts "$TOR_TARGET_HOST" | awk '{print $1; exit}') || true
  [ -n "$target_ip" ] && break
  sleep 1
done
[ -n "$target_ip" ] || { echo "cannot resolve $TOR_TARGET_HOST" >&2; exit 1; }

mkdir -p "$HS_DIR" "$DATA_DIR" "$EXPORT_DIR"
chown -R tor:tor "$HS_DIR" "$DATA_DIR"
chmod 700 "$HS_DIR" "$DATA_DIR"

cat > /etc/tor/torrc <<TORRC
DataDirectory $DATA_DIR
SocksPort 0
HiddenServiceDir $HS_DIR
HiddenServiceVersion 3
HiddenServicePort 80 $target_ip:$TOR_TARGET_PORT
HiddenServiceMaxStreams 50
HiddenServiceMaxStreamsCloseCircuit 1
HiddenServicePoWDefensesEnabled 1
HiddenServicePoWQueueRate 250
HiddenServicePoWQueueBurst 2500
Log notice stdout
TORRC

(
  for _ in $(seq 1 120); do
    if [ -s "$HS_DIR/hostname" ]; then
      cp "$HS_DIR/hostname" "$EXPORT_DIR/hostname" && chmod 644 "$EXPORT_DIR/hostname"
      echo "onion service: http://$(cat "$HS_DIR/hostname")"
      break
    fi
    sleep 1
  done
) &

exec su-exec tor tor -f /etc/tor/torrc
