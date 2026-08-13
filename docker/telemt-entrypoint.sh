#!/bin/sh
set -eu

SECRETS_FILE=${SECRETS_FILE:-/run/secrets/mtproxy-secrets}
CONFIG=/run/telemt/config.toml
DOMAIN=${FAKE_TLS_DOMAIN:?FAKE_TLS_DOMAIN is required}

umask 077
mkdir -p /run/telemt/tlsfront

cat > "$CONFIG" <<EOF
[general]
use_middle_proxy = false
log_level = "normal"

[general.modes]
classic = false
secure = false
tls = true

[general.links]
show = []
public_host = "$DOMAIN"
public_port = 443

[server]
port = 443

[[server.listeners]]
ip = "0.0.0.0"

[server.api]
enabled = false

[censorship]
tls_domain = "$DOMAIN"
mask = true
mask_host = "mask"
mask_port = 443
tls_emulation = true
tls_front_dir = "/run/telemt/tlsfront"

[access.users]
EOF

while IFS='=' read -r name secret; do
  [ -n "${name:-}" ] || continue
  case "$name$secret" in
    *[!A-Za-z0-9_-]*) echo "Invalid user secret entry" >&2; exit 1 ;;
  esac
  [ "${#secret}" -eq 32 ] || { echo "Invalid secret length for $name" >&2; exit 1; }
  safe_name=$(printf '%s' "$name" | tr '-' '_')
  printf '"%s" = "%s"\n' "$safe_name" "$secret" >> "$CONFIG"
done < "$SECRETS_FILE"

cat >> "$CONFIG" <<'EOF'

[[upstreams]]
type = "direct"
ipv4 = true
ipv6 = false
EOF

exec telemt --data-path /run/telemt "$CONFIG"
