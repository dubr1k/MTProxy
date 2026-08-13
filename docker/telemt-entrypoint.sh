#!/bin/sh
set -eu

SECRETS_FILE=${SECRETS_FILE:-/run/secrets/mtproxy-secrets}
API_TOKEN_FILE=${API_TOKEN_FILE:-/run/secrets/telemt-api-token}
CONFIG_DIR=${CONFIG_DIR:-/var/lib/telemt}
CONFIG=$CONFIG_DIR/config.toml
DOMAIN=${FAKE_TLS_DOMAIN:?FAKE_TLS_DOMAIN is required}

umask 077
mkdir -p "$CONFIG_DIR/tlsfront"

[ -s "$API_TOKEN_FILE" ] || { echo "Telemt API token is missing" >&2; exit 1; }
API_TOKEN=$(cat "$API_TOKEN_FILE")
case "$API_TOKEN" in "Bearer "*) API_TOKEN_VALUE=${API_TOKEN#Bearer };; *) echo "Telemt API token must use Bearer scheme" >&2; exit 1;; esac
case "$API_TOKEN_VALUE" in ''|*[!A-Za-z0-9._~+:/=-]*) echo "Telemt API token contains invalid characters" >&2; exit 1;; esac
[ "${#API_TOKEN}" -ge 32 ] || { echo "Telemt API token is too short" >&2; exit 1; }

# The API persists mutations with atomic rename. Never regenerate an existing config.
if [ -s "$CONFIG" ]; then
  exec telemt --data-path "$CONFIG_DIR" "$CONFIG"
fi

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
enabled = true
listen = "0.0.0.0:9091"
whitelist = ["172.16.0.0/12"]
auth_header = "$API_TOKEN"
request_body_limit_bytes = 65536
minimal_runtime_enabled = true
runtime_edge_enabled = true

[censorship]
tls_domain = "$DOMAIN"
mask = true
mask_host = "mask"
mask_port = 443
tls_emulation = true
tls_front_dir = "$CONFIG_DIR/tlsfront"

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

exec telemt --data-path "$CONFIG_DIR" "$CONFIG"
