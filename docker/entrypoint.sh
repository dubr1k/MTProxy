#!/bin/bash
set -euo pipefail

: "${FAKE_TLS_DOMAIN:?FAKE_TLS_DOMAIN is required}"
: "${SECRETS_FILE:=/run/secrets/mtproxy-secrets}"
: "${PROXY_PORT:=443}"
: "${STATS_PORT:=2398}"
: "${WORKERS:=0}"
: "${NAT_INFO:=}"

[[ -r "$SECRETS_FILE" ]] || { echo "Secrets file is not readable: $SECRETS_FILE" >&2; exit 1; }

curl -fsS --retry 3 --connect-timeout 10 https://core.telegram.org/getProxySecret -o /run/mtproxy/proxy-secret
curl -fsS --retry 3 --connect-timeout 10 https://core.telegram.org/getProxyConfig -o /run/mtproxy/proxy-multi.conf
[[ -s /run/mtproxy/proxy-secret ]]
[[ $(stat -c%s /run/mtproxy/proxy-multi.conf) -ge 64 ]]

secret_args=()
while IFS='=' read -r name secret; do
  [[ -z "${name//[[:space:]]/}" || "$name" == \#* ]] && continue
  [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] || { echo "Invalid user name: $name" >&2; exit 1; }
  [[ "$secret" =~ ^[0-9a-fA-F]{32}$ ]] || { echo "Invalid secret for: $name" >&2; exit 1; }
  secret_args+=("-S" "${secret,,}")
done < "$SECRETS_FILE"

((${#secret_args[@]} > 0)) || { echo "No valid secrets found" >&2; exit 1; }

nat_args=()
[[ -n "$NAT_INFO" ]] && nat_args=(--nat-info "$NAT_INFO")
worker_args=()
[[ "$WORKERS" =~ ^[1-9][0-9]*$ ]] && worker_args=(-M "$WORKERS")

exec /usr/local/bin/mtproto-proxy \
  -u mtproxy \
  -p "$STATS_PORT" \
  -H "$PROXY_PORT" \
  "${secret_args[@]}" \
  --http-stats \
  --domain "$FAKE_TLS_DOMAIN" \
  "${nat_args[@]}" \
  --aes-pwd /run/mtproxy/proxy-secret \
  /run/mtproxy/proxy-multi.conf \
  "${worker_args[@]}"
