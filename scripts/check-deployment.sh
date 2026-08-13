#!/usr/bin/env bash
set -Eeuo pipefail
PROJECT_DIR=/opt/mtproxy-shared443
DOMAIN=""
BACKEND_PORT=8445
while (($#)); do
  case "$1" in
    --project-dir) PROJECT_DIR=${2:-}; shift 2 ;;
    --domain) DOMAIN=${2:-}; shift 2 ;;
    --backend-port) BACKEND_PORT=${2:-}; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ -n $DOMAIN ]] || { echo "--domain required" >&2; exit 1; }

docker compose --project-directory "$PROJECT_DIR" config -q
mtproxy_id=$(docker compose --project-directory "$PROJECT_DIR" ps -q mtproxy)
mask_id=$(docker compose --project-directory "$PROJECT_DIR" ps -q mask)
[[ -n $mtproxy_id && -n $mask_id ]]
[[ $(docker inspect "$mtproxy_id" --format '{{.State.Health.Status}}') == healthy ]]
[[ $(docker inspect "$mask_id" --format '{{.State.Health.Status}}') == healthy ]]
[[ $(docker inspect "$mtproxy_id" --format '{{.RestartCount}}') == 0 ]]
ss -lntH "sport = :$BACKEND_PORT" | grep -q "127.0.0.1:$BACKEND_PORT"
nginx -t >/dev/null
systemctl is-active --quiet nginx
curl -fsS --max-time 15 "https://$DOMAIN/" >/dev/null
logs=$(docker compose --project-directory "$PROJECT_DIR" logs --since 10m --tail 500 mtproxy)
if grep -Eqi 'panic|fatal|read-only file system|SOCKS5 request failed' <<<"$logs"; then
  echo "critical Telemt log pattern detected" >&2
  exit 1
fi
printf '[mtproxy] static/runtime/public checks passed for %s\n' "$DOMAIN"
printf '[mtproxy] NOTE: run a real MTProto req_pq_multi -> resPQ checker for each user secret\n'
