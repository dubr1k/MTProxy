#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_DIR=${PROJECT_DIR:-/opt/mtproxy-shared443}
DOMAIN=""
EMAIL=""
USERS="default"
BACKEND_PORT=8445
MODE=""
ROUTE_FILE=""
COVER_FILE=""
RENEW_HOOK=""
SKIP_DNS=0
MANAGE_FIREWALL=0

log() { printf '[mtproxy] %s\n' "$*"; }
die() { printf '[mtproxy] ERROR: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
Usage:
  sudo ./install.sh --domain proxy.example.com --email admin@example.com [options]

Options:
  --mode fresh|coexist     fresh: create an extensible Nginx stream router;
                           coexist: add one route to an existing stream map
  --route-file PATH        required in coexist mode; file containing the existing map
  --users a,b,c            per-user secrets to generate (default: default)
  --backend-port PORT      loopback Telemt port (default: 8445)
  --cover-file PATH        private HTML file copied outside Git
  --project-dir PATH       deployment directory (default: /opt/mtproxy-shared443)
  --skip-dns-check         allow installation before DNS points to this VPS
  --manage-firewall        opt in to adding exact allow 80/443 rules to active UFW
  -h, --help
EOF
}

while (($#)); do
  case "$1" in
    --domain) DOMAIN=${2:-}; shift 2 ;;
    --email) EMAIL=${2:-}; shift 2 ;;
    --mode) MODE=${2:-}; shift 2 ;;
    --route-file) ROUTE_FILE=${2:-}; shift 2 ;;
    --users) USERS=${2:-}; shift 2 ;;
    --backend-port) BACKEND_PORT=${2:-}; shift 2 ;;
    --cover-file) COVER_FILE=${2:-}; shift 2 ;;
    --project-dir) PROJECT_DIR=${2:-}; shift 2 ;;
    --skip-dns-check) SKIP_DNS=1; shift ;;
    --manage-firewall) MANAGE_FIREWALL=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root"
[[ -n $DOMAIN && -n $EMAIL ]] || { usage >&2; die "--domain and --email are required"; }
[[ $EMAIL =~ ^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$ ]] || die "invalid email address"
[[ $MODE == fresh || $MODE == coexist ]] || die "--mode must be fresh or coexist"
[[ $MODE != coexist || -n $ROUTE_FILE ]] || die "--route-file is required in coexist mode"
if ! [[ $BACKEND_PORT =~ ^[0-9]+$ ]] || ((BACKEND_PORT < 1024 || BACKEND_PORT > 65535)); then
  die "invalid backend port"
fi
[[ -z $COVER_FILE || -s $COVER_FILE ]] || die "cover file is missing or empty"

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
DEPLOY_CLI="$SCRIPT_DIR/scripts/mtproxy-deploy"
[[ -x $DEPLOY_CLI ]] || die "missing scripts/mtproxy-deploy"

rollback_route=0
fresh_include_added=0
ufw_added_80=0
ufw_added_443=0
rollback() {
  local rc=$?
  if ((rollback_route)); then
    log "rolling back the Nginx SNI route"
    python3 "$DEPLOY_CLI" nginx-remove-route --domain "$DOMAIN" --route-file "$ROUTE_FILE" || true
    if nginx -t >/dev/null 2>&1; then systemctl reload nginx || true; fi
  fi
  if ((fresh_include_added)); then
    log "rolling back the fresh Nginx stream include"
    python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nginx/nginx.conf')
if p.exists():
    p.write_text(p.read_text().replace('# BEGIN mtproxy-shared443 stream include\ninclude /etc/nginx/mtproxy-stream/stream.conf;\n# END mtproxy-shared443 stream include\n\n',''))
PY
    rm -f /etc/nginx/mtproxy-stream/router.conf /etc/nginx/mtproxy-stream/routes.conf /etc/nginx/mtproxy-stream/stream.conf
    if nginx -t >/dev/null 2>&1; then systemctl reload nginx || true; fi
  fi
  if ((ufw_added_80)); then ufw delete allow 80/tcp >/dev/null 2>&1 || true; fi
  if ((ufw_added_443)); then ufw delete allow 443/tcp >/dev/null 2>&1 || true; fi
  [[ -z $RENEW_HOOK ]] || rm -f "$RENEW_HOOK"
  exit "$rc"
}
trap rollback ERR

log "installing Debian/Ubuntu dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl openssl python3 certbot >/dev/null
if ! command -v nginx >/dev/null; then
  apt-get install -y -qq nginx nginx-full libnginx-mod-stream >/dev/null
fi
if ! command -v docker >/dev/null; then
  apt-get install -y -qq docker.io >/dev/null
fi
if ! docker compose version >/dev/null 2>&1; then
  apt-get install -y -qq docker-compose-v2 >/dev/null 2>&1 || \
    apt-get install -y -qq docker-compose-plugin >/dev/null 2>&1 || \
    die "cannot install Docker Compose v2"
fi
systemctl enable --now docker nginx >/dev/null

docker compose version >/dev/null || die "Docker Compose v2 is unavailable"
nginx -V 2>&1 | grep -Eq 'stream|dynamic' || die "Nginx stream support is unavailable"

if ss -lntH "sport = :$BACKEND_PORT" | grep -q .; then
  owned_container=$(docker compose --project-directory "$PROJECT_DIR" ps -q mtproxy 2>/dev/null || true)
  if [[ -z $owned_container ]]; then
    die "127.0.0.1:$BACKEND_PORT is already occupied"
  fi
fi
if [[ $MODE == fresh ]] && ss -lntH 'sport = :443' | grep -q .; then
  existing_fresh=0
  if [[ -s $PROJECT_DIR/state.json ]]; then
    existing_fresh=$(python3 - "$PROJECT_DIR/state.json" "$DOMAIN" <<'PY'
import json,sys
try:
    s=json.load(open(sys.argv[1]))
    print(1 if s.get('mode') == 'fresh' and s.get('domain') == sys.argv[2] else 0)
except Exception:
    print(0)
PY
)
  fi
  ((existing_fresh)) || die "public TCP/443 is already occupied; use --mode coexist with the existing Nginx stream map"
fi

if ((SKIP_DNS == 0)); then
  mapfile -t dns_ips < <(getent ahostsv4 "$DOMAIN" | awk '{print $1}' | sort -u)
  ((${#dns_ips[@]})) || die "domain has no IPv4 address: $DOMAIN"
  mapfile -t local_ips < <({ ip -4 -o addr show scope global | awk '{split($4,a,"/"); print a[1]}'; curl -4fsS --max-time 10 https://api.ipify.org || true; } | sed '/^$/d' | sort -u)
  dns_match=0
  for dns_ip in "${dns_ips[@]}"; do
    printf '%s\n' "${local_ips[@]}" | grep -Fxq "$dns_ip" && dns_match=1
  done
  ((dns_match)) || die "DNS for $DOMAIN does not match any detected VPS IPv4 (${local_ips[*]}); use DNS-only and retry"
  if getent ahostsv6 "$DOMAIN" | grep -q .; then
    die "AAAA is published for $DOMAIN but this installer configures IPv4 only; remove AAAA or configure IPv6 manually"
  fi
fi

render_args=(render --domain "$DOMAIN" --email "$EMAIL" --users "$USERS" --backend-port "$BACKEND_PORT" --install-dir "$PROJECT_DIR")
[[ -z $COVER_FILE ]] || render_args+=(--cover-file "$COVER_FILE")
python3 "$DEPLOY_CLI" "${render_args[@]}"

ACME_ROOT="/var/www/$DOMAIN/.well-known/acme-challenge"
install -d -m 0755 "$ACME_ROOT"
HTTP_SITE="/etc/nginx/sites-available/mtproxy-$DOMAIN.conf"
cat >"$HTTP_SITE" <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/$DOMAIN; }
    location / { return 301 https://\$host\$request_uri; }
}
EOF
ln -sfn "$HTTP_SITE" "/etc/nginx/sites-enabled/mtproxy-$DOMAIN.conf"
nginx -t
touch "$ACME_ROOT/preflight"
systemctl reload nginx

if [[ ! -s "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]]; then
  log "requesting a Let's Encrypt certificate"
  certbot certonly --webroot -w "/var/www/$DOMAIN" -d "$DOMAIN" -m "$EMAIL" --agree-tos --non-interactive
fi

log "starting Telemt and internal Caddy"
docker compose --project-directory "$PROJECT_DIR" config -q
docker compose --project-directory "$PROJECT_DIR" pull -q
docker compose --project-directory "$PROJECT_DIR" up -d

for _ in $(seq 1 45); do
  mtproxy_id=$(docker compose --project-directory "$PROJECT_DIR" ps -q mtproxy)
  mask_id=$(docker compose --project-directory "$PROJECT_DIR" ps -q mask)
  [[ -n $mtproxy_id && $(docker inspect "$mtproxy_id" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true) == healthy ]] && \
  [[ -n $mask_id && $(docker inspect "$mask_id" --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' 2>/dev/null || true) == healthy ]] && break
  sleep 2
done
[[ $(docker inspect "$mtproxy_id" --format '{{.State.Health.Status}}') == healthy ]] || die "Telemt did not become healthy"
[[ $(docker inspect "$mask_id" --format '{{.State.Health.Status}}') == healthy ]] || die "Caddy did not become healthy"

if [[ $MODE == fresh ]]; then
  python3 "$DEPLOY_CLI" nginx-create-router --domain "$DOMAIN" --backend-port "$BACKEND_PORT"
  STREAM_INCLUDE='/etc/nginx/mtproxy-stream/stream.conf'
  cat >"$STREAM_INCLUDE" <<'EOF'
stream {
    include /etc/nginx/mtproxy-stream/router.conf;
}
EOF
  if ! grep -Fq 'include /etc/nginx/mtproxy-stream/stream.conf;' /etc/nginx/nginx.conf; then
    cp -a /etc/nginx/nginx.conf "/etc/nginx/nginx.conf.mtproxy-backup-$(date +%Y%m%d%H%M%S)"
    python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nginx/nginx.conf')
s=p.read_text()
needle='http {'
if needle not in s: raise SystemExit('cannot locate http block in nginx.conf')
s=s.replace(needle, '# BEGIN mtproxy-shared443 stream include\ninclude /etc/nginx/mtproxy-stream/stream.conf;\n# END mtproxy-shared443 stream include\n\n'+needle, 1)
p.write_text(s)
PY
    fresh_include_added=1
  fi
  ROUTE_FILE=/etc/nginx/mtproxy-stream/routes.conf
else
  python3 "$DEPLOY_CLI" nginx-add-route --domain "$DOMAIN" --backend-port "$BACKEND_PORT" --route-file "$ROUTE_FILE"
  rollback_route=1
fi

nginx -t
systemctl reload nginx

RENEW_HOOK="/etc/letsencrypt/renewal-hooks/deploy/mtproxy-$DOMAIN.sh"
install -d -m 0755 "$(dirname "$RENEW_HOOK")"
cat >"$RENEW_HOOK" <<EOF
#!/usr/bin/env bash
set -euo pipefail
docker compose --project-directory '$PROJECT_DIR' up -d --force-recreate mask
EOF
chmod 0755 "$RENEW_HOOK"

if ((MANAGE_FIREWALL)) && command -v ufw >/dev/null && ufw status | grep -q '^Status: active'; then
  if ! ufw status | grep -Eq '^80/tcp\s+ALLOW'; then
    ufw allow 80/tcp comment 'mtproxy-shared443 ACME' >/dev/null
    ufw_added_80=1
  fi
  if ! ufw status | grep -Eq '^443/tcp\s+ALLOW'; then
    ufw allow 443/tcp comment 'mtproxy-shared443 shared TLS' >/dev/null
    ufw_added_443=1
  fi
fi

python3 - "$PROJECT_DIR/state.json" "$MODE" "$ROUTE_FILE" "$HTTP_SITE" "$RENEW_HOOK" "$ufw_added_80" "$ufw_added_443" <<'PY'
import json
from pathlib import Path
import sys
p=Path(sys.argv[1])
d=json.loads(p.read_text())
d.update({'mode':sys.argv[2],'route_file':sys.argv[3],'http_site':sys.argv[4],
          'renew_hook':sys.argv[5], 'ufw_added_80':bool(int(sys.argv[6])),
          'ufw_added_443':bool(int(sys.argv[7]))})
p.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
p.chmod(0o600)
PY

"$SCRIPT_DIR/scripts/check-deployment.sh" --project-dir "$PROJECT_DIR" --domain "$DOMAIN" --backend-port "$BACKEND_PORT"
rollback_route=0
fresh_include_added=0
ufw_added_80=0
ufw_added_443=0

log "installation completed"
log "client links contain secrets; generate them locally with:"
log "python3 $PROJECT_DIR/docker/links.py --server $DOMAIN --port 443 --domain $DOMAIN --secrets $PROJECT_DIR/secrets/users.conf"
