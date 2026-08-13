#!/usr/bin/env bash
set -Eeuo pipefail
PROJECT_DIR=/opt/mtproxy-shared443
PURGE_CERT=0
PURGE_COVER=0
YES=0
usage() { echo "Usage: sudo ./uninstall.sh [--project-dir PATH] [--purge-certificate] [--purge-cover] --yes"; }
while (($#)); do
  case "$1" in
    --project-dir) PROJECT_DIR=${2:-}; shift 2 ;;
    --purge-certificate) PURGE_CERT=1; shift ;;
    --purge-cover) PURGE_COVER=1; shift ;;
    --yes) YES=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 1 ;;
  esac
done
[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
((YES)) || { usage >&2; echo "--yes is required" >&2; exit 1; }
[[ -s $PROJECT_DIR/state.json && -s $PROJECT_DIR/.mtproxy-owned ]] || { echo "owned deployment state not found" >&2; exit 1; }
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
eval "$(python3 - "$PROJECT_DIR/state.json" "$PROJECT_DIR/.mtproxy-owned" <<'PY'
import json,shlex,sys
s=json.load(open(sys.argv[1])); marker=open(sys.argv[2]).read().strip()
if not marker or s.get('install_id') != marker: raise SystemExit('ownership marker mismatch')
for k in ('domain','mode','route_file','http_site','cover_root','renew_hook','ufw_added_80','ufw_added_443'):
 print(f'{k.upper()}={shlex.quote(str(s.get(k,"")))}')
PY
)"

TX=$(mktemp -d /var/tmp/mtproxy-uninstall.XXXXXX)
chmod 0700 "$TX"
cleanup() { rm -rf "$TX"; }
trap cleanup EXIT
cp -a /etc/nginx/nginx.conf "$TX/nginx.conf"
[[ ! -e $ROUTE_FILE ]] || cp -aL "$ROUTE_FILE" "$TX/route.conf"
[[ ! -e $HTTP_SITE ]] || cp -aL "$HTTP_SITE" "$TX/http-site.conf"
[[ ! -d /etc/nginx/mtproxy-stream ]] || cp -a /etc/nginx/mtproxy-stream "$TX/mtproxy-stream"
HTTP_LINK="/etc/nginx/sites-enabled/$(basename "$HTTP_SITE")"
http_link_existed=0; [[ -L $HTTP_LINK ]] && http_link_existed=1

restore_nginx() {
  cp -a "$TX/nginx.conf" /etc/nginx/nginx.conf
  [[ ! -e $TX/route.conf ]] || cp -a "$TX/route.conf" "$ROUTE_FILE"
  [[ ! -e $TX/http-site.conf ]] || cp -a "$TX/http-site.conf" "$HTTP_SITE"
  if [[ -d $TX/mtproxy-stream ]]; then
    rm -rf /etc/nginx/mtproxy-stream
    cp -a "$TX/mtproxy-stream" /etc/nginx/mtproxy-stream
  fi
  ((http_link_existed)) && ln -sfn "$HTTP_SITE" "$HTTP_LINK"
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx || true; fi
}

# Stage public-route removal while the working containers remain online.
if [[ -n $ROUTE_FILE ]]; then
  python3 "$SCRIPT_DIR/scripts/mtproxy-deploy" nginx-remove-route --domain "$DOMAIN" --route-file "$ROUTE_FILE"
fi
if [[ $MODE == fresh ]]; then
  other_routes=$(python3 - "$ROUTE_FILE" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1]); count=0
if p.exists():
    for raw in p.read_text().splitlines():
        line=raw.strip()
        if line and not line.startswith('#') and not line.startswith('default '): count += 1
print(count)
PY
)
  if ((other_routes == 0)); then
    rm -f /etc/nginx/mtproxy-stream/router.conf /etc/nginx/mtproxy-stream/routes.conf /etc/nginx/mtproxy-stream/stream.conf
    python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nginx/nginx.conf')
if p.exists():
 s=p.read_text().replace('# BEGIN mtproxy-shared443 stream include\ninclude /etc/nginx/mtproxy-stream/stream.conf;\n# END mtproxy-shared443 stream include\n\n','')
 p.write_text(s)
PY
  else
    echo "[mtproxy] preserving shared stream router: $other_routes unrelated route(s) remain"
  fi
fi
rm -f "$HTTP_SITE" "$HTTP_LINK"
if ! nginx -t; then
  restore_nginx
  echo "Nginx validation failed; exact pre-uninstall configuration restored" >&2
  exit 1
fi
if ! systemctl reload nginx; then
  restore_nginx
  echo "Nginx reload failed; exact pre-uninstall configuration restored" >&2
  exit 1
fi

# Only after public routing is safely removed do we stop the private stack.
docker compose --project-directory "$PROJECT_DIR" down --remove-orphans || true
[[ -z $RENEW_HOOK ]] || rm -f "$RENEW_HOOK"
if [[ $UFW_ADDED_80 == True ]] && command -v ufw >/dev/null; then ufw delete allow 80/tcp >/dev/null 2>&1 || true; fi
if [[ $UFW_ADDED_443 == True ]] && command -v ufw >/dev/null; then ufw delete allow 443/tcp >/dev/null 2>&1 || true; fi
if ((PURGE_CERT)); then certbot delete --cert-name "$DOMAIN" --non-interactive || true; fi
if ((PURGE_COVER)); then rm -rf --one-file-system "$COVER_ROOT"; fi
rm -rf --one-file-system "$PROJECT_DIR"
printf '[mtproxy] removed deployment for %s; unrelated Nginx routes and services were preserved\n' "$DOMAIN"
