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
[[ -s $PROJECT_DIR/state.json ]] || { echo "state file not found: $PROJECT_DIR/state.json" >&2; exit 1; }
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
eval "$(python3 - "$PROJECT_DIR/state.json" <<'PY'
import json,shlex,sys
s=json.load(open(sys.argv[1]))
for k in ('domain','mode','route_file','http_site','cover_root'):
 print(f'{k.upper()}={shlex.quote(str(s.get(k,"")))}')
PY
)"

docker compose --project-directory "$PROJECT_DIR" down --remove-orphans || true
if [[ -n $ROUTE_FILE ]]; then
  python3 "$SCRIPT_DIR/scripts/mtproxy-deploy" nginx-remove-route --domain "$DOMAIN" --route-file "$ROUTE_FILE"
fi
if [[ $MODE == fresh ]]; then
  # Keep the shared router when the operator added other SNI services.
  other_routes=$(python3 - "$ROUTE_FILE" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
count=0
if p.exists():
    for raw in p.read_text().splitlines():
        line=raw.strip()
        if not line or line.startswith('#') or line.startswith('default '):
            continue
        count += 1
print(count)
PY
)
  if ((other_routes == 0)); then
    rm -f /etc/nginx/mtproxy-stream/router.conf /etc/nginx/mtproxy-stream/routes.conf /etc/nginx/mtproxy-stream/stream.conf
    rmdir /etc/nginx/mtproxy-stream 2>/dev/null || true
    python3 - <<'PY'
from pathlib import Path
p=Path('/etc/nginx/nginx.conf')
if p.exists():
 s=p.read_text().replace('include /etc/nginx/mtproxy-stream/stream.conf;\n\n','')
 p.write_text(s)
PY
  else
    echo "[mtproxy] preserving the shared stream router: $other_routes unrelated route(s) remain"
  fi
fi
rm -f "$HTTP_SITE" "/etc/nginx/sites-enabled/$(basename "$HTTP_SITE")"
if ! nginx -t; then
  echo "Nginx validation failed after cleanup; deployment files were retained for manual recovery" >&2
  exit 1
fi
systemctl reload nginx
if ((PURGE_CERT)); then certbot delete --cert-name "$DOMAIN" --non-interactive || true; fi
if ((PURGE_COVER)); then rm -rf --one-file-system "$COVER_ROOT"; fi
rm -rf --one-file-system "$PROJECT_DIR"
printf '[mtproxy] removed deployment for %s; unrelated Nginx routes and services were preserved\n' "$DOMAIN"
