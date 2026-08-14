#!/bin/sh
set -eu

case ${PANEL_SUPPLEMENTARY_GROUPS-} in
  "") set -- --clear-groups ;;
  10003) set -- --groups 10003 ;;
  *)
    echo "PANEL_SUPPLEMENTARY_GROUPS must be empty or exactly 10003" >&2
    exit 64
    ;;
esac

TELEMT_SOURCE=${TELEMT_API_TOKEN_SOURCE:-/run/secrets/telemt-api-token}
NAIVE_SOURCE=${NAIVE_MANAGER_TOKEN_SOURCE:-/run/secrets/naive-manager-token}
TELEMT_TARGET=/run/panel/telemt-api-token
NAIVE_TARGET=/run/panel/naive-manager-token
install -d -m 0700 -o panel -g panel /run/panel
install -m 0400 -o panel -g panel "$TELEMT_SOURCE" "$TELEMT_TARGET"
export TELEMT_API_TOKEN_FILE=$TELEMT_TARGET
if [ -r "$NAIVE_SOURCE" ]; then
  install -m 0400 -o panel -g panel "$NAIVE_SOURCE" "$NAIVE_TARGET"
  export NAIVE_MANAGER_TOKEN_FILE=$NAIVE_TARGET
fi
exec setpriv --reuid=panel --regid=panel "$@" --no-new-privs \
  uvicorn panel.app:create_app --factory --host 0.0.0.0 --port 8787 \
  --proxy-headers --forwarded-allow-ips 172.16.0.0/12
