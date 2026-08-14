#!/bin/sh
set -eu

case ${PANEL_SUPPLEMENTARY_GROUPS-} in
  "") set -- --clear-groups ;;
  10005) set -- --groups 10005 ;;
  *)
    echo "PANEL_SUPPLEMENTARY_GROUPS must be empty or exactly 10005" >&2
    exit 64
    ;;
esac

case ${MIERU_ENABLED-false} in
  true) mieru_enabled=true ;;
  false) mieru_enabled=false ;;
  *)
    echo "MIERU_ENABLED must be exactly true or false" >&2
    exit 64
    ;;
esac

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
STAGE_SECRET=$SCRIPT_DIR/stage_secret.py
TELEMT_SOURCE=${TELEMT_API_TOKEN_SOURCE:-/run/secrets/telemt-api-token}
NAIVE_SOURCE=${NAIVE_MANAGER_TOKEN_SOURCE:-/run/secrets/naive-manager-token}
MIERU_SOURCE=${MIERU_MANAGER_TOKEN_SOURCE:-/run/secrets/mieru-manager-token}
PANEL_RUNTIME_DIR=${PANEL_RUNTIME_DIR:-/run/panel}
TELEMT_TARGET=$PANEL_RUNTIME_DIR/telemt-api-token
NAIVE_TARGET=$PANEL_RUNTIME_DIR/naive-manager-token
MIERU_TARGET=$PANEL_RUNTIME_DIR/mieru-manager-token

# Validate the immutable Compose source before creating or copying any token.
if [ "$mieru_enabled" = true ]; then
  python3 "$STAGE_SECRET" verify "$MIERU_SOURCE"
fi

install -d -m 0700 -o panel -g panel "$PANEL_RUNTIME_DIR"
install -m 0400 -o panel -g panel "$TELEMT_SOURCE" "$TELEMT_TARGET"
export TELEMT_API_TOKEN_FILE="$TELEMT_TARGET"
if [ -r "$NAIVE_SOURCE" ]; then
  install -m 0400 -o panel -g panel "$NAIVE_SOURCE" "$NAIVE_TARGET"
  export NAIVE_MANAGER_TOKEN_FILE="$NAIVE_TARGET"
fi
if [ "$mieru_enabled" = true ]; then
  rm -f -- "$MIERU_TARGET"
  python3 "$STAGE_SECRET" stage "$MIERU_SOURCE" "$MIERU_TARGET"
  export MIERU_MANAGER_TOKEN_FILE="$MIERU_TARGET"
fi
exec setpriv --reuid=panel --regid=panel "$@" --no-new-privs \
  uvicorn panel.app:create_app --factory --host 0.0.0.0 --port 8787 \
  --proxy-headers --forwarded-allow-ips 172.16.0.0/12
