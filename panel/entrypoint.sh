#!/bin/sh
set -eu

SOURCE=${TELEMT_API_TOKEN_SOURCE:-/run/secrets/telemt-api-token}
TARGET=/run/panel/telemt-api-token
install -d -m 0700 -o panel -g panel /run/panel
install -m 0400 -o panel -g panel "$SOURCE" "$TARGET"
export TELEMT_API_TOKEN_FILE=$TARGET
exec setpriv --reuid=panel --regid=panel --init-groups --no-new-privs \
  uvicorn panel.app:create_app --factory --host 0.0.0.0 --port 8787 \
  --proxy-headers --forwarded-allow-ips 172.16.0.0/12
