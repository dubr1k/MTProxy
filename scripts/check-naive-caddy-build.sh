#!/bin/sh
set -eu
CADDY=${CADDY_BIN:-/usr/local/bin/caddy}
EXPECTED='v2.11.4 h1:XKxkMTgNSizEvKG6QHue6cAsFOteU2qA61w2tKkCWi0='
actual=$($CADDY version)
if [ "$actual" != "$EXPECTED" ]; then
    printf 'refusing unpinned Caddy build: expected %s, got %s\n' "$EXPECTED" "$actual" >&2
    exit 1
fi
$CADDY list-modules | grep -Fxq 'http.handlers.forward_proxy' || {
    echo 'refusing Caddy build without http.handlers.forward_proxy' >&2
    exit 1
}
