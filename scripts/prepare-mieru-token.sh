#!/bin/sh
set -eu

readonly MIERU_GID=10005
readonly TOKEN_MODE=0440
readonly MIN_TOKEN_BYTES=32
readonly MAX_TOKEN_BYTES=513

fail() {
    printf 'prepare-mieru-token: %s\n' "$*" >&2
    exit 1
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ "$#" -eq 2 ] || fail "usage: $0 prepare|verify absolute-token-file"
mode=$1
token_file=$2
case "$mode" in
    prepare|verify) ;;
    *) fail "usage: $0 prepare|verify absolute-token-file" ;;
esac
case "$token_file" in
    /*) ;;
    *) fail "token file must be an absolute path" ;;
esac
[ "$token_file" != "/" ] || fail "refusing filesystem root"
case "$token_file" in
    *//*|*/./*|*/.|*/../*|*/..|*/) fail "token file must be a normalized absolute path without traversal" ;;
esac

path_part=$token_file
while [ "$path_part" != "/" ]; do
    [ ! -L "$path_part" ] || fail "token path must not contain a symlink: $path_part"
    path_part=${path_part%/*}
    [ -n "$path_part" ] || path_part=/
done
if [ ! -f "$token_file" ] || [ -L "$token_file" ]; then
    fail "token path must be an existing regular non-symlink file"
fi
[ "$(stat -c '%u' -- "$token_file")" = 0 ] || fail "token file must be owned by root"
size=$(stat -c '%s' -- "$token_file")
if [ "$size" -lt "$MIN_TOKEN_BYTES" ] || [ "$size" -gt "$MAX_TOKEN_BYTES" ]; then
    fail "token file must be 32..513 bytes"
fi

if [ "$mode" = prepare ]; then
    chown --no-dereference "0:$MIERU_GID" -- "$token_file"
    chmod "$TOKEN_MODE" -- "$token_file"
    printf 'Prepared Mieru manager token metadata: %s\n' "$token_file"
else
    [ "$(stat -c '%u:%g' -- "$token_file")" = "0:$MIERU_GID" ] || fail "token file must have owner 0:10005"
    [ "$(stat -c '%a' -- "$token_file")" = 440 ] || fail "token file must have mode 0440"
    printf 'Verified Mieru manager token metadata: %s\n' "$token_file"
fi
