#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd -P)
exec python3 "$SCRIPT_DIR/prepare_mieru_token.py" "$@"
