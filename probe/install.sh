#!/usr/bin/env bash
set -euo pipefail

readonly IMAGE="mtproxy-respq-probe:1.0.0"
readonly DESTINATION="/usr/local/libexec/mtproxy-respq-probe"

[[ $# -eq 0 ]] || {
    printf 'usage: %s\n' "${0##*/}" >&2
    exit 2
}
[[ $(id -u) -eq 0 ]] || {
    printf 'probe install: must run as root\n' >&2
    exit 1
}

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
docker build --pull --tag "$IMAGE" "$source_dir"
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0750 "$source_dir/mtproxy-respq-probe" "$DESTINATION"
printf 'probe install: built %s and installed %s\n' "$IMAGE" "$DESTINATION"
