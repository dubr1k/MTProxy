#!/bin/sh
set -eu

readonly MIERU_UID=10003
readonly MIERU_GID=10003
readonly MIERU_MODE=0700

fail() {
    printf 'prepare-mieru-state: %s\n' "$*" >&2
    exit 1
}

verify_regular_file() {
    file=$1
    description=$2
    expected_size=${3:-}
    [ ! -L "$file" ] || fail "$description must not be a symlink: $file"
    [ -f "$file" ] || fail "$description must be a regular file: $file"
    [ "$(stat -c '%u:%g' -- "$file")" = "$MIERU_UID:$MIERU_GID" ] || fail "$description must have owner 10003:10003: $file"
    [ "$(stat -c '%a' -- "$file")" = "600" ] || fail "$description must have mode 0600: $file"
    if [ -n "$expected_size" ]; then
        [ "$(stat -c '%s' -- "$file")" = "$expected_size" ] || fail "$description must be exactly $expected_size bytes: $file"
    fi
}

[ "$(id -u)" -eq 0 ] || fail "must run as root"
[ "$#" -le 2 ] || fail "usage: $0 prepare|verify [absolute-state-directory]"
mode=${1:-}
case "$mode" in
    prepare|verify) ;;
    *) fail "usage: $0 prepare|verify [absolute-state-directory]" ;;
esac
state_dir=${2:-${MIERU_MANAGER_STATE_DIR:-/var/lib/mieru-manager}}

case "$state_dir" in
    /*) ;;
    *) fail "state directory must be an absolute path" ;;
esac

[ "$state_dir" != "/" ] || fail "refusing filesystem root"
case "$state_dir" in
    *//*|*/./*|*/.|*/../*|*/..|*/) fail "state directory must be a normalized absolute path without traversal" ;;
esac

path_part=$state_dir
while [ "$path_part" != "/" ]; do
    [ ! -L "$path_part" ] || fail "state path must not contain a symlink: $path_part"
    path_part=${path_part%/*}
    [ -n "$path_part" ] || path_part=/
done

if [ -e "$state_dir" ] || [ -L "$state_dir" ]; then
    if [ ! -d "$state_dir" ] || [ -L "$state_dir" ]; then
        fail "state path must be a real directory, not a symlink"
    fi
    if [ "$mode" = "prepare" ]; then
        [ -z "$(find "$state_dir" -mindepth 1 -maxdepth 1 -print -quit)" ] || fail "prepare refuses a non-empty state directory; use verify after restoring"
    fi
else
    [ "$mode" = "prepare" ] || fail "verify requires an existing state directory; run prepare for a fresh deployment"
    install -d -m "$MIERU_MODE" -o "$MIERU_UID" -g "$MIERU_GID" -- "$state_dir"
fi
if [ "$mode" = "prepare" ]; then
    chown "$MIERU_UID:$MIERU_GID" -- "$state_dir"
    chmod "$MIERU_MODE" -- "$state_dir"
    printf 'Prepared Mieru manager state directory: %s\n' "$state_dir"
else
    [ "$(stat -c '%u:%g' -- "$state_dir")" = "$MIERU_UID:$MIERU_GID" ] || fail "state directory must have owner 10003:10003; restore ownership explicitly, then retry verify"
    [ "$(stat -c '%a' -- "$state_dir")" = "700" ] || fail "state directory must have mode 0700; restore its mode explicitly, then retry verify"

    for name in state.json writer.lock; do
        candidate=$state_dir/$name
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            verify_regular_file "$candidate" "$name"
        fi
    done

    journal_key=$state_dir/journal.key
    if [ -e "$journal_key" ] || [ -L "$journal_key" ]; then
        verify_regular_file "$journal_key" "journal.key" 32
    fi
    journal=$state_dir/journal.json
    if [ -e "$journal" ] || [ -L "$journal" ]; then
        verify_regular_file "$journal" "journal.json"
        if [ ! -e "$journal_key" ] || [ -L "$journal_key" ]; then
            fail "active journal.json requires journal.key; co-restore the original key and never regenerate it"
        fi
    fi

    backup_dir=$state_dir/backups
    if [ -e "$backup_dir" ] || [ -L "$backup_dir" ]; then
        if [ -L "$backup_dir" ] || [ ! -d "$backup_dir" ]; then
            fail "backups must be a real directory, not a symlink"
        fi
        [ "$(stat -c '%u:%g' -- "$backup_dir")" = "$MIERU_UID:$MIERU_GID" ] || fail "backups directory must have owner 10003:10003"
        [ "$(stat -c '%a' -- "$backup_dir")" = "700" ] || fail "backups directory must have mode 0700"
        for backup in "$backup_dir"/* "$backup_dir"/.[!.]* "$backup_dir"/..?*; do
            if [ -e "$backup" ] || [ -L "$backup" ]; then
                verify_regular_file "$backup" "recovery backup"
            fi
        done
    fi
    printf 'Verified Mieru manager state directory: %s\n' "$state_dir"
fi
