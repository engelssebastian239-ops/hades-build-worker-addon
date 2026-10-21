#!/bin/sh
set -eu

uid=$(id -u)
gid=$(id -g)
printf 'bootstrap_uid=%s bootstrap_gid=%s\n' "$uid" "$gid"

probe_dir=
cleanup() {
  probe_status=$?
  trap - EXIT HUP INT TERM
  if [ -n "${probe_dir:-}" ]; then
    if [ -e "$probe_dir" ]; then
      rm -rf -- "$probe_dir" 2>/dev/null || true
    fi
    if [ -e "$probe_dir" ]; then
      rm -rf -- "$probe_dir" 2>/dev/null || true
    fi
    if [ -e "$probe_dir" ]; then
      printf 'PROBE_CLEANUP_FAILED: temporary_directory_remains=%s\n' "$probe_dir" >&2
      exit 1
    fi
    printf '%s\n' 'probe_file_removed=yes'
  fi
  exit "$probe_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$uid" -ne 0 ] || [ "$gid" -ne 0 ]; then
  printf '%s\n' 'PROBE_FAILED: bootstrap_not_root' >&2
  exit 78
fi
if [ ! -d /data ] || [ -L /data ]; then
  printf '%s\n' 'PROBE_FAILED: data_directory_missing_or_symlink' >&2
  exit 78
fi
stat -c 'data_owner=%u:%g data_mode=%a path=%n' /data

if [ "$(id -u node)" -ne 1000 ] || [ "$(id -g node)" -ne 1000 ]; then
  printf '%s\n' 'PROBE_FAILED: node_identity_unexpected' >&2
  exit 78
fi
command -v su-exec >/dev/null 2>&1 || {
  printf '%s\n' 'PROBE_FAILED: su_exec_missing' >&2
  exit 78
}

probe_dir=$(mktemp -d /data/.hades-m35-puller-permission-probe.XXXXXX)
chown 1000:1000 "$probe_dir"
chmod 0700 "$probe_dir"
if [ "$(stat -c '%u:%g:%a' "$probe_dir")" != '1000:1000:700' ]; then
  printf '%s\n' 'PROBE_FAILED: protected_directory_owner_or_mode_mismatch' >&2
  exit 1
fi
printf '%s\n' 'protected_directory_owner=1000:1000 mode=700'

probe_file="$probe_dir/probe"
su-exec 1000:1000 /bin/sh -eu -c '
  umask 077
  printf "m35-data-permission-probe\\n" > "$1"
  test "$(cat "$1")" = "m35-data-permission-probe"
' sh "$probe_file"
printf '%s\n' 'probe_write_confirmed=yes'
stat -c 'probe_owner=%u:%g probe_mode=%a path=%n' "$probe_file"
