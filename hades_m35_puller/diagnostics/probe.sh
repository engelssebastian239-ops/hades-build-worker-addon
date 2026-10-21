#!/bin/sh
set -eu

uid=$(id -u)
gid=$(id -g)
printf 'process_uid=%s process_gid=%s\n' "$uid" "$gid"

probe_file=
cleanup() {
  probe_status=$?
  trap - EXIT HUP INT TERM
  if [ -n "${probe_file:-}" ]; then
    if [ -e "$probe_file" ]; then
      rm -f -- "$probe_file" 2>/dev/null || true
    fi
    if ! test ! -e "$probe_file"; then
      rm -f -- "$probe_file" 2>/dev/null || true
    fi
    if ! test ! -e "$probe_file"; then
      printf 'PROBE_CLEANUP_FAILED: temporary_file_remains=%s\n' "$probe_file" >&2
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

if [ ! -d /data ] || [ -L /data ]; then
  printf '%s\n' 'PROBE_FAILED: data_directory_missing_or_symlink' >&2
  exit 78
fi
stat -c 'data_owner=%u:%g data_mode=%a path=%n' /data

if [ "$uid" -ne 1000 ] || [ "$gid" -ne 1000 ]; then
  printf '%s\n' 'PROBE_FAILED: unexpected_process_identity' >&2
  exit 78
fi

probe_file=$(mktemp /data/.hades-m35-puller-permission-probe.XXXXXX)
if [ ! -f "$probe_file" ] || [ -L "$probe_file" ]; then
  printf '%s\n' 'PROBE_FAILED: temporary_file_creation_invalid' >&2
  exit 1
fi

(umask 077; printf 'm35-data-permission-probe\n' > "$probe_file")
probe_contents=$(cat "$probe_file")
if [ "$probe_contents" != 'm35-data-permission-probe' ]; then
  printf '%s\n' 'PROBE_FAILED: temporary_file_write_mismatch' >&2
  exit 1
fi
printf '%s\n' 'probe_write_confirmed=yes'
stat -c 'probe_owner=%u:%g probe_mode=%a path=%n' "$probe_file"
