#!/bin/sh
set -eu

expected_uid=1000
secrets_dir=/data/hades-dev-workspace/hades-m35-secrets-20261011
token_file="$secrets_dir/github-token"

if [ "$(id -u)" -ne "$expected_uid" ] || [ "$(id -un)" != "node" ]; then
  printf '%s\n' 'START_BLOCKED: wrong_runtime_identity' >&2
  exit 78
fi
if [ ! -d "$secrets_dir" ] || [ -L "$secrets_dir" ]; then
  printf '%s\n' 'START_BLOCKED: protected_data_directory_missing' >&2
  exit 78
fi
if [ "$(stat -c '%u:%a' "$secrets_dir")" != '1000:700' ]; then
  printf '%s\n' 'START_BLOCKED: protected_data_directory_permissions' >&2
  exit 78
fi
if [ ! -w "$secrets_dir" ]; then
  printf '%s\n' 'START_BLOCKED: protected_data_directory_not_writable' >&2
  exit 78
fi
if [ ! -f "$token_file" ] || [ -L "$token_file" ] || [ ! -r "$token_file" ]; then
  printf '%s\n' 'START_BLOCKED: credential_missing_or_unreadable' >&2
  exit 78
fi

exec node /opt/hades-m35-puller/src/worker.mjs --loop
