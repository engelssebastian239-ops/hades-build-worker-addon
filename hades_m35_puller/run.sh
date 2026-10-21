#!/bin/sh
set -eu

workspace_dir=/data/hades-dev-workspace
secrets_dir="$workspace_dir/hades-m35-secrets-20261011"
state_dir="$secrets_dir/state"
token_file="$secrets_dir/github-token"

blocked() {
  printf 'START_BLOCKED: %s\n' "$1" >&2
  exit 78
}

if [ "$(id -u)" -ne 0 ] || [ "$(id -g)" -ne 0 ]; then
  blocked root_bootstrap_required
fi
if [ ! -d /data ] || [ -L /data ]; then
  blocked data_directory_missing_or_symlink
fi
if [ "$(id -u node)" -ne 1000 ] || [ "$(id -g node)" -ne 1000 ]; then
  blocked node_identity_unexpected
fi
command -v su-exec >/dev/null 2>&1 || blocked su_exec_missing

if [ -L "$workspace_dir" ]; then
  blocked workspace_directory_is_symlink
fi
if [ ! -e "$workspace_dir" ]; then
  mkdir -m 0755 -- "$workspace_dir" || blocked workspace_directory_create_failed
  chmod 0755 -- "$workspace_dir" || blocked workspace_directory_mode_failed
fi
if [ ! -d "$workspace_dir" ] || [ -L "$workspace_dir" ]; then
  blocked workspace_path_not_directory
fi
su-exec 1000:1000 test -x "$workspace_dir" || blocked workspace_directory_not_traversable

for directory in "$secrets_dir" "$state_dir"; do
  if [ -L "$directory" ]; then
    blocked protected_directory_is_symlink
  fi
  if [ ! -e "$directory" ]; then
    mkdir -m 0700 -- "$directory" || blocked protected_directory_create_failed
  fi
  if [ ! -d "$directory" ] || [ -L "$directory" ]; then
    blocked protected_path_not_directory
  fi
  chown node:node -- "$directory" || blocked protected_directory_owner_failed
  chmod 0700 -- "$directory" || blocked protected_directory_mode_failed
done

# Only known files in this app's dedicated secret directory are adjusted.
# Symlinks and unexpected file types fail closed; no recursive chown is used.
for secret_file in \
  "$token_file" \
  "$secrets_dir/provision-private.pem" \
  "$secrets_dir/provision-public.pem" \
  "$secrets_dir/public-for-windows.json" \
  "$secrets_dir/github-token.enc"; do
  if [ -e "$secret_file" ] || [ -L "$secret_file" ]; then
    if [ ! -f "$secret_file" ] || [ -L "$secret_file" ]; then
      blocked protected_file_invalid
    fi
    chown node:node -- "$secret_file" || blocked protected_file_owner_failed
    chmod 0600 -- "$secret_file" || blocked protected_file_mode_failed
  fi
done

if [ "$(stat -c '%u:%a' "$secrets_dir")" != '1000:700' ]; then
  blocked protected_data_directory_permissions
fi
if [ "$(stat -c '%u:%a' "$state_dir")" != '1000:700' ]; then
  blocked state_directory_permissions
fi
if [ ! -f "$token_file" ] || [ -L "$token_file" ] || \
   [ "$(stat -c '%u:%a' "$token_file")" != '1000:600' ]; then
  blocked credential_missing_or_insecure
fi

export HOME=/home/node USER=node LOGNAME=node
exec su-exec 1000:1000 node /opt/hades-m35-puller/src/worker.mjs --loop
