import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const appRoot = path.join(repositoryRoot, 'hades_m35_puller');
const diagnosticRoot = path.join(appRoot, 'diagnostics');

function read(relativePath) {
  return fs.readFileSync(path.join(diagnosticRoot, relativePath), 'utf8');
}

test('probe image is isolated and starts root only for the diagnostic bootstrap', () => {
  const manifest = fs.readFileSync(path.join(appRoot, 'config.yaml'), 'utf8');
  const dockerfile = fs.readFileSync(path.join(appRoot, 'Dockerfile'), 'utf8');

  assert.match(manifest, /^slug:\s*"hades_m35_puller"\s*$/m);
  assert.match(manifest, /^boot:\s*manual_only\s*$/m);
  assert.match(manifest, /^map:\s*\[\]\s*$/m);
  assert.match(manifest, /^ports:\s*\{\}\s*$/m);
  for (const flag of ['host_network', 'host_ipc', 'host_pid', 'host_uts', 'host_dbus', 'homeassistant_api', 'hassio_api', 'docker_api', 'full_access', 'ingress']) {
    assert.match(manifest, new RegExp('^' + flag + ':\\s*false\\s*$', 'm'));
  }
  assert.equal(fs.existsSync(path.join(diagnosticRoot, 'config.yaml')), false);
  assert.match(dockerfile, /^FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402\s*$/m);
  assert.deepEqual(
    dockerfile.match(/^COPY .*$/gm),
    ['COPY diagnostics/probe.sh /usr/local/bin/m35-data-permission-probe'],
  );
  assert.match(dockerfile, /apk add --no-cache su-exec/);
  assert.match(dockerfile, /id -u node.*1000/);
  assert.match(dockerfile, /id -g node.*1000/);
  assert.match(dockerfile, /^USER root$/m);
  assert.match(dockerfile, /^ENTRYPOINT \["\/usr\/local\/bin\/m35-data-permission-probe"\]$/m);
  assert.doesNotMatch(dockerfile, /m35-source|config\.json|tools\//i);
});

test('probe creates a unique node-owned private directory, verifies node write, and cleans up', () => {
  const script = read('probe.sh');

  assert.match(script, /^#!\/bin\/sh\nset -eu/m);
  assert.match(script, /id -u/);
  assert.match(script, /id -g/);
  assert.match(script, /stat -c .*\/data/);
  assert.match(script, /mktemp -d \/data\/\.hades-m35-puller-permission-probe\.XXXXXX/);
  assert.match(script, /chown 1000:1000/);
  assert.match(script, /chmod 0700/);
  assert.match(script, /su-exec 1000:1000/);
  assert.match(script, /printf "m35-data-permission-probe/);
  assert.match(script, /1000:1000:600/);
  assert.match(script, /probe_write_confirmed=yes/);
  assert.match(script, /rm -rf -- "\$probe_dir"/);
  assert.match(script, /if \[ -e "\$probe_dir" \]; then/);
  assert.match(script, /PROBE_CLEANUP_FAILED/);
  assert.match(script, /probe_file_removed=yes/);
  assert.match(script, /trap cleanup EXIT/);
  assert.doesNotMatch(script, /https?:|fetch\(|curl|wget|docker|supervisor|github|token|private.?key/i);

  const syntax = spawnSync('/bin/sh', ['-n'], { input: script, encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
});
