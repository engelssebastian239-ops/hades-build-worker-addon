import test from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
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

function runLocalProbe(source, rmShim = null) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'hades-m35-probe-test-'));
  const dataRoot = path.join(sandbox, 'data');
  const binRoot = path.join(sandbox, 'bin');
  fs.mkdirSync(dataRoot);
  fs.mkdirSync(binRoot);
  fs.writeFileSync(path.join(binRoot, 'id'), '#!/bin/sh\ncase "$1" in -u|-g) printf "1000\\n";; *) exit 2;; esac\n');
  fs.chmodSync(path.join(binRoot, 'id'), 0o755);
  if (rmShim) {
    fs.writeFileSync(path.join(binRoot, 'rm'), rmShim);
    fs.chmodSync(path.join(binRoot, 'rm'), 0o755);
  }

  const localSource = source.replaceAll('/data', dataRoot);
  const result = spawnSync('/bin/sh', ['-c', localSource], {
    cwd: sandbox,
    encoding: 'utf8',
    env: { HOME: sandbox, PATH: `${binRoot}:/usr/bin:/bin` },
  });
  const remainingProbeFiles = fs.readdirSync(dataRoot)
    .filter(name => name.startsWith('.hades-m35-puller-permission-probe.'));
  const outcome = {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    remainingProbeFiles,
  };
  fs.rmSync(sandbox, { recursive: true, force: true });
  return outcome;
}

test('permission probe is a diagnostic-only image for the existing puller add-on identity', () => {
  const manifest = fs.readFileSync(path.join(appRoot, 'config.yaml'), 'utf8');
  const dockerfile = read('Dockerfile');

  assert.match(manifest, /^slug:\s*"hades_m35_puller"\s*$/m);
  assert.match(manifest, /^boot:\s*manual_only\s*$/m);
  assert.match(manifest, /^map:\s*\[\]\s*$/m);
  assert.match(manifest, /^ports:\s*\{\}\s*$/m);
  assert.match(manifest, /^ingress:\s*true\s*$/m);
  assert.match(manifest, /^ingress_port:\s*8099\s*$/m);
  for (const flag of ['host_network', 'host_ipc', 'host_pid', 'host_uts', 'host_dbus', 'homeassistant_api', 'hassio_api', 'docker_api', 'full_access']) {
    assert.match(manifest, new RegExp(`^${flag}:\\s*false\\s*$`, 'm'));
  }
  assert.equal(fs.existsSync(path.join(diagnosticRoot, 'config.yaml')), false);
  assert.match(dockerfile, /^FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402\s*$/m);
  assert.deepEqual(
    dockerfile.match(/^COPY .*$/gm),
    ['COPY diagnostics/probe.sh /usr/local/bin/m35-data-permission-probe'],
  );
  assert.doesNotMatch(dockerfile, /m35-source|config\.json|tools\/|\bADD\b/i);
  assert.match(dockerfile, /id -u node.*1000/);
  assert.match(dockerfile, /id -g node.*1000/);
  assert.match(dockerfile, /^USER node:node$/m);
  assert.match(dockerfile, /^ENTRYPOINT \["\/usr\/local\/bin\/m35-data-permission-probe"\]$/m);
});

test('probe reports identity and permissions, writes one unique secret-free file, and verifies cleanup', () => {
  const script = read('probe.sh');

  assert.match(script, /^#!\/bin\/sh\nset -eu/m);
  assert.match(script, /id -u/);
  assert.match(script, /id -g/);
  assert.match(script, /stat -c .*\/data/);
  assert.match(script, /mktemp \/data\/\.hades-m35-puller-permission-probe\.XXXXXX/);
  assert.match(script, /printf 'm35-data-permission-probe\\n' > "\$probe_file"/);
  assert.match(script, /stat -c .*probe_file/);
  assert.match(script, /rm -f -- "\$probe_file"/);
  assert.match(script, /test ! -e "\$probe_file"/);
  assert.match(script, /probe_file_removed=yes/);
  assert.match(script, /trap cleanup EXIT/);
  assert.doesNotMatch(script, /https?:|fetch\(|curl|wget|node |child_process|docker|supervisor|github|token|private.?key/i);
});

test('probe removes and confirms the temporary file on success and ordinary post-create failures', () => {
  const source = read('probe.sh');
  const successful = runLocalProbe(source);
  assert.equal(successful.status, 0);
  assert.match(successful.stdout, /probe_write_confirmed=yes/);
  assert.match(successful.stdout, /probe_file_removed=yes/);
  assert.deepEqual(successful.remainingProbeFiles, []);

  const failedWriteSource = source.replace(
    '(umask 077; printf \'m35-data-permission-probe\\n\' > "$probe_file")',
    '(umask 077; false > "$probe_file")',
  );
  assert.notEqual(failedWriteSource, source);
  const failedWrite = runLocalProbe(failedWriteSource);
  assert.notEqual(failedWrite.status, 0);
  assert.match(failedWrite.stdout, /probe_file_removed=yes/);
  assert.deepEqual(failedWrite.remainingProbeFiles, []);

  const failedStatSource = source.replace(
    'stat -c \'probe_owner=%u:%g probe_mode=%a path=%n\' "$probe_file"',
    'false',
  );
  assert.notEqual(failedStatSource, source);
  const failedStat = runLocalProbe(failedStatSource);
  assert.notEqual(failedStat.status, 0);
  assert.match(failedStat.stdout, /probe_write_confirmed=yes/);
  assert.match(failedStat.stdout, /probe_file_removed=yes/);
  assert.deepEqual(failedStat.remainingProbeFiles, []);
});

test('probe retries a transient cleanup failure and confirms the file is gone', () => {
  const source = read('probe.sh');
  const marker = path.join(os.tmpdir(), `hades-m35-rm-once-${process.pid}`);
  fs.rmSync(marker, { force: true });
  const rmShim = `#!/bin/sh\nif [ ! -e '${marker}' ]; then : > '${marker}'; exit 1; fi\nexec /bin/rm "$@"\n`;

  try {
    const result = runLocalProbe(source, rmShim);
    assert.equal(result.status, 0);
    assert.match(result.stdout, /probe_file_removed=yes/);
    assert.deepEqual(result.remainingProbeFiles, []);
  } finally {
    fs.rmSync(marker, { force: true });
  }
});
