import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertTrustedPublicKeyFingerprint,
  createPublicKeyDocument,
} from '../hades_m35_puller/m35-source/src/rsa-oaep.mjs';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const appRoot = path.join(repositoryRoot, 'hades_m35_puller');

function readApp(relativePath) {
  return fs.readFileSync(path.join(appRoot, relativePath), 'utf8');
}

test('root repository metadata and top-level app manifest make the puller discoverable beside the Build Worker', () => {
  const repository = fs.readFileSync(path.join(repositoryRoot, 'repository.yaml'), 'utf8');
  const appDirectories = fs.readdirSync(repositoryRoot, { withFileTypes: true })
    .filter(entry => entry.isDirectory() && fs.existsSync(path.join(repositoryRoot, entry.name, 'config.yaml')))
    .map(entry => entry.name);

  assert.match(repository, /^name:\s*"H\.A\.D\.E\.S\. Apps"\s*$/m);
  assert.match(repository, /^url:\s*"https:\/\/github\.com\/engelssebastian239-ops\/hades-build-worker-addon"\s*$/m);
  assert.ok(appDirectories.includes('hades_build_worker'));
  assert.ok(appDirectories.includes('hades_m35_puller'));
  assert.match(readApp('config.yaml'), /^slug:\s*"hades_m35_puller"\s*$/m);
});

test('app is manual-start, intake-only, and cannot execute issue content', () => {
  const manifest = readApp('config.yaml');
  const config = JSON.parse(readApp('config.json'));
  const worker = readApp('m35-source/src/worker.mjs');
  const task = readApp('m35-source/src/task.mjs');
  const toolsDirectory = path.join(appRoot, 'm35-source/tools');
  const runScript = readApp('run.sh');

  assert.match(manifest, /^boot:\s*manual_only\s*$/m);
  assert.match(manifest, /^arch:\n  - aarch64\n  - amd64\s*$/m);
  assert.match(manifest, /^map:\s*\[\]\s*$/m);
  for (const flag of ['host_network', 'host_ipc', 'host_pid', 'host_uts', 'homeassistant_api', 'hassio_api', 'docker_api', 'full_access', 'ingress']) {
    assert.match(manifest, new RegExp(`^${flag}:\\s*false\\s*$`, 'm'));
  }
  assert.equal(config.mode, 'intake-only');
  assert.match(task, /t\.action!==['"]proposal-only['"]/);
  assert.match(worker, /No model call, no code, no shell/);
  assert.doesNotMatch(worker, /child_process|execSync|spawn\(/);
  assert.ok(fs.existsSync(path.join(toolsDirectory, 'encrypt-github-token.mjs')));
  assert.equal(fs.readdirSync(toolsDirectory).some(file => file.endsWith('.ps1')), false);
  assert.match(runScript, /worker\.mjs --loop/);
  assert.match(runScript, /! -w "\$secrets_dir"/);
});

test('Node 22 Alpine OCI index is pinned and declares ARM64', () => {
  const dockerfile = readApp('Dockerfile');
  const manifest = readApp('config.yaml');
  assert.match(dockerfile, /^FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402\s*$/m);
  assert.match(manifest, /^arch:\n  - aarch64\n  - amd64\s*$/m);
  assert.match(dockerfile, /test "\$\(id -u node\)" = "1000"/);
  assert.match(dockerfile, /^USER node:node$/m);
});

test('provisioner requires an independently supplied fingerprint and verifies it before reading the private key', () => {
  const source = readApp('m35-source/tools/provision-github-token.mjs');
  const verify = source.indexOf('assertTrustedPublicKeyFingerprint(publicKeyDocument,trustedFingerprint)');
  const privateKeyRead = source.indexOf("fs.readFileSync(keyFile,'utf8')");
  const githubRequest = source.indexOf("fetch('https://api.github.com'");

  assert.match(source, /process\.env\.HADES_M35_TRUSTED_PUBLIC_KEY_SHA256/);
  assert.ok(verify >= 0 && verify < privateKeyRead && privateKeyRead < githubRequest);
});

test('trusted fingerprint accepts only the independently matching public key', () => {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 });
  const document = createPublicKeyDocument(pair.publicKey.export({ type: 'spki', format: 'pem' }));
  const serialized = JSON.stringify(document);

  assert.equal(assertTrustedPublicKeyFingerprint(serialized, document.publicKeySha256), document.publicKeySha256);
  assert.throws(() => assertTrustedPublicKeyFingerprint(serialized, '0'.repeat(64)), /trusted_public_key_fingerprint_mismatch/);
  assert.throws(() => assertTrustedPublicKeyFingerprint(serialized, undefined), /trusted_public_key_fingerprint_required/);
});
