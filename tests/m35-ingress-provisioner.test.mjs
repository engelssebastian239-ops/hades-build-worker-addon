import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { once } from 'node:events';
import { createProvisionServer } from '../hades_m35_puller/m35-source/tools/ingress-provisioner.mjs';

const token = 'github_pat_' + 'A'.repeat(35);

async function withServer(options, run) {
  const server = createProvisionServer({
    tokenFile: options.tokenFile,
    allowIngressPeer: options.allowIngressPeer ?? (() => true),
    fetchFn: options.fetchFn ?? (async url => {
      if (url.endsWith('/user')) return { ok: true, json: async () => ({ login: 'engelssebastian239-ops' }) };
      if (url.endsWith('/repos/engelssebastian239-ops/hades-hermes-queue')) {
        return { ok: true, json: async () => ({ full_name: 'engelssebastian239-ops/hades-hermes-queue', private: true }) };
      }
      if (url.endsWith('/issues/1')) return { ok: true, json: async () => ({ number: 1 }) };
      throw Error('unexpected_test_request');
    }),
    startWorker: options.startWorker ?? (() => ({ exitCode: null, kill() {} })),
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  try {
    await run('http://127.0.0.1:' + server.address().port);
  } finally {
    server.close();
    await once(server, 'close');
  }
}

function csrfFrom(html) {
  const match = html.match(/name="csrf" value="([a-f0-9]{64})"/);
  assert.ok(match);
  return match[1];
}

test('ingress provisioning rejects non-ingress peers and does not contact GitHub', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hades-ingress-deny-'));
  try {
    let contacted = false;
    await withServer({
      tokenFile: path.join(dir, 'github-token'),
      allowIngressPeer: () => false,
      fetchFn: async () => { contacted = true; throw Error('must_not_call'); },
    }, async base => {
      const response = await fetch(base + '/');
      assert.equal(response.status, 403);
      assert.equal(contacted, false);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('token is accepted only with the session form nonce, validated, stored 0600, and never returned', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hades-ingress-ok-'));
  const tokenFile = path.join(dir, 'github-token');
  let workerStarts = 0;
  try {
    await withServer({ tokenFile, startWorker: () => { workerStarts++; return { exitCode: null, kill() {} }; } }, async base => {
      const page = await fetch(base + '/');
      assert.equal(page.status, 200);
      const html = await page.text();
      const csrf = csrfFrom(html);
      assert.match(html, /type="password"/);
      const denied = await fetch(base + '/', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf: '0'.repeat(64), token }),
      });
      assert.equal(denied.status, 400);
      assert.equal(fs.existsSync(tokenFile), false);
      assert.equal(workerStarts, 0);

      const response = await fetch(base + '/', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf, token }),
      });
      const responseText = await response.text();
      assert.equal(response.status, 200);
      assert.match(responseText, /Einrichtung abgeschlossen/);
      assert.doesNotMatch(responseText, new RegExp(token));
      assert.equal(fs.readFileSync(tokenFile, 'utf8'), token + '\n');
      assert.equal(fs.statSync(tokenFile).mode & 0o777, 0o600);
      assert.equal(workerStarts, 1);

      const duplicate = await fetch(base + '/', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ csrf, token }),
      });
      assert.equal(duplicate.status, 409);
      assert.equal(workerStarts, 1);
    });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
