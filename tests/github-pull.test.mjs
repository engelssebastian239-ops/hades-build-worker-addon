import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ACTION, TTL_MS, VERSION, identityId, signRequest, verifyResponse } from '../hades_build_worker/shared/protocol.mjs';
import { createDiagnosticBrokerKey } from '../hades_build_worker/tools/create-diagnostic-broker-key.mjs';
import { createSignedDiagnosticRequest } from '../hades_build_worker/tools/sign-diagnostic-request.mjs';
import { createDiagnosticReceiver } from '../hades_build_worker/worker/main.mjs';
import {
  GITHUB_OWNER, GITHUB_REPOSITORY, GITHUB_TASK_SCHEMA, GITHUB_TASK_TITLE, GITHUB_RESULT_MARKER,
  createGithubPullProvisioner, createGithubPullTransport, formatGithubDiagnosticResult,
  loadGithubPullToken, writeGithubPullToken
} from '../hades_build_worker/worker/github-pull.mjs';

const token = 'github_pat_' + 'A'.repeat(35);
const jsonResponse = (value, status = 200, extraHeaders = {}) => new Response(JSON.stringify(value), {
  status, headers: { 'content-type': 'application/json', ...extraHeaders }
});
const privateRepositoryResponse = parsed => parsed.pathname === `/repos/${GITHUB_REPOSITORY}`
  ? jsonResponse({ full_name: GITHUB_REPOSITORY, private: true }) : null;

function tempDir(prefix = 'hades-github-pull-') {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  fs.chmodSync(dir, 0o700);
  return dir;
}

function memoryProvisioner(options = {}) {
  let handler;const timeoutEvents=[];
  createGithubPullProvisioner({
    ...options,
    serverFactory: callback => { handler = callback; return {}; }
  });
  return { request: async ({ method = 'GET', url = '/', peer = '172.30.32.2', body = '' } = {}) => {
    const raw = Buffer.from(body);
    const req = {
      method, url, headers: { ...(body ? { 'content-type': 'application/x-www-form-urlencoded', 'content-length': String(raw.length) } : {}) },
      socket: { remoteAddress: peer }, setTimeout(ms) { timeoutEvents.push(ms); },
      async *[Symbol.asyncIterator]() { if (raw.length) yield raw; }
    };
    const result = { status: 0, headers: {}, body: '' };
    const res = {
      writeHead(status, headers) { result.status = status; result.headers = headers; },
      end(data) { result.body = Buffer.isBuffer(data) ? data.toString('utf8') : String(data ?? ''); }
    };
    await handler(req, res);
    return result;
  },timeoutEvents };
}

function requestFixture({ broker, worker, now, kind = 'STATUS_CHECK', changes = {} }) {
  const brokerId = identityId(broker.publicKey);
  const workerId = identityId(worker.publicKey);
  const fields = {
    version: VERSION, action: ACTION, brokerId, workerId,
    taskId: crypto.randomUUID(), jobId: crypto.randomUUID(), nonce: crypto.randomUUID(),
    issuedAt: now, expiresAt: now + 60_000, kind, ...changes
  };
  return { brokerId, workerId, envelope: signRequest(fields, broker.privateKey) };
}

function taskIssue(envelope, { number = 7, user = GITHUB_OWNER, title, body, state = 'open', pullRequest = false } = {}) {
  const issue = {
    number, user: { login: user }, title: title ?? `${GITHUB_TASK_TITLE} ${envelope.taskId}`,
    body: body ?? JSON.stringify({ schema: GITHUB_TASK_SCHEMA, envelope }), state
  };
  if (pullRequest) issue.pull_request = { url: 'https://api.github.com/pulls/7' };
  return issue;
}

function testWorker({ now = Date.now() } = {}) {
  const broker = crypto.generateKeyPairSync('ed25519');
  const worker = crypto.generateKeyPairSync('ed25519');
  const { brokerId, workerId } = requestFixture({ broker, worker, now });
  const dir = tempDir();
  const receiver = createDiagnosticReceiver({ enabled: true, brokerId, trustedBrokerPublicKey: broker.publicKey,
    workerPrivateKey: worker.privateKey, ledgerPath: path.join(dir, 'diagnostic-ledger.json'), clock: () => now });
  return { broker, worker, brokerId, workerId, dir, receiver, now };
}

test('pull credential file is exclusive, owned, mode 0600, non-symlink, and never returned by the setup page', async () => {
  const dir = tempDir();
  const file = path.join(dir, 'github-pull-token');
  const helper = { uid: process.getuid() };
  writeGithubPullToken(file, token, helper);
  assert.equal(loadGithubPullToken(file, helper), token);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.throws(() => writeGithubPullToken(file, token, helper), /github_pull_credential_already_exists/);
  const link = path.join(dir, 'token-link');
  fs.symlinkSync(file, link);
  assert.throws(() => loadGithubPullToken(link, helper), /github_pull_credential_permissions/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('Ingress setup requires the Supervisor peer and CSRF, verifies fixed owner/private repo, stores token without echo', async () => {
  const dir = tempDir();
  const tokenFile = path.join(dir, 'github-pull-token');
  const calls = [];
  let activated = '';
  const provisioner = memoryProvisioner({ tokenFile,
    fetchFn: async (url, init) => {
      calls.push({ url, init });
      assert.equal(init.redirect, 'error');
      assert.equal(init.credentials, 'omit');
      assert.equal(init.headers.authorization, `Bearer ${token}`);
      if (url.endsWith('/user')) return jsonResponse({ login: GITHUB_OWNER });
      if (url.endsWith(`/repos/${GITHUB_REPOSITORY}`)) return jsonResponse({ full_name: GITHUB_REPOSITORY, private: true });
      if (url.includes(`/repos/${GITHUB_REPOSITORY}/issues?`)) return jsonResponse([]);
      throw Error('unexpected_route');
    },
    onProvisioned: async saved => { activated = saved; }
  });
  const denied = await provisioner.request({ peer: '127.0.0.1' });
  const page = await provisioner.request();
  const csrf = /name="csrf" value="([a-f0-9]{64})"/.exec(page.body)?.[1];
  assert.ok(csrf);
  const bad = await provisioner.request({ method: 'POST', body: new URLSearchParams({ csrf: '0'.repeat(64), token }).toString() });
  assert.equal(bad.status, 400);
  assert.equal(fs.existsSync(tokenFile), false);
  const accepted = await provisioner.request({ method: 'POST', body: new URLSearchParams({ csrf, token }).toString() });
  assert.equal(accepted.status, 200);
  assert.doesNotMatch(accepted.body, new RegExp(token));
  assert.equal(activated, token);
  assert.equal(loadGithubPullToken(tokenFile), token);
  assert.equal(fs.statSync(tokenFile).mode & 0o777, 0o600);
  assert.equal(calls.length, 3);
  assert.equal(denied.status, 403);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('optional Mobile read preflight runs before shared credential persistence',async t=>{
  await t.test('preflight rejection leaves no token file',async()=>{
    const dir=tempDir(),tokenFile=path.join(dir,'github-pull-token'),order=[];
    const provisioner=memoryProvisioner({tokenFile,mobileInstallEnabled:true,
      fetchFn:async url=>{assert.equal(provisioner.timeoutEvents.at(-1),0);return url.endsWith('/user')?jsonResponse({login:GITHUB_OWNER}):url.endsWith(`/repos/${GITHUB_REPOSITORY}`)?jsonResponse({full_name:GITHUB_REPOSITORY,private:true}):jsonResponse([]);},
      validateToken:async()=>{order.push('preflight');assert.equal(provisioner.timeoutEvents.at(-1),0);assert.equal(fs.existsSync(tokenFile),false);await new Promise(resolve=>setTimeout(resolve,10));throw Object.assign(Error('mobile preflight rejected'),{code:'mobile_github_contents_read_unverified'});}});
    const page=await provisioner.request();assert.match(page.body,/Contents read und Actions read/);
    const csrf=/name="csrf" value="([a-f0-9]{64})"/.exec(page.body)[1];
    const response=await provisioner.request({method:'POST',body:new URLSearchParams({csrf,token}).toString()});
    assert.equal(response.status,400);assert.deepEqual(order,['preflight']);assert.equal(provisioner.timeoutEvents.at(-1),0);assert.equal(fs.existsSync(tokenFile),false);assert.doesNotMatch(response.body,new RegExp(token));fs.rmSync(dir,{recursive:true,force:true});
  });
  await t.test('successful preflight completes before file exists, then stores mode 0600',async()=>{
    const dir=tempDir(),tokenFile=path.join(dir,'github-pull-token'),order=[];
    const provisioner=memoryProvisioner({tokenFile,mobileInstallEnabled:true,
      fetchFn:async url=>url.endsWith('/user')?jsonResponse({login:GITHUB_OWNER}):url.endsWith(`/repos/${GITHUB_REPOSITORY}`)?jsonResponse({full_name:GITHUB_REPOSITORY,private:true}):jsonResponse([]),
      validateToken:async()=>{order.push('preflight');assert.equal(fs.existsSync(tokenFile),false);},
      onProvisioned:async()=>{order.push('persisted');assert.equal(fs.statSync(tokenFile).mode&0o777,0o600);}});
    const page=await provisioner.request(),csrf=/name="csrf" value="([a-f0-9]{64})"/.exec(page.body)[1];
    const response=await provisioner.request({method:'POST',body:new URLSearchParams({csrf,token}).toString()});
    assert.equal(response.status,200);assert.deepEqual(order,['preflight','persisted']);assert.equal(loadGithubPullToken(tokenFile),token);fs.rmSync(dir,{recursive:true,force:true});
  });
});

test('provisioner rejects wrong GitHub owner and leaves no credential file', async () => {
  const dir = tempDir();
  const tokenFile = path.join(dir, 'github-pull-token');
  const provisioner = memoryProvisioner({ tokenFile,
    fetchFn: async url => url.endsWith('/user') ? jsonResponse({ login: 'attacker' }) : jsonResponse({}) });
  const page = await provisioner.request();
  const csrf = /name="csrf" value="([a-f0-9]{64})"/.exec(page.body)[1];
  const res = await provisioner.request({ method: 'POST', body: new URLSearchParams({ csrf, token }).toString() });
  assert.equal(res.status, 400);
  assert.equal(fs.existsSync(tokenFile), false);
  assert.doesNotMatch(res.body, new RegExp(token));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('poll relays only signed owner issue envelope and posts the exact worker-signed result once', async () => {
  const env = testWorker();
  const fixture = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const issue = taskIssue(fixture.envelope);
  const comments = [];
  const routes = [];
  let handleCount = 0;
  const receiver = { handle(raw) { handleCount++; return env.receiver.handle(raw); } };
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver, ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      routes.push({ url, init });
      assert.equal(parsed.origin, 'https://api.github.com');
      assert.equal(init.redirect, 'error');
      assert.equal(init.credentials, 'omit');
      assert.equal(init.headers.authorization, `Bearer ${token}`);
      if (parsed.pathname === '/user') return jsonResponse({ login: GITHUB_OWNER });
      if (parsed.pathname === `/repos/${GITHUB_REPOSITORY}`) return jsonResponse({ full_name: GITHUB_REPOSITORY, private: true });
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse([issue]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'GET') return jsonResponse(comments);
      if (parsed.pathname.endsWith('/comments') && init.method === 'POST') {
        const body = JSON.parse(init.body).body;
        const comment = { id: 42, body, user: { login: GITHUB_OWNER } };
        comments.push(comment);
        return jsonResponse(comment, 201);
      }
      throw Error('unexpected_route');
    }
  });
  await transport.verifyConnection();
  const first = await transport.pollOnce();
  assert.equal(first.posted, 1);
  assert.equal(handleCount, 1);
  assert.equal(comments.length, 1);
  assert.ok(comments[0].body.startsWith(GITHUB_RESULT_MARKER + '\n'));
  const signedResult = JSON.parse(comments[0].body.slice(GITHUB_RESULT_MARKER.length + 1));
  const verified = verifyResponse(signedResult, env.worker.publicKey, {
    brokerId: env.brokerId, workerId: env.workerId, taskId: fixture.envelope.taskId,
    jobId: fixture.envelope.jobId, nonce: fixture.envelope.nonce, kind: 'STATUS_CHECK', expiresAt: fixture.envelope.expiresAt
  }, env.now);
  assert.equal(verified.result.executionEnabled, false);
  assert.equal(routes.filter(row => row.init.method === 'POST').length, 1);
  const second = await transport.pollOnce();
  assert.equal(second.alreadyPosted, 1);
  assert.equal(handleCount, 1);
  assert.equal(routes.filter(row => row.init.method === 'POST').length, 1);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('terminal issues do not occupy the five active task slots and a sixth valid issue is processed next poll', async () => {
  const env = testWorker();
  const fixtures = Array.from({ length: 6 }, () => requestFixture({ broker: env.broker, worker: env.worker, now: env.now }));
  const issues = fixtures.map((fixture, index) => taskIssue(fixture.envelope, { number: index + 1 }));
  const comments = new Map();
  let posts = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: env.receiver,
    ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      const repoResponse = privateRepositoryResponse(parsed);
      if (repoResponse) return repoResponse;
      const commentIssue = /\/issues\/(\d+)\/comments$/.exec(parsed.pathname)?.[1];
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse(issues);
      if (commentIssue && init.method === 'GET') return jsonResponse(comments.get(commentIssue) ?? []);
      if (commentIssue && init.method === 'POST') {
        posts++;
        const comment = { id: posts, body: JSON.parse(init.body).body, user: { login: GITHUB_OWNER } };
        comments.set(commentIssue, [comment]);
        return jsonResponse(comment, 201);
      }
      throw Error('unexpected_route');
    }
  });
  const first = await transport.pollOnce();
  assert.equal(first.posted, 5);
  assert.equal(first.deferred, 1);
  assert.equal(posts, 5);
  const second = await transport.pollOnce();
  assert.equal(second.alreadyPosted, 5);
  assert.equal(second.posted, 1);
  assert.equal(posts, 6);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('invalid signature and expired envelope before a valid issue are rejected without blocking it', async () => {
  const env = testWorker();
  const invalidSignature = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const expired = requestFixture({ broker: env.broker, worker: env.worker, now: env.now - 120_000 });
  const valid = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const issues = [
    taskIssue({ ...invalidSignature.envelope, signature: 'A'.repeat(86) }, { number: 1 }),
    taskIssue(expired.envelope, { number: 2 }),
    taskIssue(valid.envelope, { number: 3 })
  ];
  const comments = [];
  let handleCount = 0;
  let posts = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey,
    receiver: { handle(raw) { handleCount++; return env.receiver.handle(raw); } },
    ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      const repoResponse = privateRepositoryResponse(parsed);
      if (repoResponse) return repoResponse;
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse(issues);
      if (parsed.pathname.endsWith('/comments') && init.method === 'GET') return jsonResponse(comments);
      if (parsed.pathname.endsWith('/comments') && init.method === 'POST') {
        posts++;
        const comment = { id: posts, body: JSON.parse(init.body).body, user: { login: GITHUB_OWNER } };
        comments.push(comment);
        return jsonResponse(comment, 201);
      }
      throw Error('unexpected_route');
    }
  });
  const counts = await transport.pollOnce();
  assert.equal(counts.rejected, 2);
  assert.equal(counts.posted, 1);
  assert.equal(handleCount, 3);
  assert.equal(posts, 1);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('overlapping pollOnce calls are rejected and can issue at most one result comment', async () => {
  const env = testWorker();
  const fixture = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const issue = taskIssue(fixture.envelope);
  const comments = [];
  let posts = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: env.receiver,
    ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      const repoResponse = privateRepositoryResponse(parsed);
      if (repoResponse) return repoResponse;
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse([issue]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'GET') return jsonResponse(comments);
      if (parsed.pathname.endsWith('/comments') && init.method === 'POST') {
        posts++;
        const comment = { id: posts, body: JSON.parse(init.body).body, user: { login: GITHUB_OWNER } };
        comments.push(comment);
        return jsonResponse(comment, 201);
      }
      throw Error('unexpected_route');
    }
  });
  const [first, second] = await Promise.allSettled([transport.pollOnce(), transport.pollOnce()]);
  assert.equal(first.status, 'fulfilled');
  assert.equal(second.status, 'rejected');
  assert.equal(second.reason.code, 'github_pull_poll_already_running');
  assert.equal(posts, 1);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('each poll rechecks that the fixed repository is still private before handling issues', async () => {
  const env = testWorker();
  const fixture = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  let repositoryPrivate = true;
  let handleCount = 0;
  let posts = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: { handle(raw) { handleCount++; return env.receiver.handle(raw); } },
    ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      if (parsed.pathname === '/user') return jsonResponse({ login: GITHUB_OWNER });
      if (parsed.pathname === `/repos/${GITHUB_REPOSITORY}`)
        return jsonResponse({ full_name: GITHUB_REPOSITORY, private: repositoryPrivate });
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse([taskIssue(fixture.envelope)]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'GET') return jsonResponse([]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'POST') { posts++; return jsonResponse({}, 201); }
      throw Error('unexpected_route');
    }
  });
  await transport.verifyConnection();
  repositoryPrivate = false;
  await assert.rejects(transport.pollOnce(), /github_pull_repository_identity_rejected/);
  assert.equal(handleCount, 0);
  assert.equal(posts, 0);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('strict issue owner, title, body schema, and PR filtering prevent receiver invocation', async () => {
  const env = testWorker();
  const fixture = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const issues = [
    taskIssue(fixture.envelope, { number: 1, user: 'other' }),
    taskIssue(fixture.envelope, { number: 2, title: 'HADES-DIAGNOSTIC-V1 extra ' + fixture.envelope.taskId }),
    taskIssue(fixture.envelope, { number: 3, body: JSON.stringify({ schema: GITHUB_TASK_SCHEMA, envelope: fixture.envelope, extra: true }) }),
    taskIssue(fixture.envelope, { number: 4, pullRequest: true })
  ];
  let handleCount = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: { handle() { handleCount++; throw Error('must_not_run'); } },
    ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      const repoResponse = privateRepositoryResponse(parsed);
      if (repoResponse) return repoResponse;
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse(issues);
      throw Error('unexpected_route');
    }
  });
  const counts = await transport.pollOnce();
  assert.equal(counts.inspected, 0);
  assert.equal(handleCount, 0);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('ambiguous comment timeout is durably at-most-once and later recovery only reconciles', async () => {
  const env = testWorker();
  const fixture = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const issue = taskIssue(fixture.envelope);
  const comments = [];
  let posts = 0;
  let failPost = true;
  let handleCount = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: { handle(raw) { handleCount++; return env.receiver.handle(raw); } },
    ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      const repoResponse = privateRepositoryResponse(parsed);
      if (repoResponse) return repoResponse;
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse([issue]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'GET') return jsonResponse(comments);
      if (parsed.pathname.endsWith('/comments') && init.method === 'POST') {
        posts++;
        if (failPost) { failPost = false; throw Error('connection_lost_after_possible_write'); }
        throw Error('must_not_retry');
      }
      throw Error('unexpected_route');
    }
  });
  await assert.rejects(transport.pollOnce(), /github_pull_result_post_ambiguous/);
  let ledger = JSON.parse(fs.readFileSync(path.join(env.dir, 'github-ledger.json'), 'utf8'));
  assert.equal(ledger.entries[0][1].state, 'POST_ATTEMPTED');
  const recoveredBody = ledger.entries[0][1].responseBody;
  comments.push({ id: 99, body: recoveredBody, user: { login: GITHUB_OWNER } });
  const recovered = await transport.pollOnce();
  assert.equal(recovered.posted, 1);
  assert.equal(posts, 1);
  assert.equal(handleCount, 1);
  ledger = JSON.parse(fs.readFileSync(path.join(env.dir, 'github-ledger.json'), 'utf8'));
  assert.equal(ledger.entries[0][1].state, 'POSTED');
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('ambiguous missing result comment is terminal and never sends a second POST', async () => {
  const env = testWorker();
  const fixture = requestFixture({ broker: env.broker, worker: env.worker, now: env.now });
  const issue = taskIssue(fixture.envelope);
  let posts = 0;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: env.receiver, ledgerPath: path.join(env.dir, 'github-ledger.json'), clock: () => env.now,
    fetchFn: async (url, init) => {
      const parsed = new URL(url);
      const repoResponse = privateRepositoryResponse(parsed);
      if (repoResponse) return repoResponse;
      if (parsed.pathname.endsWith('/issues') && init.method === 'GET') return jsonResponse([issue]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'GET') return jsonResponse([]);
      if (parsed.pathname.endsWith('/comments') && init.method === 'POST') { posts++; throw Error('unknown_commit_state'); }
      throw Error('unexpected_route');
    }
  });
  await assert.rejects(transport.pollOnce(), /github_pull_result_post_ambiguous/);
  const counts = await transport.pollOnce();
  assert.equal(counts.ambiguous, 1);
  assert.equal(posts, 1);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('oversized API responses and pagination overflow fail closed before handling tasks', async () => {
  const env = testWorker();
  const oversized = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: env.receiver, ledgerPath: path.join(env.dir, 'large-ledger.json'),
    fetchFn: async () => new Response(JSON.stringify({ data: 'x'.repeat(300 * 1024) }), { headers: { 'content-type': 'application/json' } })
  });
  await assert.rejects(oversized.pollOnce(), /github_response_too_large/);
  const fullPage = Array.from({ length: 30 }, (_, i) => ({ number: i + 1 }));
  const overflow = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: env.receiver, ledgerPath: path.join(env.dir, 'overflow-ledger.json'),
    fetchFn: async url => new URL(url).pathname === `/repos/${GITHUB_REPOSITORY}`
      ? jsonResponse({ full_name: GITHUB_REPOSITORY, private: true }) : jsonResponse(fullPage)
  });
  await assert.rejects(overflow.pollOnce(), /github_pull_issue_pagination_limit/);
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('GitHub API calls are fixed to an 8-second abort signal and fail closed on timeout', async () => {
  const env = testWorker();
  let timeoutMs = 0;
  let seenSignal;
  const transport = createGithubPullTransport({ token, brokerId: env.brokerId, workerId: env.workerId,
    workerPublicKey: env.worker.publicKey, receiver: { handle() { throw Error('must_not_run'); } },
    ledgerPath: path.join(env.dir, 'timeout-ledger.json'),
    timeoutSignal: ms => { timeoutMs = ms; return { aborted: true }; },
    fetchFn: async (_url, init) => {
      seenSignal = init.signal;
      if (init.signal.aborted) throw Error('aborted');
      return jsonResponse([]);
    }
  });
  await assert.rejects(transport.pollOnce(), /github_pull_network_failure/);
  assert.equal(timeoutMs, 8000);
  assert.deepEqual(seenSignal, { aborted: true });
  fs.rmSync(env.dir, { recursive: true, force: true });
});

test('result formatter contains only the signed response and fixed marker', () => {
  const formatted = formatGithubDiagnosticResult({ signature: 'x', state: 'COMPLETED' });
  assert.equal(formatted, `${GITHUB_RESULT_MARKER}\n{"signature":"x","state":"COMPLETED"}`);
  assert.equal(GITHUB_REPOSITORY, 'engelssebastian239-ops/hades-hermes-queue');
});

test('broker key helper never removes an existing key when exclusive creation fails', () => {
  const dir = tempDir();
  const file = path.join(dir, 'broker-ed25519.pem');
  const first = createDiagnosticBrokerKey(file);
  assert.equal(first.privateKeyPrinted, false);
  const original = fs.readFileSync(file);
  const originalMode = fs.statSync(file).mode & 0o777;
  assert.throws(() => createDiagnosticBrokerKey(file), /broker_key_already_exists/);
  assert.deepEqual(fs.readFileSync(file), original);
  assert.equal(fs.statSync(file).mode & 0o777, originalMode);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('signing helper uses the full bounded diagnostic TTL without printing the private key', () => {
  const dir = tempDir();
  const privatePath = path.join(dir, 'broker-ed25519.pem');
  createDiagnosticBrokerKey(privatePath);
  const worker = crypto.generateKeyPairSync('ed25519');
  const workerPublicKeyBase64 = worker.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  const output = createSignedDiagnosticRequest(privatePath, workerPublicKeyBase64, 'STATUS_CHECK');
  const body = JSON.parse(output.body);
  assert.equal(body.envelope.expiresAt - body.envelope.issuedAt, TTL_MS);
  assert.equal(output.privateKeyPrinted, false);
  fs.rmSync(dir, { recursive: true, force: true });
});
