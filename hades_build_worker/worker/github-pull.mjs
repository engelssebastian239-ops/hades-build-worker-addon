import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { ACTION, VERSION, MAX_MESSAGE_BYTES, verifyResponse } from '../shared/protocol.mjs';

export const GITHUB_API_ORIGIN = 'https://api.github.com';
export const GITHUB_REPOSITORY = 'engelssebastian239-ops/hades-hermes-queue';
export const GITHUB_OWNER = 'engelssebastian239-ops';
export const GITHUB_TASK_SCHEMA = 'HADES_GITHUB_DIAGNOSTIC_V1';
export const GITHUB_TASK_TITLE = 'HADES-DIAGNOSTIC-V1';
export const GITHUB_RESULT_MARKER = '<!-- HADES-DIAGNOSTIC-RESULT-V1 -->';
export const GITHUB_PULL_TOKEN_FILE = '/data/hades-m42.5/github-pull-token';
export const GITHUB_PULL_LEDGER_FILE = '/data/hades-m42.5/github-pull-ledger.json';
export const GITHUB_PULL_INGRESS_PORT = 8766;

const PAGE_SIZE = 30;
const MAX_ISSUE_PAGES = 3;
const MAX_COMMENT_PAGES = 2;
const MAX_TASKS_PER_POLL = 5;
const MAX_API_CALLS_PER_POLL = 20;
const MAX_API_BODY_BYTES = 256 * 1024;
const MAX_FORM_BODY_BYTES = 512;
const MAX_LEDGER_ENTRIES = 2048;
const TOKEN_PATTERN = /^github_pat_[A-Za-z0-9_]{20,}$/;
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const REQUEST_KEYS = ['version','action','brokerId','workerId','taskId','jobId','nonce','issuedAt','expiresAt','kind','signature'];
const LEDGER_STATES = new Set(['PREPARED','POST_ATTEMPTED','POSTED','AMBIGUOUS']);
const REJECTED_ENVELOPE_ERRORS = new Set([
  'invalid_request_schema', 'invalid_request_time', 'invalid_signature_encoding',
  'peer_identity_mismatch', 'request_signature_invalid', 'replay_conflict'
]);

const exact = (value, keys) => !!value && Object.getPrototypeOf(value) === Object.prototype &&
  Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const genericError = code => Object.assign(Error(code), { code });

export function loadGithubPullToken(file = GITHUB_PULL_TOKEN_FILE, {
  lstatSync = fs.lstatSync, readFileSync = fs.readFileSync, uid = process.getuid?.()
} = {}) {
  const st = lstatSync(file);
  if (!st.isFile() || st.isSymbolicLink() || st.uid !== uid || (st.mode & 0o777) !== 0o600 || st.size > 512)
    throw genericError('github_pull_credential_permissions');
  const token = readFileSync(file, 'utf8').trim();
  if (!TOKEN_PATTERN.test(token)) throw genericError('github_pull_credential_invalid');
  return token;
}

export function writeGithubPullToken(file, token, {
  openSync = fs.openSync, writeFileSync = fs.writeFileSync, fstatSync = fs.fstatSync,
  fsyncSync = fs.fsyncSync, closeSync = fs.closeSync, unlinkSync = fs.unlinkSync,
  uid = process.getuid?.()
} = {}) {
  if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) throw genericError('github_pull_token_rejected');
  let fd;
  let created = false;
  try {
    fd = openSync(file, 'wx', 0o600);
    created = true;
    writeFileSync(fd, `${token}\n`, 'utf8');
    fsyncSync(fd);
    const st = fstatSync(fd);
    if (!st.isFile() || st.uid !== uid || (st.mode & 0o777) !== 0o600)
      throw genericError('github_pull_credential_permissions');
    closeSync(fd);
    fd = undefined;
  } catch (error) {
    if (fd !== undefined) { try { closeSync(fd); } catch {} }
    if (!created) throw error.code === 'EEXIST' ? genericError('github_pull_credential_already_exists') : genericError('github_pull_credential_write_failed');
    try { unlinkSync(file); } catch {}
    try { fs.lstatSync(file); } catch (check) { if (check.code === 'ENOENT') throw genericError('github_pull_credential_write_failed'); }
    throw genericError('github_pull_credential_cleanup_failed');
  }
}

async function readBoundedJson(response, limit = MAX_API_BODY_BYTES) {
  if (!String(response.headers?.get?.('content-type') ?? '').toLowerCase().startsWith('application/json') ||
      !response.body?.getReader) throw genericError('github_response_type_invalid');
  const reader = response.body.getReader();
  const chunks = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > limit) throw genericError('github_response_too_large');
      chunks.push(value);
    }
    const all = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { all.set(chunk, offset); offset += chunk.byteLength; }
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(all)); }
    catch { throw genericError('github_response_json_invalid'); }
  } finally {
    await reader.cancel().catch(() => {});
  }
}

async function readLimitedForm(req) {
  if (!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(req.headers['content-type'] ?? ''))
    throw genericError('github_pull_form_type_invalid');
  const announced = req.headers['content-length'] === undefined ? null : Number(req.headers['content-length']);
  if (announced !== null && (!Number.isInteger(announced) || announced < 1 || announced > MAX_FORM_BODY_BYTES))
    throw genericError('github_pull_form_invalid');
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > MAX_FORM_BODY_BYTES) throw genericError('github_pull_form_too_large');
    chunks.push(chunk);
  }
  if (announced !== null && announced !== bytes) throw genericError('github_pull_form_invalid');
  const rawBytes = Buffer.concat(chunks);
  try { return { form: new URLSearchParams(rawBytes.toString('utf8')), bytes: rawBytes }; }
  catch { rawBytes.fill(0); throw genericError('github_pull_form_invalid'); }
}

function ingressPath(req) {
  if (String(req.url ?? '').includes('?')) return null;
  const prefix = typeof req.headers['x-ingress-path'] === 'string' ? req.headers['x-ingress-path'] : '';
  let pathname;
  try { pathname = new URL(req.url || '/', 'http://ingress.local').pathname; } catch { return null; }
  return prefix && pathname.startsWith(prefix) ? (pathname.slice(prefix.length) || '/') : pathname;
}

function sendProvisionPage(res, status, body) {
  const bytes = Buffer.from(body);
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8', 'content-length': bytes.length,
    'cache-control': 'no-store, max-age=0', pragma: 'no-cache',
    'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer',
    'x-frame-options': 'SAMEORIGIN',
    'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'"
  });
  res.end(bytes);
}

const escapeHtml = value => String(value).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const CONFIGURED_PAGE = `<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>H.A.D.E.S. Build Worker</title><main><h1>GitHub Pull Transport</h1><p>Credential ist geschützt eingerichtet. Der Worker prüft ausschließlich signierte Diagnoseaufträge.</p></main></html>`;
const SETUP_PAGE = csrf => `<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer"><title>H.A.D.E.S. Build Worker</title><main><h1>GitHub Pull Transport</h1><p>Einmalige Einrichtung für das private H.A.D.E.S. Diagnose-Repository.</p><form method="post" action=""><input type="hidden" name="csrf" value="${csrf}"><label for="token">GitHub fine-grained token</label><input id="token" name="token" type="password" autocomplete="new-password" autocapitalize="off" spellcheck="false" required><button type="submit">Prüfen und geschützt speichern</button></form><p>Erforderlich: Metadata read und Issues read/write für dieses Repository. Die Eingabe wird nicht protokolliert.</p></main></html>`;

export function createGithubPullProvisioner({
  tokenFile = GITHUB_PULL_TOKEN_FILE,
  fetchFn = globalThis.fetch,
  serverFactory = handler => http.createServer(handler),
  allowIngressPeer = req => String(req.socket?.remoteAddress ?? '').replace(/^::ffff:/, '') === '172.30.32.2',
  onProvisioned = () => {}
} = {}) {
  const csrf = crypto.randomBytes(32).toString('hex');
  let attempts = 0;
  let provisioning = false;
  const authCheck = async token => {
    if (!TOKEN_PATTERN.test(token)) throw genericError('github_pull_token_rejected');
    const headers = {
      authorization: `Bearer ${token}`, accept: 'application/vnd.github+json',
      'x-github-api-version': '2022-11-28', 'user-agent': 'HADES-Build-Worker-Diagnostic-Pull'
    };
    const get = async route => {
      let response;
      try {
        response = await fetchFn(GITHUB_API_ORIGIN + route, {
          method: 'GET', headers, redirect: 'error', credentials: 'omit', cache: 'no-store',
          signal: AbortSignal.timeout(8000)
        });
      } catch { throw genericError('github_pull_token_check_unavailable'); }
      if (!response.ok) throw genericError('github_pull_token_rejected');
      return readBoundedJson(response, 64 * 1024);
    };
    const user = await get('/user');
    const repo = await get('/repos/' + GITHUB_REPOSITORY);
    const issuePage = await get('/repos/' + GITHUB_REPOSITORY + '/issues?state=open&per_page=1&page=1');
    if (user?.login !== GITHUB_OWNER || repo?.full_name !== GITHUB_REPOSITORY || repo?.private !== true ||
        !Array.isArray(issuePage)) throw genericError('github_pull_token_rejected');
  };

  const server = serverFactory(async (req, res) => {
    if (!allowIngressPeer(req)) return sendProvisionPage(res, 403, '<!doctype html><p>Nur Home Assistant Ingress ist zugelassen.</p>');
    const pathname = ingressPath(req);
    req.setTimeout(5000, () => req.destroy());
    if (req.method === 'GET' && pathname === '/') {
      try { loadGithubPullToken(tokenFile); return sendProvisionPage(res, 200, CONFIGURED_PAGE); }
      catch (error) {
        if (error.code !== 'ENOENT') return sendProvisionPage(res, 503, '<!doctype html><p>Credential-Status unsicher. Einrichtung blockiert.</p>');
        return sendProvisionPage(res, 200, SETUP_PAGE(csrf));
      }
    }
    if (req.method !== 'POST' || pathname !== '/') return sendProvisionPage(res, 404, '<!doctype html><p>Nicht gefunden.</p>');
    try { loadGithubPullToken(tokenFile); return sendProvisionPage(res, 409, CONFIGURED_PAGE); }
    catch (error) { if (error.code !== 'ENOENT') return sendProvisionPage(res, 503, '<!doctype html><p>Credential-Status unsicher. Einrichtung blockiert.</p>'); }
    if (attempts >= 3) return sendProvisionPage(res, 429, '<!doctype html><p>Zu viele Versuche. Worker sicher neu starten.</p>');
    if (provisioning) return sendProvisionPage(res, 409, '<!doctype html><p>Prüfung läuft bereits.</p>');
    attempts++;
    provisioning = true;
    let form;
    let formBytes;
    let token = '';
    let tokenStored = false;
    try {
      const parsed = await readLimitedForm(req);
      form = parsed.form;
      formBytes = parsed.bytes;
      if (form.getAll('csrf').length !== 1 || form.getAll('token').length !== 1 ||
          [...form.keys()].some(key => !['csrf','token'].includes(key)))
        throw genericError('github_pull_form_invalid');
      const suppliedCsrf = form.get('csrf') ?? '';
      if (suppliedCsrf.length !== csrf.length || !crypto.timingSafeEqual(Buffer.from(suppliedCsrf), Buffer.from(csrf)))
        throw genericError('github_pull_csrf_rejected');
      token = form.get('token') ?? '';
      await authCheck(token);
      writeGithubPullToken(tokenFile, token);
      tokenStored = true;
      const savedToken = loadGithubPullToken(tokenFile);
      await onProvisioned(savedToken);
      sendProvisionPage(res, 200, '<!doctype html><html lang="de"><meta charset="utf-8"><title>Einrichtung abgeschlossen</title><main><h1>Einrichtung abgeschlossen</h1><p>GitHub-Token geprüft und geschützt gespeichert. Der Worker startet den signierten Diagnose-Pull.</p><p>Der Token wurde nicht ausgegeben.</p></main></html>');
    } catch (error) {
      const unavailable = error.code === 'github_pull_token_check_unavailable';
      if (tokenStored) {
        try { fs.unlinkSync(tokenFile); }
        catch { sendProvisionPage(res, 503, '<!doctype html><p>Aktivierung fehlgeschlagen; Credential-Status unsicher. Worker sicher neu starten und prüfen.</p>'); return; }
      }
      sendProvisionPage(res, unavailable ? 503 : 400,
        unavailable
          ? '<!doctype html><p>GitHub ist nicht erreichbar. Es wurde nichts gespeichert.</p>'
          : '<!doctype html><p>Token oder Einrichtung abgelehnt. Es wurde kein Credential ausgegeben.</p>');
    } finally {
      form?.delete('token');
      formBytes?.fill(0);
      token = '';
      provisioning = false;
    }
  });
  return server;
}

function readPullLedger(file, uid = process.getuid?.()) {
  try {
    const st = fs.lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink() || st.uid !== uid || (st.mode & 0o777) !== 0o600 || st.size > 4 * 1024 * 1024)
      throw genericError('github_pull_ledger_permissions');
    const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!parsed || parsed.version !== 1 || !Array.isArray(parsed.entries) || parsed.entries.length > MAX_LEDGER_ENTRIES)
      throw genericError('github_pull_ledger_invalid');
    const entries = new Map();
    for (const row of parsed.entries) {
      if (!Array.isArray(row) || row.length !== 2 || !/^\d+$/.test(row[0]) || !row[1] ||
          typeof row[1].digest !== 'string' || !LEDGER_STATES.has(row[1].state) || !row[1].response)
        throw genericError('github_pull_ledger_invalid');
      entries.set(row[0], row[1]);
    }
    return entries;
  } catch (error) {
    if (error.code === 'ENOENT') return new Map();
    throw genericError(error.code?.startsWith('github_pull_ledger_') ? error.code : 'github_pull_ledger_unavailable');
  }
}

function persistPullLedger(file, ledger, uid = process.getuid?.()) {
  const directory = path.dirname(file);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const dirStat = fs.lstatSync(directory);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink() || dirStat.uid !== uid || (dirStat.mode & 0o777) !== 0o700)
    throw genericError('github_pull_ledger_directory_permissions');
  const temp = `${file}.tmp-${process.pid}-${crypto.randomUUID()}`;
  let fd;
  try {
    fd = fs.openSync(temp, 'wx', 0o600);
    fs.writeFileSync(fd, JSON.stringify({ version: 1, entries: [...ledger] }), 'utf8');
    fs.fsyncSync(fd);
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.uid !== uid || (st.mode & 0o777) !== 0o600) throw genericError('github_pull_ledger_permissions');
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(temp, file);
    const dirFd = fs.openSync(directory, fs.constants.O_RDONLY);
    try { fs.fsyncSync(dirFd); } finally { fs.closeSync(dirFd); }
  } catch (error) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    try { fs.unlinkSync(temp); } catch {}
    throw genericError(error.code?.startsWith('github_pull_ledger_') ? error.code : 'github_pull_ledger_write_failed');
  }
}

function taskFromIssue(issue) {
  if (!issue || Object.hasOwn(issue, 'pull_request') || issue.state !== 'open' ||
      issue.user?.login !== GITHUB_OWNER || !Number.isSafeInteger(issue.number) || issue.number < 1 ||
      typeof issue.title !== 'string' || typeof issue.body !== 'string' || issue.body.length > MAX_MESSAGE_BYTES)
    return null;
  const titleMatch = new RegExp(`^${GITHUB_TASK_TITLE} (${UUID})$`).exec(issue.title);
  if (!titleMatch) return null;
  let body;
  try { body = JSON.parse(issue.body); } catch { return null; }
  if (!exact(body, ['schema','envelope']) || body.schema !== GITHUB_TASK_SCHEMA ||
      !exact(body.envelope, REQUEST_KEYS) || body.envelope.taskId !== titleMatch[1] ||
      body.envelope.action !== ACTION || body.envelope.version !== VERSION)
    return null;
  return { issueNumber: issue.number, taskId: titleMatch[1], envelope: body.envelope, raw: JSON.stringify(body.envelope) };
}

export function formatGithubDiagnosticResult(response) {
  return `${GITHUB_RESULT_MARKER}\n${JSON.stringify(response)}`;
}

export function createGithubPullTransport({
  token, owner = GITHUB_OWNER, brokerId, workerId, workerPublicKey, receiver,
  ledgerPath = GITHUB_PULL_LEDGER_FILE, fetchFn = globalThis.fetch, clock = Date.now,
  timeoutSignal = AbortSignal.timeout, uid = process.getuid?.()
} = {}) {
  if (owner !== GITHUB_OWNER || !TOKEN_PATTERN.test(token ?? '') || !brokerId || !workerId || !workerPublicKey ||
      !receiver || typeof receiver.handle !== 'function' || !ledgerPath)
    throw genericError('github_pull_configuration_invalid');
  const ledger = readPullLedger(ledgerPath, uid);
  let callCount = 0;
  let pollInFlight = false;

  async function call(method, route, body) {
    if ((route !== '/user' && route !== `/repos/${GITHUB_REPOSITORY}` && !route.startsWith(`/repos/${GITHUB_REPOSITORY}/`)) ||
        route.includes('..') || route.startsWith('//'))
      throw genericError('github_pull_route_rejected');
    if (++callCount > MAX_API_CALLS_PER_POLL) throw genericError('github_pull_request_budget_exceeded');
    let response;
    try {
      response = await fetchFn(GITHUB_API_ORIGIN + route, {
        method,
        headers: {
          authorization: `Bearer ${token}`, accept: 'application/vnd.github+json',
          'x-github-api-version': '2022-11-28', 'user-agent': 'HADES-Build-Worker-Diagnostic-Pull',
          ...(body === undefined ? {} : { 'content-type': 'application/json' })
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        signal: timeoutSignal(8000), redirect: 'error', credentials: 'omit', cache: 'no-store'
      });
    } catch { throw genericError('github_pull_network_failure'); }
    if (!response.ok) {
      const status = response.status;
      const error = genericError(status === 401 || status === 403 ? 'github_pull_authorization_failed' : `github_pull_http_${status}`);
      const retry = Number(response.headers?.get?.('retry-after'));
      const remaining = response.headers?.get?.('x-ratelimit-remaining');
      const reset = Number(response.headers?.get?.('x-ratelimit-reset'));
      if (Number.isFinite(retry) && retry > 0) error.retryAfterMs = Math.min(retry * 1000, 24 * 60 * 60 * 1000);
      else if (remaining === '0' && Number.isFinite(reset) && reset > 0) error.retryAfterMs = Math.min(Math.max(60_000, reset * 1000 - clock() + 5000), 24 * 60 * 60 * 1000);
      throw error;
    }
    return readBoundedJson(response, body === undefined ? MAX_API_BODY_BYTES : 64 * 1024);
  }

  async function listIssues() {
    const all = [];
    for (let page = 1; page <= MAX_ISSUE_PAGES; page++) {
      const rows = await call('GET', `/repos/${GITHUB_REPOSITORY}/issues?state=open&sort=created&direction=desc&per_page=${PAGE_SIZE}&page=${page}`);
      if (!Array.isArray(rows) || rows.length > PAGE_SIZE) throw genericError('github_pull_issue_list_invalid');
      all.push(...rows);
      if (rows.length < PAGE_SIZE) return all;
    }
    throw genericError('github_pull_issue_pagination_limit');
  }

  async function listComments(issueNumber) {
    const all = [];
    for (let page = 1; page <= MAX_COMMENT_PAGES; page++) {
      const rows = await call('GET', `/repos/${GITHUB_REPOSITORY}/issues/${issueNumber}/comments?per_page=100&page=${page}`);
      if (!Array.isArray(rows) || rows.length > 100) throw genericError('github_pull_comment_list_invalid');
      all.push(...rows);
      if (rows.length < 100) return all;
    }
    throw genericError('github_pull_comment_pagination_limit');
  }

  async function reconcileComment(issueNumber, expectedBody) {
    const comments = await listComments(issueNumber);
    const marked = comments.filter(item => typeof item?.body === 'string' && item.body.startsWith(GITHUB_RESULT_MARKER));
    if (marked.length === 0) return 'ABSENT';
    if (marked.length === 1 && marked[0].body === expectedBody && marked[0].user?.login === GITHUB_OWNER) return 'MATCH';
    return 'CONFLICT';
  }

  function persist(issueNumber, row) {
    ledger.set(String(issueNumber), row);
    if (ledger.size > MAX_LEDGER_ENTRIES) throw genericError('github_pull_ledger_full');
    persistPullLedger(ledgerPath, ledger, uid);
  }

  async function processTask(task) {
    const issueKey = String(task.issueNumber);
    const digest = crypto.createHash('sha256').update(task.raw).digest('hex');
    const prior = ledger.get(issueKey);
    if (prior && prior.digest !== digest) return 'CONFLICT';
    if (prior?.state === 'POSTED') return 'ALREADY_POSTED';
    if (prior?.state === 'AMBIGUOUS') return 'AMBIGUOUS';

    let row = prior;
    if (!row) {
      let response;
      try { response = receiver.handle(task.raw); }
      catch (error) {
        if (REJECTED_ENVELOPE_ERRORS.has(error?.code ?? error?.message)) return 'REJECTED';
        throw error;
      }
      const expected = {
        brokerId, workerId, taskId: task.envelope.taskId, jobId: task.envelope.jobId,
        nonce: task.envelope.nonce, kind: task.envelope.kind, expiresAt: task.envelope.expiresAt
      };
      const verified = verifyResponse(response, workerPublicKey, expected, clock());
      const responseBody = formatGithubDiagnosticResult(verified);
      if (Buffer.byteLength(responseBody, 'utf8') > MAX_MESSAGE_BYTES) throw genericError('github_pull_result_too_large');
      row = { digest, state: 'PREPARED', response: verified, responseBody, preparedAt: clock() };
      persist(task.issueNumber, row);
    }

    const expectedBody = formatGithubDiagnosticResult(row.response);
    if (row.responseBody !== expectedBody || Buffer.byteLength(expectedBody, 'utf8') > MAX_MESSAGE_BYTES)
      throw genericError('github_pull_ledger_invalid');

    if (row.state === 'POST_ATTEMPTED') {
      const reconciliation = await reconcileComment(task.issueNumber, expectedBody);
      if (reconciliation === 'MATCH') {
        persist(task.issueNumber, { ...row, state: 'POSTED', reconciledAt: clock() });
        return 'POSTED';
      }
      persist(task.issueNumber, { ...row, state: 'AMBIGUOUS', reconciledAt: clock() });
      return 'AMBIGUOUS';
    }
    if (row.state !== 'PREPARED') return 'CONFLICT';

    const reconciliation = await reconcileComment(task.issueNumber, expectedBody);
    if (reconciliation === 'MATCH') {
      persist(task.issueNumber, { ...row, state: 'POSTED', reconciledAt: clock() });
      return 'POSTED';
    }
    if (reconciliation === 'CONFLICT') {
      persist(task.issueNumber, { ...row, state: 'AMBIGUOUS', reconciledAt: clock() });
      return 'AMBIGUOUS';
    }

    // Persist the attempt before the only POST. A crash or timeout can only
    // reconcile an existing comment; it never sends this result a second time.
    row = { ...row, state: 'POST_ATTEMPTED', postAttemptedAt: clock() };
    persist(task.issueNumber, row);
    try {
      const created = await call('POST', `/repos/${GITHUB_REPOSITORY}/issues/${task.issueNumber}/comments`, { body: expectedBody });
      if (created?.body !== expectedBody || created?.user?.login !== GITHUB_OWNER || !Number.isSafeInteger(created?.id))
        throw genericError('github_pull_post_response_ambiguous');
      persist(task.issueNumber, { ...row, state: 'POSTED', commentId: created.id, postedAt: clock() });
      return 'POSTED';
    } catch {
      // Leave POST_ATTEMPTED durable. The next poll reconciles by comment body.
      throw genericError('github_pull_result_post_ambiguous');
    }
  }

  return Object.freeze({
    async verifyConnection() {
      callCount = 0;
      const user = await call('GET', '/user');
      const repo = await call('GET', `/repos/${GITHUB_REPOSITORY}`);
      const issues = await call('GET', `/repos/${GITHUB_REPOSITORY}/issues?state=open&per_page=1&page=1`);
      if (user?.login !== GITHUB_OWNER || repo?.full_name !== GITHUB_REPOSITORY || repo?.private !== true || !Array.isArray(issues))
        throw genericError('github_pull_repository_identity_rejected');
      return true;
    },
    async pollOnce() {
      if (pollInFlight) throw genericError('github_pull_poll_already_running');
      pollInFlight = true;
      callCount = 0;
      try {
        const repo = await call('GET', `/repos/${GITHUB_REPOSITORY}`);
        if (repo?.full_name !== GITHUB_REPOSITORY || repo?.private !== true)
          throw genericError('github_pull_repository_identity_rejected');
        const issues = await listIssues();
        const counts = { inspected: 0, posted: 0, alreadyPosted: 0, ambiguous: 0,
          conflicts: 0, rejected: 0, deferred: 0 };
        let acceptedThisPoll = 0;
        for (const issue of issues) {
          const task = taskFromIssue(issue);
          if (!task) { counts.rejected++; continue; }

          const prior = ledger.get(String(task.issueNumber));
          const digest = crypto.createHash('sha256').update(task.raw).digest('hex');
          if (prior && prior.digest !== digest) { counts.conflicts++; continue; }
          if (prior?.state === 'POSTED') { counts.alreadyPosted++; continue; }
          if (prior?.state === 'AMBIGUOUS') { counts.ambiguous++; continue; }
          if (acceptedThisPoll >= MAX_TASKS_PER_POLL) { counts.deferred++; continue; }

          counts.inspected++;
          const state = await processTask(task);
          if (state !== 'REJECTED') acceptedThisPoll++;
          if (state === 'POSTED') counts.posted++;
          else if (state === 'AMBIGUOUS') counts.ambiguous++;
          else if (state === 'CONFLICT') counts.conflicts++;
          else if (state === 'ALREADY_POSTED') counts.alreadyPosted++;
          else if (state === 'REJECTED') counts.rejected++;
        }
        return Object.freeze(counts);
      } finally {
        pollInFlight = false;
      }
    },
    snapshot: () => Object.freeze({ entries: ledger.size, requestsThisPoll: callCount })
  });
}

export function startGithubPullLoop(transport, { pollSeconds = 120, log = () => {}, timers = globalThis } = {}) {
  if (!Number.isInteger(pollSeconds) || pollSeconds < 60 || pollSeconds > 3600)
    throw genericError('github_pull_poll_interval_invalid');
  let stopped = false;
  let timer = null;
  let failures = 0;
  const poll = async () => {
    if (stopped) return;
    let delay = pollSeconds * 1000;
    try {
      const counts = await transport.pollOnce();
      failures = 0;
      log({ state: 'GITHUB_PULL_OK', ...counts });
    } catch (error) {
      failures++;
      delay = Number.isFinite(error.retryAfterMs)
        ? Math.min(Math.max(1000, error.retryAfterMs), 24 * 60 * 60 * 1000)
        : Math.min(pollSeconds * 1000 * 2 ** Math.min(failures - 1, 4), 15 * 60 * 1000);
      log({ state: 'GITHUB_PULL_FAILED', error: /^[a-z0-9_]+$/i.test(error.code ?? '') ? error.code : 'github_pull_failure', retryInSeconds: Math.ceil(delay / 1000) });
    }
    if (!stopped) timer = timers.setTimeout(poll, delay);
  };
  void poll();
  return () => { stopped = true; if (timer) timers.clearTimeout(timer); };
}
