import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { writeProvisionedCredential } from '../src/credential-file.mjs';

const CONFIG_FILE = '/opt/hades-m35-puller/config.json';
const TOKEN_FILE = '/data/hades-dev-workspace/hades-m35-secrets-20261011/github-token';
const INGRESS_PEER = '172.30.32.2';
const PORT = 8099;
const MAX_BODY_BYTES = 512;
const TOKEN_PATTERN = /^(github_pat_|ghp_)[A-Za-z0-9_]{20,}$/;

const PAGE = `<!doctype html>
<html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>H.A.D.E.S. Puller</title>
<style>body{font:16px system-ui;max-width:34rem;margin:3rem auto;padding:0 1rem;background:#101827;color:#edf2ff}main{padding:1.5rem;border:1px solid #405273;border-radius:1rem}input,button{box-sizing:border-box;width:100%;padding:1rem;margin:.6rem 0;border-radius:.7rem;font:inherit}input{background:#09111e;color:white;border:1px solid #405273}button{background:#1683a4;color:white;border:0;font-weight:700}.note{color:#aebbd0}</style>
<main><h1>H.A.D.E.S. M3.5 Puller</h1><p>Einmalige sichere Einrichtung</p>
<form method="post" action=""><input type="hidden" name="csrf" value="__CSRF__">
<label for="token">GitHub fine-grained token</label>
<input id="token" name="token" type="password" autocomplete="new-password" autocapitalize="off" spellcheck="false" required>
<button type="submit">Token sicher prüfen und speichern</button></form>
<p class="note">Eingabe wird nicht protokolliert. Der Token wird nur nach erfolgreicher Prüfung lokal mit Modus 0600 gespeichert.</p></main></html>`;

function send(res, status, body) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'SAMEORIGIN',
    'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'self'",
  });
  res.end(body);
}

function routePath(req) {
  const prefix = typeof req.headers['x-ingress-path'] === 'string' ? req.headers['x-ingress-path'] : '';
  let pathname;
  try { pathname = new URL(req.url || '/', 'http://ingress.local').pathname; } catch { return null; }
  if (prefix && pathname.startsWith(prefix)) pathname = pathname.slice(prefix.length) || '/';
  return pathname;
}

function peerAllowed(req) {
  const peer = req.socket.remoteAddress?.replace(/^::ffff:/, '');
  return peer === INGRESS_PEER;
}

async function readBody(req) {
  const lengthHeader = req.headers['content-length'];
  const announced = lengthHeader === undefined ? null : Number(lengthHeader);
  if (announced !== null && (!Number.isInteger(announced) || announced < 1 || announced > MAX_BODY_BYTES)) {
    throw Error('invalid_body');
  }
  const chunks = [];
  let total = 0;
  for await (const chunk of req) {
    total += chunk.length;
    if (total > MAX_BODY_BYTES) throw Error('body_too_large');
    chunks.push(chunk);
  }
  if (announced !== null && total !== announced) throw Error('invalid_body');
  return Buffer.concat(chunks);
}

function equalSecret(actual, expected) {
  if (typeof actual !== 'string' || actual.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(actual), Buffer.from(expected));
}

async function verifyToken(token, repository, authorizedAccount, fetchFn) {
  if (!TOKEN_PATTERN.test(token)) throw Error('token_rejected');
  const headers = {
    Authorization: 'Bearer ' + token,
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'HADES-HERMES-M35-provisioner',
  };
  async function get(url) {
    let response;
    try {
      response = await fetchFn('https://api.github.com' + url, {
        headers, signal: AbortSignal.timeout(12000), redirect: 'error',
      });
    } catch {
      throw Error('token_check_unavailable');
    }
    if (!response.ok) throw Error('token_rejected');
    return response.json();
  }
  const user = await get('/user');
  if (user.login !== authorizedAccount) throw Error('token_rejected');
  const repo = await get('/repos/' + repository);
  if (repo.full_name !== repository || repo.private !== true) throw Error('token_rejected');
  const issue = await get('/repos/' + repository + '/issues/1');
  if (issue.number !== 1) throw Error('token_rejected');
}

export function createProvisionServer({
  tokenFile = TOKEN_FILE,
  repository = 'engelssebastian239-ops/hades-hermes-queue',
  authorizedAccount = 'engelssebastian239-ops',
  fetchFn = globalThis.fetch,
  allowIngressPeer = peerAllowed,
  startWorker = () => spawn(process.execPath, [
    path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../src/worker.mjs'),
    '--loop',
  ], { stdio: 'inherit', shell: false }),
} = {}) {
  const csrf = crypto.randomBytes(32).toString('hex');
  let attempts = 0;
  let provisioning = false;
  let worker = null;

  const server = http.createServer(async (req, res) => {
    if (!allowIngressPeer(req)) return send(res, 403, '<!doctype html><p>Nur Home Assistant Ingress ist zugelassen.</p>');
    const pathname = routePath(req);
    if (req.method === 'GET' && pathname === '/') {
      if (fs.existsSync(tokenFile)) {
        if (!worker) worker = startWorker();
        return send(res, 200, '<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>H.A.D.E.S. Puller</title><main><h1>H.A.D.E.S. M3.5 Puller</h1><p>Token ist eingerichtet. Der Intake-only Worker läuft.</p><p>Issue-Inhalte werden nicht ausgeführt.</p></main></html>');
      }
      return send(res, 200, PAGE.replace('__CSRF__', csrf));
    }
    if (req.method !== 'POST' || pathname !== '/') return send(res, 404, '<!doctype html><p>Nicht gefunden.</p>');
    if (fs.existsSync(tokenFile)) return send(res, 409, '<!doctype html><p>Einrichtung bereits abgeschlossen.</p>');
    if (attempts >= 3) return send(res, 429, '<!doctype html><p>Zu viele Versuche. Starte das Add-on neu.</p>');
    if (provisioning) return send(res, 409, '<!doctype html><p>Prüfung läuft bereits.</p>');
    attempts++;
    provisioning = true;
    let raw;
    let token;
    try {
      if (!/^application\/x-www-form-urlencoded(?:\s*;|$)/i.test(req.headers['content-type'] || '')) {
        throw Error('invalid_content_type');
      }
      raw = await readBody(req);
      const form = new URLSearchParams(raw.toString('utf8'));
      if (!equalSecret(form.get('csrf'), csrf)) throw Error('invalid_csrf');
      token = form.get('token') || '';
      await verifyToken(token, repository, authorizedAccount, fetchFn);
      writeProvisionedCredential(tokenFile, token);
      worker = startWorker();
      send(res, 200, '<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>H.A.D.E.S. Puller</title><main><h1>Einrichtung abgeschlossen</h1><p>Token geprüft und geschützt gespeichert. Der Intake-only Worker wurde gestartet.</p><p>Der Token wurde nicht ausgegeben.</p></main></html>');
    } catch (error) {
      const message = error.message === 'token_check_unavailable'
        ? 'GitHub ist gerade nicht erreichbar. Bitte später erneut versuchen.'
        : 'Token konnte nicht bestätigt werden. Prüfe die GitHub-Berechtigungen und versuche es erneut.';
      send(res, error.message === 'token_check_unavailable' ? 503 : 400,
        '<!doctype html><html lang="de"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Einrichtung</title><main><h1>Einrichtung nicht abgeschlossen</h1><p>' + message + '</p><p><a href="">Zurück</a></p></main></html>');
    } finally {
      raw?.fill(0);
      token = '';
      provisioning = false;
    }
  });

  server.on('close', () => {
    if (worker && worker.exitCode === null) worker.kill('SIGTERM');
  });
  return server;
}

async function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(config.repository) ||
      !Array.isArray(config.authorizedAuthors) || config.authorizedAuthors.length !== 1) {
    throw Error('invalid_fixed_configuration');
  }
  const server = createProvisionServer({
    tokenFile: config.tokenFile,
    repository: config.repository,
    authorizedAccount: config.authorizedAuthors[0],
  });
  server.listen(PORT, '0.0.0.0', () => {
    console.log('PROVISION_UI_READY ingress_only=true token_logged=false');
  });
  const stop = () => server.close();
  process.once('SIGTERM', stop);
  process.once('SIGINT', stop);
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(() => {
    console.error('PROVISION_UI_START_BLOCKED');
    process.exitCode = 1;
  });
}
