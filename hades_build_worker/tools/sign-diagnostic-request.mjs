import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, createPublicKey, randomUUID } from 'node:crypto';
import { ACTION, VERSION, TTL_MS, ALLOWED_KINDS, identityId, signRequest } from '../shared/protocol.mjs';

const fail = code => { throw Error(code); };

export function createSignedDiagnosticRequest(privateKeyPath, workerPublicKeyBase64, kind) {
  if (!privateKeyPath || !workerPublicKeyBase64 || !ALLOWED_KINDS.includes(kind))
    fail('usage_sign_diagnostic_request_private_key_path_worker_public_key_base64_kind');
  if (workerPublicKeyBase64.length < 40 || workerPublicKeyBase64.length > 512 || !/^[A-Za-z0-9+/]+={0,2}$/.test(workerPublicKeyBase64))
    fail('worker_public_key_invalid');
  const stat = fs.lstatSync(privateKeyPath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0 || stat.size > 4096)
    fail('broker_private_key_permissions');
  const privateKey = createPrivateKey(fs.readFileSync(privateKeyPath));
  if (privateKey.asymmetricKeyType !== 'ed25519') fail('broker_private_key_type_invalid');
  const publicKey = createPublicKey(privateKey);
  const brokerId = identityId(publicKey);
  const workerPublicKey = createPublicKey({ key: Buffer.from(workerPublicKeyBase64, 'base64'), format: 'der', type: 'spki' });
  const workerId = identityId(workerPublicKey);
  const issuedAt = Date.now();
  const taskId = randomUUID();
  const envelope = signRequest({
    version: VERSION, action: ACTION, brokerId, workerId, taskId, jobId: randomUUID(), nonce: randomUUID(),
    issuedAt, expiresAt: issuedAt + TTL_MS, kind
  }, privateKey);
  const title = `HADES-DIAGNOSTIC-V1 ${taskId}`;
  const body = JSON.stringify({ schema: 'HADES_GITHUB_DIAGNOSTIC_V1', envelope });
  return { title, body, brokerId, workerId, taskId, kind, expiresAt: envelope.expiresAt, privateKeyPrinted: false };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const [privateKeyPath, workerPublicKeyBase64, kind] = process.argv.slice(2);
    if (process.argv.length !== 5) fail('usage_sign_diagnostic_request_private_key_path_worker_public_key_base64_kind');
    console.log(JSON.stringify(createSignedDiagnosticRequest(privateKeyPath, workerPublicKeyBase64, kind)));
  } catch (error) {
    console.error(/^[a-z0-9_]+$/i.test(error?.message ?? '') ? error.message : 'broker_request_signing_failed');
    process.exitCode = 1;
  }
}
