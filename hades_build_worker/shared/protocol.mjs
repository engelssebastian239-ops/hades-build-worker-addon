import { createHash, createPublicKey, sign, verify } from 'node:crypto';

export const VERSION = 'HADES_DIAGNOSTIC_TASK_V1';
export const ACTION = 'diagnostic-only';
export const ALLOWED_KINDS = Object.freeze(['STATUS_CHECK', 'HEARTBEAT_CHECK', 'QUEUE_HEALTH_CHECK']);
export const TTL_MS = 300_000;
export const MAX_MESSAGE_BYTES = 4096;
export const QUEUE_CAPACITY = 3;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const FINGERPRINT = /^sha256:[0-9a-f]{64}$/;
const REQUEST_KEYS = ['version','action','brokerId','workerId','taskId','jobId','nonce','issuedAt','expiresAt','kind','signature'];
const RESPONSE_KEYS = ['version','brokerId','workerId','taskId','jobId','nonce','issuedAt','expiresAt','kind','state','result','signature'];

function exactObject(value, keys) {
  return !!value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function validSignature(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{86}$/.test(value);
}
function validFingerprint(value) {
  return typeof value === 'string' && FINGERPRINT.test(value);
}
function publicKeyOf(key) {
  return key?.type === 'public' ? key : createPublicKey(key);
}
export function identityId(publicKey) {
  return 'sha256:' + createHash('sha256').update(publicKeyOf(publicKey).export({type:'spki',format:'der'})).digest('hex');
}
function requestFields(value, now) {
  if (!exactObject(value, REQUEST_KEYS) || value.version !== VERSION || value.action !== ACTION ||
      !validFingerprint(value.brokerId) || !validFingerprint(value.workerId) ||
      !UUID.test(value.taskId) || !UUID.test(value.jobId) || !UUID.test(value.nonce) ||
      !ALLOWED_KINDS.includes(value.kind)) throw Error('invalid_request_schema');
  if (!Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
      value.issuedAt > now + 5000 || value.expiresAt <= now ||
      value.expiresAt <= value.issuedAt || value.expiresAt - value.issuedAt > TTL_MS)
    throw Error('invalid_request_time');
  if (!validSignature(value.signature)) throw Error('invalid_signature_encoding');
  return value;
}
function resultValid(kind, result) {
  if (kind === 'STATUS_CHECK')
    return exactObject(result, ['component','version','state','executionEnabled','uptimeSeconds']) &&
      result.component === 'HADES_BUILD_WORKER' && result.version === '0.0.4-dev.m4.2.5' &&
      result.state === 'READY' && result.executionEnabled === false &&
      Number.isSafeInteger(result.uptimeSeconds) && result.uptimeSeconds >= 0;
  if (kind === 'HEARTBEAT_CHECK')
    return exactObject(result, ['state','uptimeSeconds','observedAt']) && result.state === 'ALIVE' &&
      Number.isSafeInteger(result.uptimeSeconds) && result.uptimeSeconds >= 0 &&
      Number.isSafeInteger(result.observedAt);
  if (kind === 'QUEUE_HEALTH_CHECK')
    return exactObject(result, ['state','depth','capacity','ledgerEntries','executable']) &&
      result.state === 'HEALTHY' && result.depth === 0 && result.capacity === QUEUE_CAPACITY &&
      Number.isSafeInteger(result.ledgerEntries) && result.ledgerEntries >= 0 &&
      result.executable === false;
  return false;
}
function responseFields(value, now) {
  if (!exactObject(value, RESPONSE_KEYS) || value.version !== VERSION ||
      !validFingerprint(value.brokerId) || !validFingerprint(value.workerId) ||
      !UUID.test(value.taskId) || !UUID.test(value.jobId) || !UUID.test(value.nonce) ||
      !ALLOWED_KINDS.includes(value.kind) || value.state !== 'COMPLETED' ||
      !resultValid(value.kind, value.result)) throw Error('invalid_response_schema');
  if (!Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt) ||
      value.issuedAt > now + 5000 || value.expiresAt <= now || value.expiresAt <= value.issuedAt ||
      value.expiresAt - value.issuedAt > TTL_MS) throw Error('invalid_response_time');
  if (!validSignature(value.signature)) throw Error('invalid_signature_encoding');
  return value;
}
const requestBytes = value => Buffer.from(JSON.stringify([
  value.version,value.action,value.brokerId,value.workerId,value.taskId,value.jobId,
  value.nonce,value.issuedAt,value.expiresAt,value.kind
]));
const responseBytes = value => Buffer.from(JSON.stringify([
  value.version,value.brokerId,value.workerId,value.taskId,value.jobId,value.nonce,
  value.issuedAt,value.expiresAt,value.kind,value.state,value.result
]));

export function signRequest(fields, privateKey) {
  const value = {...fields, signature:''};
  value.signature = sign(null, requestBytes(value), privateKey).toString('base64url');
  return Object.freeze({...requestFields(value, fields.issuedAt)});
}
export function verifyRequest(value, trustedBrokerPublicKey, {brokerId,workerId,now=Date.now()} = {}) {
  const checked = requestFields(value, now);
  const publicKey = publicKeyOf(trustedBrokerPublicKey);
  if (identityId(publicKey) !== checked.brokerId || checked.brokerId !== brokerId ||
      checked.workerId !== workerId) throw Error('peer_identity_mismatch');
  if (!verify(null, requestBytes(checked), publicKey, Buffer.from(checked.signature,'base64url')))
    throw Error('request_signature_invalid');
  return Object.freeze({...checked});
}
export function signResponse(fields, workerPrivateKey) {
  const value = {...fields, signature:''};
  value.signature = sign(null, responseBytes(value), workerPrivateKey).toString('base64url');
  return Object.freeze({...responseFields(value, fields.issuedAt)});
}
export function verifyResponse(value, trustedWorkerPublicKey, expected, now=Date.now()) {
  const checked = responseFields(value, now);
  const publicKey = publicKeyOf(trustedWorkerPublicKey);
  if (identityId(publicKey) !== checked.workerId || checked.workerId !== expected.workerId ||
      checked.brokerId !== expected.brokerId || checked.taskId !== expected.taskId ||
      checked.jobId !== expected.jobId || checked.nonce !== expected.nonce ||
      checked.kind !== expected.kind || checked.expiresAt !== expected.expiresAt)
    throw Error('response_correlation_failed');
  if (!verify(null, responseBytes(checked), publicKey, Buffer.from(checked.signature,'base64url')))
    throw Error('response_signature_invalid');
  return Object.freeze({...checked});
}
export const replayKey = value => [value.brokerId,value.taskId,value.jobId,value.nonce].join(':');
export const requestDigest = value => requestBytes(value).toString('base64url');