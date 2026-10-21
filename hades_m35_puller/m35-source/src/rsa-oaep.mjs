import crypto from 'node:crypto';

export const PUBLIC_KEY_SCHEMA = 'hades-m35-public-key-v1';
export const PUBLIC_KEY_ALGORITHM = 'RSA-OAEP-SHA1';
const RSA_BITS = 3072;
const CIPHERTEXT_BYTES = RSA_BITS / 8;
const MAX_OAEP_SHA1_PLAINTEXT_BYTES = CIPHERTEXT_BYTES - 2 * 20 - 2;
const TOKEN_PATTERN = /^github_pat_[a-zA-Z0-9_]{20,}$/;

function assertRsa3072(key) {
  if (key.asymmetricKeyType !== 'rsa' || key.asymmetricKeyDetails?.modulusLength !== RSA_BITS) {
    throw Error('invalid_rsa_3072_key');
  }
  return key;
}

export function createPublicKeyDocument(publicKeyPem) {
  let key;
  try {
    key = assertRsa3072(crypto.createPublicKey(publicKeyPem));
  } catch {
    throw Error('invalid_public_key');
  }
  const publicKeyDer = key.export({ type: 'spki', format: 'der' });
  return {
    schema: PUBLIC_KEY_SCHEMA,
    algorithm: PUBLIC_KEY_ALGORITHM,
    publicKeySha256: crypto.createHash('sha256').update(publicKeyDer).digest('hex'),
    publicKeyPem: key.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

export function parsePublicKeyDocument(serialized) {
  let document;
  try {
    document = JSON.parse(serialized);
  } catch {
    throw Error('invalid_public_key_document');
  }
  if (!document || typeof document !== 'object' || Array.isArray(document)) {
    throw Error('invalid_public_key_document');
  }
  const keys = Object.keys(document).sort();
  if (keys.join(',') !== ['algorithm', 'publicKeyPem', 'publicKeySha256', 'schema'].join(',')) {
    throw Error('invalid_public_key_document');
  }
  if (document.schema !== PUBLIC_KEY_SCHEMA || document.algorithm !== PUBLIC_KEY_ALGORITHM ||
      typeof document.publicKeyPem !== 'string' || !/^[a-f0-9]{64}$/.test(document.publicKeySha256)) {
    throw Error('invalid_public_key_document');
  }
  try {
    const key = assertRsa3072(crypto.createPublicKey(document.publicKeyPem));
    const fingerprint = crypto.createHash('sha256').update(key.export({ type: 'spki', format: 'der' })).digest('hex');
    if (fingerprint !== document.publicKeySha256) throw Error('public_key_fingerprint_mismatch');
    return key;
  } catch {
    throw Error('invalid_public_key_document');
  }
}

export function assertTrustedPublicKeyFingerprint(serialized, trustedFingerprint) {
  if (typeof trustedFingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(trustedFingerprint)) {
    throw Error('trusted_public_key_fingerprint_required');
  }
  const publicKey = parsePublicKeyDocument(serialized);
  const actualFingerprint = crypto.createHash('sha256')
    .update(publicKey.export({ type: 'spki', format: 'der' }))
    .digest('hex');
  if (actualFingerprint !== trustedFingerprint) {
    throw Error('trusted_public_key_fingerprint_mismatch');
  }
  return actualFingerprint;
}

export function validateProvisionKeyPair(privateKeyPem, publicKeyDocument) {
  let privateKey;
  try {
    privateKey = assertRsa3072(crypto.createPrivateKey(privateKeyPem));
  } catch {
    throw Error('invalid_provision_private_key');
  }
  const publicKey = parsePublicKeyDocument(publicKeyDocument);
  const derived = crypto.createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
  const declared = publicKey.export({ type: 'spki', format: 'der' });
  if (!derived.equals(declared)) throw Error('provision_key_pair_mismatch');
  return privateKey;
}

export function decryptTokenCiphertext(base64Ciphertext, privateKeyPem, publicKeyDocument) {
  const encoded = typeof base64Ciphertext === 'string' ? base64Ciphertext.trim() : '';
  if (!/^[A-Za-z0-9+/]{4,600}={0,2}$/.test(encoded)) throw Error('invalid_encrypted_input');
  const encrypted = Buffer.from(encoded, 'base64');
  if (encrypted.length !== CIPHERTEXT_BYTES || encrypted.toString('base64') !== encoded) {
    throw Error('invalid_rsa_packet_size');
  }
  const privateKey = validateProvisionKeyPair(privateKeyPem, publicKeyDocument);
  let plaintext;
  try {
    plaintext = crypto.privateDecrypt({ key: privateKey, oaepHash: 'sha1' }, encrypted);
    if (plaintext.length > MAX_OAEP_SHA1_PLAINTEXT_BYTES) throw Error('invalid_token_payload');
    const token = new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    if (!TOKEN_PATTERN.test(token)) throw Error('invalid_token_payload');
    return token;
  } catch {
    throw Error('invalid_token_ciphertext_or_payload');
  } finally {
    plaintext?.fill(0);
    encrypted.fill(0);
  }
}
