import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { DEFAULT_PRIVATE_DIR } from './create-provision-keypair.mjs';
import { parsePublicKeyDocument } from '../src/rsa-oaep.mjs';

const PUBLIC_KEY_FILE = 'public-for-windows.json';
const CIPHERTEXT_FILE = 'github-token.enc';
const TOKEN_PREFIX = Buffer.from('github_pat_');
const MAX_TOKEN_BYTES = 342;

function assertSecureDirectory(directory) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
    throw Error('insecure_provision_directory');
  }
}

function validateTokenBytes(token) {
  if (token.length < TOKEN_PREFIX.length + 20 || token.length > MAX_TOKEN_BYTES ||
      !token.subarray(0, TOKEN_PREFIX.length).equals(TOKEN_PREFIX)) {
    throw Error('invalid_github_fine_grained_token');
  }
  for (const byte of token.subarray(TOKEN_PREFIX.length)) {
    if (!((byte >= 0x41 && byte <= 0x5a) || (byte >= 0x61 && byte <= 0x7a) ||
        (byte >= 0x30 && byte <= 0x39) || byte === 0x5f)) {
      throw Error('invalid_github_fine_grained_token');
    }
  }
}

export function readHiddenTTY(input = process.stdin, output = process.stderr) {
  if (!input.isTTY || typeof input.setRawMode !== 'function') throw Error('secure_tty_required');

  return new Promise((resolve, reject) => {
    const bytes = Buffer.alloc(MAX_TOKEN_BYTES);
    let length = 0;
    let settled = false;
    const cleanup = () => {
      input.off('data', onData);
      input.off('end', onEnd);
      input.off('error', onError);
      try { input.setRawMode(false); } catch {}
      input.pause();
      output.write('\n');
    };
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      cleanup();
      bytes.fill(0);
      if (error) reject(error);
      else resolve(value);
    };
    const onData = chunk => {
      for (const byte of chunk) {
        if (byte === 0x0d || byte === 0x0a) {
          chunk.fill(0);
          if (length === 0) return finish(Error('empty_github_token_input'));
          const token = Buffer.from(bytes.subarray(0, length));
          return finish(null, token);
        }
        if (byte === 0x03) {
          chunk.fill(0);
          return finish(Error('input_cancelled'));
        }
        if (byte === 0x08 || byte === 0x7f) {
          if (length > 0) bytes[--length] = 0;
          continue;
        }
        if (byte < 0x20 || byte > 0x7e || length >= bytes.length) {
          chunk.fill(0);
          return finish(Error('invalid_github_fine_grained_token'));
        }
        bytes[length++] = byte;
      }
      chunk.fill(0);
    };
    const onEnd = () => finish(Error('tty_input_ended'));
    const onError = () => finish(Error('tty_input_failure'));

    output.write('GitHub fine-grained PAT (hidden input): ');
    input.on('data', onData);
    input.once('end', onEnd);
    input.once('error', onError);
    input.setRawMode(true);
    input.resume();
  });
}

export async function encryptTokenFromTTY({ privateDir = DEFAULT_PRIVATE_DIR, input = process.stdin, output = process.stderr } = {}) {
  if (process.getuid() === 0) throw Error('wrong_execution_identity');
  assertSecureDirectory(privateDir);
  const publicKeyPath = path.join(privateDir, PUBLIC_KEY_FILE);
  const publicStat = fs.lstatSync(publicKeyPath);
  if (!publicStat.isFile() || publicStat.isSymbolicLink() || publicStat.uid !== process.getuid() ||
      (publicStat.mode & 0o077) !== 0) {
    throw Error('invalid_public_key_file');
  }

  const publicKeyDocument = fs.readFileSync(publicKeyPath, 'utf8');
  const publicKey = parsePublicKeyDocument(publicKeyDocument);
  const fingerprint = JSON.parse(publicKeyDocument).publicKeySha256;
  output.write(`Server public-key SHA-256: ${fingerprint}\n`);

  let token;
  let encrypted;
  let descriptor;
  let created = false;
  const cipherFile = path.join(privateDir, CIPHERTEXT_FILE);
  try {
    token = await readHiddenTTY(input, output);
    validateTokenBytes(token);
    encrypted = crypto.publicEncrypt({ key: publicKey, oaepHash: 'sha1' }, token);
    if (encrypted.length !== 384) throw Error('invalid_rsa_packet_size');

    descriptor = fs.openSync(cipherFile, 'wx', 0o600);
    created = true;
    fs.writeSync(descriptor, encrypted.toString('base64'), null, 'ascii');
    fs.fsyncSync(descriptor);
    const stat = fs.fstatSync(descriptor);
    if ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) {
      throw Error('encrypted_file_permission_failure');
    }
    fs.closeSync(descriptor);
    descriptor = undefined;
    output.write(`Encrypted input saved with restrictive permissions: ${cipherFile}\n`);
    return { cipherFile, fingerprint };
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (created) {
      try { fs.unlinkSync(cipherFile); } catch {}
      try {
        fs.lstatSync(cipherFile);
      } catch (verificationError) {
        if (verificationError.code === 'ENOENT') throw error;
      }
      throw Error('encrypted_file_cleanup_failure');
    }
    throw error;
  } finally {
    token?.fill(0);
    encrypted?.fill(0);
  }
}

async function main() {
  const result = await encryptTokenFromTTY();
  console.log(JSON.stringify({ result: 'ENCRYPTED', file: result.cipherFile, tokenLogged: false }));
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    console.error(JSON.stringify({ result: 'BLOCKED', reason: error.code ?? error.message }));
    process.exitCode = 1;
  });
}
