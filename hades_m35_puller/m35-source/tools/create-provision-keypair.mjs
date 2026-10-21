import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createPublicKeyDocument } from '../src/rsa-oaep.mjs';

export const DEFAULT_PRIVATE_DIR = '/data/hades-dev-workspace/hades-m35-secrets-20261011';

export function createProvisionKeyPair(privateDir = DEFAULT_PRIVATE_DIR) {
  if (!path.isAbsolute(privateDir)) throw Error('invalid_provision_directory');
  fs.mkdirSync(privateDir, { recursive: true, mode: 0o700 });
  const dir = fs.lstatSync(privateDir);
  if (!dir.isDirectory() || dir.isSymbolicLink() || dir.uid !== process.getuid() || (dir.mode & 0o077) !== 0) {
    throw Error('insecure_provision_directory');
  }

  const privateKeyPath = path.join(privateDir, 'provision-private.pem');
  const publicKeyPemPath = path.join(privateDir, 'provision-public.pem');
  const publicKeyJsonPath = path.join(privateDir, 'public-for-windows.json');
  if ([privateKeyPath, publicKeyPemPath, publicKeyJsonPath].some(file => fs.existsSync(file))) {
    throw Error('provision_key_already_exists');
  }

  const pair = crypto.generateKeyPairSync('rsa', {
    modulusLength: 3072,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  const document = createPublicKeyDocument(pair.publicKey);
  const outputs = [
    [privateKeyPath, pair.privateKey],
    [publicKeyPemPath, pair.publicKey],
    [publicKeyJsonPath, `${JSON.stringify(document, null, 2)}\n`],
  ];
  const created = [];
  try {
    for (const [file, contents] of outputs) {
      fs.writeFileSync(file, contents, { flag: 'wx', mode: 0o600 });
      created.push(file);
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.uid !== process.getuid() || (stat.mode & 0o077) !== 0) {
        throw Error('provision_key_permission_failure');
      }
    }
  } catch (error) {
    for (const file of created) {
      try { fs.unlinkSync(file); } catch {}
    }
    throw error;
  } finally {
    pair.privateKey = '';
  }
  return { privateKeyPath, publicKeyPemPath, publicKeyJsonPath };
}

async function main() {
  if (process.getuid() === 0) throw Error('wrong_execution_identity');
  const files = createProvisionKeyPair();
  const document = JSON.parse(fs.readFileSync(files.publicKeyJsonPath, 'utf8'));
  console.log(JSON.stringify({ result: 'KEYPAIR_CREATED', ...files, publicKeySha256: document.publicKeySha256, privateKeyPrinted: false }));
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => {
    console.error(JSON.stringify({ result: 'BLOCKED', reason: error.message }));
    process.exitCode = 1;
  });
}
