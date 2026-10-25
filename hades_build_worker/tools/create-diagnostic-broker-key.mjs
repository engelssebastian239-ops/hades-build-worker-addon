import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { createPrivateKey, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { identityId } from '../shared/protocol.mjs';

const fail = code => { throw Error(code); };

export function createDiagnosticBrokerKey(file) {
  if (!file || !path.isAbsolute(file)) fail('usage_create_diagnostic_broker_key_absolute_path');
  const directory = path.dirname(file);
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const dirStat = fs.lstatSync(directory);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink() || dirStat.uid !== process.getuid() || (dirStat.mode & 0o077) !== 0)
    fail('broker_key_directory_permissions');

  const pair = generateKeyPairSync('ed25519');
  const pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' });
  let fd;
  let created = false;
  try {
    fd = fs.openSync(file, 'wx', 0o600);
    created = true;
    fs.writeFileSync(fd, pem, 'utf8');
    fs.fsyncSync(fd);
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.uid !== process.getuid() || (st.mode & 0o077) !== 0) fail('broker_key_file_permissions');
    fs.closeSync(fd);
    fd = undefined;
  } catch (error) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch {} }
    if (created) { try { fs.unlinkSync(file); } catch {} }
    throw Error(error.code === 'EEXIST' ? 'broker_key_already_exists' : 'broker_key_create_failed');
  }
  const publicKey = createPublicKey(createPrivateKey(pem));
  const publicKeyBase64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
  return { brokerId: identityId(publicKey), publicKeyBase64, privateKeyPath: file, privateKeyPrinted: false };
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 3) fail('usage_create_diagnostic_broker_key_absolute_path');
    process.umask(0o077);
    console.log(JSON.stringify(createDiagnosticBrokerKey(process.argv[2])));
  } catch (error) {
    console.error(/^[a-z0-9_]+$/i.test(error?.message ?? '') ? error.message : 'broker_key_create_failed');
    process.exitCode = 1;
  }
}
