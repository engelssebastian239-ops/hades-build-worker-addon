import fs from 'node:fs';

export function writeProvisionedCredential(filePath, plaintext, { fstatSync = fs.fstatSync } = {}) {
  let descriptor;
  let created = false;

  try {
    descriptor = fs.openSync(filePath, 'wx', 0o600);
    created = true;
    fs.writeFileSync(descriptor, `${plaintext}\n`, 'utf8');
    const stat = fstatSync(descriptor);
    if ((stat.mode & 0o077) !== 0 || stat.uid !== process.getuid()) {
      throw Error('credential_permission_failure');
    }
    fs.closeSync(descriptor);
    descriptor = undefined;
  } catch (error) {
    if (descriptor !== undefined) {
      try { fs.closeSync(descriptor); } catch {}
    }
    if (!created) throw error;

    try { fs.unlinkSync(filePath); } catch {}
    try {
      fs.lstatSync(filePath);
    } catch (verificationError) {
      if (verificationError.code === 'ENOENT') throw error;
    }
    throw Error('credential_cleanup_failure');
  }
}
