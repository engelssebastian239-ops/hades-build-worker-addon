import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { writeProvisionedCredential } from '../hades_m35_puller/m35-source/src/credential-file.mjs';

test('removes and verifies absence of a newly written credential after permission verification fails', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hades-puller-credential-test-'));
  fs.chmodSync(directory, 0o700);
  const filePath = path.join(directory, 'credential');

  try {
    assert.throws(
      () => writeProvisionedCredential(filePath, 'dummy-credential', {
        fstatSync: () => ({ mode: 0o100644, uid: process.getuid() }),
      }),
      /credential_permission_failure/,
    );
    assert.equal(fs.existsSync(filePath), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
