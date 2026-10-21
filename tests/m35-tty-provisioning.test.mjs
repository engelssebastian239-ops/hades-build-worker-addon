import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Readable, Writable } from 'node:stream';
import { createProvisionKeyPair } from '../hades_m35_puller/m35-source/tools/create-provision-keypair.mjs';
import { encryptTokenFromTTY } from '../hades_m35_puller/m35-source/tools/encrypt-github-token.mjs';
import { decryptTokenCiphertext } from '../hades_m35_puller/m35-source/src/rsa-oaep.mjs';

const dummyToken = ['github', 'pat', 'TEST_ONLY_NOT_A_CREDENTIAL_000000000000000000000000'].join('_');

class FakeTTY extends Readable {
  constructor(value) {
    super();
    this.isTTY = true;
    this.value = Buffer.from(`${value}\r`);
    this.rawModes = [];
    this.sent = false;
  }

  setRawMode(enabled) {
    this.rawModes.push(enabled);
    return this;
  }

  _read() {
    if (this.sent) return;
    this.sent = true;
    this.push(this.value);
    this.push(null);
  }
}

function fixture() {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'hades-puller-tty-test-'));
  fs.chmodSync(directory, 0o700);
  return { directory, close: () => fs.rmSync(directory, { recursive: true, force: true }) };
}

function captureOutput() {
  let value = '';
  const stream = new Writable({ write(chunk, _encoding, callback) { value += chunk.toString(); callback(); } });
  return { stream, read: () => value };
}

test('TTY path encrypts a dummy token to mode-0600 ciphertext without displaying plaintext', async () => {
  const test = fixture();
  try {
    const files = createProvisionKeyPair(test.directory);
    const input = new FakeTTY(dummyToken);
    const output = captureOutput();
    const result = await encryptTokenFromTTY({ privateDir: test.directory, input, output: output.stream });
    const ciphertext = fs.readFileSync(result.cipherFile, 'utf8');
    const stat = fs.statSync(result.cipherFile);
    const publicDocument = fs.readFileSync(files.publicKeyJsonPath, 'utf8');
    const privateKey = fs.readFileSync(files.privateKeyPath, 'utf8');

    assert.equal(input.rawModes[0], true);
    assert.equal(input.rawModes.at(-1), false);
    assert.equal(stat.mode & 0o777, 0o600);
    assert.equal(stat.uid, process.getuid());
    assert.equal(Buffer.from(ciphertext, 'base64').length, 384);
    assert.equal(decryptTokenCiphertext(ciphertext, privateKey, publicDocument), dummyToken);
    assert.doesNotMatch(ciphertext, /github_pat_/);
    assert.doesNotMatch(output.read(), /github_pat_/);
  } finally {
    test.close();
  }
});

test('TTY helper refuses non-interactive input', async () => {
  const test = fixture();
  try {
    createProvisionKeyPair(test.directory);
    const input = Readable.from([]);
    input.isTTY = false;
    await assert.rejects(encryptTokenFromTTY({ privateDir: test.directory, input, output: captureOutput().stream }), /secure_tty_required/);
    assert.equal(fs.existsSync(path.join(test.directory, 'github-token.enc')), false);
  } finally {
    test.close();
  }
});

test('TTY helper refuses to overwrite an existing ciphertext file', async () => {
  const test = fixture();
  try {
    createProvisionKeyPair(test.directory);
    const ciphertextFile = path.join(test.directory, 'github-token.enc');
    fs.writeFileSync(ciphertextFile, 'existing-ciphertext', { mode: 0o600 });
    await assert.rejects(
      encryptTokenFromTTY({ privateDir: test.directory, input: new FakeTTY(dummyToken), output: captureOutput().stream }),
      error => error.code === 'EEXIST',
    );
    assert.equal(fs.readFileSync(ciphertextFile, 'utf8'), 'existing-ciphertext');
  } finally {
    test.close();
  }
});

test('TTY encryption entrypoint does not accept argv or environment tokens', () => {
  const source = fs.readFileSync(new URL('../hades_m35_puller/m35-source/tools/encrypt-github-token.mjs', import.meta.url), 'utf8');
  assert.match(source, /process\.stdin/);
  assert.match(source, /setRawMode\(true\)/);
  assert.doesNotMatch(source, /process\.argv\[2\]|process\.env\./);
});
