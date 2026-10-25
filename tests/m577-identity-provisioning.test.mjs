import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createPublicKey,createHash,generateKeyPairSync} from 'node:crypto';
import {loadKey} from '../hades_mobile_build_worker/worker/main.mjs';
import {loadAdapterKey} from '../hades_mobile_installer/main.mjs';

function temp(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'m577-ident-'));fs.chmodSync(dir,0o700);return dir;}
test('separate identities are created once with mode 0600 and reload stably',()=>{
  const workerDir=temp(),installerDir=temp();
  const worker=loadKey(path.join(workerDir,'worker-key.pem')),workerAgain=loadKey(path.join(workerDir,'worker-key.pem'));
  const adapter=loadAdapterKey(installerDir),adapterAgain=loadAdapterKey(installerDir);
  assert.equal(worker.created,true);assert.equal(workerAgain.created,false);
  assert.equal(adapter.created,true);assert.equal(adapterAgain.created,false);
  const fingerprint=key=>createHash('sha256').update(createPublicKey(key).export({type:'spki',format:'der'})).digest('hex');
  assert.equal(fingerprint(worker.key),fingerprint(workerAgain.key));assert.equal(fingerprint(adapter.key),fingerprint(adapterAgain.key));
  assert.notEqual(fingerprint(worker.key),fingerprint(adapter.key));
  assert.equal(fs.statSync(path.join(workerDir,'worker-key.pem')).mode&0o777,0o600);
  assert.equal(fs.statSync(path.join(installerDir,'adapter-ed25519.pem')).mode&0o777,0o600);
});
test('identity loaders reject permissive, symlinked and hard-linked key files',()=>{
  const workerDir=temp(),installerDir=temp();
  const workerFile=path.join(workerDir,'worker-key.pem'),adapter=loadAdapterKey(installerDir);
  loadKey(workerFile);fs.chmodSync(workerFile,0o644);assert.throws(()=>loadKey(workerFile),/worker_key_permissions/);
  fs.chmodSync(workerFile,0o600);const workerLink=path.join(workerDir,'worker-hardlink.pem');fs.linkSync(workerFile,workerLink);assert.throws(()=>loadKey(workerFile),/worker_key_permissions/);fs.unlinkSync(workerLink);
  const workerSymlink=path.join(workerDir,'worker-symlink.pem');fs.symlinkSync(workerFile,workerSymlink);assert.throws(()=>loadKey(workerSymlink),/worker_key_permissions/);
  const adapterFile=path.join(installerDir,'adapter-ed25519.pem');fs.chmodSync(adapterFile,0o644);assert.throws(()=>loadAdapterKey(installerDir),/private_key_permissions/);
  fs.chmodSync(adapterFile,0o600);const adapterLink=path.join(installerDir,'adapter-hardlink.pem');fs.linkSync(adapterFile,adapterLink);assert.throws(()=>loadAdapterKey(installerDir),/private_key_permissions/);fs.unlinkSync(adapterLink);
  const adapterSymlink=path.join(installerDir,'adapter-symlink.pem');fs.symlinkSync(adapterFile,adapterSymlink);fs.renameSync(adapterFile,adapterFile+'.saved');fs.renameSync(adapterSymlink,adapterFile);assert.throws(()=>loadAdapterKey(installerDir),/private_key_permissions/);
  const rsaDir=temp(),rsaFile=path.join(rsaDir,'worker-key.pem'),rsa=generateKeyPairSync('rsa',{modulusLength:2048});fs.writeFileSync(rsaFile,rsa.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  assert.throws(()=>loadKey(rsaFile),/worker_key_type_invalid/);
  const rsaInstallerDir=temp(),rsaInstaller=generateKeyPairSync('rsa',{modulusLength:2048});fs.writeFileSync(path.join(rsaInstallerDir,'adapter-ed25519.pem'),rsaInstaller.privateKey.export({type:'pkcs8',format:'pem'}),{mode:0o600});
  assert.throws(()=>loadAdapterKey(rsaInstallerDir),/private_key_type_invalid/);
  assert.equal(adapter.created,true);
});
