import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {gzipSync} from 'node:zlib';
import {createHash,createPublicKey,generateKeyPairSync,randomUUID} from 'node:crypto';
import {createServer} from '../hades_build_worker/worker/main.mjs';
import {ALLOWED_PACKAGES,PACKAGE_STAGE_ACTION,PACKAGE_STAGE_TTL_MS,PACKAGE_STAGE_VERSION,
  createPackageStageReceiver,packageStageIdentity,signPackageStageRequest,verifyPackageStageResponse} from '../hades_build_worker/worker/package-stage.mjs';

function oct(n,width){return n.toString(8).padStart(width-1,'0')+'\0';}
function tarEntry(name,data,type='0'){
  const header=Buffer.alloc(512);header.write(name,0,100,'utf8');header.write('0000600\0',100,8,'ascii');
  header.write('0000000\0',108,8,'ascii');header.write('0000000\0',116,8,'ascii');header.write(oct(data.length,12),124,12,'ascii');
  header.write(oct(0,12),136,12,'ascii');header.fill(32,148,156);header[156]=type.charCodeAt(0);header.write('ustar\0',257,6,'ascii');
  header.write('00',263,2,'ascii');const sum=header.reduce((a,b)=>a+b,0);header.write(sum.toString(8).padStart(6,'0')+'\0 ',148,8,'ascii');
  return Buffer.concat([header,data,Buffer.alloc((512-data.length%512)%512)]);
}
function archive(entries){return gzipSync(Buffer.concat([...entries,Buffer.alloc(1024)]));}
function temp(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'hades-stage-'));fs.chmodSync(dir,0o700);return dir;}
function keyPair(){
  const broker=generateKeyPairSync('ed25519'),worker=generateKeyPairSync('ed25519');
  return {brokerPrivateKey:broker.privateKey,brokerPublicKey:broker.publicKey,workerPrivateKey:worker.privateKey,workerPublicKey:worker.publicKey};
}
function requestFixture(pair,archiveBytes,now=Date.now()){
  const brokerId=packageStageIdentity(createPublicKey(pair.brokerPrivateKey));
  const workerId=packageStageIdentity(createPublicKey(pair.workerPrivateKey));
  return {brokerId,workerId,taskId:randomUUID(),jobId:randomUUID(),nonce:randomUUID(),issuedAt:now,expiresAt:now+PACKAGE_STAGE_TTL_MS,
    repository:'engelssebastian239-ops/hades-hermes-queue',commit:'a'.repeat(40),packagePath:ALLOWED_PACKAGES['engelssebastian239-ops/hades-hermes-queue'][0],
    archiveSha256:createHash('sha256').update(archiveBytes).digest('hex'),archiveSize:archiveBytes.length};
}

test('stages an authorized pinned package safely and returns a signed correlated receipt',()=>{
  const dir=temp(),stageRoot=path.join(dir,'stage');fs.mkdirSync(stageRoot,{mode:0o700});
  const pair=keyPair(),bytes=Buffer.from('mobile source');
  const archiveBytes=archive([tarEntry('repo-a/hades-m2-local-app/hades_m2_mobile/README.md',bytes)]);
  const fields=requestFixture(pair,archiveBytes),request=signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...fields},pair.brokerPrivateKey);
  const receiver=createPackageStageReceiver({enabled:true,brokerId:fields.brokerId,trustedBrokerPublicKey:pair.brokerPublicKey.export({type:'spki',format:'der'}).toString('base64'),
    workerPrivateKey:pair.workerPrivateKey,stageRoot,ledgerPath:path.join(dir,'ledger.json')});
  const response=receiver.stage(request,archiveBytes);
  assert.equal(response.state,'STAGED');assert.equal(response.fileCount,1);assert.equal(response.byteCount,bytes.length);
  assert.equal(fs.readFileSync(path.join(stageRoot,response.stageId,'README.md'),'utf8'),'mobile source');
  assert.equal(verifyPackageStageResponse(response,pair.workerPublicKey,{brokerId:fields.brokerId,workerId:fields.workerId,
    taskId:fields.taskId,jobId:fields.jobId,nonce:fields.nonce,expiresAt:fields.expiresAt}).state,'STAGED');
});

test('rejects unknown repositories, mutable refs, and package path overrides before signing',()=>{
  const pair=keyPair(),archiveBytes=archive([tarEntry('root/file',Buffer.from('x'))]),base=requestFixture(pair,archiveBytes);
  for(const change of [{repository:'attacker/repo'},{commit:'main'},{packagePath:'../etc'}])
    assert.throws(()=>signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...base,...change},pair.brokerPrivateKey));
});

test('rejects archive digest mismatch, path traversal, and symlink entries without leaving staged files',()=>{
  const dir=temp(),stageRoot=path.join(dir,'stage');fs.mkdirSync(stageRoot,{mode:0o700});
  const pair=keyPair(),bytes=Buffer.from('safe');
  const valid=archive([tarEntry('repo/hades-m2-local-app/hades_m2_mobile/ok.txt',bytes)]);
  const fields=requestFixture(pair,valid),receiver=createPackageStageReceiver({enabled:true,brokerId:fields.brokerId,
    trustedBrokerPublicKey:pair.brokerPublicKey,workerPrivateKey:pair.workerPrivateKey,stageRoot,ledgerPath:path.join(dir,'ledger.json')});
  const signed=()=>signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...fields},pair.brokerPrivateKey);
  assert.throws(()=>receiver.stage(signed(),Buffer.from('corrupt')),/digest_mismatch/);
  const traversal=archive([tarEntry('repo/hades-m2-local-app/hades_m2_mobile/../../escape.txt',bytes)]);
  const maliciousFields={...fields,archiveSize:traversal.length,archiveSha256:createHash('sha256').update(traversal).digest('hex'),taskId:randomUUID(),jobId:randomUUID(),nonce:randomUUID()};
  assert.throws(()=>receiver.stage(signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...maliciousFields},pair.brokerPrivateKey),traversal));
  const symlink=archive([tarEntry('repo/hades-m2-local-app/hades_m2_mobile/link',Buffer.from('../outside'),'2')]);
  const linkFields={...fields,archiveSize:symlink.length,archiveSha256:createHash('sha256').update(symlink).digest('hex'),taskId:randomUUID(),jobId:randomUUID(),nonce:randomUUID()};
  assert.throws(()=>receiver.stage(signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...linkFields},pair.brokerPrivateKey),symlink),/special_file/);
  assert.equal(fs.readdirSync(stageRoot).length,0);
});

test('rejects replay conflicts and requires the explicit feature gate',()=>{
  const dir=temp(),stageRoot=path.join(dir,'stage');fs.mkdirSync(stageRoot,{mode:0o700});
  assert.throws(()=>createPackageStageReceiver({enabled:false}),/disabled/);
  const pair=keyPair(),bytes=archive([tarEntry('repo/hades-m2-local-app/hades_m2_mobile/x',Buffer.from('x'))]);
  const fields=requestFixture(pair,bytes),request=signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...fields},pair.brokerPrivateKey);
  const receiver=createPackageStageReceiver({enabled:true,brokerId:fields.brokerId,trustedBrokerPublicKey:pair.brokerPublicKey,
    workerPrivateKey:pair.workerPrivateKey,stageRoot,ledgerPath:path.join(dir,'ledger.json')});
  receiver.stage(request,bytes);
  const altered=signPackageStageRequest({...request,archiveSha256:'b'.repeat(64)},pair.brokerPrivateKey);
  assert.throws(()=>receiver.stage(altered,bytes),/digest_mismatch|replay_conflict/);
});

test('exposes a separate bounded internal HTTP endpoint only when explicitly enabled',async(t)=>{
  const dir=temp(),stageRoot=path.join(dir,'stage');fs.mkdirSync(stageRoot,{mode:0o700});
  const pair=keyPair(),bytes=archive([tarEntry('repo/hades-m2-local-app/hades_m2_mobile/x.txt',Buffer.from('x'))]);
  const fields=requestFixture(pair,bytes),request=signPackageStageRequest({version:PACKAGE_STAGE_VERSION,action:PACKAGE_STAGE_ACTION,...fields},pair.brokerPrivateKey);
  const receiver=createPackageStageReceiver({enabled:true,brokerId:fields.brokerId,trustedBrokerPublicKey:pair.brokerPublicKey,
    workerPrivateKey:pair.workerPrivateKey,stageRoot,ledgerPath:path.join(dir,'ledger.json')});
  const server=createServer({handle(){throw Error('wrong_dispatch');}},{port:0,host:'127.0.0.1',packageStageReceiver:receiver});
  try { await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);}); }
  catch(error){ if(error.code==='EPERM'){t.skip('sandbox prohibits local TCP listeners');return;} throw error; }
  try {
    const url=`http://127.0.0.1:${server.address().port}/v1/package-stage`;
    const response=await fetch(url,{method:'POST',headers:{'content-type':'application/gzip','x-hades-package-envelope':Buffer.from(JSON.stringify(request)).toString('base64url')},body:bytes});
    assert.equal(response.status,200);assert.equal((await response.json()).state,'STAGED');
    const disabled=createServer({handle(){}},{port:0,host:'127.0.0.1'});await new Promise(resolve=>disabled.once('listening',resolve));
    try { const denied=await fetch(`http://127.0.0.1:${disabled.address().port}/v1/package-stage`,{method:'POST'});assert.equal(denied.status,404); }
    finally { await new Promise(resolve=>disabled.close(resolve)); }
  } finally { await new Promise(resolve=>server.close(resolve)); }
});

test('rejects malformed configured base64 DER public keys before starting stage receiver',()=>{
  const dir=temp(),stageRoot=path.join(dir,'stage');fs.mkdirSync(stageRoot,{mode:0o700});
  const pair=keyPair(),brokerId=packageStageIdentity(pair.brokerPublicKey);
  for(const invalid of ['wrong_key_format','', '-----BEGIN PUBLIC KEY-----']) {
    assert.throws(()=>createPackageStageReceiver({enabled:true,brokerId,
      trustedBrokerPublicKey:invalid,workerPrivateKey:pair.workerPrivateKey,
      stageRoot,ledgerPath:path.join(dir,'ledger.json')}),/trusted_key_invalid|unsupported|decode|key/i);
  }
});
