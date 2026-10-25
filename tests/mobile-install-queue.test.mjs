import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,sign} from 'node:crypto';
import {identityId} from '../hades_build_worker/shared/protocol.mjs';
import {
  MOBILE_INSTALL_CONFIRMATION,MOBILE_INSTALL_GITHUB_OWNER,MOBILE_INSTALL_JOB_TTL_MS,MOBILE_INSTALL_QUEUE_PROTOCOL,
  parseMobileInstallIssue
} from '../hades_build_worker/worker/mobile-install-queue.mjs';
import {
  MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY
} from '../hades_build_worker/worker/mobile-install-plan.mjs';
import {createMobileInstallStoreForTests} from '../hades_build_worker/worker/mobile-install-store.mjs';
import {
  MOBILE_INSTALL_PROTOCOL,createMobileInstallClient
} from '../hades_build_worker/worker/mobile-install-client.mjs';

const now=1_800_000_000_000,hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const repo={full_name:MOBILE_INSTALL_REPOSITORY,private:true};
let ids=100;
function uuid(){return `00000000-0000-4000-8000-${(++ids).toString(16).padStart(12,'0')}`;}
function jobBody(action,patch={}){
  const base={protocol:MOBILE_INSTALL_QUEUE_PROTOCOL,action,requestId:uuid(),nonce:uuid(),issuedAt:now,expiresAt:now+MOBILE_INSTALL_JOB_TTL_MS};
  return action==='PLAN_M574'?{...base,...patch}:{...base,planId:uuid(),archiveSha256:'a'.repeat(64),manifestSha256:'b'.repeat(64),confirmation:MOBILE_INSTALL_CONFIRMATION,...patch};
}
function issue(action,body=jobBody(action),patch={}){return {number:++ids,title:`HADES ${action}`,body:JSON.stringify(body),user:{login:MOBILE_INSTALL_GITHUB_OWNER},...patch};}
function parse(value,{repositoryInfo=repo,owner=MOBILE_INSTALL_GITHUB_OWNER,time=now}={}){return parseMobileInstallIssue({issue:value,repository:repositoryInfo,authenticatedOwner:owner,now:time});}
function tempRoot(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'m576-mobile-store-'));fs.chmodSync(dir,0o700);return dir;}
const archive=Buffer.from('synthetic package archive bytes');
function plan(){return {repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW,
  archive,archiveSha256:hash(archive),archiveSize:archive.length,manifestSha256:'c'.repeat(64),fileCount:3,expandedBytes:1024};}
function planJob(number=101){return parse(issue('PLAN_M574',jobBody('PLAN_M574'),{number}));}
function installJob(planResult,number=102,patch={}){
  const body={...jobBody('INSTALL_M574',{planId:planResult.planId,archiveSha256:planResult.archiveSha256,manifestSha256:planResult.manifestSha256}),...patch};
  return parse(issue('INSTALL_M574',body,{number}));
}
function makeStore(root,{beforeAtomicWrite=()=>{}}={}){return createMobileInstallStoreForTests({testOnlyDataRoot:root,clock:()=>now,uuidFactory:uuid,testOnlyBeforeAtomicWrite:beforeAtomicWrite});}

test('parses only exact owner-created PLAN_M574 and INSTALL_M574 jobs for the private pinned repository',()=>{
  assert.equal(MOBILE_INSTALL_GITHUB_OWNER,'engelssebastian239-ops');
  const p=parse(issue('PLAN_M574'));assert.equal(p.action,'PLAN_M574');assert.equal(p.owner,MOBILE_INSTALL_GITHUB_OWNER);assert.deepEqual(p.fixedSource,{repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW});
  const body=jobBody('INSTALL_M574');assert.equal(parse(issue('INSTALL_M574',body)).confirmation,MOBILE_INSTALL_CONFIRMATION);
  assert.throws(()=>parse(issue('PLAN_M574'),{owner:'attacker'}),/queue_repository_or_owner_rejected/);
  assert.throws(()=>parse(issue('PLAN_M574'),{repositoryInfo:{...repo,private:false}}),/queue_repository_or_owner_rejected/);
  assert.throws(()=>parse(issue('PLAN_M574'),{repositoryInfo:{...repo,full_name:'attacker/repo'}}),/queue_repository_or_owner_rejected/);
  assert.throws(()=>parse(issue('PLAN_M574',jobBody('PLAN_M574'),{user:{login:'attacker'}})),/queue_issue_owner_rejected/);
  assert.throws(()=>parse({...issue('PLAN_M574'),pull_request:{url:'x'}}),/queue_issue_owner_rejected/);
});

test('rejects extra fields, URLs, commands, wrong action/title and noncanonical or stale bodies',()=>{
  const extra=jobBody('PLAN_M574');extra.command='id';assert.throws(()=>parse(issue('PLAN_M574',extra)),/queue_schema_rejected/);
  assert.throws(()=>parse(issue('PLAN_M574',jobBody('PLAN_M574'),{title:'HADES PLAN_M574 https://evil.invalid'})),/queue_schema_rejected/);
  assert.throws(()=>parse(issue('PLAN_M574',jobBody('PLAN_M574'),{body:'{"protocol":"HADES_MOBILE_M574_QUEUE_V1","action":"PLAN_M574","requestId":"x","nonce":"x","issuedAt":1,"expiresAt":2,"url":"http://evil","command":"sh"}'})),/queue_schema_rejected/);
  const body=jobBody('INSTALL_M574');assert.throws(()=>parse(issue('INSTALL_M574',{...body,confirmation:'yes'})),/queue_install_binding_rejected/);
  assert.throws(()=>parse(issue('PLAN_M574',jobBody('PLAN_M574'),{title:'HADES INSTALL_M574'})),/queue_schema_rejected/);
  assert.equal(parse(issue('PLAN_M574',jobBody('PLAN_M574',{issuedAt:now-MOBILE_INSTALL_JOB_TTL_MS-1,expiresAt:now-1}))).action,'PLAN_M574');
  assert.throws(()=>parse(issue('PLAN_M574',jobBody('PLAN_M574',{expiresAt:now+MOBILE_INSTALL_JOB_TTL_MS+1}))),/queue_ttl_or_id_rejected/);
});

test('stores verified plan archive privately and binds INSTALL to exact plan hashes',()=>{
  const root=tempRoot(),store=makeStore(root),job=planJob(),created=store.createPlan(job,plan());
  assert.match(created.planId,/^[0-9a-f-]{36}$/);
  assert.deepEqual(store.readPlan(created.planId).archive,archive);
  const dir=path.join(store.storeDir,'plans',created.planId);assert.equal(fs.statSync(dir).mode&0o777,0o700);
  assert.equal(fs.statSync(path.join(dir,'archive.gz')).mode&0o777,0o600);assert.equal(fs.statSync(path.join(dir,'metadata.json')).mode&0o777,0o600);
  assert.throws(()=>store.createPlan(job,plan()),/mobile_job_replay/);
  assert.throws(()=>store.beginInstall(installJob(created,201,{archiveSha256:'d'.repeat(64)})),/mobile_plan_binding_mismatch/);
  assert.throws(()=>store.beginInstall(installJob(created,202,{manifestSha256:'e'.repeat(64)})),/mobile_plan_binding_mismatch/);
  const prepared=store.beginInstall(installJob(created));assert.equal(prepared.plan.archiveSha256,created.archiveSha256);assert.equal(store.snapshot().installs[0].state,'PREPARING');
});

test('binds the actual client request before POST and restart makes sent work UNKNOWN without retry',()=>{
  const root=tempRoot(),store=makeStore(root),created=store.createPlan(planJob(),plan()),prepared=store.beginInstall(installJob(created));
  const adapter=generateKeyPairSync('ed25519'),worker=generateKeyPairSync('ed25519');let sent=0;
  const client=createMobileInstallClient({workerPrivateKey:worker.privateKey,trustedAdapterId:identityId(adapter.publicKey),trustedAdapterPublicKey:adapter.publicKey,
    persistIntent:prepared.persistIntent,fetchImpl:async(_url,init)=>{sent++;const request=JSON.parse(Buffer.from(init.headers['x-hades-install-request'],'base64url').toString('utf8'));
      const result={protocol:MOBILE_INSTALL_PROTOCOL,adapterId:client.adapterId,jobId:request.jobId,nonce:request.nonce,issuedAt:now,expiresAt:now+300_000,state:'COMPLETED',
        targetSlug:'local_hades_m2_mobile',commit:MOBILE_INSTALL_COMMIT,archiveSha256:request.archiveSha256,backupSlug:'backup-fixed',sourceSha256:'d'.repeat(64),errorCode:'',signature:''};
      result.signature=sign(null,Buffer.from(JSON.stringify([result.protocol,result.adapterId,result.jobId,result.nonce,result.issuedAt,result.expiresAt,result.state,result.targetSlug,result.commit,result.archiveSha256,result.backupSlug,result.sourceSha256,result.errorCode])),adapter.privateKey).toString('base64url');
      return new Response(JSON.stringify(result),{status:200,headers:{'content-type':'application/json'}});},uuidFactory:uuid,clock:()=>now});
  assert.equal(client.brokerId,identityId(worker.publicKey));
  assert.throws(()=>store.persistInstallIntent(installJob(created).issueNumber,{request:{}}),/mobile_install_intent_invalid/);
  // The actual client callback must make the signed request durable before its single POST.
  return client.install(prepared.plan).then(()=>{
  const row=store.snapshot().installs[0];assert.equal(row.state,'SENT');assert.equal(row.jobId,row.signedRequest.jobId);assert.equal(row.installNonce,row.signedRequest.nonce);assert.equal(sent,1);
  const recovered=makeStore(root);assert.equal(recovered.snapshot().installs[0].state,'UNKNOWN');assert.equal(recovered.snapshot().installs[0].interruptedState,'SENT');
  assert.equal(recovered.recordTransportUnknown(row.issueNumber),true);assert.equal(recovered.snapshot().installs[0].errorCode,'TRANSPORT_OUTCOME_UNKNOWN');
  assert.throws(()=>recovered.beginInstall(installJob(created,204)),/mobile_install_gate_closed/);assert.equal(sent,1);
  assert.equal(recovered.snapshot().installs[0].signedRequest.jobId,row.jobId);
  assert.equal(recovered.recordTransportUnknown(row.issueNumber),true);
  });
});

test('client persistence-hook failure produces zero POSTs and a plan remains gated',async()=>{
  const root=tempRoot();let failWrite=false;const store=makeStore(root,{beforeAtomicWrite:()=>{if(failWrite)throw Error('simulated fsync failure');}});
  const created=store.createPlan(planJob(),plan()),prepared=store.beginInstall(installJob(created,301));const adapter=generateKeyPairSync('ed25519'),worker=generateKeyPairSync('ed25519');let calls=0;
  failWrite=true;
  const client=createMobileInstallClient({workerPrivateKey:worker.privateKey,trustedAdapterId:identityId(adapter.publicKey),trustedAdapterPublicKey:adapter.publicKey,persistIntent:prepared.persistIntent,
    fetchImpl:async()=>{calls++;},uuidFactory:uuid,clock:()=>now});
  await assert.rejects(client.install(prepared.plan),error=>error.code==='install_intent_persist_failed');assert.equal(calls,0);
  failWrite=false;assert.equal(store.recordTransportUnknown(301),true);const restarted=makeStore(root);assert.equal(restarted.snapshot().installs[0].state,'UNKNOWN');
  assert.equal(restarted.snapshot().installs[0].errorCode,'TRANSPORT_OUTCOME_UNKNOWN');assert.throws(()=>restarted.beginInstall(installJob(created,302)),/mobile_install_gate_closed/);
});

test('records only a correlated verified terminal response and releases the single-install gate',async()=>{
  const store=makeStore(tempRoot()),created=store.createPlan(planJob(401),plan()),pending=store.beginInstall(installJob(created,402));
  const adapter=generateKeyPairSync('ed25519'),worker=generateKeyPairSync('ed25519');let installClient;
  installClient=createMobileInstallClient({workerPrivateKey:worker.privateKey,trustedAdapterId:identityId(adapter.publicKey),trustedAdapterPublicKey:adapter.publicKey,persistIntent:pending.persistIntent,
    fetchImpl:async(_url,init)=>{const request=JSON.parse(Buffer.from(init.headers['x-hades-install-request'],'base64url').toString('utf8'));
      const result={protocol:MOBILE_INSTALL_PROTOCOL,adapterId:installClient.adapterId,jobId:request.jobId,nonce:request.nonce,issuedAt:now,expiresAt:now+300_000,state:'COMPLETED',targetSlug:'local_hades_m2_mobile',
        commit:MOBILE_INSTALL_COMMIT,archiveSha256:request.archiveSha256,backupSlug:'backup-proof',sourceSha256:'e'.repeat(64),errorCode:'',signature:''};
      result.signature=sign(null,Buffer.from(JSON.stringify([result.protocol,result.adapterId,result.jobId,result.nonce,result.issuedAt,result.expiresAt,result.state,result.targetSlug,result.commit,result.archiveSha256,result.backupSlug,result.sourceSha256,result.errorCode])),adapter.privateKey).toString('base64url');
      return new Response(JSON.stringify(result),{status:200,headers:{'content-type':'application/json'}});},uuidFactory:uuid,clock:()=>now});
  const verified=await installClient.install(pending.plan);
  assert.throws(()=>store.recordVerifiedResponse(402,{...verified,adapterId:'sha256:'+'f'.repeat(64)}),/mobile_install_response_unbound/);
  assert.equal(store.recordVerifiedResponse(402,verified),true);assert.equal(store.snapshot().installs[0].state,'COMPLETED');
  const second=store.createPlan(planJob(403),plan());assert.equal(store.beginInstall(installJob(second,404)).plan.planId,second.planId);
  assert.throws(()=>store.recordVerifiedResponse(402,{...verified,jobId:uuid()}),/mobile_install_response_unbound/);
});

test('rejects symlinked store paths and hard-linked ledger files',()=>{
  const root=tempRoot(),storePath=path.join(root,'mobile-install');fs.mkdirSync(storePath,{mode:0o700});const outside=fs.mkdtempSync(path.join(os.tmpdir(),'m576-outside-'));fs.chmodSync(outside,0o700);fs.symlinkSync(outside,path.join(storePath,'plans'));
  assert.throws(()=>makeStore(root),/mobile_store_directory_unsafe/);
  const safe=tempRoot(),store=makeStore(safe),copy=path.join(safe,'ledger-copy');fs.linkSync(path.join(store.storeDir,'ledger.json'),copy);
  assert.throws(()=>makeStore(safe),/mobile_store_file_unsafe/);
  const changed=tempRoot(),planStore=makeStore(changed),saved=planStore.createPlan(planJob(),plan());fs.writeFileSync(path.join(planStore.storeDir,'plans',saved.planId,'archive.gz'),'tampered');
  assert.throws(()=>planStore.readPlan(saved.planId),/mobile_store_file_unsafe|mobile_plan_metadata_invalid/);
});
