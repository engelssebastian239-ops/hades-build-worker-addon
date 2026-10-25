import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,sign,verify} from 'node:crypto';
import {identityId} from '../hades_mobile_build_worker/shared/protocol.mjs';
import {
  MOBILE_INSTALL_CONFIRMATION,MOBILE_INSTALL_GITHUB_OWNER,MOBILE_INSTALL_JOB_TTL_MS,MOBILE_INSTALL_QUEUE_PROTOCOL,parseMobileInstallIssue
} from '../hades_mobile_build_worker/worker/mobile-install-queue.mjs';
import {
  MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY
} from '../hades_mobile_build_worker/worker/mobile-install-plan.mjs';
import {createMobileInstallClient} from '../hades_mobile_build_worker/worker/mobile-install-client.mjs';
import {createMobileInstallController,createMobileInstallControllerForTests} from '../hades_mobile_build_worker/worker/mobile-install-controller.mjs';
import {createMobileInstallStoreForTests} from '../hades_mobile_build_worker/worker/mobile-install-store.mjs';
import {verifyMobileInstallReceipt} from '../hades_mobile_build_worker/worker/mobile-install-receipt.mjs';

const hash=data=>createHash('sha256').update(data).digest('hex');
const archive=Buffer.from('synthetic-fixed-package-archive'),archiveSha256=hash(archive),manifestSha256='b'.repeat(64);
const baseTime=1_800_000_000_000,repository={full_name:MOBILE_INSTALL_REPOSITORY,private:true};
const worker=generateKeyPairSync('ed25519'),adapter=generateKeyPairSync('ed25519'),workerId=identityId(worker.publicKey),adapterId=identityId(adapter.publicKey);
let ids=9000;
function uuid(){return `00000000-0000-4000-8000-${(++ids).toString(16).padStart(12,'0')}`;}
function body(action,patch={}){const x={protocol:MOBILE_INSTALL_QUEUE_PROTOCOL,action,requestId:uuid(),nonce:uuid(),issuedAt:baseTime,expiresAt:baseTime+MOBILE_INSTALL_JOB_TTL_MS};return action==='PLAN_M574'?{...x,...patch}:{...x,planId:uuid(),archiveSha256,manifestSha256,confirmation:MOBILE_INSTALL_CONFIRMATION,...patch};}
function job(action,number,patch={}){const fields=body(action,patch),issue={number,title:`HADES ${action}`,body:JSON.stringify(fields),user:{login:MOBILE_INSTALL_GITHUB_OWNER}};return parseMobileInstallIssue({issue,repository,authenticatedOwner:MOBILE_INSTALL_GITHUB_OWNER,now:baseTime});}
function plan(){return {repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW,
  archive:Buffer.from(archive),archiveSha256,archiveSize:archive.length,manifestSha256,fileCount:7,expandedBytes:4096};}
function tempRoot(){const root=fs.mkdtempSync(path.join(os.tmpdir(),'m576-controller-'));fs.chmodSync(root,0o700);return root;}
function makeStore(root,{beforeAtomicWrite=()=>{}}={}){return createMobileInstallStoreForTests({testOnlyDataRoot:root,clock:()=>baseTime,uuidFactory:uuid,testOnlyBeforeAtomicWrite:beforeAtomicWrite});}
function responseBody(request,now=baseTime,state='COMPLETED'){
  const value={protocol:'HADES_MOBILE_M574_INSTALL_V1',adapterId,jobId:request.jobId,nonce:request.nonce,issuedAt:now,expiresAt:now+300_000,state,targetSlug:'local_hades_m2_mobile',
    commit:MOBILE_INSTALL_COMMIT,archiveSha256:request.archiveSha256,backupSlug:'backup-fixed',sourceSha256:'c'.repeat(64),errorCode:'',signature:''};
  value.signature=sign(null,Buffer.from(JSON.stringify([value.protocol,value.adapterId,value.jobId,value.nonce,value.issuedAt,value.expiresAt,value.state,value.targetSlug,value.commit,value.archiveSha256,value.backupSlug,value.sourceSha256,value.errorCode])),adapter.privateKey).toString('base64url');return value;
}
function controllerFor({store,planner,clock=()=>baseTime,fetchImpl=async()=>{throw Error('unexpected transport');}}){
  const testOnlyClientFactory=options=>createMobileInstallClient({...options,fetchImpl,uuidFactory:uuid});
  return createMobileInstallControllerForTests({planner,store,workerPrivateKey:worker.privateKey,trustedAdapterId:adapterId,trustedAdapterPublicKey:adapter.publicKey,clock,testOnlyClientFactory});
}
function assertReceipt(controller,value,jobValue){
  const checked=controller.verifyReceipt(value,{expectedAction:jobValue.action,expectedIssueNumber:jobValue.issueNumber,expectedRequestId:jobValue.requestId,expectedNonce:jobValue.nonce});
  assert.equal(checked.workerId,workerId);assert.equal(checked.repository,MOBILE_INSTALL_REPOSITORY);assert.equal(checked.commit,MOBILE_INSTALL_COMMIT);assert.equal(checked.ciRun,MOBILE_INSTALL_CI_RUN);return checked;
}

test('PLAN is signed, contains only metadata/hashes, and duplicate concurrent jobs call Planner once',async()=>{
  const root=tempRoot(),store=makeStore(root);let plannerCalls=0,now=baseTime;
  const planner={async createPlan(){plannerCalls++;return plan();}};
  const controller=controllerFor({store,planner,clock:()=>now});const request=job('PLAN_M574',1001);
  const [first,duplicate]=await Promise.all([controller.handle(request),controller.handle(request)]);
  assert.deepEqual(first,duplicate);assert.equal(plannerCalls,1);
  const verified=assertReceipt(controller,first,request);assert.equal(verified.state,'PLANNED');assert.equal(verified.archiveSha256,archiveSha256);assert.equal(verified.manifestSha256,manifestSha256);
  assert.equal(Object.hasOwn(verified,'archive'),false);assert.equal(Object.hasOwn(verified,'token'),false);
  assert.deepEqual(Object.keys(verified).sort(),['action','archiveSha256','backupSlug','ciRun','commit','errorCode','expiresAt','installerJobId','installerNonce','issueNumber','manifestSha256','nonce','owner','packagePath','planId','protocol','repository','requestId','signature','sourceSha256','state','workerId','workflow','issuedAt'].sort());
  assert.throws(()=>controller.verifyReceipt({...first,archiveSha256:'f'.repeat(64)}),/mobile_receipt_signature_invalid/);
  assert.throws(()=>controller.verifyReceipt(first,{expectedIssueNumber:9999}),/mobile_receipt_correlation_failed/);
  await assert.rejects(controller.handle({...request,command:'id'}),/mobile_controller_job_invalid/);
  assert.equal(store.snapshot().plans[0].receipt.signature,first.signature);
  now=baseTime+300_001;const restarted=controllerFor({store:makeStore(root),planner,clock:()=>now}),refreshed=await restarted.handle(request);
  assert.equal(plannerCalls,1);assert.notEqual(refreshed.signature,first.signature);assert.equal(refreshed.state,'PLANNED');assert.ok(refreshed.issuedAt>first.issuedAt);
  assert.equal(assertReceipt(restarted,refreshed,request).archiveSha256,first.archiveSha256);
});

test('INSTALL revalidates the pinned successful CI, persists exact request before one POST, then deduplicates',async()=>{
  const store=makeStore(tempRoot());let plannerCalls=0,postCalls=0;
  const planner={async createPlan(){plannerCalls++;return plan();}};
  const controller=controllerFor({store,planner,fetchImpl:async(_url,init)=>{postCalls++;const request=JSON.parse(Buffer.from(init.headers['x-hades-install-request'],'base64url').toString('utf8'));return new Response(JSON.stringify(responseBody(request)),{status:200,headers:{'content-type':'application/json'}});}});
  const planRequest=job('PLAN_M574',1010),planReceipt=await controller.handle(planRequest);const info=store.snapshot().plans[0];
  const installRequest=job('INSTALL_M574',1011,{planId:info.planId,archiveSha256:info.archiveSha256,manifestSha256:info.manifestSha256});
  const [result,again]=await Promise.all([controller.handle(installRequest),controller.handle(installRequest)]);
  const verified=assertReceipt(controller,result,installRequest);assert.deepEqual(result,again);assert.equal(plannerCalls,2);assert.equal(postCalls,1);
  assert.equal(verified.state,'COMPLETED');assert.ok(verified.installerJobId);assert.ok(verified.installerNonce);assert.equal(verified.backupSlug,'backup-fixed');assert.equal(verified.sourceSha256,'c'.repeat(64));
  assert.equal(verifyMobileInstallReceipt(result,worker.publicKey,{expectedWorkerId:workerId,expectedAction:'INSTALL_M574',expectedIssueNumber:1011,expectedRequestId:installRequest.requestId,expectedNonce:installRequest.nonce,now:baseTime}).signature,result.signature);
  assert.equal(store.snapshot().installs[0].state,'COMPLETED');assert.equal(store.snapshot().installs[0].receipt.signature,result.signature);
  const changedPlan={...installRequest,planId:uuid()};await assert.rejects(controller.handle(changedPlan),/mobile_job_replay/);
  const changedHashes={...installRequest,archiveSha256:'f'.repeat(64)};await assert.rejects(controller.handle(changedHashes),/mobile_job_replay/);
  const changedExpiry={...installRequest,issuedAt:installRequest.issuedAt+1,expiresAt:installRequest.expiresAt+1};await assert.rejects(controller.handle(changedExpiry),/mobile_job_replay/);
  assert.equal(postCalls,1);assert.equal(plannerCalls,2);
});

test('job expiry after CI await rejects before POST and does not retry on duplicate',async()=>{
  const store=makeStore(tempRoot());let plannerCalls=0,posts=0,now=baseTime;
  const planner={async createPlan(){plannerCalls++;if(plannerCalls===2)now=baseTime+MOBILE_INSTALL_JOB_TTL_MS;return plan();}};
  const controller=controllerFor({store,planner,clock:()=>now,fetchImpl:async()=>{posts++;throw Error('must not post');}});
  const p=job('PLAN_M574',1020),pReceipt=await controller.handle(p),row=store.snapshot().plans[0];
  now=baseTime;const install=job('INSTALL_M574',1021,{planId:row.planId,archiveSha256:row.archiveSha256,manifestSha256:row.manifestSha256});
  const expired=await controller.handle(install),duplicate=await controller.handle(install);
  assert.deepEqual(expired,duplicate);assert.equal(assertReceipt(controller,expired,install).state,'REJECTED');assert.equal(expired.errorCode,'JOB_EXPIRED');assert.equal(plannerCalls,2);assert.equal(posts,0);assert.equal(store.snapshot().installs[0].state,'REJECTED');assert.ok(pReceipt);
});

test('persistence failure before POST and transport timeout produce signed UNKNOWN without retries',async t=>{
  await t.test('persist hook failure has no POST',async()=>{
    let failNext=false,posts=0;const store=makeStore(tempRoot(),{beforeAtomicWrite:()=>{if(failNext){failNext=false;throw Error('simulated private ledger write failure');}}});let plannerCalls=0;
    const planner={async createPlan(){plannerCalls++;if(plannerCalls===2)failNext=true;return plan();}};
    const controller=controllerFor({store,planner,fetchImpl:async()=>{posts++;throw Error('must not post');}});
    await controller.handle(job('PLAN_M574',1030));const row=store.snapshot().plans[0],install=job('INSTALL_M574',1031,{planId:row.planId,archiveSha256:row.archiveSha256,manifestSha256:row.manifestSha256});
    const result=await controller.handle(install);assert.equal(assertReceipt(controller,result,install).state,'UNKNOWN');assert.equal(result.errorCode,'TRANSPORT_OUTCOME_UNKNOWN');assert.equal(posts,0);assert.equal(store.snapshot().installs[0].state,'UNKNOWN');
  });
  await t.test('one failed transport is never posted again',async()=>{
    const store=makeStore(tempRoot());let plannerCalls=0,posts=0;const planner={async createPlan(){plannerCalls++;return plan();}};
    const controller=controllerFor({store,planner,fetchImpl:async()=>{posts++;throw Object.assign(Error('network down'),{name:'AbortError'});}});
    await controller.handle(job('PLAN_M574',1040));const row=store.snapshot().plans[0],install=job('INSTALL_M574',1041,{planId:row.planId,archiveSha256:row.archiveSha256,manifestSha256:row.manifestSha256});
    const result=await controller.handle(install),duplicate=await controller.handle(install);assert.deepEqual(result,duplicate);assert.equal(assertReceipt(controller,result,install).state,'UNKNOWN');assert.equal(posts,1);assert.equal(plannerCalls,2);
  });
});

test('expired-after-await PLAN is durably rejected and duplicate does not rerun Planner',async()=>{
  const store=makeStore(tempRoot());let now=baseTime,calls=0;const planner={async createPlan(){calls++;now=baseTime+MOBILE_INSTALL_JOB_TTL_MS;return plan();}};
  const controller=controllerFor({store,planner,clock:()=>now}),request=job('PLAN_M574',1050);
  const first=await controller.handle(request),duplicate=await controller.handle(request);assert.deepEqual(first,duplicate);assert.equal(calls,1);assert.equal(assertReceipt(controller,first,request).state,'REJECTED');assert.equal(first.errorCode,'JOB_EXPIRED');
});

test('a new already-expired PLAN is rejected without Planner work',async()=>{
  const store=makeStore(tempRoot());let calls=0;const planner={async createPlan(){calls++;return plan();}},controller=controllerFor({store,planner});
  const fields=body('PLAN_M574',{issuedAt:baseTime-MOBILE_INSTALL_JOB_TTL_MS,expiresAt:baseTime-1});
  const issueValue={number:1051,title:'HADES PLAN_M574',body:JSON.stringify(fields),user:{login:MOBILE_INSTALL_GITHUB_OWNER}};
  const stale=parseMobileInstallIssue({issue:issueValue,repository,authenticatedOwner:MOBILE_INSTALL_GITHUB_OWNER,now:baseTime});
  const result=await controller.handle(stale);assert.equal(assertReceipt(controller,result,stale).state,'REJECTED');assert.equal(result.errorCode,'JOB_EXPIRED');assert.equal(calls,0);
});

test('expired signed receipt refresh rejects ledger payload tampering',async()=>{
  const root=tempRoot(),store=makeStore(root);let now=baseTime,calls=0;const planner={async createPlan(){calls++;return plan();}},request=job('PLAN_M574',1052);
  const firstController=controllerFor({store,planner,clock:()=>now}),first=await firstController.handle(request);
  const ledgerFile=path.join(store.storeDir,'ledger.json'),ledger=JSON.parse(fs.readFileSync(ledgerFile,'utf8'));ledger.plans[0].receipt.archiveSha256='f'.repeat(64);fs.writeFileSync(ledgerFile,JSON.stringify(ledger),{mode:0o600});
  now=baseTime+300_001;const reopened=makeStore(root),controller=controllerFor({store:reopened,planner,clock:()=>now});
  await assert.rejects(controller.handle(request),/mobile_receipt_signature_invalid/);assert.equal(calls,1);assert.equal(first.state,'PLANNED');
});

test('production controller ignores the test-only client factory seam',()=>{
  const controller=createMobileInstallController({planner:{createPlan(){}},store:makeStore(tempRoot()),workerPrivateKey:worker.privateKey,trustedAdapterId:adapterId,trustedAdapterPublicKey:adapter.publicKey,
    clientFactory:()=>({install:async()=>{throw Error('bypass');}})});
  assert.equal(controller.workerId,workerId);
});
