import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,generateKeyPairSync,sign,verify} from 'node:crypto';
import {
  MOBILE_INSTALL_ACTION,MOBILE_INSTALL_PROTOCOL,MOBILE_INSTALL_TARGET_SLUG,MOBILE_INSTALLER_TIMEOUT_MS,
  MOBILE_INSTALLER_ORIGIN,MOBILE_INSTALLER_ROUTE,MOBILE_INSTALL_TTL_MS,createMobileInstallClient
} from '../hades_mobile_build_worker/worker/mobile-install-client.mjs';
import {MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY} from '../hades_mobile_build_worker/worker/mobile-install-plan.mjs';
import {identityId} from '../hades_mobile_build_worker/shared/protocol.mjs';

const hash=bytes=>createHash('sha256').update(bytes).digest('hex');
const worker=generateKeyPairSync('ed25519'),adapter=generateKeyPairSync('ed25519'),attacker=generateKeyPairSync('ed25519');
const workerPublic=worker.publicKey,adapterPublic=adapter.publicKey,adapterId=identityId(adapterPublic),now=1_800_000_000_000;
const archive=Buffer.from('synthetic-compressed-package'),archiveSha256=hash(archive),manifestSha256='a'.repeat(64);
const plan={repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,archive,archiveSha256,archiveSize:archive.length,manifestSha256};
let idCounter=1;
function uuid(){return `00000000-0000-4000-8000-${(idCounter++).toString(16).padStart(12,'0')}`;}
function makeClient({fetchImpl,trustedAdapterPublicKey=adapterPublic,trustedAdapterId=adapterId,timeoutMs=1000,clock=()=>now,workerPrivateKey=worker.privateKey,persistIntent=async()=>{}}={}){
  return createMobileInstallClient({workerPrivateKey,trustedAdapterId,trustedAdapterPublicKey,persistIntent,fetchImpl,timeoutMs,clock,uuidFactory:uuid});
}
function responseFor(request,patch={},signingKey=adapter.privateKey,{issuedAt=now}={}){
  const result={protocol:MOBILE_INSTALL_PROTOCOL,adapterId,jobId:request.jobId,nonce:request.nonce,issuedAt,expiresAt:issuedAt+MOBILE_INSTALL_TTL_MS,
    state:'COMPLETED',targetSlug:MOBILE_INSTALL_TARGET_SLUG,commit:MOBILE_INSTALL_COMMIT,archiveSha256:request.archiveSha256,backupSlug:'backup-abc',sourceSha256:'b'.repeat(64),errorCode:'',signature:'',...patch};
  const bytes=Buffer.from(JSON.stringify([result.protocol,result.adapterId,result.jobId,result.nonce,result.issuedAt,result.expiresAt,result.state,result.targetSlug,result.commit,result.archiveSha256,result.backupSlug,result.sourceSha256,result.errorCode]));
  result.signature=sign(null,bytes,signingKey).toString('base64url');return result;
}
function responseFetch(makeResult,observe=()=>{}){return async(url,init)=>{
  observe(url,init);const request=JSON.parse(Buffer.from(init.headers['x-hades-install-request'],'base64url').toString('utf8'));
  const body=JSON.stringify(makeResult(request));return new Response(body,{status:200,headers:{'content-type':'application/json'}});
};}
function assertUnknown(promise,code){return assert.rejects(promise,error=>error?.outcome==='UNKNOWN'&&error.code===code);}

test('POST sends the exact signed installer contract to one fixed origin and verifies its response',async()=>{
  let seen,persisted;
  const client=makeClient({persistIntent:async intent=>{persisted=intent;},fetchImpl:responseFetch(request=>responseFor(request),(...args)=>{seen=args;})});
  const result=await client.install(plan);assert.equal(result.state,'COMPLETED');assert.equal(result.adapterId,adapterId);
  const [url,init]=seen;assert.equal(url,MOBILE_INSTALLER_ORIGIN+MOBILE_INSTALLER_ROUTE);assert.equal(init.method,'POST');assert.equal(init.redirect,'error');
  assert.equal(init.headers['content-type'],'application/gzip');assert.equal(init.headers.authorization,undefined);assert.deepEqual(init.body,archive);
  const request=JSON.parse(Buffer.from(init.headers['x-hades-install-request'],'base64url').toString('utf8'));
  assert.deepEqual(persisted.request,request);assert.equal(persisted.requestHeader,init.headers['x-hades-install-request']);assert.equal(persisted.origin,MOBILE_INSTALLER_ORIGIN);assert.equal(persisted.route,MOBILE_INSTALLER_ROUTE);
  assert.deepEqual(Object.keys(request).sort(),['action','adapterId','archiveSha256','archiveSize','brokerId','commit','expiresAt','issuedAt','jobId','manifestSha256','nonce','packagePath','protocol','repository','signature'].sort());
  assert.equal(request.protocol,MOBILE_INSTALL_PROTOCOL);assert.equal(request.action,MOBILE_INSTALL_ACTION);assert.equal(request.adapterId,adapterId);
  assert.equal(request.repository,MOBILE_INSTALL_REPOSITORY);assert.equal(request.commit,MOBILE_INSTALL_COMMIT);assert.equal(request.packagePath,MOBILE_INSTALL_PACKAGE_PATH);
  assert.equal(request.archiveSha256,archiveSha256);assert.equal(request.archiveSize,archive.length);assert.equal(request.manifestSha256,manifestSha256);
  assert.equal(request.issuedAt,now);assert.equal(request.expiresAt-now,MOBILE_INSTALL_TTL_MS);
  const requestBytes=Buffer.from(JSON.stringify([request.protocol,request.action,request.brokerId,request.adapterId,request.jobId,request.nonce,request.issuedAt,request.expiresAt,request.repository,request.commit,request.packagePath,request.archiveSha256,request.archiveSize,request.manifestSha256]));
  assert.ok(verify(null,requestBytes,workerPublic,Buffer.from(request.signature,'base64url')));
});

test('client rejects missing worker/adapter keys and a mismatched adapter pin before sending',()=>{
  const noNetwork=async()=>{throw Error('should_not_send');};
  assert.throws(()=>makeClient({workerPrivateKey:null,fetchImpl:noNetwork}),/worker_private_key_missing/);
  assert.throws(()=>createMobileInstallClient({workerPrivateKey:worker.privateKey,fetchImpl:noNetwork}),/adapter_identity_missing/);
  assert.throws(()=>createMobileInstallClient({workerPrivateKey:worker.privateKey,trustedAdapterId:adapterId,trustedAdapterPublicKey:adapterPublic,fetchImpl:noNetwork}),/install_client_options_invalid/);
  assert.throws(()=>makeClient({trustedAdapterPublicKey:null,fetchImpl:noNetwork}),/adapter_public_key_missing/);
  assert.throws(()=>makeClient({trustedAdapterId:'sha256:'+'0'.repeat(64),fetchImpl:noNetwork}),/adapter_identity_mismatch/);
});

test('intent persistence failure and restart reconciliation use the exact stored job id',async()=>{
  let sends=0;const client=makeClient({persistIntent:async()=>{throw Error('private store unavailable');},fetchImpl:async()=>{sends++;}});
  await assert.rejects(client.install(plan),error=>error.code==='install_intent_persist_failed');assert.equal(sends,0);
  let stored;const durableClient=makeClient({persistIntent:async intent=>{stored=structuredClone(intent);},fetchImpl:responseFetch(request=>responseFor(request))});
  await durableClient.install(plan);
  const persistedRequest=stored.request;
  assert.equal(persistedRequest.jobId,JSON.parse(Buffer.from(stored.requestHeader,'base64url').toString('utf8')).jobId);
  const control={protocol:MOBILE_INSTALL_PROTOCOL,action:'RECONCILE_MOBILE_INSTALL',brokerId:persistedRequest.brokerId,adapterId:persistedRequest.adapterId,
    jobId:persistedRequest.jobId,nonce:uuid(),issuedAt:now,expiresAt:now+MOBILE_INSTALL_TTL_MS,decision:'ABORT_NO_SOURCE_CHANGE',reviewId:uuid(),signature:''};
  const controlBytes=Buffer.from(JSON.stringify([control.protocol,control.action,control.brokerId,control.adapterId,control.jobId,control.nonce,control.issuedAt,control.expiresAt,control.decision,control.reviewId]));
  control.signature=sign(null,controlBytes,worker.privateKey).toString('base64url');
  assert.equal(control.jobId,persistedRequest.jobId);assert.ok(verify(null,controlBytes,workerPublic,Buffer.from(control.signature,'base64url')));
});

test('installer-success replies require verified backup and source evidence',async t=>{
  assert.ok(MOBILE_INSTALLER_TIMEOUT_MS>=40*60_000);
  for(const [label,patch] of [['missing backup',{backupSlug:''}],['missing source hash',{sourceSha256:''}],['reported error',{errorCode:'BUILD_FAILED'}]]){
    await t.test(label,async()=>{
      const fetchImpl=responseFetch(request=>responseFor(request,patch));
      await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_success_evidence_missing');
    });
  }
});

test('does not allow a caller-supplied origin and reports redirect-origin changes as UNKNOWN',async()=>{
  let calledUrl='';const fetchImpl=responseFetch(request=>responseFor(request),(url)=>{calledUrl=url;});
  const client=makeClient({fetchImpl,origin:'https://example.invalid'});await client.install(plan);assert.equal(calledUrl,MOBILE_INSTALLER_ORIGIN+MOBILE_INSTALLER_ROUTE);
  const wrongOrigin=async(url,init)=>{
    const request=JSON.parse(Buffer.from(init.headers['x-hades-install-request'],'base64url').toString('utf8'));
    const response=new Response(JSON.stringify(responseFor(request)),{status:200,headers:{'content-type':'application/json'}});
    return {status:200,ok:true,url:'http://other-installer:8767/v1/mobile/install',headers:response.headers,body:response.body};
  };
  await assertUnknown(makeClient({fetchImpl:wrongOrigin}).install(plan),'installer_origin_mismatch');
});

test('rejects response signature and identity mismatches as UNKNOWN',async t=>{
  await t.test('wrong signing key',async()=>{
    const fetchImpl=responseFetch(request=>responseFor(request,{},attacker.privateKey));
    await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_response_signature_invalid');
  });
  await t.test('wrong adapter id',async()=>{
    const fetchImpl=responseFetch(request=>responseFor(request,{adapterId:'sha256:'+'c'.repeat(64)}));
    await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_response_invalid');
  });
});

test('rejects stale replay and mismatched request correlations as UNKNOWN',async t=>{
  for(const [label,patch] of [
    ['old job',{jobId:'00000000-0000-4000-8000-ffffffffffff'}],
    ['old nonce',{nonce:'00000000-0000-4000-8000-eeeeeeeeeeee'}],
    ['wrong commit',{commit:'f'.repeat(40)}],['wrong target',{targetSlug:'local_other_app'}],['wrong archive',{archiveSha256:'d'.repeat(64)}],
    ['expired',{issuedAt:now-MOBILE_INSTALL_TTL_MS-100,expiresAt:now-100}]
  ])await t.test(label,async()=>{
    const fetchImpl=responseFetch(request=>responseFor(request,patch));await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_response_invalid');
  });
});

test('timeout, non-success upstream status, malformed and oversized bodies stay UNKNOWN without retry',async t=>{
  await t.test('timeout exactly one POST',async()=>{
    let calls=0;const fetchImpl=async(_url,init)=>{calls++;return new Promise((_resolve,reject)=>{init.signal.addEventListener('abort',()=>reject(Object.assign(Error('aborted'),{name:'AbortError'})));});};
    await assertUnknown(makeClient({fetchImpl,timeoutMs:100}).install(plan),'installer_outcome_unknown');assert.equal(calls,1);
  });
  await t.test('upstream 500',async()=>{
    let calls=0;const fetchImpl=async()=>{calls++;return new Response('untrusted upstream error',{status:500});};
    await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_upstream_error');assert.equal(calls,1);
  });
  await t.test('malformed response',async()=>{
    const fetchImpl=async()=>new Response('{bad',{status:200,headers:{'content-type':'application/json'}});
    await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_response_invalid');
  });
  await t.test('bounded response',async()=>{
    const fetchImpl=async()=>new Response(JSON.stringify({payload:'x'.repeat(20*1024)}),{status:200,headers:{'content-type':'application/json'}});
    await assertUnknown(makeClient({fetchImpl}).install(plan),'installer_response_too_large');
  });
});

test('rejects an altered package plan before sending',async()=>{
  let calls=0;const client=makeClient({fetchImpl:async()=>{calls++;}});
  await assert.rejects(client.install({...plan,commit:'0'.repeat(40)}),/install_plan_invalid/);
  await assert.rejects(client.install({...plan,archiveSha256:'0'.repeat(64)}),/install_plan_invalid/);assert.equal(calls,0);
});
