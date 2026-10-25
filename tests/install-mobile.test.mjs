import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync,sign,verify} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {EventEmitter} from 'node:events';
import {readBody} from '../hades_mobile_installer/main.mjs';
import {
  APPARMOR_PROFILE_NAME,APPARMOR_PROFILE_SHA256,INSTALL_COMMIT,INSTALL_PACKAGE_PATH,INSTALL_PROTOCOL,INSTALL_REPOSITORY,
  MAX_TTL_MS,SUPPORTED_SUPERVISOR_VERSIONS,TARGET_DIR,TARGET_SLUG,
  createMobileInstaller,createSupervisorClient,signControlRequest,signInstallRequest
} from '../hades_mobile_installer/installer.mjs';

const beforeDockerfile=Buffer.from('# synthetic test baseline\nFROM scratch\n');
const afterDockerfile=Buffer.from('# synthetic test candidate\nFROM scratch\n');
const config=Buffer.from('name: synthetic-mobile-test\nversion: 0.0.0\n');
const hash=data=>createHash('sha256').update(data).digest('hex');
const expectedDockerfileHashes={old:hash(beforeDockerfile),candidate:hash(afterDockerfile)};
const broker=generateKeyPairSync('ed25519');
const brokerId='sha256:'+hash(broker.publicKey.export({type:'spki',format:'der'}));
let nextId=1;
function id(){const n=(nextId++).toString(16).padStart(12,'0');return `00000000-0000-4000-8000-${n}`;}
function tempDir(){return fs.mkdtempSync(path.join(os.tmpdir(),'hades-m575-test-'));}
function octal(n,width){return Buffer.from(n.toString(8).padStart(width-1,'0')+'\0','ascii');}
function tarEntry(name,body,mode=0o644,type=48){const h=Buffer.alloc(512);Buffer.from(name).copy(h);octal(mode,8).copy(h,100);octal(0,8).copy(h,108);octal(0,8).copy(h,116);octal(body.length,12).copy(h,124);octal(0,12).copy(h,136);h.fill(32,148,156);h[156]=type;Buffer.from('ustar\0').copy(h,257);Buffer.from('00').copy(h,263);let sum=0;for(const b of h)sum+=b;Buffer.from(sum.toString(8).padStart(6,'0')+'\0 ','ascii').copy(h,148);return Buffer.concat([h,body,Buffer.alloc((512-body.length%512)%512)]);}
function archive({dockerfile=afterDockerfile,configBytes=config,extra=[],duplicate=false}={}){
  const rows=[{path:'Dockerfile',bytes:dockerfile},{path:'config.yaml',bytes:configBytes}].map(x=>({path:x.path,sha256:hash(x.bytes),size:x.bytes.length,mode:0o644})).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  const manifest={protocol:'HADES_MOBILE_M574_PACKAGE_V1',repository:INSTALL_REPOSITORY,commit:INSTALL_COMMIT,packagePath:INSTALL_PACKAGE_PATH,files:rows};
  const manifestBytes=Buffer.from(JSON.stringify(manifest));
  const entries=[tarEntry('HADES-M574-MANIFEST.json',manifestBytes,0o600),tarEntry(`${INSTALL_PACKAGE_PATH}/Dockerfile`,dockerfile),tarEntry(`${INSTALL_PACKAGE_PATH}/config.yaml`,configBytes)];
  if(duplicate)entries.push(tarEntry(`${INSTALL_PACKAGE_PATH}/config.yaml`,configBytes));
  for(const entry of extra)entries.push(entry);
  return {bytes:gzipSync(Buffer.concat([...entries,Buffer.alloc(1024)]),{level:9}),manifestSha256:hash(manifestBytes)};
}
function fixtureTree(parent=tempDir()){
  const target=path.join(parent,'addons','hades_m2_mobile');fs.mkdirSync(target,{recursive:true,mode:0o755});
  fs.writeFileSync(path.join(target,'Dockerfile'),beforeDockerfile,{mode:0o644});fs.chmodSync(path.join(target,'Dockerfile'),0o644);fs.writeFileSync(path.join(target,'config.yaml'),config,{mode:0o644});fs.chmodSync(path.join(target,'config.yaml'),0o644);return {parent,target};
}
function makeInstaller({target,supervisor,root=tempDir(),clock=()=>1_800_000_000_000,buildTimeoutMs=1000,profileReader=()=>`${APPARMOR_PROFILE_NAME} (enforce)`}={}){
  return createMobileInstaller({enabled:true,brokerId,trustedBrokerPublicKey:broker.publicKey.export({type:'spki',format:'der'}).toString('base64'),privateDir:path.join(root,'private'),targetDir:target||TARGET_DIR,testOnlyAllowTargetOverride:!!target,testOnlyExpectedDockerfileHashes:expectedDockerfileHashes,supervisor,clock,buildTimeoutMs,profileReader,profileFile:path.resolve('hades_mobile_installer/apparmor.txt'),filesystemProfileProbe:(dir,file)=>{assert.equal(hash(fs.readFileSync(file)),APPARMOR_PROFILE_SHA256);assert.ok(fs.statSync(dir).isDirectory());}});
}
function requestFor(installer,packed,{now=1_800_000_000_000,jobId=id(),nonce=id(),expiresAt=now+60_000}={}){
  return signInstallRequest({protocol:INSTALL_PROTOCOL,action:'INSTALL_MOBILE_M574',brokerId,adapterId:installer.adapterId,jobId,nonce,issuedAt:now,expiresAt,repository:INSTALL_REPOSITORY,commit:INSTALL_COMMIT,packagePath:INSTALL_PACKAGE_PATH,archiveSha256:hash(packed.bytes),archiveSize:packed.bytes.length,manifestSha256:packed.manifestSha256},broker.privateKey);
}
function verifyResponse(response,adapterPublicKey){const fields=[response.protocol,response.adapterId,response.jobId,response.nonce,response.issuedAt,response.expiresAt,response.state,response.targetSlug,response.commit,response.archiveSha256,response.backupSlug,response.sourceSha256,response.errorCode];return verify(null,Buffer.from(JSON.stringify(fields)),adapterPublicKey,Buffer.from(response.signature,'base64url'));}
function fakeSupervisor({onBackup=()=>{},rebuild=async()=>{},preflight=async()=>({supervisorVersion:'2026.10.3',appVersion:'0.5.71-dev.m5.71'}),targetBuildRunning=async()=>false}={}){
  const calls=[];return {calls,async preflight(){calls.push('preflight');return preflight();},async createBackup(password,onStarted){calls.push('backup');assert.equal(typeof password,'string');onStarted({jobId:'job-fixed'});await onBackup();return 'backup-fixed';},async rebuild(){calls.push('rebuild');return rebuild();},async targetBuildRunning(){calls.push('jobs-info');return targetBuildRunning();}};
}

test('request body reader clears socket timeout and listeners after complete body',async()=>{
  class FakeRequest extends EventEmitter{
    setTimeout(milliseconds,callback){this.timeoutMs=milliseconds;this.timeoutCallback=milliseconds?callback:null;return this;}
    destroy(){this.destroyed=true;return this;}
  }
  const req=new FakeRequest();const pending=readBody(req,16);req.emit('data',Buffer.from('complete'));req.emit('end');
  assert.equal((await pending).toString(),'complete');assert.equal(req.timeoutMs,0);assert.equal(req.timeoutCallback,null);assert.equal(req.listenerCount('data'),0);assert.equal(req.listenerCount('end'),0);assert.equal(req.listenerCount('error'),0);
  req.emit('timeout');assert.equal(req.destroyed,undefined);
});

test('installer publishes default-off, exact target and supported Supervisor version gates',()=>{
  assert.equal(TARGET_DIR,'/addons/hades_m2_mobile');assert.equal(TARGET_SLUG,'local_hades_m2_mobile');assert.deepEqual(SUPPORTED_SUPERVISOR_VERSIONS,['2026.10.3']);assert.ok(MAX_TTL_MS<=300_000);
  assert.match(fs.readFileSync('hades_mobile_installer/config.yaml','utf8'),/^apparmor: true$/m);
  assert.throws(()=>makeInstaller({supervisor:fakeSupervisor(),profileReader:()=> 'unconfined'}),/apparmor_profile_not_enforcing/);
  assert.throws(()=>createMobileInstaller({enabled:false}),/installer_disabled/);
});

test('accepted package changes only Dockerfile and backs up before atomic promotion',async()=>{
  const {target,parent}=fixtureTree();const packed=archive();let instance,backupSawOld=false;
  const supervisor=fakeSupervisor({onBackup:async()=>{backupSawOld=hash(fs.readFileSync(path.join(target,'Dockerfile')))==hash(beforeDockerfile);}});
  instance=makeInstaller({target,root:parent,supervisor});const request=requestFor(instance,packed);const response=await instance.install(request,packed.bytes);
  assert.equal(response.state,'COMPLETED');assert.equal(response.targetSlug,TARGET_SLUG);assert.equal(response.commit,INSTALL_COMMIT);assert.equal(response.backupSlug,'backup-fixed');assert.ok(verifyResponse(response,(await import('node:crypto')).createPublicKey({key:Buffer.from(instance.publicKey,'base64'),format:'der',type:'spki'})));
  assert.equal(backupSawOld,true);assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(afterDockerfile));assert.equal(fs.readFileSync(path.join(target,'config.yaml'),'utf8'),config.toString());
  assert.deepEqual(supervisor.calls,['preflight','jobs-info','backup','jobs-info','rebuild']);
  assert.ok(fs.existsSync(target));
  const encrypted=fs.readdirSync(path.join(parent,'private','source-backups'));
  assert.equal(encrypted.length,1);assert.equal(fs.statSync(path.join(parent,'private','source-backups',encrypted[0])).mode&0o777,0o600);
  const journal=path.join(parent,'private','journal.json'),beforeReject=fs.readFileSync(journal);
  const invalid={...request,signature:'A'.repeat(86)};await assert.rejects(instance.install(invalid,packed.bytes),/INSTALL_REJECTED/);
  const expired=requestFor(instance,packed,{jobId:request.jobId,now:1_799_000_000_000,expiresAt:1_799_000_100_000});await assert.rejects(instance.install(expired,packed.bytes),/INSTALL_REJECTED/);
  const conflict=requestFor(instance,archive({configBytes:Buffer.from('different but signed\n')}),{jobId:request.jobId});await assert.rejects(instance.install(conflict,packed.bytes),/INSTALL_REJECTED/);
  assert.deepEqual(fs.readFileSync(journal),beforeReject);
});

test('candidate config mutation is signed-rejected before any backup or write',async()=>{
  const {target}=fixtureTree();const supervisor=fakeSupervisor();const instance=makeInstaller({target,supervisor});const packed=archive({configBytes:Buffer.from(config.toString()+'queue_enabled: true\n')});
  const response=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(response.state,'REJECTED');assert.equal(response.errorCode,'SOURCE_DELTA_REJECTED');assert.deepEqual(supervisor.calls,[]);assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(beforeDockerfile));
});

test('tar parser rejects duplicate names and link/special entries',async t=>{
  for(const [name,packed] of [['duplicate',archive({duplicate:true})],['symlink',archive({extra:[tarEntry(`${INSTALL_PACKAGE_PATH}/link`,Buffer.alloc(0),0o777,50)]})]]){
    await t.test(name,async()=>{const {target}=fixtureTree();const supervisor=fakeSupervisor();const instance=makeInstaller({target,supervisor});const response=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(response.state,'REJECTED');assert.deepEqual(supervisor.calls,[]);});
  }
});

test('request expiry and signature failures make no Supervisor calls',async()=>{
  const {target}=fixtureTree(),supervisor=fakeSupervisor(),instance=makeInstaller({target,supervisor}),packed=archive();
  const expired=requestFor(instance,packed,{now:1_800_000_000_000,expiresAt:1_800_000_000_000});await assert.rejects(instance.install(expired,packed.bytes),/INSTALL_REJECTED/);
  const valid=requestFor(instance,packed),bad={...valid,signature:'A'.repeat(86)};await assert.rejects(instance.install(bad,packed.bytes),/INSTALL_REJECTED/);
  assert.deepEqual(supervisor.calls,[]);
});

test('unsupported Supervisor build is recorded and no backup begins',async()=>{
  const {target}=fixtureTree(),supervisor=fakeSupervisor({preflight:async()=>{const e=Error('supervisor_version_unsupported');e.supervisorVersion='2026.10.4';throw e;}}),instance=makeInstaller({target,supervisor}),packed=archive();
  const response=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(response.state,'REJECTED');assert.equal(response.errorCode,'SUPERVISOR_VERSION_UNSUPPORTED');assert.deepEqual(supervisor.calls,['preflight']);assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(beforeDockerfile));
});

test('confirmed build failure restores exact previous source then rebuilds once',async()=>{
  const {target}=fixtureTree();let calls=0;const supervisor=fakeSupervisor({rebuild:async()=>{if(++calls===1){const e=Error('build failed');e.code='SUPERVISOR_HTTP_500';throw e;}return {};}}),instance=makeInstaller({target,supervisor}),packed=archive();
  const response=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(response.state,'ROLLED_BACK');assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(beforeDockerfile));assert.equal(calls,2);assert.deepEqual(supervisor.calls,['preflight','jobs-info','backup','jobs-info','rebuild','jobs-info','rebuild']);
});

test('rebuild timeout is UNKNOWN and prevents a second install from mutating',async()=>{
  const {target}=fixtureTree();const supervisor=fakeSupervisor({rebuild:()=>new Promise(()=>{})});const instance=makeInstaller({target,supervisor,buildTimeoutMs:5}),packed=archive();
  const first=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(first.state,'UNKNOWN');assert.equal(first.errorCode,'BUILD_OUTCOME_UNKNOWN');assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(afterDockerfile));
  const second=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(second.state,'REJECTED');assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(afterDockerfile));assert.equal(supervisor.calls.filter(x=>x==='rebuild').length,1);
});

test('reviewed signed reconciliation can explicitly restore only original source',async()=>{
  const {target}=fixtureTree();let statusCalls=0;const supervisor=fakeSupervisor({rebuild:()=>new Promise(()=>{}),targetBuildRunning:async()=>++statusCalls>2});const instance=makeInstaller({target,supervisor,buildTimeoutMs:5}),packed=archive();const installed=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(installed.state,'UNKNOWN');
  const now=1_800_000_000_100,fields={protocol:INSTALL_PROTOCOL,action:'RECONCILE_MOBILE_INSTALL',brokerId,adapterId:instance.adapterId,jobId:installed.jobId,nonce:id(),issuedAt:now,expiresAt:now+60_000,decision:'ROLLBACK_SOURCE',reviewId:id()};
  // The build still appears active, so reconciliation returns a signed status without a write.
  const busy=await instance.reconcile(signControlRequest(fields,broker.privateKey));assert.equal(busy.errorCode,'BUILD_STILL_RUNNING');assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(afterDockerfile));
});

test('KEEP_CANDIDATE requires the exact backed-up tree with only the pinned Dockerfile delta',async()=>{
  const {target,parent}=fixtureTree();const supervisor=fakeSupervisor({rebuild:()=>new Promise(()=>{})}),instance=makeInstaller({target,root:parent,supervisor,buildTimeoutMs:5}),packed=archive();
  const installed=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(installed.state,'UNKNOWN');
  fs.appendFileSync(path.join(target,'config.yaml'),'tampered: true\n');
  const now=1_800_000_000_100,fields={protocol:INSTALL_PROTOCOL,action:'RECONCILE_MOBILE_INSTALL',brokerId,adapterId:instance.adapterId,jobId:installed.jobId,nonce:id(),issuedAt:now,expiresAt:now+60_000,decision:'KEEP_CANDIDATE',reviewId:id()};
  const result=await instance.reconcile(signControlRequest(fields,broker.privateKey));assert.equal(result.state,'UNKNOWN');assert.equal(result.errorCode,'RECONCILIATION_FAILED');
});

test('reconciliation reply gets a fresh signed TTL after a long rollback build',async()=>{
  const {target}=fixtureTree();let now=1_800_000_000_000,builds=0;
  const supervisor=fakeSupervisor({rebuild:async()=>{if(++builds===1)return new Promise(()=>{});now+=600_000;return {};}});
  const instance=makeInstaller({target,supervisor,clock:()=>now,buildTimeoutMs:5}),packed=archive(),installed=await instance.install(requestFor(instance,packed),packed.bytes);assert.equal(installed.state,'UNKNOWN');
  const fields={protocol:INSTALL_PROTOCOL,action:'RECONCILE_MOBILE_INSTALL',brokerId,adapterId:instance.adapterId,jobId:installed.jobId,nonce:id(),issuedAt:now,expiresAt:now+60_000,decision:'ROLLBACK_SOURCE',reviewId:id()};
  const response=await instance.reconcile(signControlRequest(fields,broker.privateKey));assert.equal(response.state,'ROLLED_BACK_RECONCILED');assert.equal(response.issuedAt,now);assert.equal(response.expiresAt-now,MAX_TTL_MS);
  assert.ok(verifyResponse(response,(await import('node:crypto')).createPublicKey({key:Buffer.from(instance.publicKey,'base64'),format:'der',type:'spki'})));
});

test('startup converts a persisted in-flight journal entry to UNKNOWN without mutation',()=>{
  const {target,parent}=fixtureTree(),privateDir=path.join(parent,'private');fs.mkdirSync(privateDir,{mode:0o700});fs.chmodSync(privateDir,0o700);
  fs.writeFileSync(path.join(privateDir,'journal.json'),JSON.stringify({version:1,jobs:[{jobId:id(),nonce:id(),state:'BUILD_FAILED',errorCode:'',reconciliations:[]}]}),{mode:0o600});fs.chmodSync(path.join(privateDir,'journal.json'),0o600);
  const instance=makeInstaller({target,root:parent,supervisor:fakeSupervisor()});assert.equal(instance.snapshot().jobs[0].state,'UNKNOWN');assert.equal(instance.snapshot().jobs[0].errorCode,'INTERRUPTED_STATE');assert.equal(hash(fs.readFileSync(path.join(target,'Dockerfile'))),hash(beforeDockerfile));
});

test('Supervisor client unwraps real API envelopes and checks actual backup model and child jobs',async()=>{
  const seen=[];const fake=async(url,init)=>{
    seen.push({url:String(url),method:init.method,token:init.headers.authorization,body:init.body});let data={};
    if(String(url).endsWith('/supervisor/info'))data={version:'2026.10.3'};
    else if(String(url).endsWith('/addons'))data={addons:[{slug:TARGET_SLUG,build:true,version:'0.5.71-dev.m5.71',version_latest:'0.5.71-dev.m5.71',installed:'0.5.71-dev.m5.71'}]};
    else if(String(url).endsWith('/backups/new/partial'))data={job_id:'job-1'};
    else if(String(url).endsWith('/jobs/job-1'))data={done:true,reference:'back-1',errors:[],child_jobs:[{done:true,errors:[],child_jobs:[]}]};
    else if(String(url).endsWith('/backups/back-1/info'))data={slug:'back-1',type:'partial',protected:true,homeassistant:null,addons:[{slug:TARGET_SLUG,version:'0.5.71-dev.m5.71',size:1}],folders:[],repositories:['supervisor metadata is also present']};
    else if(String(url).endsWith('/jobs/info'))data={jobs:[]};
    return new Response(JSON.stringify({result:'ok',data}),{status:200,headers:{'content-type':'application/json'}});
  };
  const client=createSupervisorClient({token:'x'.repeat(24),fetchImpl:fake});assert.deepEqual(await client.preflight(),{supervisorVersion:'2026.10.3',appVersion:'0.5.71-dev.m5.71'});
  let started;assert.equal(await client.createBackup('p'.repeat(32),value=>{started=value;}),'back-1');assert.deepEqual(started,{jobId:'job-1'});assert.equal(await client.targetBuildRunning(),false);
  assert.ok(seen.every(x=>x.token==='Bearer '+'x'.repeat(24)));assert.ok(seen.every(x=>!x.url.endsWith('/addons/local_hades_m2_mobile/info')));
  const partial=JSON.parse(seen.find(x=>x.url.endsWith('/backups/new/partial')).body);assert.deepEqual(partial.addons,[TARGET_SLUG]);assert.equal(partial.homeassistant,false);assert.deepEqual(partial.folders,[]);assert.equal(partial.background,true);assert.equal(Object.hasOwn(partial,'slug'),false);
});

test('Supervisor client rejects unwrapped errors and backup child-job failures',async t=>{
  await t.test('unwrapped response',async()=>{const client=createSupervisorClient({token:'y'.repeat(24),fetchImpl:async()=>new Response(JSON.stringify({error:'not the Supervisor envelope'}),{status:200})});await assert.rejects(client.preflight());});
  await t.test('child error',async()=>{const fake=async(url)=>{let data={};if(String(url).endsWith('/backups/new/partial'))data={job_id:'j'};else if(String(url).endsWith('/jobs/j'))data={done:true,reference:'b',errors:[],child_jobs:[{done:true,errors:[{type:'failed'}]}]};return new Response(JSON.stringify({result:'ok',data}),{status:200});};const client=createSupervisorClient({token:'z'.repeat(24),fetchImpl:fake});await assert.rejects(client.createBackup('z'.repeat(32)),/backup_job_failed/);});
});

test('Supervisor preflight uses the actual info response without an undocumented state field',async()=>{
  const client=createSupervisorClient({token:'r'.repeat(24),fetchImpl:async url=>{
    let data={};if(String(url).endsWith('/supervisor/info'))data={version:'2026.10.3'};
    else if(String(url).endsWith('/addons'))data={addons:[{slug:TARGET_SLUG,build:true,version:'0.5.71-dev.m5.71',version_latest:'0.5.71-dev.m5.71',installed:'0.5.71-dev.m5.71'}]};
    return new Response(JSON.stringify({result:'ok',data}),{status:200});
  }});
  assert.deepEqual(await client.preflight(),{supervisorVersion:'2026.10.3',appVersion:'0.5.71-dev.m5.71'});
});

test('Supervisor job polling rejects malformed data and detects active nested target jobs',async t=>{
  const clientFor=jobs=>createSupervisorClient({token:'j'.repeat(24),fetchImpl:async()=>new Response(JSON.stringify({result:'ok',data:{jobs}}),{status:200})});
  await assert.rejects(clientFor(undefined).targetBuildRunning(),/jobs_info_invalid/);
  await assert.rejects(clientFor([{}]).targetBuildRunning(),/jobs_info_invalid/);
  assert.equal(await clientFor([{done:true,reference:'other',child_jobs:[{done:false,reference:TARGET_SLUG,child_jobs:[]}]}]).targetBuildRunning(),true);
});

test('Supervisor API response stream has a hard read limit',async()=>{
  const oversized=new Response(JSON.stringify({result:'ok',data:{x:'a'.repeat(1024*1024+20)}}),{status:200});const client=createSupervisorClient({token:'t'.repeat(24),fetchImpl:async()=>oversized});await assert.rejects(client.preflight(),/supervisor_outcome_unknown/);
});
