import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {createPrivateKey,createPublicKey,generateKeyPairSync} from 'node:crypto';
import {VERSION,MAX_MESSAGE_BYTES,QUEUE_CAPACITY,identityId,verifyRequest,signResponse,replayKey,requestDigest} from '../shared/protocol.mjs';
import {createPackageStageReceiver,MAX_ARCHIVE_BYTES} from './package-stage.mjs';

const MAX_LEDGER=2048;
const HTTP_PATH='/v1/diagnostic';
const HTTP_PACKAGE_PATH='/v1/package-stage';
const VERSION_WORKER='0.0.6-dev.m5.12';

function readPrivateKey(file) {
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)!==0||
      (typeof process.getuid==='function'&&st.uid!==process.getuid())) throw Error('private_key_permissions');
  return createPrivateKey(fs.readFileSync(file));
}
function loadOrCreatePrivateKey(file) {
  try { return {key:readPrivateKey(file),created:false}; }
  catch(error) { if(error.code!=='ENOENT') throw error; }
  const pair=generateKeyPairSync('ed25519');
  const pem=pair.privateKey.export({type:'pkcs8',format:'pem'});
  const fd=fs.openSync(file,'wx',0o600);
  try { fs.writeFileSync(fd,pem); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.chmodSync(file,0o600);
  return {key:pair.privateKey,created:true};
}
function publicKeyFromB64(value) {
  if(typeof value!=='string'||value.length<40||value.length>512||!/^[A-Za-z0-9+/]+={0,2}$/.test(value))
    throw Error('trusted_key_invalid');
  return createPublicKey({key:Buffer.from(value,'base64'),format:'der',type:'spki'});
}
function loadLedger(file) {
  try {
    const st=fs.lstatSync(file);
    if(!st.isFile()||st.isSymbolicLink()||(st.mode&0o077)!==0||
        (typeof process.getuid==='function'&&st.uid!==process.getuid())) throw Error('ledger_permissions');
    const value=JSON.parse(fs.readFileSync(file,'utf8'));
    if(!value||value.version!==1||!Array.isArray(value.entries)||value.entries.length>MAX_LEDGER)
      throw Error('ledger_invalid');
    const entries=new Map();
    for(const pair of value.entries) {
      if(!Array.isArray(pair)||pair.length!==2||typeof pair[0]!=='string'||!pair[1]||
          typeof pair[1].digest!=='string'||!pair[1].response) throw Error('ledger_invalid');
      entries.set(pair[0],pair[1]);
    }
    return entries;
  } catch(error) {
    if(error.code==='ENOENT') return new Map();
    throw Error('ledger_unavailable');
  }
}
function saveLedger(file,ledger) {
  const directory=path.dirname(file);
  fs.mkdirSync(directory,{recursive:true,mode:0o700});
  const dirStat=fs.statSync(directory);
  if((dirStat.mode&0o077)!==0||(typeof process.getuid==='function'&&dirStat.uid!==process.getuid()))
    throw Error('ledger_directory_permissions');
  const temp=file+'.tmp-'+process.pid;
  fs.writeFileSync(temp,JSON.stringify({version:1,entries:[...ledger]}),{mode:0o600,flag:'wx'});
  fs.renameSync(temp,file);
}
function diagnosticResult(kind,{startedAt,ledger}) {
  const uptimeSeconds=Math.max(0,Math.floor((Date.now()-startedAt)/1000));
  if(kind==='STATUS_CHECK') return {
    component:'HADES_BUILD_WORKER',version:VERSION_WORKER,state:'READY',
    executionEnabled:false,uptimeSeconds
  };
  if(kind==='HEARTBEAT_CHECK') return {state:'ALIVE',uptimeSeconds,observedAt:Date.now()};
  if(kind==='QUEUE_HEALTH_CHECK') return {
    state:'HEALTHY',depth:0,capacity:QUEUE_CAPACITY,ledgerEntries:ledger.size,executable:false
  };
  throw Error('unsupported_operation');
}
export function createDiagnosticReceiver({enabled,brokerId,trustedBrokerPublicKey,workerPrivateKey,ledgerPath,clock=Date.now}={}) {
  if(enabled!==true) throw Error('worker_disabled');
  if(!brokerId||!trustedBrokerPublicKey||!workerPrivateKey||!ledgerPath) throw Error('worker_identity_or_state_missing');
  const brokerKey=typeof trustedBrokerPublicKey==='string'?publicKeyFromB64(trustedBrokerPublicKey):trustedBrokerPublicKey;
  const workerKey=typeof workerPrivateKey==='string'?createPrivateKey(workerPrivateKey):workerPrivateKey;
  const workerId=identityId(createPublicKey(workerKey));
  if(identityId(brokerKey)!==brokerId) throw Error('trusted_broker_identity_mismatch');
  const ledger=loadLedger(ledgerPath),startedAt=clock();
  function handle(raw) {
    if(typeof raw!=='string'||Buffer.byteLength(raw,'utf8')>MAX_MESSAGE_BYTES) throw Error('request_too_large');
    let value; try { value=JSON.parse(raw); } catch { throw Error('request_json_invalid'); }
    const request=verifyRequest(value,brokerKey,{brokerId,workerId,now:clock()});
    const key=replayKey(request),digest=requestDigest(request),prior=ledger.get(key);
    if(prior) {
      if(prior.digest!==digest) throw Error('replay_conflict');
      return prior.response;
    }
    for(const row of ledger.values())
      if(row.taskId===request.taskId||row.jobId===request.jobId||row.nonce===request.nonce)
        throw Error('replay_conflict');
    if(ledger.size>=MAX_LEDGER) throw Error('ledger_full');
    const result=diagnosticResult(request.kind,{startedAt,ledger});
    const response=signResponse({
      version:VERSION,brokerId,workerId,taskId:request.taskId,jobId:request.jobId,
      nonce:request.nonce,issuedAt:clock(),expiresAt:request.expiresAt,kind:request.kind,
      state:'COMPLETED',result
    },workerKey);
    ledger.set(key,{taskId:request.taskId,jobId:request.jobId,nonce:request.nonce,digest,response});
    saveLedger(ledgerPath,ledger);
    return response;
  }
  return Object.freeze({workerId,handle,snapshot:()=>Object.freeze({
    ledgerEntries:ledger.size,ledgerCapacity:MAX_LEDGER,queueDepth:0,queueCapacity:QUEUE_CAPACITY,executable:false
  })});
}
function parseOptions(file) {
  const options=process.env.HADES_OPTIONS_JSON
    ?JSON.parse(process.env.HADES_OPTIONS_JSON)
    :JSON.parse(fs.readFileSync(file,'utf8'));
  if(!options||typeof options!=='object'||Array.isArray(options)) throw Error('options_invalid');
  if(typeof options.enabled!=='boolean'||(options.package_stage_enabled!==undefined&&typeof options.package_stage_enabled!=='boolean')||!Number.isInteger(options.listen_port)||
      options.listen_port<1024||options.listen_port>65535||
      typeof options.trusted_broker_id!=='string'||typeof options.trusted_broker_public_key!=='string')
    throw Error('options_invalid');
  return options;
}
export function createServer(receiver,{port,host='::',clock=Date.now,packageStageReceiver=null}) {
  let active=0,windowStart=clock(),windowCount=0;
  const server=http.createServer((req,res)=>{
    const release=()=>{if(active>0)active--;};
    if(req.method!=='POST'||![HTTP_PATH,HTTP_PACKAGE_PATH].includes(req.url)){res.writeHead(404,{'cache-control':'no-store'}).end();return;}
    const isPackage=req.url===HTTP_PACKAGE_PATH;
    if(isPackage&&!packageStageReceiver){res.writeHead(404,{'cache-control':'no-store'}).end();return;}
    const expectedType=isPackage?'application/gzip':'application/json';
    if(req.headers['content-type']?.split(';')[0].trim().toLowerCase()!==expectedType){
      res.writeHead(415,{'cache-control':'no-store'}).end();return;
    }
    const now=clock();
    if(now-windowStart>=60_000){windowStart=now;windowCount=0;}
    if(active>=8||windowCount>=60){res.writeHead(429,{'cache-control':'no-store'}).end();return;}
    active++;windowCount++;
    res.once('close',release);
    req.setTimeout(5000,()=>req.destroy());
    let size=0;const chunks=[];
    req.on('data',chunk=>{
      size+=chunk.length;
      if(size>(isPackage?MAX_ARCHIVE_BYTES:MAX_MESSAGE_BYTES)){res.writeHead(413,{'cache-control':'no-store'}).end();req.destroy();return;}
      chunks.push(chunk);
    });
    req.on('error',()=>{});
    req.on('end',()=>{
      if(res.writableEnded)return;
      try {
        const bytes=Buffer.concat(chunks);
        let value;
        if(isPackage){
          const encoded=req.headers['x-hades-package-envelope'];
          if(typeof encoded!=='string'||encoded.length>4096||!/^[A-Za-z0-9_-]+$/.test(encoded))throw Error('package_envelope_invalid');
          value=packageStageReceiver.stage(JSON.parse(Buffer.from(encoded,'base64url').toString('utf8')),bytes);
        }else value=receiver.handle(bytes.toString('utf8'));
        res.writeHead(200,{'content-type':'application/json','cache-control':'no-store'}).end(JSON.stringify(value));
      } catch {
        res.writeHead(400,{'cache-control':'no-store'}).end(isPackage?'package stage rejected':'diagnostic request rejected');
      }
    });
  });
  return server.listen(port,host);
}
export async function main() {
  if(typeof process.getuid!=='function'||process.getuid()===0) throw Error('unprivileged_uid_required');
  const options=parseOptions(process.env.HADES_OPTIONS_FILE||'/data/options.json');
  if(options.enabled!==true) {
    console.log(JSON.stringify({state:'HADES_BUILD_WORKER_DISABLED',version:VERSION_WORKER,executionEnabled:false}));
    const timer=setInterval(()=>{},120_000);timer.ref();return;
  }
  const keyPath=process.env.HADES_PRIVATE_KEY_PATH||'/data/hades-m42.4/worker-ed25519.pem';
  const provisioned=loadOrCreatePrivateKey(keyPath);
  const privateKey=provisioned.key;
  const publicKey=createPublicKey(privateKey);
  const publicKeyBase64=publicKey.export({type:'spki',format:'der'}).toString('base64');
  const receiver=createDiagnosticReceiver({
    enabled:true,brokerId:options.trusted_broker_id,
    trustedBrokerPublicKey:options.trusted_broker_public_key,
    workerPrivateKey:privateKey,
    ledgerPath:process.env.HADES_LEDGER_PATH||'/data/hades-m42.4/diagnostic-ledger.json'
  });
  let packageStageReceiver=null;
  if(options.package_stage_enabled===true){
    // launcher.mjs prepares this existing worker-owned, mode-0700 data root
    // before dropping to UID/GID 1000. Keeping stage data beneath it avoids
    // writes to the Supervisor-owned /data parent and preserves old ledgers.
    const workerDataRoot='/data/hades-m42.5';
    const stageRoot=path.join(workerDataRoot,'package-stage');
    try { fs.mkdirSync(stageRoot,{mode:0o700}); }
    catch(error) { if(error.code!=='EEXIST') throw error; }
    const stageStat=fs.lstatSync(stageRoot);
    if(!stageStat.isDirectory()||stageStat.isSymbolicLink()||stageStat.uid!==process.getuid())
      throw Error('stage_root_unsafe');
    fs.chmodSync(stageRoot,0o700);
    packageStageReceiver=createPackageStageReceiver({enabled:true,brokerId:options.trusted_broker_id,
      trustedBrokerPublicKey:options.trusted_broker_public_key,workerPrivateKey:privateKey,
      stageRoot,ledgerPath:path.join(workerDataRoot,'package-stage-ledger.json')});
  }
  const server=createServer(receiver,{port:options.listen_port,host:'::',packageStageReceiver});
  server.on('error',()=>{console.error(JSON.stringify({state:'STARTUP_BLOCKED',error:'listener_unavailable'}));process.exitCode=2;});
  await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
  console.log(JSON.stringify({state:'HADES_BUILD_WORKER_READY',version:VERSION_WORKER,workerId:receiver.workerId,
    workerPublicKeyBase64:publicKeyBase64,identityCreatedThisStart:provisioned.created,
    host:'::',port:options.listen_port,executionEnabled:false,packageStageEnabled:!!packageStageReceiver,publicPort:false}));
  const stop=()=>server.close(()=>process.exit(0));
  process.once('SIGTERM',stop);process.once('SIGINT',stop);
}
if(process.argv[1]&&path.resolve(process.argv[1])===path.resolve(new URL(import.meta.url).pathname))
  main().catch(error=>{console.error(JSON.stringify({state:'STARTUP_BLOCKED',error:/^[a-z0-9_]+$/i.test(error?.message||'')?error.message:'worker_startup_error'}));process.exitCode=2;});
