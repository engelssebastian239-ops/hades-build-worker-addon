import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import net from 'node:net';
import {spawn} from 'node:child_process';
import {generateKeyPairSync,createPublicKey,createHash} from 'node:crypto';

const ROOT=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const workerPath=path.join(ROOT,'hades_build_worker/worker/main.mjs');
const brokerPair=generateKeyPairSync('ed25519');
const brokerPub=brokerPair.publicKey.export({type:'spki',format:'der'});
function brokerIdentity(){return 'sha256:'+createHash('sha256').update(brokerPub).digest('hex');}
function brokerPublicKey(){return brokerPub.toString('base64');}
async function freePortForTest(){
  const server=net.createServer();
  await new Promise((resolve,reject)=>server.once('error',reject).listen(0,'127.0.0.1',resolve));
  const port=server.address().port;
  await new Promise(resolve=>server.close(resolve));
  return port;
}
function spawnWorker(options,key,ledger){
  const child=spawn(process.execPath,[workerPath],{env:{...process.env,HADES_OPTIONS_FILE:options,
    HADES_PRIVATE_KEY_PATH:key,HADES_LEDGER_PATH:ledger},stdio:['ignore','pipe','pipe']});
  const ready=new Promise((resolve,reject)=>{
    let pending='',errors='';
    const timer=setTimeout(()=>reject(Error('worker_ready_timeout_'+errors)),5000);
    const finish=(err,value)=>{clearTimeout(timer);err?reject(err):resolve(value);};
    child.stdout.on('data',chunk=>{
      pending+=String(chunk);
      for(const line of pending.split('\n').slice(0,-1)){
        try{const value=JSON.parse(line);if(value.state==='HADES_BUILD_WORKER_READY')finish(null,value);}catch{}
      }
      pending=pending.slice(pending.lastIndexOf('\n')+1);
    });
    child.stderr.on('data',chunk=>{errors+=String(chunk);});
    child.once('error',finish);
    child.once('exit',(code,signal)=>finish(Error('worker_exit_'+code+'_'+signal+'_'+errors)));
  });
  return {child,ready};
}
async function stopChild(child){
  if(child.exitCode!==null)return;
  child.kill('SIGTERM');
  await new Promise((resolve,reject)=>{
    const timer=setTimeout(()=>reject(Error('worker_stop_timeout')),3000);
    child.once('exit',()=>{clearTimeout(timer);resolve();});
  });
}
const APP=path.join(ROOT,'hades_build_worker');
const config=fs.readFileSync(path.join(APP,'config.yaml'),'utf8');
const docker=fs.readFileSync(path.join(APP,'Dockerfile'),'utf8');
const worker=fs.readFileSync(path.join(APP,'worker/main.mjs'),'utf8');
const launcher=fs.readFileSync(path.join(APP,'worker/launcher.mjs'),'utf8');

test('local Home Assistant app has consistent version and aarch64 target',()=>{
  const version=config.match(/^version: "([^"]+)"/m)?.[1];
  assert.equal(version,'0.0.6-dev.m5.13');
  assert.match(docker,new RegExp('ARG BUILD_VERSION='+version.replaceAll('.','\\.')));
  assert.equal(JSON.parse(fs.readFileSync(path.join(ROOT,'package.json'),'utf8')).version,version);
  assert.ok(worker.includes("const VERSION_WORKER='"+version+"'"));
  assert.match(config,/^arch:\n  - aarch64$/m);
  assert.match(config,/^boot: manual_only$/m);
});

test('Docker build context contains every copied source',()=>{
  for(const match of docker.matchAll(/^COPY ([^ ]+) /gm))
    assert.equal(fs.existsSync(path.join(APP,match[1])),true,'missing Docker COPY source '+match[1]);
  assert.match(docker,/^FROM ghcr\.io\/home-assistant\/base@sha256:[a-f0-9]{64}$/m);
  assert.match(docker,/io\.hass\.type="app"/);
  assert.match(docker,/io\.hass\.arch="\$\{BUILD_ARCH\}"/);
});

test('worker creates only its own 0600 runtime key and keeps the same identity after restart',async t=>{
  let port;
  try { port=await freePortForTest(); }
  catch(error) {
    if(error.code==='EPERM') { t.skip('sandbox prohibits local TCP listeners'); return; }
    throw error;
  }
  const dir=fs.mkdtempSync(path.join(process.env.TMPDIR||'/tmp','hades-key-provision-'));
  fs.chmodSync(dir,0o700);
  const options=path.join(dir,'options.json');
  const key=path.join(dir,'worker-ed25519.pem');
  const ledger=path.join(dir,'ledger.json');
  fs.writeFileSync(options,JSON.stringify({enabled:true,listen_port:port,
    trusted_broker_id:brokerIdentity(),trusted_broker_public_key:brokerPublicKey()}),{mode:0o600});
  let proc=spawnWorker(options,key,ledger);
  t.after(async()=>{await stopChild(proc.child).catch(()=>{});fs.rmSync(dir,{recursive:true,force:true});});
  const first=await proc.ready;
  const st=fs.statSync(key);
  assert.equal(st.mode&0o777,0o600);
  assert.equal(st.uid,process.getuid());
  assert.equal(first.identityCreatedThisStart,true);
  assert.equal(typeof first.workerPublicKeyBase64,'string');
  assert.equal(first.workerId,'sha256:'+createHash('sha256').update(Buffer.from(first.workerPublicKeyBase64,'base64')).digest('hex'));
  await stopChild(proc.child);
  proc=spawnWorker(options,key,ledger);
  const second=await proc.ready;
  assert.equal(second.identityCreatedThisStart,false);
  assert.equal(second.workerId,first.workerId);
});

test('app is internal-only and has no host/API access or mounts',()=>{
  assert.match(config,/^ports: \{\}$/m);
  assert.match(config,/^map: \[\]$/m);
  for(const key of ['host_network','host_ipc','host_pid','host_uts','homeassistant_api','hassio_api','docker_api','full_access'])
    assert.match(config,new RegExp('^'+key+': false$','m'));
  assert.match(config,/^privileged: \[\]$/m);
  assert.match(config,/^  enabled: false$/m);
});

test('package staging uses the existing private worker data root without replacing diagnostic state',()=>{
  assert.match(worker,/const workerDataRoot='\/data\/hades-m42\.5'/);
  assert.match(worker,/path\.join\(workerDataRoot,'package-stage'\)/);
  assert.match(worker,/path\.join\(workerDataRoot,'package-stage-ledger\.json'\)/);
  assert.doesNotMatch(worker,/hades-m42\.4\/package-stage-ledger/);
  assert.match(launcher,/HADES_LEDGER_PATH=DATA_DIR\+'\/diagnostic-ledger\.json'/);
  assert.match(launcher,/fs\.chmodSync\(DATA_DIR,0o700\)/);
});

test('root bootstrap reads Supervisor options then drops to UID/GID 1000 before worker import',()=>{
  assert.match(launcher,/\/data\/options\.json/);
  assert.match(launcher,/process\.setgroups\(\[SERVICE_GID\]\)/);
  assert.match(launcher,/process\.setgid\(SERVICE_GID\)/);
  assert.match(launcher,/process\.setuid\(SERVICE_UID\)/);
  assert.ok(launcher.indexOf('dropPrivileges();')<launcher.indexOf("import('./main.mjs')"));
  assert.doesNotMatch(launcher,/console\.log\(.*private|console\.log\(.*pem/i);
  assert.match(worker,/process\.getuid\(\)===0/);
});

test('diagnostics remain exactly the approved three operations and execution stays disabled',()=>{
  const protocol=fs.readFileSync(path.join(APP,'shared/protocol.mjs'),'utf8');
  for(const op of ['STATUS_CHECK','HEARTBEAT_CHECK','QUEUE_HEALTH_CHECK'])
    assert.ok(protocol.includes(op),op);
  assert.match(worker,/executionEnabled:false/);
  assert.match(worker,/executable:false/);
  assert.doesNotMatch(worker,/child_process|execSync|spawn\(/);
});
