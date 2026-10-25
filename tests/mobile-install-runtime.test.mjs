import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {generateKeyPairSync} from 'node:crypto';
import {identityId} from '../hades_mobile_build_worker/shared/protocol.mjs';
import {createMobileInstallRuntime,createMobileInstallRuntimeForTests} from '../hades_mobile_build_worker/worker/mobile-install-runtime.mjs';
import * as workerMain from '../hades_mobile_build_worker/worker/main.mjs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const worker=generateKeyPairSync('ed25519'),adapter=generateKeyPairSync('ed25519');
const adapterId=identityId(adapter.publicKey),adapterKey=adapter.publicKey.export({type:'spki',format:'der'}).toString('base64');
const stubStore={findJob(){},beginPlan(){},beginInstall(){}};

test('default-off runtime does not construct transports or touch credentials',async()=>{
  let created=0;const runtime=createMobileInstallRuntimeForTests({testOnlyDependencies:{createPlanner(){created++;},createStore(){created++;}},enabled:false});
  assert.deepEqual(runtime.snapshot(),{enabled:false,running:false,ready:false});assert.equal(runtime.start(),false);assert.equal(await runtime.verifyConnection(),false);runtime.stop();assert.equal(created,0);
});

test('adapter public pin is checked before runtime accepts the optional feature',()=>{
  let created=0;
  assert.throws(()=>createMobileInstallRuntimeForTests({enabled:true,token:'github_pat_'+('x'.repeat(32)),workerPrivateKey:worker.privateKey,
    adapterId:'sha256:'+'0'.repeat(64),adapterPublicKey:adapterKey,testOnlyDependencies:{createPlanner:()=>({createPlan(){}}),createStore:()=>{created++;return stubStore;}}}),/mobile_install_adapter_pin_mismatch/);
  assert.equal(created,0);
});

test('pull loop starts only after read preflight, starts once, and stops cleanly',async()=>{
  const events=[],seen={};let timerId=0,resolvePoll;const pendingPoll=new Promise(resolve=>{resolvePoll=resolve;});
  const timers=new Map(),fakeTimers={setTimeout(fn,ms){const id=++timerId;timers.set(id,{fn,ms});return id;},clearTimeout(id){timers.delete(id);},run(id){const timer=timers.get(id);timers.delete(id);timer.fn();}};
  const dependencies={createPlanner:({token})=>{seen.token=token;return {createPlan(){}};},createStore:()=>stubStore,
    timers:fakeTimers,
    createTransport:({token,controller,planner})=>{seen.transportToken=token;seen.controller=controller;seen.planner=planner;return {async verifyConnection(){events.push('preflight');if(token==='bad')throw Error('blocked');events.push('ready');},pollOnce(){events.push('poll');return pendingPoll;}};}};
  const runtime=createMobileInstallRuntimeForTests({enabled:true,token:'github_pat_'+('x'.repeat(32)),workerPrivateKey:worker.privateKey,
    adapterId,adapterPublicKey:adapterKey,testOnlyDependencies:dependencies});
  assert.throws(()=>runtime.start(),/mobile_install_preflight_required/);await runtime.verifyConnection();assert.equal(runtime.start(),true);assert.equal(runtime.start(),false);
  assert.deepEqual(events,['preflight','ready']);assert.equal(runtime.snapshot().running,true);assert.equal(timers.size,1);fakeTimers.run(1);assert.deepEqual(events,['preflight','ready','poll']);
  runtime.stop();runtime.stop();resolvePoll({writeState:'UNVERIFIED'});await new Promise(resolve=>setImmediate(resolve));
  assert.equal(timers.size,0);assert.deepEqual(events,['preflight','ready','poll']);assert.equal(runtime.snapshot().running,false);
});

test('preflight failure never starts a loop and remains restartable after a later successful check',async()=>{
  let ready=false,starts=0;const dependencies={createPlanner:()=>({createPlan(){}}),createStore:()=>stubStore,
    createTransport:()=>({async verifyConnection(){if(!ready)throw Error('read gate failed');}}),startLoop:()=>{starts++;return {stop(){}};}};
  const runtime=createMobileInstallRuntimeForTests({enabled:true,token:'github_pat_'+('x'.repeat(32)),workerPrivateKey:worker.privateKey,
    adapterId,adapterPublicKey:adapterKey,testOnlyDependencies:dependencies});await assert.rejects(runtime.verifyConnection(),/read gate failed/);
  assert.throws(()=>runtime.start(),/mobile_install_preflight_required/);assert.equal(starts,0);ready=true;await runtime.verifyConnection();assert.equal(runtime.start(),true);assert.equal(starts,1);runtime.stop();
});

test('shipped Worker graph includes every Mobile module and keeps the feature default off',()=>{
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..'),docker=fs.readFileSync(path.join(root,'hades_mobile_build_worker/Dockerfile'),'utf8');
  for(const name of ['mobile-install-plan.mjs','mobile-install-queue.mjs','mobile-install-receipt.mjs','mobile-install-client.mjs','mobile-install-store.mjs','mobile-install-controller.mjs','mobile-install-github.mjs','mobile-install-runtime.mjs'])
    assert.ok(docker.includes(`COPY worker/${name} ./worker/${name}`),`Dockerfile omits ${name}`);
  const config=fs.readFileSync(path.join(root,'hades_mobile_build_worker/config.yaml'),'utf8');assert.match(config,/mobile_install_enabled: false/);assert.match(config,/mobile_plan_enabled: false/);
  assert.equal(typeof workerMain.main,'function');assert.equal(typeof workerMain.createDiagnosticReceiver,'undefined');
});
