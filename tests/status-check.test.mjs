import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {generateKeyPairSync} from 'node:crypto';
import {ACTION,VERSION,identityId,signRequest,verifyResponse} from '../hades_build_worker/shared/protocol.mjs';
import {createDiagnosticReceiver} from '../hades_build_worker/worker/main.mjs';

test('signed STATUS_CHECK completes from broker request through worker response verification',()=>{
  const broker=generateKeyPairSync('ed25519');
  const worker=generateKeyPairSync('ed25519');
  const brokerId=identityId(broker.publicKey), workerId=identityId(worker.publicKey);
  const dir=fs.mkdtempSync(path.join(os.tmpdir(),'hades-status-check-'));
  fs.chmodSync(dir,0o700);
  try {
    const receiver=createDiagnosticReceiver({enabled:true,brokerId,trustedBrokerPublicKey:broker.publicKey,
      workerPrivateKey:worker.privateKey,ledgerPath:path.join(dir,'ledger.json')});
    const now=Date.now();
    const taskId='123e4567-e89b-42d3-a456-426614174000';
    const jobId='123e4567-e89b-42d3-b456-426614174001';
    const nonce='123e4567-e89b-42d3-9456-426614174002';
    const request=signRequest({version:VERSION,action:ACTION,brokerId,workerId,taskId,jobId,nonce,
      issuedAt:now,expiresAt:now+60_000,kind:'STATUS_CHECK'},broker.privateKey);
    const response=receiver.handle(JSON.stringify(request));
    const verified=verifyResponse(response,worker.publicKey,
      {brokerId,workerId,taskId,jobId,nonce,kind:'STATUS_CHECK',expiresAt:request.expiresAt});
    assert.equal(verified.state,'COMPLETED');
    assert.deepEqual(verified.result,{component:'HADES_BUILD_WORKER',version:'0.0.6-dev.m5.13',
      state:'READY',executionEnabled:false,uptimeSeconds:0});
  } finally { fs.rmSync(dir,{recursive:true,force:true}); }
});
