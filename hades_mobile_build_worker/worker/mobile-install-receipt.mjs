import {createPublicKey,sign,verify} from 'node:crypto';
import {identityId} from '../shared/identity.mjs';
import {MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY,MOBILE_INSTALL_CI_WORKFLOW} from './mobile-install-plan.mjs';
import {MOBILE_INSTALL_GITHUB_OWNER} from './mobile-install-queue.mjs';

export const MOBILE_INSTALL_RECEIPT_PROTOCOL='HADES_MOBILE_M574_RECEIPT_V1';
export const MOBILE_INSTALL_RECEIPT_TTL_MS=300_000;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const FINGERPRINT=/^sha256:[a-f0-9]{64}$/;
const SIGNATURE=/^[A-Za-z0-9_-]{86}$/;
const KEYS=['protocol','workerId','repository','owner','action','issueNumber','requestId','nonce','issuedAt','expiresAt','state','planId','commit','packagePath','ciRun','workflow','archiveSha256','manifestSha256','installerJobId','installerNonce','backupSlug','sourceSha256','errorCode','signature'];
const bytes=v=>Buffer.from(JSON.stringify([v.protocol,v.workerId,v.repository,v.owner,v.action,v.issueNumber,v.requestId,v.nonce,v.issuedAt,v.expiresAt,v.state,v.planId,v.commit,v.packagePath,v.ciRun,v.workflow,v.archiveSha256,v.manifestSha256,v.installerJobId,v.installerNonce,v.backupSlug,v.sourceSha256,v.errorCode]));
const fail=code=>{throw Object.assign(new Error(code),{code});};
function exact(v){return !!v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===[...KEYS].sort().join(',');}
function validate(v,{workerId,now,allowExpired=false}){
  const allowed=v?.action==='PLAN_M574'?['PLANNED','UNKNOWN','REJECTED']:['COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK','UNKNOWN','REJECTED'];
  if(!exact(v)||v.protocol!==MOBILE_INSTALL_RECEIPT_PROTOCOL||v.workerId!==workerId||!FINGERPRINT.test(v.workerId)||v.repository!==MOBILE_INSTALL_REPOSITORY||v.owner!==MOBILE_INSTALL_GITHUB_OWNER||
    !['PLAN_M574','INSTALL_M574'].includes(v.action)||!Number.isSafeInteger(v.issueNumber)||v.issueNumber<1||!UUID.test(v.requestId)||!UUID.test(v.nonce)||!allowed.includes(v.state)||
    v.commit!==MOBILE_INSTALL_COMMIT||v.packagePath!==MOBILE_INSTALL_PACKAGE_PATH||v.ciRun!==MOBILE_INSTALL_CI_RUN||v.workflow!==MOBILE_INSTALL_CI_WORKFLOW||
    !Number.isSafeInteger(v.issuedAt)||!Number.isSafeInteger(v.expiresAt)||v.issuedAt>now+5_000||!allowExpired&&v.expiresAt<=now||v.expiresAt<=v.issuedAt||v.expiresAt-v.issuedAt>MOBILE_INSTALL_RECEIPT_TTL_MS||
    typeof v.planId!=='string'||v.planId!==''&&!UUID.test(v.planId)||typeof v.archiveSha256!=='string'||v.archiveSha256!==''&&!SHA.test(v.archiveSha256)||
    typeof v.manifestSha256!=='string'||v.manifestSha256!==''&&!SHA.test(v.manifestSha256)||typeof v.installerJobId!=='string'||v.installerJobId!==''&&!UUID.test(v.installerJobId)||
    typeof v.installerNonce!=='string'||v.installerNonce!==''&&!UUID.test(v.installerNonce)||typeof v.backupSlug!=='string'||v.backupSlug.length>128||v.backupSlug!==''&&!/^[A-Za-z0-9_-]+$/.test(v.backupSlug)||
    typeof v.sourceSha256!=='string'||v.sourceSha256!==''&&!SHA.test(v.sourceSha256)||typeof v.errorCode!=='string'||v.errorCode.length>128||v.errorCode!==''&&!/^[A-Z0-9_]+$/.test(v.errorCode)||
    typeof v.signature!=='string'||!SIGNATURE.test(v.signature))fail('mobile_receipt_invalid');
  if(v.state==='PLANNED'&&(!UUID.test(v.planId)||!SHA.test(v.archiveSha256)||!SHA.test(v.manifestSha256)))fail('mobile_receipt_plan_evidence_missing');
  if(['COMPLETED','COMPLETED_WITH_STAGE_RETAINED'].includes(v.state)&&(!UUID.test(v.planId)||!SHA.test(v.archiveSha256)||!SHA.test(v.manifestSha256)||!UUID.test(v.installerJobId)||!UUID.test(v.installerNonce)||!v.backupSlug||!SHA.test(v.sourceSha256)||v.errorCode!==''))fail('mobile_receipt_install_evidence_missing');
  if(v.action==='PLAN_M574'&&(['COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK'].includes(v.state)||v.installerJobId!==''||v.installerNonce!==''||v.backupSlug!==''||v.sourceSha256!==''))fail('mobile_receipt_action_state_invalid');
  if(v.action==='INSTALL_M574'&&v.state==='PLANNED')fail('mobile_receipt_action_state_invalid');
  return v;
}

export function signMobileInstallReceipt(fields,workerPrivateKey,{clock=Date.now}={}){
  if(!workerPrivateKey||workerPrivateKey.type!=='private'||workerPrivateKey.asymmetricKeyType!=='ed25519'||typeof clock!=='function')fail('mobile_receipt_signer_invalid');
  const workerId=identityId(createPublicKey(workerPrivateKey));
  const value={...fields,protocol:MOBILE_INSTALL_RECEIPT_PROTOCOL,workerId,signature:''};
  value.signature=sign(null,bytes(value),workerPrivateKey).toString('base64url');
  validate(value,{workerId,now:clock()});return Object.freeze(value);
}

export function verifyMobileInstallReceipt(receipt,trustedWorkerPublicKey,{expectedWorkerId,expectedAction,expectedIssueNumber,expectedRequestId,expectedNonce,now=Date.now()}={}){
  if(!trustedWorkerPublicKey||typeof now!=='number'||!Number.isSafeInteger(now))fail('mobile_receipt_verifier_invalid');
  const key=trustedWorkerPublicKey.type==='public'?trustedWorkerPublicKey:createPublicKey(trustedWorkerPublicKey);
  const workerId=identityId(key);const checked=validate(receipt,{workerId,now});
  if(expectedWorkerId!==undefined&&expectedWorkerId!==workerId||expectedAction!==undefined&&checked.action!==expectedAction||
    expectedIssueNumber!==undefined&&checked.issueNumber!==expectedIssueNumber||expectedRequestId!==undefined&&checked.requestId!==expectedRequestId||
    expectedNonce!==undefined&&checked.nonce!==expectedNonce)fail('mobile_receipt_correlation_failed');
  if(!verify(null,bytes(checked),key,Buffer.from(checked.signature,'base64url')))fail('mobile_receipt_signature_invalid');
  return Object.freeze({...checked});
}

export function verifyHistoricalMobileInstallReceipt(receipt,trustedWorkerPublicKey,{expectedWorkerId,expectedAction,expectedIssueNumber,expectedRequestId,expectedNonce,now=Date.now()}={}){
  if(!trustedWorkerPublicKey||typeof now!=='number'||!Number.isSafeInteger(now))fail('mobile_receipt_verifier_invalid');
  const key=trustedWorkerPublicKey.type==='public'?trustedWorkerPublicKey:createPublicKey(trustedWorkerPublicKey),workerId=identityId(key);
  const checked=validate(receipt,{workerId,now,allowExpired:true});
  if(expectedWorkerId!==undefined&&expectedWorkerId!==workerId||expectedAction!==undefined&&checked.action!==expectedAction||
    expectedIssueNumber!==undefined&&checked.issueNumber!==expectedIssueNumber||expectedRequestId!==undefined&&checked.requestId!==expectedRequestId||
    expectedNonce!==undefined&&checked.nonce!==expectedNonce)fail('mobile_receipt_correlation_failed');
  if(!verify(null,bytes(checked),key,Buffer.from(checked.signature,'base64url')))fail('mobile_receipt_signature_invalid');
  return Object.freeze({...checked});
}
