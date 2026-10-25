import {createHash,createPublicKey,randomUUID,sign,verify} from 'node:crypto';
import {identityId} from '../shared/protocol.mjs';
import {
  MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_DOCKERFILE_SHA256,MOBILE_INSTALL_MAX_ARCHIVE_BYTES,
  MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY
} from './mobile-install-plan.mjs';

export const MOBILE_INSTALL_PROTOCOL='HADES_MOBILE_M574_INSTALL_V1';
export const MOBILE_INSTALL_ACTION='INSTALL_MOBILE_M574';
export const MOBILE_INSTALL_TARGET_SLUG='local_hades_m2_mobile';
export const MOBILE_INSTALLER_ORIGIN='http://c406e920-hades-mobile-installer:8767';
export const MOBILE_INSTALLER_ROUTE='/v1/mobile/install';
// Supervisor can spend up to 20 minutes on the backup and another 20 on each
// of the primary/rollback builds. Keep one POST open beyond one backup+build.
export const MOBILE_INSTALLER_TIMEOUT_MS=45*60_000;
export const MOBILE_INSTALL_RESPONSE_MAX_BYTES=16*1024;
export const MOBILE_INSTALL_TTL_MS=300_000;

const REQUEST_KEYS=['protocol','action','brokerId','adapterId','jobId','nonce','issuedAt','expiresAt','repository','commit','packagePath','archiveSha256','archiveSize','manifestSha256','signature'];
const RESPONSE_KEYS=['protocol','adapterId','jobId','nonce','issuedAt','expiresAt','state','targetSlug','commit','archiveSha256','backupSlug','sourceSha256','errorCode','signature'];
const HEX_SHA256=/^[a-f0-9]{64}$/;
const BASE64=/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const RESPONSE_STATES=new Set(['COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK','UNKNOWN','REJECTED']);
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const requestBytes=v=>Buffer.from(JSON.stringify([v.protocol,v.action,v.brokerId,v.adapterId,v.jobId,v.nonce,v.issuedAt,v.expiresAt,v.repository,v.commit,v.packagePath,v.archiveSha256,v.archiveSize,v.manifestSha256]));
const responseBytes=v=>Buffer.from(JSON.stringify([v.protocol,v.adapterId,v.jobId,v.nonce,v.issuedAt,v.expiresAt,v.state,v.targetSlug,v.commit,v.archiveSha256,v.backupSlug,v.sourceSha256,v.errorCode]));
const exact=(value,keys)=>!!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function error(code,outcomeUnknown=false){const e=new Error(code);e.code=code;if(outcomeUnknown)e.outcome='UNKNOWN';return e;}
function privateEd25519(key){return key&&key.type==='private'&&key.asymmetricKeyType==='ed25519';}
function publicEd25519(value){
  let key;
  if(value?.type==='public')key=value;
  else if(typeof value==='string'&&value.length>=40&&value.length<=512&&BASE64.test(value)){
    const der=Buffer.from(value,'base64');if(der.toString('base64')!==value)throw error('adapter_public_key_invalid');
    try{key=createPublicKey({key:der,format:'der',type:'spki'});}catch{throw error('adapter_public_key_invalid');}
  }else throw error('adapter_public_key_missing');
  if(key.asymmetricKeyType!=='ed25519')throw error('adapter_public_key_invalid');
  return key;
}
function validatePlan(plan){
  if(!plan||plan.repository!==MOBILE_INSTALL_REPOSITORY||plan.commit!==MOBILE_INSTALL_COMMIT||plan.packagePath!==MOBILE_INSTALL_PACKAGE_PATH||
    !Buffer.isBuffer(plan.archive)||plan.archive.length<1||plan.archive.length>MOBILE_INSTALL_MAX_ARCHIVE_BYTES||
    plan.archiveSize!==plan.archive.length||!HEX_SHA256.test(plan.archiveSha256||'')||sha256(plan.archive)!==plan.archiveSha256||
    !HEX_SHA256.test(plan.manifestSha256||''))throw error('install_plan_invalid');
}
function validateResponse(response,{adapterId,request,now}){
  if(!exact(response,RESPONSE_KEYS)||response.protocol!==MOBILE_INSTALL_PROTOCOL||response.adapterId!==adapterId||
    response.jobId!==request.jobId||response.nonce!==request.nonce||response.targetSlug!==MOBILE_INSTALL_TARGET_SLUG||
    response.commit!==MOBILE_INSTALL_COMMIT||response.archiveSha256!==request.archiveSha256||!RESPONSE_STATES.has(response.state)||
    typeof response.backupSlug!=='string'||response.backupSlug.length>128||response.backupSlug!==''&&!/^[A-Za-z0-9_-]+$/.test(response.backupSlug)||
    typeof response.sourceSha256!=='string'||response.sourceSha256!==''&&!HEX_SHA256.test(response.sourceSha256)||
    typeof response.errorCode!=='string'||response.errorCode.length>128||response.errorCode!==''&&!/^[A-Z0-9_]+$/.test(response.errorCode)||
    !Number.isSafeInteger(response.issuedAt)||!Number.isSafeInteger(response.expiresAt)||response.issuedAt>now+5_000||
    response.issuedAt<request.issuedAt-5_000||response.expiresAt<=now||response.expiresAt<=response.issuedAt||response.expiresAt-response.issuedAt>MOBILE_INSTALL_TTL_MS||
    typeof response.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(response.signature))throw error('installer_response_invalid',true);
  if(['COMPLETED','COMPLETED_WITH_STAGE_RETAINED'].includes(response.state)&&
    (!/^[A-Za-z0-9_-]{1,128}$/.test(response.backupSlug)||!HEX_SHA256.test(response.sourceSha256)||response.errorCode!==''))
    throw error('installer_success_evidence_missing',true);
  return response;
}
async function readBounded(response,maxBytes){
  if(!response.body)throw error('installer_response_invalid',true);
  const reader=response.body.getReader(),chunks=[];let size=0;
  try{
    while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>maxBytes){await reader.cancel();throw error('installer_response_too_large',true);}chunks.push(Buffer.from(value));}
  }catch(e){if(e?.outcome==='UNKNOWN')throw e;throw error(e?.name==='AbortError'?'installer_response_timeout':'installer_response_invalid',true);}
  return Buffer.concat(chunks);
}

export function createMobileInstallClient({workerPrivateKey,trustedAdapterId,trustedAdapterPublicKey,persistIntent,fetchImpl=fetch,clock=Date.now,timeoutMs=MOBILE_INSTALLER_TIMEOUT_MS,uuidFactory=randomUUID}={}){
  if(!privateEd25519(workerPrivateKey))throw error('worker_private_key_missing');
  if(typeof trustedAdapterId!=='string'||!/^sha256:[a-f0-9]{64}$/.test(trustedAdapterId))throw error('adapter_identity_missing');
  const adapterKey=publicEd25519(trustedAdapterPublicKey);if(identityId(adapterKey)!==trustedAdapterId)throw error('adapter_identity_mismatch');
  if(typeof persistIntent!=='function'||typeof fetchImpl!=='function'||typeof clock!=='function'||!Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>60*60_000||typeof uuidFactory!=='function')throw error('install_client_options_invalid');
  const workerPublicKey=createPublicKey(workerPrivateKey),brokerId=identityId(workerPublicKey);
  async function install(plan){
    validatePlan(plan);
    const issuedAt=clock(),request={protocol:MOBILE_INSTALL_PROTOCOL,action:MOBILE_INSTALL_ACTION,brokerId,adapterId:trustedAdapterId,
      jobId:uuidFactory(),nonce:uuidFactory(),issuedAt,expiresAt:issuedAt+MOBILE_INSTALL_TTL_MS,repository:MOBILE_INSTALL_REPOSITORY,
      commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,archiveSha256:plan.archiveSha256,archiveSize:plan.archiveSize,manifestSha256:plan.manifestSha256,signature:''};
    if(!UUID.test(request.jobId)||!UUID.test(request.nonce))throw error('install_id_generation_failed');
    request.signature=sign(null,requestBytes(request),workerPrivateKey).toString('base64url');
    const requestEnvelope=Object.freeze({...request});
    const requestHeader=Buffer.from(JSON.stringify(requestEnvelope)).toString('base64url');
    try{await persistIntent(Object.freeze({request:requestEnvelope,requestHeader,origin:MOBILE_INSTALLER_ORIGIN,route:MOBILE_INSTALLER_ROUTE}));}
    catch{throw error('install_intent_persist_failed');}
    const url=MOBILE_INSTALLER_ORIGIN+MOBILE_INSTALLER_ROUTE,controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeoutMs);
    let response,bytes;
    try{
      response=await fetchImpl(url,{method:'POST',redirect:'error',signal:controller.signal,headers:{'content-type':'application/gzip','x-hades-install-request':requestHeader},body:plan.archive});
      if(!response||response.status!==200||response.ok!==true)throw error('installer_upstream_error',true);
      if(response.url&&response.url!==url)throw error('installer_origin_mismatch',true);
      if(response.headers?.get('content-type')?.split(';')[0].trim().toLowerCase()!=='application/json')throw error('installer_response_invalid',true);
      bytes=await readBounded(response,MOBILE_INSTALL_RESPONSE_MAX_BYTES);
    }catch(e){if(e?.outcome==='UNKNOWN')throw e;throw error(e?.name==='AbortError'?'installer_outcome_unknown':'installer_outcome_unknown',true);}
    finally{clearTimeout(timer);}
    let result;try{result=JSON.parse(bytes.toString('utf8'));}catch{throw error('installer_response_invalid',true);}
    const checked=validateResponse(result,{adapterId:trustedAdapterId,request,now:clock()});
    if(!verify(null,responseBytes(checked),adapterKey,Buffer.from(checked.signature,'base64url')))throw error('installer_response_signature_invalid',true);
    return Object.freeze({...checked});
  }
  return Object.freeze({brokerId,adapterId:trustedAdapterId,install});
}
