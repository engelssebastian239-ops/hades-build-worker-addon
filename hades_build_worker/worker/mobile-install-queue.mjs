import {
  MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY,
  MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW
} from './mobile-install-plan.mjs';

export const MOBILE_INSTALL_GITHUB_OWNER='engelssebastian239-ops';
export const MOBILE_INSTALL_QUEUE_PROTOCOL='HADES_MOBILE_M574_QUEUE_V1';
export const MOBILE_INSTALL_CONFIRMATION='INSTALL_LOCAL_HADES_M2_MOBILE';
export const MOBILE_INSTALL_JOB_TTL_MS=5*60_000;
export const MOBILE_INSTALL_MAX_JOB_BODY_BYTES=4096;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const PLAN_KEYS=['protocol','action','requestId','nonce','issuedAt','expiresAt'];
const INSTALL_KEYS=[...PLAN_KEYS,'planId','archiveSha256','manifestSha256','confirmation'];

function reject(code){throw Object.assign(new Error(code),{code});}
function exact(value,keys){return !!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');}

export function parseMobileInstallIssue({issue,repository,authenticatedOwner,now=Date.now()}={}){
  if(!repository||repository.full_name!==MOBILE_INSTALL_REPOSITORY||repository.private!==true||authenticatedOwner!==MOBILE_INSTALL_GITHUB_OWNER)
    reject('queue_repository_or_owner_rejected');
  if(!issue||issue.pull_request!==undefined||!Number.isSafeInteger(issue.number)||issue.number<1||issue.user?.login!==MOBILE_INSTALL_GITHUB_OWNER)
    reject('queue_issue_owner_rejected');
  if(typeof now!=='number'||!Number.isSafeInteger(now))reject('queue_clock_invalid');
  if(typeof issue.title!=='string'||typeof issue.body!=='string'||Buffer.byteLength(issue.body)>MOBILE_INSTALL_MAX_JOB_BODY_BYTES)
    reject('queue_issue_shape_rejected');
  let body;try{body=JSON.parse(issue.body);}catch{reject('queue_body_invalid');}
  if(!body||Object.getPrototypeOf(body)!==Object.prototype)reject('queue_body_invalid');
  const action=body.action,keys=action==='PLAN_M574'?PLAN_KEYS:action==='INSTALL_M574'?INSTALL_KEYS:null;
  if(!keys||!exact(body,keys)||body.protocol!==MOBILE_INSTALL_QUEUE_PROTOCOL||
    issue.title!==(action==='PLAN_M574'?'HADES PLAN_M574':'HADES INSTALL_M574')||
    JSON.stringify(body)!==issue.body)reject('queue_schema_rejected');
  if(!UUID.test(body.requestId)||!UUID.test(body.nonce)||!Number.isSafeInteger(body.issuedAt)||!Number.isSafeInteger(body.expiresAt)||
    body.issuedAt>now+5_000||body.expiresAt<=body.issuedAt||body.expiresAt-body.issuedAt>MOBILE_INSTALL_JOB_TTL_MS)
    reject('queue_ttl_or_id_rejected');
  if(action==='INSTALL_M574'&&(!UUID.test(body.planId)||!SHA.test(body.archiveSha256)||!SHA.test(body.manifestSha256)||body.confirmation!==MOBILE_INSTALL_CONFIRMATION))
    reject('queue_install_binding_rejected');
  return Object.freeze({action,issueNumber:issue.number,owner:MOBILE_INSTALL_GITHUB_OWNER,repository:MOBILE_INSTALL_REPOSITORY,
    requestId:body.requestId,nonce:body.nonce,issuedAt:body.issuedAt,expiresAt:body.expiresAt,
    ...(action==='INSTALL_M574'?{planId:body.planId,archiveSha256:body.archiveSha256,manifestSha256:body.manifestSha256,confirmation:body.confirmation}:{}),
    fixedSource:Object.freeze({repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW})});
}
