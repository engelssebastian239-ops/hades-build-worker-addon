import fs from 'node:fs';
import path from 'node:path';
import {createHash,randomUUID} from 'node:crypto';
import {
  MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY,
  MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_MAX_ARCHIVE_BYTES
} from './mobile-install-plan.mjs';
import {MOBILE_INSTALL_GITHUB_OWNER} from './mobile-install-queue.mjs';
import {MOBILE_INSTALL_PROTOCOL,MOBILE_INSTALLER_ORIGIN,MOBILE_INSTALLER_ROUTE} from './mobile-install-client.mjs';
import {MOBILE_INSTALL_RECEIPT_PROTOCOL} from './mobile-install-receipt.mjs';

export const MOBILE_INSTALL_DATA_ROOT='/data/hades-m42.5';
export const MOBILE_INSTALL_STORE_NAME='mobile-install';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const SIGNATURE=/^[A-Za-z0-9_-]{86}$/;
const MAX_LEDGER_BYTES=2*1024*1024;
const MAX_LEDGER_ROWS=2048;
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
function jobDigest(job){
  const fields=[job.action,job.owner,job.repository,job.issueNumber,job.requestId,job.nonce,job.issuedAt,job.expiresAt,
    job.fixedSource?.repository,job.fixedSource?.commit,job.fixedSource?.packagePath,job.fixedSource?.ciRun,job.fixedSource?.workflow];
  if(job.action==='INSTALL_M574')fields.push(job.planId,job.archiveSha256,job.manifestSha256,job.confirmation);
  return sha256(Buffer.from(JSON.stringify(fields)));
}
const fail=code=>{throw Object.assign(new Error(code),{code});};

function ownerId(){return typeof process.getuid==='function'?process.getuid():null;}
function checkDirectory(dir,{create=false,mode=0o700,owner=ownerId()}={}){
  if(create){try{fs.mkdirSync(dir,{mode});fsyncDir(path.dirname(dir));}catch(e){if(e.code!=='EEXIST')throw e;}}
  const st=fs.lstatSync(dir);
  if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o777)!==mode||(owner!==null&&st.uid!==owner))fail('mobile_store_directory_unsafe');
  return st;
}
function checkFile(file,{owner=ownerId()}={}){
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o777)!==0o600||(owner!==null&&st.uid!==owner))fail('mobile_store_file_unsafe');
  return st;
}
function fsyncDir(dir){const fd=fs.openSync(dir,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function exact(value,keys){return !!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');}
function atomicWrite(file,bytes,{beforeAtomicWrite=()=>{}}={}){
  const dir=path.dirname(file),temp=path.join(dir,`.tmp-${process.pid}-${randomUUID()}`);
  beforeAtomicWrite(file);
  const fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  checkFile(temp);fs.renameSync(temp,file);fsyncDir(dir);checkFile(file);
}
function emptyLedger(){return {protocol:'HADES_MOBILE_M574_LEDGER_V1',plans:[],installs:[]};}
function validateLedger(value){
  if(!exact(value,['protocol','plans','installs'])||value.protocol!=='HADES_MOBILE_M574_LEDGER_V1'||!Array.isArray(value.plans)||!Array.isArray(value.installs)||value.plans.length+value.installs.length>MAX_LEDGER_ROWS)fail('mobile_ledger_invalid');
  const basePlanKeys=['issueNumber','owner','repository','requestId','nonce','jobDigest','planId','archiveSha256','manifestSha256','state','createdAt'];
  const validPlan=x=>{
    const keys=[...basePlanKeys,...(x?.errorCode!==undefined?['errorCode']:[]),...(x?.receipt!==undefined?['receipt']:[])];
    return exact(x,keys)&&x.owner===MOBILE_INSTALL_GITHUB_OWNER&&x.repository===MOBILE_INSTALL_REPOSITORY&&Number.isSafeInteger(x.issueNumber)&&UUID.test(x.requestId)&&UUID.test(x.nonce)&&SHA.test(x.jobDigest)&&UUID.test(x.planId)&&
      ['PLANNING','PLANNED','INSTALL_PENDING','UNKNOWN','REJECTED','COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK'].includes(x.state)&&Number.isSafeInteger(x.createdAt)&&
      (x.state==='PLANNING'||['UNKNOWN','REJECTED'].includes(x.state)&&x.archiveSha256===''&&x.manifestSha256===''||SHA.test(x.archiveSha256)&&SHA.test(x.manifestSha256))&&
      (x.errorCode===undefined||typeof x.errorCode==='string'&&/^[A-Z0-9_]{1,128}$/.test(x.errorCode))&&
      (x.receipt===undefined||x.receipt?.protocol===MOBILE_INSTALL_RECEIPT_PROTOCOL&&SIGNATURE.test(x.receipt.signature));
  };
  const baseInstallKeys=['issueNumber','owner','repository','requestId','nonce','jobDigest','planId','archiveSha256','manifestSha256','jobId','installNonce','state','createdAt','errorCode'];
  const validInstall=x=>{
    const keys=[...baseInstallKeys,...(x?.interruptedState!==undefined?['interruptedState']:[]),...(x?.signedRequest!==undefined?['signedRequest','requestHeader','sentAt']:[]),...(x?.response!==undefined?['response']:[]),...(x?.transportUnknownAt!==undefined?['transportUnknownAt']:[]),...(x?.receipt!==undefined?['receipt']:[])];
    return exact(x,keys)&&x.owner===MOBILE_INSTALL_GITHUB_OWNER&&x.repository===MOBILE_INSTALL_REPOSITORY&&Number.isSafeInteger(x.issueNumber)&&UUID.test(x.requestId)&&UUID.test(x.nonce)&&SHA.test(x.jobDigest)&&UUID.test(x.planId)&&SHA.test(x.archiveSha256)&&SHA.test(x.manifestSha256)&&['PREPARING','SENT','UNKNOWN','COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK','REJECTED'].includes(x.state)&&Number.isSafeInteger(x.createdAt)&&typeof x.jobId==='string'&&(x.jobId===''||UUID.test(x.jobId))&&typeof x.installNonce==='string'&&(x.installNonce===''||UUID.test(x.installNonce))&&typeof x.errorCode==='string'&&
      (x.interruptedState===undefined||['PREPARING','SENT'].includes(x.interruptedState))&&
      (x.signedRequest===undefined||exact(x.signedRequest,['protocol','action','brokerId','adapterId','jobId','nonce','issuedAt','expiresAt','repository','commit','packagePath','archiveSha256','archiveSize','manifestSha256','signature'])&&SIGNATURE.test(x.signedRequest.signature)&&typeof x.requestHeader==='string'&&Number.isSafeInteger(x.sentAt))&&
      (x.response===undefined||exact(x.response,['protocol','adapterId','jobId','nonce','issuedAt','expiresAt','state','targetSlug','commit','archiveSha256','backupSlug','sourceSha256','errorCode','signature'])&&SIGNATURE.test(x.response.signature))&&
      (x.transportUnknownAt===undefined||Number.isSafeInteger(x.transportUnknownAt))&&
      (x.receipt===undefined||x.receipt?.protocol===MOBILE_INSTALL_RECEIPT_PROTOCOL&&SIGNATURE.test(x.receipt.signature));
  };
  if(value.plans.some(x=>!validPlan(x))||
    value.installs.some(x=>!validInstall(x)))fail('mobile_ledger_invalid');
  return value;
}
function checkJob(job,action){
  if(!job||job.action!==action||job.owner!==MOBILE_INSTALL_GITHUB_OWNER||job.repository!==MOBILE_INSTALL_REPOSITORY||!Number.isSafeInteger(job.issueNumber)||job.issueNumber<1||!UUID.test(job.requestId)||!UUID.test(job.nonce))fail('mobile_job_invalid');
}
function validatePlan(plan){
  if(!plan||plan.repository!==MOBILE_INSTALL_REPOSITORY||plan.commit!==MOBILE_INSTALL_COMMIT||plan.packagePath!==MOBILE_INSTALL_PACKAGE_PATH||
    plan.ciRun!==MOBILE_INSTALL_CI_RUN||plan.workflow!==MOBILE_INSTALL_CI_WORKFLOW||!Buffer.isBuffer(plan.archive)||plan.archive.length<1||
    plan.archive.length>MOBILE_INSTALL_MAX_ARCHIVE_BYTES||plan.archiveSize!==plan.archive.length||!SHA.test(plan.archiveSha256||'')||
    sha256(plan.archive)!==plan.archiveSha256||!SHA.test(plan.manifestSha256||'')||!Number.isSafeInteger(plan.fileCount)||plan.fileCount<1||plan.fileCount>512)
    fail('mobile_plan_invalid');
}

function createStore({dataRoot,clock=Date.now,uuidFactory=randomUUID,beforeAtomicWrite=()=>{}}={}){
  if(typeof dataRoot!=='string'||!path.isAbsolute(dataRoot)||typeof clock!=='function'||typeof uuidFactory!=='function'||typeof beforeAtomicWrite!=='function')fail('mobile_store_options_invalid');
  const root=path.resolve(dataRoot),storeDir=path.join(root,MOBILE_INSTALL_STORE_NAME),plansDir=path.join(storeDir,'plans'),ledgerFile=path.join(storeDir,'ledger.json'),owner=ownerId();
  checkDirectory(root,{mode:0o700,owner});checkDirectory(storeDir,{create:true,mode:0o700,owner});checkDirectory(plansDir,{create:true,mode:0o700,owner});
  let ledger;
  try{const st=checkFile(ledgerFile,{owner});if(st.size>MAX_LEDGER_BYTES)fail('mobile_ledger_too_large');const bytes=fs.readFileSync(ledgerFile);if(bytes.length!==st.size)fail('mobile_ledger_changed');ledger=validateLedger(JSON.parse(bytes.toString('utf8')));}
  catch(e){if(e.code==='ENOENT')ledger=emptyLedger();else throw e;}
  const recovered=structuredClone(ledger);let changed=false;
  for(const row of recovered.installs){if(row.state==='PREPARING'||row.state==='SENT'){row.interruptedState=row.state;row.state='UNKNOWN';row.errorCode='INTERRUPTED_STATE';changed=true;const p=recovered.plans.find(x=>x.planId===row.planId);if(p)p.state='UNKNOWN';}}
  for(const row of recovered.plans){if(row.state==='PLANNING'){row.state='UNKNOWN';row.archiveSha256='';row.manifestSha256='';changed=true;}}
  ledger=recovered;
  if(changed||!fs.existsSync(ledgerFile))persist(ledger);

  function persist(next){
    validateLedger(next);const bytes=Buffer.from(JSON.stringify(next));if(bytes.length>MAX_LEDGER_BYTES)fail('mobile_ledger_too_large');
    atomicWrite(ledgerFile,bytes,{beforeAtomicWrite});ledger=next;
  }
  function update(fn){const next=structuredClone(ledger);fn(next);persist(next);}
  function planPath(planId){if(!UUID.test(planId))fail('mobile_plan_id_invalid');return path.join(plansDir,planId);}
  function findJob(job){
    if(!job||!Number.isSafeInteger(job.issueNumber)||!['PLAN_M574','INSTALL_M574'].includes(job.action))fail('mobile_job_invalid');
    const row=job.action==='PLAN_M574'?ledger.plans.find(x=>x.issueNumber===job.issueNumber):ledger.installs.find(x=>x.issueNumber===job.issueNumber);
    if(!row)return null;
    if(row.owner!==job.owner||row.repository!==job.repository||row.requestId!==job.requestId||row.nonce!==job.nonce||row.jobDigest!==jobDigest(job))fail('mobile_job_replay');
    return Object.freeze(structuredClone(row));
  }
  function readPlan(planId){
    const dir=planPath(planId);checkDirectory(dir,{mode:0o700,owner});
    const metaFile=path.join(dir,'metadata.json'),archiveFile=path.join(dir,'archive.gz'),metaStat=checkFile(metaFile,{owner}),archiveStat=checkFile(archiveFile,{owner});
    if(metaStat.size>16*1024||archiveStat.size>MOBILE_INSTALL_MAX_ARCHIVE_BYTES)fail('mobile_plan_file_too_large');
    const metaBytes=fs.readFileSync(metaFile),archive=fs.readFileSync(archiveFile);
    if(metaBytes.length!==metaStat.size||archive.length!==archiveStat.size)fail('mobile_plan_changed_during_read');
    let meta;try{meta=JSON.parse(metaBytes.toString('utf8'));}catch{fail('mobile_plan_metadata_invalid');}
    const keys=['planId','repository','commit','packagePath','ciRun','workflow','archiveSha256','archiveSize','manifestSha256','fileCount','expandedBytes','createdAt'];
    if(!exact(meta,keys)||meta.planId!==planId||meta.repository!==MOBILE_INSTALL_REPOSITORY||meta.commit!==MOBILE_INSTALL_COMMIT||meta.packagePath!==MOBILE_INSTALL_PACKAGE_PATH||
      meta.ciRun!==MOBILE_INSTALL_CI_RUN||meta.workflow!==MOBILE_INSTALL_CI_WORKFLOW||!SHA.test(meta.archiveSha256)||sha256(archive)!==meta.archiveSha256||
      archive.length!==meta.archiveSize||!SHA.test(meta.manifestSha256)||!Number.isSafeInteger(meta.fileCount)||meta.fileCount<1||meta.fileCount>512||
      !Number.isSafeInteger(meta.expandedBytes)||meta.expandedBytes<1||meta.expandedBytes>12*1024*1024||!Number.isSafeInteger(meta.createdAt))fail('mobile_plan_metadata_invalid');
    return Object.freeze({...meta,archive});
  }
  function beginPlan(job){
    checkJob(job,'PLAN_M574');
    if(ledger.plans.length+ledger.installs.length>=MAX_LEDGER_ROWS)fail('mobile_ledger_full');
    if(ledger.plans.some(x=>x.issueNumber===job.issueNumber)||ledger.plans.some(x=>x.requestId===job.requestId||x.nonce===job.nonce)||ledger.installs.some(x=>x.requestId===job.requestId||x.nonce===job.nonce))fail('mobile_job_replay');
    const planId=uuidFactory();if(!UUID.test(planId)||ledger.plans.some(x=>x.planId===planId))fail('mobile_plan_id_invalid');
    const row={issueNumber:job.issueNumber,owner:job.owner,repository:job.repository,requestId:job.requestId,nonce:job.nonce,jobDigest:jobDigest(job),planId,
      archiveSha256:'',manifestSha256:'',state:'PLANNING',createdAt:clock()};
    update(next=>{next.plans.push(row);});return planId;
  }
  function savePlan(job,planId,plan,receipt){
    checkJob(job,'PLAN_M574');validatePlan(plan);
    const row=ledger.plans.find(x=>x.planId===planId);if(!row||row.state!=='PLANNING'||row.issueNumber!==job.issueNumber||row.requestId!==job.requestId||row.nonce!==job.nonce)fail('mobile_plan_reservation_invalid');
    const dir=planPath(planId);fs.mkdirSync(dir,{mode:0o700});fsyncDir(plansDir);checkDirectory(dir,{mode:0o700,owner});
    const meta={planId,repository:plan.repository,commit:plan.commit,packagePath:plan.packagePath,ciRun:plan.ciRun,workflow:plan.workflow,
      archiveSha256:plan.archiveSha256,archiveSize:plan.archiveSize,manifestSha256:plan.manifestSha256,fileCount:plan.fileCount,expandedBytes:plan.expandedBytes,createdAt:clock()};
    atomicWrite(path.join(dir,'archive.gz'),plan.archive,{beforeAtomicWrite});
    atomicWrite(path.join(dir,'metadata.json'),Buffer.from(JSON.stringify(meta)),{beforeAtomicWrite});
    update(next=>{const target=next.plans.find(x=>x.planId===planId);target.archiveSha256=plan.archiveSha256;target.manifestSha256=plan.manifestSha256;target.state='PLANNED';if(receipt)target.receipt=receipt;});
    return Object.freeze({...meta,archive:Buffer.from(plan.archive)});
  }
  function recordPlanOutcome(job,planId,{state='UNKNOWN',errorCode='PLAN_OUTCOME_UNKNOWN',receipt}={}){
    checkJob(job,'PLAN_M574');const row=ledger.plans.find(x=>x.planId===planId);
    if(!row||row.state!=='PLANNING'||row.issueNumber!==job.issueNumber||row.requestId!==job.requestId||row.nonce!==job.nonce||!['UNKNOWN','REJECTED'].includes(state)||! /^[A-Z0-9_]{1,128}$/.test(errorCode))fail('mobile_plan_outcome_invalid');
    update(next=>{const target=next.plans.find(x=>x.planId===planId);target.state=state;target.errorCode=errorCode;if(receipt)target.receipt=receipt;});return true;
  }
  function createPlan(job,plan){const planId=beginPlan(job);return savePlan(job,planId,plan);}
  function beginInstall(job){
    checkJob(job,'INSTALL_M574');
    if(job.confirmation!=='INSTALL_LOCAL_HADES_M2_MOBILE'||!UUID.test(job.planId)||!SHA.test(job.archiveSha256||'')||!SHA.test(job.manifestSha256||''))fail('mobile_install_binding_rejected');
    if(ledger.installs.some(x=>['PREPARING','SENT','UNKNOWN'].includes(x.state)))fail('mobile_install_gate_closed');
    const planRow=ledger.plans.find(x=>x.planId===job.planId);if(!planRow||planRow.state!=='PLANNED'||planRow.archiveSha256!==job.archiveSha256||planRow.manifestSha256!==job.manifestSha256)fail('mobile_plan_binding_mismatch');
    if(ledger.installs.some(x=>x.issueNumber===job.issueNumber)||ledger.plans.some(x=>x.issueNumber===job.issueNumber)||
      [...ledger.plans,...ledger.installs].some(x=>x.requestId===job.requestId||x.nonce===job.nonce))fail('mobile_job_replay');
    if(ledger.plans.length+ledger.installs.length>=MAX_LEDGER_ROWS)fail('mobile_ledger_full');
    const plan=readPlan(job.planId),row={issueNumber:job.issueNumber,owner:job.owner,repository:job.repository,requestId:job.requestId,nonce:job.nonce,jobDigest:jobDigest(job),
      planId:job.planId,archiveSha256:job.archiveSha256,manifestSha256:job.manifestSha256,jobId:'',installNonce:'',state:'PREPARING',createdAt:clock(),errorCode:''};
    update(next=>{next.plans.find(x=>x.planId===job.planId).state='INSTALL_PENDING';next.installs.push(row);});
    const persistIntent=intent=>persistInstallIntent(row.issueNumber,intent);
    return Object.freeze({plan,persistIntent});
  }
  function persistInstallIntent(issueNumber,intent){
    if(!Number.isSafeInteger(issueNumber)||!intent||!exact(intent,['request','requestHeader','origin','route'])||intent.origin!==MOBILE_INSTALLER_ORIGIN||intent.route!==MOBILE_INSTALLER_ROUTE)fail('mobile_install_intent_invalid');
    const request=intent.request,keys=['protocol','action','brokerId','adapterId','jobId','nonce','issuedAt','expiresAt','repository','commit','packagePath','archiveSha256','archiveSize','manifestSha256','signature'];
    if(!exact(request,keys)||request.protocol!==MOBILE_INSTALL_PROTOCOL||request.action!=='INSTALL_MOBILE_M574'||!UUID.test(request.jobId)||!UUID.test(request.nonce)||
      !SIGNATURE.test(request.signature)||request.repository!==MOBILE_INSTALL_REPOSITORY||request.commit!==MOBILE_INSTALL_COMMIT||request.packagePath!==MOBILE_INSTALL_PACKAGE_PATH||
      !SHA.test(request.archiveSha256)||!SHA.test(request.manifestSha256)||!Number.isSafeInteger(request.archiveSize)||request.archiveSize<1||request.archiveSize>MOBILE_INSTALL_MAX_ARCHIVE_BYTES||
      !/^sha256:[a-f0-9]{64}$/.test(request.brokerId)||!/^sha256:[a-f0-9]{64}$/.test(request.adapterId)||
      !Number.isSafeInteger(request.issuedAt)||!Number.isSafeInteger(request.expiresAt)||request.issuedAt>clock()+5_000||request.expiresAt<=clock()||
      request.expiresAt<=request.issuedAt||request.expiresAt-request.issuedAt>5*60_000||
      typeof intent.requestHeader!=='string'||intent.requestHeader.length>8192||intent.requestHeader!==Buffer.from(JSON.stringify(request)).toString('base64url'))fail('mobile_install_intent_invalid');
    const row=ledger.installs.find(x=>x.issueNumber===issueNumber);if(!row||row.state!=='PREPARING'||row.archiveSha256!==request.archiveSha256||row.manifestSha256!==request.manifestSha256)fail('mobile_install_intent_replay');
    if(ledger.installs.some(x=>x!==row&&(x.jobId===request.jobId||x.installNonce===request.nonce)))fail('mobile_install_intent_replay');
    update(next=>{const target=next.installs.find(x=>x.issueNumber===issueNumber);target.jobId=request.jobId;target.installNonce=request.nonce;target.signedRequest=request;target.requestHeader=intent.requestHeader;target.state='SENT';target.sentAt=clock();});
    return true;
  }
  function recordVerifiedResponse(issueNumber,response,receipt){
    const keys=['protocol','adapterId','jobId','nonce','issuedAt','expiresAt','state','targetSlug','commit','archiveSha256','backupSlug','sourceSha256','errorCode','signature'];
    const row=ledger.installs.find(x=>x.issueNumber===issueNumber);
    if(!row||row.state!=='SENT'||!row.signedRequest||!exact(response,keys)||response.protocol!==MOBILE_INSTALL_PROTOCOL||
      response.adapterId!==row.signedRequest.adapterId||response.jobId!==row.jobId||response.nonce!==row.installNonce||response.archiveSha256!==row.archiveSha256||response.commit!==MOBILE_INSTALL_COMMIT||
      response.targetSlug!=='local_hades_m2_mobile'||!['COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK','UNKNOWN','REJECTED'].includes(response.state)||
      typeof response.adapterId!=='string'||!/^sha256:[a-f0-9]{64}$/.test(response.adapterId)||!SIGNATURE.test(response.signature)||
      !Number.isSafeInteger(response.issuedAt)||!Number.isSafeInteger(response.expiresAt)||response.issuedAt>clock()+5_000||response.expiresAt<=clock()||
      response.expiresAt<=response.issuedAt||response.expiresAt-response.issuedAt>5*60_000||typeof response.errorCode!=='string'||
      typeof response.backupSlug!=='string'||typeof response.sourceSha256!=='string')fail('mobile_install_response_unbound');
    if(['COMPLETED','COMPLETED_WITH_STAGE_RETAINED'].includes(response.state)&&
      (!/^[A-Za-z0-9_-]{1,128}$/.test(response.backupSlug)||!SHA.test(response.sourceSha256)||response.errorCode!==''))fail('mobile_install_response_evidence_missing');
    const result=Object.freeze({...response});
    update(next=>{
      const target=next.installs.find(x=>x.issueNumber===issueNumber),planRow=next.plans.find(x=>x.planId===target.planId);
      target.response=result;target.state=response.state;target.errorCode=response.errorCode;planRow.state=response.state;if(receipt)target.receipt=receipt;
    });
    return true;
  }
  function recordTransportUnknown(issueNumber,receipt){
    const row=ledger.installs.find(x=>x.issueNumber===issueNumber);
    if(!row||!['PREPARING','SENT','UNKNOWN'].includes(row.state)||row.response!==undefined)fail('mobile_transport_unknown_not_allowed');
    if(row.state==='UNKNOWN'&&row.errorCode==='TRANSPORT_OUTCOME_UNKNOWN')return true;
    update(next=>{
      const target=next.installs.find(x=>x.issueNumber===issueNumber),planRow=next.plans.find(x=>x.planId===target.planId);
      target.state='UNKNOWN';target.errorCode='TRANSPORT_OUTCOME_UNKNOWN';target.transportUnknownAt=clock();planRow.state='UNKNOWN';if(receipt)target.receipt=receipt;
    });
    return true;
  }
  function recordInstallRejected(issueNumber,errorCode,receipt){
    const row=ledger.installs.find(x=>x.issueNumber===issueNumber);
    if(!row||row.state!=='PREPARING'||!/^[A-Z0-9_]{1,128}$/.test(errorCode))fail('mobile_install_rejection_not_allowed');
    update(next=>{
      const target=next.installs.find(x=>x.issueNumber===issueNumber),planRow=next.plans.find(x=>x.planId===target.planId);
      target.state='REJECTED';target.errorCode=errorCode;if(receipt)target.receipt=receipt;planRow.state='REJECTED';
    });return true;
  }
  function recordReceiptForJob(job,receipt){
    const row=findJob(job);if(!row||row.receipt)fail('mobile_receipt_replay');
    if(receipt?.issueNumber!==job.issueNumber||receipt?.requestId!==job.requestId||receipt?.nonce!==job.nonce||receipt?.action!==job.action)fail('mobile_receipt_unbound');
    update(next=>{
      const rows=job.action==='PLAN_M574'?next.plans:next.installs,target=rows.find(x=>x.issueNumber===job.issueNumber);target.receipt=receipt;
    });return true;
  }
  function refreshReceiptForJob(job,previous,nextReceipt){
    const row=findJob(job);if(!row?.receipt||JSON.stringify(row.receipt)!==JSON.stringify(previous))fail('mobile_receipt_refresh_conflict');
    const stable=value=>{const copy={...value};delete copy.issuedAt;delete copy.expiresAt;delete copy.signature;return JSON.stringify(copy);};
    if(stable(previous)!==stable(nextReceipt)||!SIGNATURE.test(nextReceipt?.signature)||!Number.isSafeInteger(nextReceipt.issuedAt)||
      !Number.isSafeInteger(nextReceipt.expiresAt)||nextReceipt.issuedAt<=previous.issuedAt||nextReceipt.expiresAt<=previous.expiresAt)fail('mobile_receipt_refresh_invalid');
    update(state=>{
      const rows=job.action==='PLAN_M574'?state.plans:state.installs,target=rows.find(x=>x.issueNumber===job.issueNumber);
      if(JSON.stringify(target.receipt)!==JSON.stringify(previous))fail('mobile_receipt_refresh_conflict');target.receipt=nextReceipt;
    });return true;
  }
  function snapshot(){return Object.freeze({plans:ledger.plans.map(x=>Object.freeze({...x})),installs:ledger.installs.map(x=>Object.freeze({...x}))});}
  return Object.freeze({storeDir,createPlan,beginPlan,savePlan,recordPlanOutcome,readPlan,findJob,beginInstall,persistInstallIntent,recordVerifiedResponse,recordTransportUnknown,recordInstallRejected,recordReceiptForJob,refreshReceiptForJob,snapshot});
}

export function createMobileInstallStore(){return createStore({dataRoot:MOBILE_INSTALL_DATA_ROOT});}
export function createMobileInstallStoreForTests({testOnlyDataRoot,clock=Date.now,uuidFactory=randomUUID,testOnlyBeforeAtomicWrite=()=>{}}={}){
  if(typeof testOnlyDataRoot!=='string'||typeof testOnlyBeforeAtomicWrite!=='function')fail('mobile_store_test_options_invalid');
  return createStore({dataRoot:testOnlyDataRoot,clock,uuidFactory,beforeAtomicWrite:testOnlyBeforeAtomicWrite});
}
