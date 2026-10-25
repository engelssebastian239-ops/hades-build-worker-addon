import {createPublicKey} from 'node:crypto';
import {identityId} from '../shared/identity.mjs';
import {
  MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY
} from './mobile-install-plan.mjs';
import {MOBILE_INSTALL_GITHUB_OWNER} from './mobile-install-queue.mjs';
import {createMobileInstallClient} from './mobile-install-client.mjs';
import {MOBILE_INSTALL_RECEIPT_TTL_MS,signMobileInstallReceipt,verifyHistoricalMobileInstallReceipt,verifyMobileInstallReceipt} from './mobile-install-receipt.mjs';

const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA=/^[a-f0-9]{64}$/;
const fail=code=>{throw Object.assign(new Error(code),{code});};
const FIXED_SOURCE=Object.freeze({repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW});
function exact(value,keys){return !!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');}

function validateJob(job,now){
  const keys=job?.action==='PLAN_M574'?['action','issueNumber','owner','repository','requestId','nonce','issuedAt','expiresAt','fixedSource']:
    ['action','issueNumber','owner','repository','requestId','nonce','issuedAt','expiresAt','fixedSource','planId','archiveSha256','manifestSha256','confirmation'];
  if(!exact(job,keys)||!['PLAN_M574','INSTALL_M574'].includes(job.action)||job.owner!==MOBILE_INSTALL_GITHUB_OWNER||job.repository!==MOBILE_INSTALL_REPOSITORY||
    !Number.isSafeInteger(job.issueNumber)||job.issueNumber<1||!UUID.test(job.requestId)||!UUID.test(job.nonce)||!Number.isSafeInteger(job.issuedAt)||
    !Number.isSafeInteger(job.expiresAt)||job.issuedAt>now+5_000||job.expiresAt<=job.issuedAt||job.expiresAt-job.issuedAt>300_000||
    JSON.stringify(job.fixedSource)!==JSON.stringify(FIXED_SOURCE))fail('mobile_controller_job_invalid');
  if(job.action==='INSTALL_M574'&&(!UUID.test(job.planId)||!SHA.test(job.archiveSha256)||!SHA.test(job.manifestSha256)||job.confirmation!=='INSTALL_LOCAL_HADES_M2_MOBILE'))fail('mobile_controller_install_binding_invalid');
}
function fresh(job,now){return job.expiresAt>now;}
function createController({planner,store,workerPrivateKey,trustedAdapterId,trustedAdapterPublicKey,clock=Date.now,clientFactory=createMobileInstallClient}={}){
  if(!planner||typeof planner.createPlan!=='function'||!store||typeof store.findJob!=='function'||typeof store.beginPlan!=='function'||
    !workerPrivateKey||workerPrivateKey.type!=='private'||workerPrivateKey.asymmetricKeyType!=='ed25519'||
    typeof trustedAdapterId!=='string'||!/^sha256:[a-f0-9]{64}$/.test(trustedAdapterId)||!trustedAdapterPublicKey||typeof clock!=='function'||typeof clientFactory!=='function')fail('mobile_controller_options_invalid');
  const workerPublicKey=createPublicKey(workerPrivateKey),workerId=identityId(workerPublicKey);
  let queue=Promise.resolve();

  function receipt(job,{state,planId='',archiveSha256='',manifestSha256='',installerJobId='',installerNonce='',backupSlug='',sourceSha256='',errorCode=''}){
    const issuedAt=clock();return signMobileInstallReceipt({repository:MOBILE_INSTALL_REPOSITORY,owner:MOBILE_INSTALL_GITHUB_OWNER,action:job.action,
      issueNumber:job.issueNumber,requestId:job.requestId,nonce:job.nonce,issuedAt,expiresAt:issuedAt+MOBILE_INSTALL_RECEIPT_TTL_MS,state,planId,
      commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW,
      archiveSha256,manifestSha256,installerJobId,installerNonce,backupSlug,sourceSha256,errorCode},workerPrivateKey,{clock});
  }
  function publishExisting(job,row){
    if(row.receipt){
      try{return verifyMobileInstallReceipt(row.receipt,workerPublicKey,{expectedWorkerId:workerId,expectedAction:job.action,expectedIssueNumber:job.issueNumber,expectedRequestId:job.requestId,expectedNonce:job.nonce,now:clock()});}
      catch{
        const previous=verifyHistoricalMobileInstallReceipt(row.receipt,workerPublicKey,{expectedWorkerId:workerId,expectedAction:job.action,expectedIssueNumber:job.issueNumber,expectedRequestId:job.requestId,expectedNonce:job.nonce,now:clock()});
        const refreshed=receipt(job,{state:previous.state,planId:previous.planId,archiveSha256:previous.archiveSha256,manifestSha256:previous.manifestSha256,
          installerJobId:previous.installerJobId,installerNonce:previous.installerNonce,backupSlug:previous.backupSlug,sourceSha256:previous.sourceSha256,errorCode:previous.errorCode});
        store.refreshReceiptForJob(job,previous,refreshed);return refreshed;
      }
    }
    let signed;
    if(job.action==='PLAN_M574'){
      if(row.state==='PLANNED'){
        const plan=store.readPlan(row.planId);signed=receipt(job,{state:'PLANNED',planId:row.planId,archiveSha256:plan.archiveSha256,manifestSha256:plan.manifestSha256});
      }else signed=receipt(job,{state:'UNKNOWN',planId:row.planId,archiveSha256:row.archiveSha256||'',manifestSha256:row.manifestSha256||'',errorCode:row.errorCode||'INTERRUPTED_STATE'});
    }else if(['COMPLETED','COMPLETED_WITH_STAGE_RETAINED','ROLLED_BACK','REJECTED'].includes(row.state)&&row.response){
      const response=row.response;signed=receipt(job,{state:response.state,planId:row.planId,archiveSha256:row.archiveSha256,manifestSha256:row.manifestSha256,
        installerJobId:row.jobId,installerNonce:row.installNonce,backupSlug:response.backupSlug,sourceSha256:response.sourceSha256,errorCode:response.errorCode});
    }else signed=receipt(job,{state:'UNKNOWN',planId:row.planId,archiveSha256:row.archiveSha256||'',manifestSha256:row.manifestSha256||'',
      installerJobId:row.jobId||'',installerNonce:row.installNonce||'',errorCode:row.errorCode||'INTERRUPTED_STATE'});
    if(job.action==='INSTALL_M574'&&['PREPARING','SENT'].includes(row.state))store.recordTransportUnknown(job.issueNumber,signed);
    else store.recordReceiptForJob(job,signed);
    return signed;
  }
  async function process(job){
    validateJob(job,clock());
    const existing=store.findJob(job);if(existing)return publishExisting(job,existing);
    if(job.action==='PLAN_M574'){
      const planId=store.beginPlan(job);
      if(!fresh(job,clock())){
        const signed=receipt(job,{state:'REJECTED',planId,errorCode:'JOB_EXPIRED'});store.recordPlanOutcome(job,planId,{state:'REJECTED',errorCode:'JOB_EXPIRED',receipt:signed});return signed;
      }
      let plan;
      try{plan=await planner.createPlan();}catch{
        const signed=receipt(job,{state:'UNKNOWN',planId,errorCode:'PLAN_OUTCOME_UNKNOWN'});store.recordPlanOutcome(job,planId,{state:'UNKNOWN',errorCode:'PLAN_OUTCOME_UNKNOWN',receipt:signed});return signed;
      }
      if(!fresh(job,clock())){
        const signed=receipt(job,{state:'REJECTED',planId,errorCode:'JOB_EXPIRED'});store.recordPlanOutcome(job,planId,{state:'REJECTED',errorCode:'JOB_EXPIRED',receipt:signed});return signed;
      }
      const signed=receipt(job,{state:'PLANNED',planId,archiveSha256:plan.archiveSha256,manifestSha256:plan.manifestSha256});
      store.savePlan(job,planId,plan,signed);return signed;
    }

    const prepared=store.beginInstall(job);
    if(!fresh(job,clock())){
      const signed=receipt(job,{state:'REJECTED',planId:job.planId,archiveSha256:job.archiveSha256,manifestSha256:job.manifestSha256,errorCode:'JOB_EXPIRED'});
      store.recordInstallRejected(job.issueNumber,'JOB_EXPIRED',signed);return signed;
    }
    let currentPlan;
    try{currentPlan=await planner.createPlan();}catch{
      const signed=receipt(job,{state:'REJECTED',planId:job.planId,archiveSha256:job.archiveSha256,manifestSha256:job.manifestSha256,errorCode:'CI_REVALIDATION_FAILED'});
      store.recordInstallRejected(job.issueNumber,'CI_REVALIDATION_FAILED',signed);return signed;
    }
    if(currentPlan.repository!==MOBILE_INSTALL_REPOSITORY||currentPlan.commit!==MOBILE_INSTALL_COMMIT||currentPlan.packagePath!==MOBILE_INSTALL_PACKAGE_PATH||
      currentPlan.ciRun!==MOBILE_INSTALL_CI_RUN||currentPlan.workflow!==MOBILE_INSTALL_CI_WORKFLOW||currentPlan.archiveSha256!==job.archiveSha256||
      currentPlan.manifestSha256!==job.manifestSha256||currentPlan.archiveSize!==prepared.plan.archiveSize||currentPlan.archiveSha256!==job.archiveSha256){
      const signed=receipt(job,{state:'REJECTED',planId:job.planId,archiveSha256:job.archiveSha256,manifestSha256:job.manifestSha256,errorCode:'CI_PLAN_MISMATCH'});
      store.recordInstallRejected(job.issueNumber,'CI_PLAN_MISMATCH',signed);return signed;
    }
    if(!fresh(job,clock())){
      const signed=receipt(job,{state:'REJECTED',planId:job.planId,archiveSha256:job.archiveSha256,manifestSha256:job.manifestSha256,errorCode:'JOB_EXPIRED'});
      store.recordInstallRejected(job.issueNumber,'JOB_EXPIRED',signed);return signed;
    }
    try{
      const client=clientFactory({workerPrivateKey,trustedAdapterId,trustedAdapterPublicKey,persistIntent:async intent=>{
        if(!fresh(job,clock()))fail('mobile_job_expired_before_send');
        await prepared.persistIntent(intent);
        if(!fresh(job,clock()))fail('mobile_job_expired_before_send');
      },clock});
      const response=await client.install(prepared.plan);
      const signed=receipt(job,{state:response.state,planId:job.planId,archiveSha256:response.archiveSha256,manifestSha256:job.manifestSha256,
        installerJobId:response.jobId,installerNonce:response.nonce,backupSlug:response.backupSlug,sourceSha256:response.sourceSha256,errorCode:response.errorCode});
      store.recordVerifiedResponse(job.issueNumber,response,signed);return signed;
    }catch{
      const signed=receipt(job,{state:'UNKNOWN',planId:job.planId,archiveSha256:job.archiveSha256,manifestSha256:job.manifestSha256,
        installerJobId:store.findJob(job)?.jobId||'',installerNonce:store.findJob(job)?.installNonce||'',errorCode:'TRANSPORT_OUTCOME_UNKNOWN'});
      store.recordTransportUnknown(job.issueNumber,signed);return signed;
    }
  }
  function handle(job){
    const run=queue.then(()=>process(job),()=>process(job));queue=run.catch(()=>{});return run;
  }
  return Object.freeze({workerId,handle,verifyReceipt:(value,expected={})=>verifyMobileInstallReceipt(value,workerPublicKey,{expectedWorkerId:workerId,...expected,now:clock()})});
}

export function createMobileInstallController({planner,store,workerPrivateKey,trustedAdapterId,trustedAdapterPublicKey,clock=Date.now}={}){
  return createController({planner,store,workerPrivateKey,trustedAdapterId,trustedAdapterPublicKey,clock,clientFactory:createMobileInstallClient});
}
export function createMobileInstallControllerForTests({testOnlyClientFactory,...options}={}){
  if(typeof testOnlyClientFactory!=='function')fail('mobile_controller_test_factory_missing');
  return createController({...options,clientFactory:testOnlyClientFactory});
}
