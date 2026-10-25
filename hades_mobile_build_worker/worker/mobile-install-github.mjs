import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {createPublicKey} from 'node:crypto';
import {
  MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY,MOBILE_INSTALL_REQUIRED_ASSET
} from './mobile-install-plan.mjs';
import {MOBILE_INSTALL_GITHUB_OWNER,parseMobileInstallIssue} from './mobile-install-queue.mjs';
import {MOBILE_INSTALL_DATA_ROOT} from './mobile-install-store.mjs';
import {verifyHistoricalMobileInstallReceipt,verifyMobileInstallReceipt} from './mobile-install-receipt.mjs';
import {identityId} from '../shared/identity.mjs';

export const MOBILE_INSTALL_GITHUB_API_ORIGIN='https://api.github.com';
export const MOBILE_INSTALL_GITHUB_RESULT_MARKER='<!-- HADES-MOBILE-M574-RESULT-V1 -->';
export const MOBILE_INSTALL_GITHUB_OUTBOX_PATH=`${MOBILE_INSTALL_DATA_ROOT}/mobile-install/github-outbox.json`;
const PAGE_SIZE=30,MAX_ISSUE_PAGES=3,MAX_COMMENT_PAGES=2,MAX_JOBS_PER_POLL=3,MAX_API_CALLS=32,MAX_API_BYTES=8*1024*1024,MAX_COMMENT_BYTES=16*1024;
const TOKEN=/^github_pat_[A-Za-z0-9_]{20,}$/;
const SHA=/^[a-f0-9]{64}$/;
const SIGNATURE=/^[A-Za-z0-9_-]{86}$/;
const LEDGER_STATES=new Set(['PREPARED','POST_ATTEMPTED','POSTED','AMBIGUOUS']);
const fail=code=>{throw Object.assign(new Error(code),{code});};
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex');
const exact=(value,keys)=>!!value&&Object.getPrototypeOf(value)===Object.prototype&&Object.keys(value).sort().join(',')===[...keys].sort().join(',');
function normalizedJobDigest(job){
  const fields=[job.action,job.owner,job.repository,job.issueNumber,job.requestId,job.nonce,job.issuedAt,job.expiresAt,
    job.fixedSource.repository,job.fixedSource.commit,job.fixedSource.packagePath,job.fixedSource.ciRun,job.fixedSource.workflow];
  if(job.action==='INSTALL_M574')fields.push(job.planId,job.archiveSha256,job.manifestSha256,job.confirmation);
  return sha(Buffer.from(JSON.stringify(fields)));
}
const receiptBody=receipt=>`${MOBILE_INSTALL_GITHUB_RESULT_MARKER}\n${JSON.stringify(receipt)}`;

function ownerUid(){return typeof process.getuid==='function'?process.getuid():null;}
function checkDir(dir,{create=false,uid=ownerUid()}={}){
  if(create){try{fs.mkdirSync(dir,{mode:0o700});const fd=fs.openSync(path.dirname(dir),fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}catch(e){if(e.code!=='EEXIST')throw e;}}
  const st=fs.lstatSync(dir);if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o777)!==0o700||(uid!==null&&st.uid!==uid))fail('mobile_outbox_directory_unsafe');return st;
}
function checkFile(file,{uid=ownerUid()}={}){const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o777)!==0o600||(uid!==null&&st.uid!==uid))fail('mobile_outbox_file_unsafe');return st;}
function fsyncDir(dir){const fd=fs.openSync(dir,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function atomicWrite(file,bytes,uid){
  const dir=path.dirname(file),temp=path.join(dir,`.tmp-${process.pid}-${crypto.randomUUID()}`);let fd;
  try{
    fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
    fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);const st=fs.fstatSync(fd);if(!st.isFile()||(st.mode&0o777)!==0o600||(uid!==null&&st.uid!==uid))fail('mobile_outbox_file_unsafe');
    fs.closeSync(fd);fd=undefined;checkFile(temp,{uid});fs.renameSync(temp,file);fsyncDir(dir);checkFile(file,{uid});
  }catch(error){if(fd!==undefined){try{fs.closeSync(fd);}catch{}}try{fs.unlinkSync(temp);}catch{}throw error;}
}
function validLedger(value){
  if(!exact(value,['protocol','entries'])||value.protocol!=='HADES_MOBILE_M574_GITHUB_OUTBOX_V1'||!Array.isArray(value.entries)||value.entries.length>1024)fail('mobile_outbox_invalid');
  const seen=new Set();
  for(const row of value.entries){
    const keys=['issueNumber','jobDigest','state','receipt','body','createdAt',...(row?.postAttemptedAt!==undefined?['postAttemptedAt']:[]),...(row?.postedAt!==undefined?['postedAt']:[]),...(row?.commentId!==undefined?['commentId']:[]),...(row?.ambiguousAt!==undefined?['ambiguousAt']:[])];
    if(!exact(row,keys)||!Number.isSafeInteger(row.issueNumber)||row.issueNumber<1||!SHA.test(row.jobDigest)||!LEDGER_STATES.has(row.state)||
      !row.receipt||row.receipt.protocol!=='HADES_MOBILE_M574_RECEIPT_V1'||!SIGNATURE.test(row.receipt.signature)||typeof row.body!=='string'||
      Buffer.byteLength(row.body)>MAX_COMMENT_BYTES||!Number.isSafeInteger(row.createdAt)||seen.has(row.issueNumber)||
      row.postAttemptedAt!==undefined&&!Number.isSafeInteger(row.postAttemptedAt)||row.postedAt!==undefined&&!Number.isSafeInteger(row.postedAt)||
      row.commentId!==undefined&&(!Number.isSafeInteger(row.commentId)||row.commentId<1)||row.ambiguousAt!==undefined&&!Number.isSafeInteger(row.ambiguousAt))fail('mobile_outbox_invalid');
    seen.add(row.issueNumber);
  }
  return value;
}

function createOutbox({file,uid=ownerUid(),clock=Date.now,beforeWrite=()=>{}}={}){
  if(typeof file!=='string'||!path.isAbsolute(file)||typeof clock!=='function'||typeof beforeWrite!=='function')fail('mobile_outbox_options_invalid');
  const dir=path.dirname(file);checkDir(dir,{create:true,uid});let ledger;
  try{const stat=checkFile(file,{uid});if(stat.size>2*1024*1024)fail('mobile_outbox_too_large');const data=fs.readFileSync(file);if(data.length!==stat.size)fail('mobile_outbox_changed');ledger=validLedger(JSON.parse(data.toString('utf8')));}
  catch(e){if(e.code==='ENOENT')ledger={protocol:'HADES_MOBILE_M574_GITHUB_OUTBOX_V1',entries:[]};else throw e;}
  function persist(next){validLedger(next);const bytes=Buffer.from(JSON.stringify(next));if(bytes.length>2*1024*1024)fail('mobile_outbox_too_large');beforeWrite(file);atomicWrite(file,bytes,uid);ledger=next;}
  function update(fn){const next=structuredClone(ledger);fn(next);persist(next);}
  function find(issueNumber){return ledger.entries.find(x=>x.issueNumber===issueNumber)||null;}
  function prepare(job,digest,receipt){
    const old=find(job.issueNumber),body=receiptBody(receipt);
    if(old){if(old.jobDigest!==digest)fail('mobile_outbox_replay_conflict');if(old.body!==body||JSON.stringify(old.receipt)!==JSON.stringify(receipt))fail('mobile_outbox_receipt_conflict');return Object.freeze(structuredClone(old));}
    update(next=>next.entries.push({issueNumber:job.issueNumber,jobDigest:digest,state:'PREPARED',receipt,body,createdAt:clock()}));
    return Object.freeze(structuredClone(find(job.issueNumber)));
  }
  function replacePrepared(issueNumber,receipt){
    const old=find(issueNumber);if(!old||old.state!=='PREPARED')fail('mobile_outbox_state_conflict');
    update(next=>{const row=next.entries.find(x=>x.issueNumber===issueNumber);row.receipt=receipt;row.body=receiptBody(receipt);});return Object.freeze(structuredClone(find(issueNumber)));
  }
  function attempted(issueNumber){const old=find(issueNumber);if(!old||old.state!=='PREPARED')fail('mobile_outbox_state_conflict');update(next=>{const row=next.entries.find(x=>x.issueNumber===issueNumber);row.state='POST_ATTEMPTED';row.postAttemptedAt=clock();});}
  function posted(issueNumber,commentId){const old=find(issueNumber);if(!old||!['PREPARED','POST_ATTEMPTED'].includes(old.state))fail('mobile_outbox_state_conflict');update(next=>{const row=next.entries.find(x=>x.issueNumber===issueNumber);row.state='POSTED';row.commentId=commentId;row.postedAt=clock();});}
  function ambiguous(issueNumber){const old=find(issueNumber);if(!old||!['PREPARED','POST_ATTEMPTED'].includes(old.state))fail('mobile_outbox_state_conflict');update(next=>{const row=next.entries.find(x=>x.issueNumber===issueNumber);row.state='AMBIGUOUS';row.ambiguousAt=clock();});}
  if(!fs.existsSync(file))persist(ledger);
  return Object.freeze({find,prepare,replacePrepared,attempted,posted,ambiguous,snapshot:()=>Object.freeze({entries:ledger.entries.length})});
}

export function createGithubMobileInstallTransport({token,workerPublicKey,controller,planner,installEnabled=false,fetchImpl=globalThis.fetch,clock=Date.now,timeoutSignal=AbortSignal.timeout}={}){
  return createTransport({token,workerPublicKey,controller,planner,installEnabled,fetchImpl,clock,timeoutSignal,outbox:createOutbox({file:MOBILE_INSTALL_GITHUB_OUTBOX_PATH})});
}
export function createGithubMobileInstallTransportForTests({token,workerPublicKey,controller,planner,installEnabled=false,testOnlyOutboxPath,fetchImpl,clock=Date.now,timeoutSignal=AbortSignal.timeout,testOnlyBeforeWrite=()=>{}}={}){
  if(typeof testOnlyOutboxPath!=='string')fail('mobile_github_test_path_missing');
  return createTransport({token,workerPublicKey,controller,planner,installEnabled,fetchImpl,clock,timeoutSignal,outbox:createOutbox({file:testOnlyOutboxPath,clock,beforeWrite:testOnlyBeforeWrite})});
}

function createTransport({token,workerPublicKey,controller,planner,installEnabled=false,fetchImpl,clock,timeoutSignal,outbox}){
  if(typeof installEnabled!=='boolean'||typeof token!=='string'||!TOKEN.test(token)||!workerPublicKey||!controller||typeof controller.handle!=='function'||typeof planner?.createPlan!=='function'||
    typeof fetchImpl!=='function'||typeof clock!=='function'||typeof timeoutSignal!=='function')fail('mobile_github_configuration_invalid');
  const pub=workerPublicKey.type==='public'?workerPublicKey:createPublicKey(workerPublicKey),workerId=identityId(pub);
  if(controller.workerId!==workerId)fail('mobile_github_worker_identity_mismatch');
  let callCount=0,inFlight=false,preflightVerified=false,writeVerified=false;
  const prefix=`/repos/${MOBILE_INSTALL_REPOSITORY}`;
  async function call(method,route,payload,withHeaders=false){
    const valid=route==='/user'||route===prefix||route===`${prefix}/actions/runs/${MOBILE_INSTALL_CI_RUN}`||
      route===`${prefix}/contents/${`${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REQUIRED_ASSET}`.split('/').map(encodeURIComponent).join('/')}?ref=${MOBILE_INSTALL_COMMIT}`||
      /^\/repos\/engelssebastian239-ops\/hades-hermes-queue\/issues\?state=open&per_page=30&page=1$/.test(route)||
      /^\/repos\/engelssebastian239-ops\/hades-hermes-queue\/issues\?state=open&sort=created&direction=desc&per_page=30&page=[1-3]$/.test(route)||
      /^\/repos\/engelssebastian239-ops\/hades-hermes-queue\/issues\/[1-9][0-9]{0,9}\/comments\?per_page=100&page=[1-2]$/.test(route)||
      /^\/repos\/engelssebastian239-ops\/hades-hermes-queue\/issues\/[1-9][0-9]{0,9}\/comments$/.test(route);
    if(!valid||route.includes('..')||route.startsWith('//'))fail('mobile_github_route_rejected');
    if(++callCount>MAX_API_CALLS)fail('mobile_github_api_budget_exceeded');
    let response;try{response=await fetchImpl(MOBILE_INSTALL_GITHUB_API_ORIGIN+route,{method,redirect:'error',credentials:'omit',cache:'no-store',signal:timeoutSignal(8000),
      headers:{authorization:`Bearer ${token}`,accept:'application/vnd.github+json','x-github-api-version':'2022-11-28','user-agent':'HADES-Mobile-Install-Pull',...(payload?{'content-type':'application/json'}:{})},
      ...(payload?{body:JSON.stringify(payload)}:{})});}catch(error){fail(error?.name==='AbortError'?'mobile_github_timeout':'mobile_github_network_failure');}
    if(response?.url&&response.url!==MOBILE_INSTALL_GITHUB_API_ORIGIN+route)fail('mobile_github_origin_mismatch');
    if(!response?.ok)fail(response?.status===401||response?.status===403?'mobile_github_authorization_failed':`mobile_github_http_${Number(response?.status)||0}`);
    const data=await readBoundedJson(response,payload?MAX_COMMENT_BYTES:MAX_API_BYTES);
    return withHeaders?{data,headers:response.headers,status:response.status}:data;
  }
  async function readBoundedJson(response,limit){
    if(!String(response.headers?.get?.('content-type')||'').toLowerCase().startsWith('application/json')||!response.body?.getReader)fail('mobile_github_response_type_invalid');
    const reader=response.body.getReader(),chunks=[];let size=0;
    try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>limit){await reader.cancel().catch(()=>{});fail('mobile_github_response_too_large');}chunks.push(Buffer.from(value));}}
    catch(e){if(e?.code?.startsWith('mobile_github_'))throw e;fail(e?.name==='AbortError'?'mobile_github_timeout':'mobile_github_response_invalid');}
    const bytes=Buffer.concat(chunks);try{return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{fail('mobile_github_json_invalid');}
  }
  async function identityCheck(){
    const user=await call('GET','/user'),repo=await call('GET',prefix);
    if(user?.login!==MOBILE_INSTALL_GITHUB_OWNER||repo?.full_name!==MOBILE_INSTALL_REPOSITORY||repo?.private!==true)fail('mobile_github_repository_identity_rejected');
    return repo;
  }
  async function preflight(){
    callCount=0;preflightVerified=false;
    const userReply=await call('GET','/user',undefined,true),repoReply=await call('GET',prefix,undefined,true),user=userReply.data,repo=repoReply.data;
    if(user?.login!==MOBILE_INSTALL_GITHUB_OWNER||repo?.full_name!==MOBILE_INSTALL_REPOSITORY||repo?.private!==true)fail('mobile_github_repository_identity_rejected');
    const runReply=await call('GET',`${prefix}/actions/runs/${MOBILE_INSTALL_CI_RUN}`,undefined,true),run=runReply.data;
    if(run?.id!==MOBILE_INSTALL_CI_RUN||run.status!=='completed'||run.conclusion!=='success'||run.head_sha!==MOBILE_INSTALL_COMMIT||run.path!==MOBILE_INSTALL_CI_WORKFLOW)fail('mobile_github_actions_read_unverified');
    const assetPath=`${prefix}/contents/${`${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REQUIRED_ASSET}`.split('/').map(encodeURIComponent).join('/')}?ref=${MOBILE_INSTALL_COMMIT}`;
    const contentReply=await call('GET',assetPath,undefined,true),content=contentReply.data;
    if(content?.path!==MOBILE_INSTALL_PACKAGE_PATH+'/'+MOBILE_INSTALL_REQUIRED_ASSET||!/^[a-f0-9]{40}$/.test(content.sha||''))fail('mobile_github_contents_read_unverified');
    const issueReply=await call('GET',`${prefix}/issues?state=open&per_page=30&page=1`,undefined,true);if(!Array.isArray(issueReply.data))fail('mobile_github_issues_read_unverified');
    if(repo.permissions?.push===false)fail('mobile_github_repository_write_rejected');
    preflightVerified=true;
    return Object.freeze({state:'READ_READY_WRITE_UNVERIFIED',owner:MOBILE_INSTALL_GITHUB_OWNER,repository:MOBILE_INSTALL_REPOSITORY,private:true,
      contentsRead:true,actionsRead:true,issuesRead:true,issuesWrite:false});
  }
  async function listIssues(){
    const all=[];for(let page=1;page<=MAX_ISSUE_PAGES;page++){
      const rows=await call('GET',`${prefix}/issues?state=open&sort=created&direction=desc&per_page=${PAGE_SIZE}&page=${page}`);
      if(!Array.isArray(rows)||rows.length>PAGE_SIZE)fail('mobile_github_issue_list_invalid');all.push(...rows);if(rows.length<PAGE_SIZE)return {rows:all,truncated:false};
    }return {rows:all,truncated:true};
  }
  async function listComments(issueNumber){
    const all=[];for(let page=1;page<=MAX_COMMENT_PAGES;page++){
      const rows=await call('GET',`${prefix}/issues/${issueNumber}/comments?per_page=100&page=${page}`);
      if(!Array.isArray(rows)||rows.length>100)fail('mobile_github_comment_list_invalid');all.push(...rows);if(rows.length<100)return all;
    }fail('mobile_github_comment_pagination_limit');
  }
  function verifyReceipt(receipt,job,{historical=false}={}){
    const options={expectedWorkerId:workerId,expectedAction:job.action,expectedIssueNumber:job.issueNumber,expectedRequestId:job.requestId,expectedNonce:job.nonce,now:clock()};
    return historical?verifyHistoricalMobileInstallReceipt(receipt,pub,options):verifyMobileInstallReceipt(receipt,pub,options);
  }
  function commentStatus(comments,entry,job){
    const marked=comments.filter(x=>typeof x?.body==='string'&&x.body.startsWith(MOBILE_INSTALL_GITHUB_RESULT_MARKER));
    if(marked.length===0)return {state:'ABSENT'};
    if(marked.length!==1)return {state:'CONFLICT'};
    const item=marked[0];if(item.user?.login!==MOBILE_INSTALL_GITHUB_OWNER||item.body!==entry.body||!Number.isSafeInteger(item.id)||item.id<1)return {state:'CONFLICT'};
    let receipt;try{receipt=JSON.parse(item.body.slice(MOBILE_INSTALL_GITHUB_RESULT_MARKER.length+1));verifyReceipt(receipt,job,{historical:true});}catch{return {state:'CONFLICT'};}
    return JSON.stringify(receipt)===JSON.stringify(entry.receipt)?{state:'MATCH',commentId:item.id}:{state:'CONFLICT'};
  }
  async function reconcile(issueNumber,entry,job){return commentStatus(await listComments(issueNumber),entry,job);}
  async function processIssue(issue,parsedJob){
    let job=parsedJob;try{job??=parseMobileInstallIssue({issue,repository:{full_name:MOBILE_INSTALL_REPOSITORY,private:true},authenticatedOwner:MOBILE_INSTALL_GITHUB_OWNER,now:clock()});}catch{return 'REJECTED';}
    if(job.action==='INSTALL_M574'&&!installEnabled)return 'INSTALL_DISABLED';
    if(job.action==='INSTALL_M574'&&!writeVerified)return 'WRITE_UNVERIFIED';
    const digest=normalizedJobDigest(job);let entry=outbox.find(job.issueNumber);
    if(entry&&entry.jobDigest!==digest)return 'CONFLICT';
    if(entry?.state==='POSTED')return 'ALREADY_POSTED';if(entry?.state==='AMBIGUOUS')return 'AMBIGUOUS';
    if(entry?.state==='POST_ATTEMPTED'){
      const status=await reconcile(job.issueNumber,entry,job);
      if(status.state==='MATCH'){outbox.posted(job.issueNumber,status.commentId);return 'POSTED';}
      outbox.ambiguous(job.issueNumber);return 'AMBIGUOUS';
    }
    if(!entry){
      const receipt=await controller.handle(job);verifyReceipt(receipt,job);
      entry=outbox.prepare(job,digest,receipt);
    }else{
      try{verifyReceipt(entry.receipt,job);}
      catch{
        const historical=verifyReceipt(entry.receipt,job,{historical:true});
        const refreshed=await controller.handle(job);verifyReceipt(refreshed,job);
        const stable=v=>{const x={...v};delete x.issuedAt;delete x.expiresAt;delete x.signature;return JSON.stringify(x);};
        if(stable(historical)!==stable(refreshed))return 'CONFLICT';entry=outbox.replacePrepared(job.issueNumber,refreshed);
      }
    }
    const status=await reconcile(job.issueNumber,entry,job);
    if(status.state==='MATCH'){outbox.posted(job.issueNumber,status.commentId);return 'POSTED';}
    if(status.state==='CONFLICT'){outbox.ambiguous(job.issueNumber);return 'AMBIGUOUS';}
    await identityCheck();outbox.attempted(job.issueNumber);
    try{
      const createdReply=await call('POST',`${prefix}/issues/${job.issueNumber}/comments`,{body:entry.body},true),created=createdReply.data;
      if(created?.body!==entry.body||created.user?.login!==MOBILE_INSTALL_GITHUB_OWNER||!Number.isSafeInteger(created.id)||created.id<1)throw Error('ambiguous');
      const parsed=JSON.parse(created.body.slice(MOBILE_INSTALL_GITHUB_RESULT_MARKER.length+1));verifyReceipt(parsed,job,{historical:true});
      if(createdReply.status!==201)throw Error('ambiguous');
      if(job.action==='PLAN_M574'&&parsed.state==='PLANNED')writeVerified=true;
      outbox.posted(job.issueNumber,created.id);return 'POSTED';
    }catch{throw Object.assign(new Error('mobile_github_comment_post_ambiguous'),{code:'mobile_github_comment_post_ambiguous'});}
  }
  return Object.freeze({
    verifyConnection:preflight,
    async pollOnce(){
      if(!preflightVerified)fail('mobile_github_preflight_required');
      if(inFlight)fail('mobile_github_poll_already_running');inFlight=true;callCount=0;
      try{
        await identityCheck();const page=await listIssues();const counts={inspected:0,posted:0,alreadyPosted:0,ambiguous:0,conflicts:0,rejected:0,deferred:0,truncatedIssues:page.truncated};let handled=0;
        for(const issue of page.rows){
          if(!issue||typeof issue.title!=='string'||!/^HADES (?:PLAN_M574|INSTALL_M574)$/.test(issue.title))continue;
          let job;try{job=parseMobileInstallIssue({issue,repository:{full_name:MOBILE_INSTALL_REPOSITORY,private:true},authenticatedOwner:MOBILE_INSTALL_GITHUB_OWNER,now:clock()});}
          catch{counts.rejected++;continue;}
          counts.inspected++;
          const digest=normalizedJobDigest(job),existing=outbox.find(job.issueNumber);
          if(existing&&existing.jobDigest!==digest){counts.conflicts++;continue;}
          if(existing?.state==='POSTED'){counts.alreadyPosted++;continue;}
          if(existing?.state==='AMBIGUOUS'){counts.ambiguous++;continue;}
          if(job.action==='INSTALL_M574'&&!installEnabled){counts.deferred++;continue;}
          if(job.action==='INSTALL_M574'&&!writeVerified){counts.deferred++;continue;}
          if(handled>=MAX_JOBS_PER_POLL){counts.deferred++;continue;}
          handled++;
          const result=await processIssue(issue,job);
          if(result==='POSTED')counts.posted++;else if(result==='ALREADY_POSTED')counts.alreadyPosted++;else if(result==='AMBIGUOUS')counts.ambiguous++;
          else if(result==='CONFLICT')counts.conflicts++;else if(result==='REJECTED')counts.rejected++;else if(result==='WRITE_UNVERIFIED')counts.deferred++;
        }
        counts.writeState=writeVerified?'VERIFIED':'UNVERIFIED';return Object.freeze(counts);
      }finally{inFlight=false;}
    },
    snapshot:()=>Object.freeze({outboxEntries:outbox.snapshot().entries,apiCallsThisPoll:callCount,writeVerified})
  });
}

export function startGithubMobileInstallLoop(transport,{pollSeconds=120,log=()=>{},timers=globalThis}={}){
  if(!Number.isInteger(pollSeconds)||pollSeconds!==120)fail('mobile_github_poll_interval_invalid');
  let stopped=false,timer=null,failures=0;
  const poll=async()=>{if(stopped)return;let delay=120_000;try{const counts=await transport.pollOnce();failures=0;log({state:'MOBILE_GITHUB_POLL_OK',...counts});}
    catch(error){failures++;delay=Math.min(120_000*2**Math.min(failures-1,4),15*60_000);log({state:'MOBILE_GITHUB_POLL_FAILED',error:/^[a-z0-9_]+$/i.test(error?.code||'')?error.code:'mobile_github_failure',retryInSeconds:delay/1000});}
    if(!stopped)timer=timers.setTimeout(poll,delay);};
  timer=timers.setTimeout(poll,0);return Object.freeze({stop(){stopped=true;if(timer!==null)timers.clearTimeout(timer);}});
}

export function createGithubMobileInstallTransportForUnitTests(options={}){return createTransport(options);}
