import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash,generateKeyPairSync} from 'node:crypto';
import {identityId} from '../hades_mobile_build_worker/shared/protocol.mjs';
import {
  MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_PACKAGE_PATH,MOBILE_INSTALL_REPOSITORY,MOBILE_INSTALL_REQUIRED_ASSET
} from '../hades_mobile_build_worker/worker/mobile-install-plan.mjs';
import {MOBILE_INSTALL_CONFIRMATION,MOBILE_INSTALL_GITHUB_OWNER,MOBILE_INSTALL_JOB_TTL_MS,MOBILE_INSTALL_QUEUE_PROTOCOL} from '../hades_mobile_build_worker/worker/mobile-install-queue.mjs';
import {MOBILE_INSTALL_RECEIPT_PROTOCOL,signMobileInstallReceipt,verifyHistoricalMobileInstallReceipt} from '../hades_mobile_build_worker/worker/mobile-install-receipt.mjs';
import {
  MOBILE_INSTALL_GITHUB_API_ORIGIN,MOBILE_INSTALL_GITHUB_RESULT_MARKER,createGithubMobileInstallTransportForTests
} from '../hades_mobile_build_worker/worker/mobile-install-github.mjs';

const hash=x=>createHash('sha256').update(x).digest('hex'),now=1_800_000_000_000;
const TOKEN='github_pat_'+('s'.repeat(32)),pair=generateKeyPairSync('ed25519'),workerId=identityId(pair.publicKey);
const sha='a'.repeat(64),manifest='b'.repeat(64),planId='00000000-0000-4000-8000-000000000101';
let ids=1100;function uuid(){return `00000000-0000-4000-8000-${(++ids).toString(16).padStart(12,'0')}`;}
function body(action,{stale=false,...extra}={}){const issuedAt=stale?now-MOBILE_INSTALL_JOB_TTL_MS-1:now;const common={protocol:MOBILE_INSTALL_QUEUE_PROTOCOL,action,requestId:uuid(),nonce:uuid(),issuedAt,expiresAt:issuedAt+MOBILE_INSTALL_JOB_TTL_MS};
  return action==='PLAN_M574'?{...common,...extra}:{...common,planId,archiveSha256:sha,manifestSha256:manifest,confirmation:MOBILE_INSTALL_CONFIRMATION,...extra};}
function issue(action,number,{stale=false,...extra}={}){return {number,title:`HADES ${action}`,body:JSON.stringify(body(action,{stale,...extra})),user:{login:MOBILE_INSTALL_GITHUB_OWNER},state:'open'};}
function signedReceipt(job,clock=()=>now){const fields={repository:MOBILE_INSTALL_REPOSITORY,owner:MOBILE_INSTALL_GITHUB_OWNER,action:job.action,issueNumber:job.issueNumber,
  requestId:job.requestId,nonce:job.nonce,issuedAt:clock(),expiresAt:clock()+300_000,state:job.expiresAt<=clock()?'REJECTED':job.action==='PLAN_M574'?'PLANNED':'COMPLETED',
  planId:job.action==='PLAN_M574'?'00000000-0000-4000-8000-000000000102':job.planId,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,
  ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW,archiveSha256:job.expiresAt<=clock()?'':job.archiveSha256||sha,
  manifestSha256:job.expiresAt<=clock()?'':job.manifestSha256||manifest,installerJobId:job.action==='INSTALL_M574'?'00000000-0000-4000-8000-000000000103':'',
  installerNonce:job.action==='INSTALL_M574'?'00000000-0000-4000-8000-000000000104':'',backupSlug:job.action==='INSTALL_M574'?'backup-1':'',
  sourceSha256:job.action==='INSTALL_M574'?'c'.repeat(64):'',errorCode:job.expiresAt<=clock()?'JOB_EXPIRED':''};
  return signMobileInstallReceipt(fields,pair.privateKey,{clock});}
function tempFile(){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'m576-mobile-gh-'));fs.chmodSync(dir,0o700);return path.join(dir,'outbox.json');}
function createHarness({issues=[],comments=new Map(),owner=MOBILE_INSTALL_GITHUB_OWNER,privateRepo=true,scopes='repo',faults={},controller=null,token=TOKEN,installEnabled=false,outboxPath:testOutboxPath}={}){
  const calls=[],posted=[],handled=[];let requests=0,isPrivate=privateRepo,issueRows=issues;
  const fakeController=controller||{workerId,async handle(job){handled.push(job);return signedReceipt(job);}};
  function json(data,{status=200,headers={}}={}){return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json',...headers}});}
  const fetchImpl=async(url,init)=>{
    requests++;const parsed=new URL(url);calls.push({url,method:init.method,headers:init.headers,body:init.body});
    if(faults.redirect)return Promise.reject(Object.assign(Error('redirect blocked'),{name:'TypeError'}));
    if(faults.timeout)return new Promise((_resolve,reject)=>init.signal.addEventListener('abort',()=>reject(Object.assign(Error('timeout'),{name:'AbortError'}))));
    const route=parsed.pathname+parsed.search,headers={'x-oauth-scopes':scopes};
    if(route==='/user')return json({login:owner},{headers});
    if(route===`/repos/${MOBILE_INSTALL_REPOSITORY}`)return json({full_name:MOBILE_INSTALL_REPOSITORY,private:isPrivate,permissions:{push:true}},{headers});
    if(route===`/repos/${MOBILE_INSTALL_REPOSITORY}/actions/runs/${MOBILE_INSTALL_CI_RUN}`){if(faults.actionsFail)return json({message:'forbidden'},{status:403,headers});return json({id:MOBILE_INSTALL_CI_RUN,status:'completed',conclusion:'success',head_sha:MOBILE_INSTALL_COMMIT,path:MOBILE_INSTALL_CI_WORKFLOW},{headers});}
    const asset=`/repos/${MOBILE_INSTALL_REPOSITORY}/contents/${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REQUIRED_ASSET}?ref=${MOBILE_INSTALL_COMMIT}`;
    if(route===asset)return json({path:`${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REQUIRED_ASSET}`,sha:'c'.repeat(40)},{headers});
    if(route.startsWith(`/repos/${MOBILE_INSTALL_REPOSITORY}/issues?`)){
      if(faults.delayIssues)await new Promise(resolve=>setTimeout(resolve,25));
      const page=Number(parsed.searchParams.get('page'))||1;
      if(faults.largeIssueSet){
        if(page===1)return json([...(issueRows.slice(0,1)),...Array.from({length:29},(_,i)=>({number:6000+i,title:'unrelated',body:'',user:{login:'someone'},state:'open'}))],{headers});
        return json(Array.from({length:30},(_,i)=>({number:6100+(page-2)*30+i,title:'unrelated',body:'',user:{login:'someone'},state:'open'})),{headers:page===3?{...headers,link:'<https://api.github.com/repos/x/y/issues?page=4>; rel="next"'}:headers});
      }
      if(faults.fullIssuePages)return json(Array.from({length:30},(_,i)=>({number:5000+(page-1)*30+i,title:'not-a-mobile-job',body:'',user:{login:'someone'},state:'open'})),{headers});
      if(page>1)return json([],{headers});
      return json(issueRows,{headers});
    }
    const commentMatch=new RegExp(`^/repos/${MOBILE_INSTALL_REPOSITORY}/issues/(\\d+)/comments(?:\\?per_page=100&page=[1-2])?$`).exec(route);
    if(commentMatch&&init.method==='GET'){
      if(faults.foreignMarker){return json([{id:9,user:{login:'someone-else'},body:`${MOBILE_INSTALL_GITHUB_RESULT_MARKER}\n{}` }],{headers});}
      if(faults.fullCommentPages)return json(Array.from({length:100},(_,i)=>({id:i+1,user:{login:'someone'},body:'ordinary'})),{headers});
      const reply=json(comments.get(Number(commentMatch[1]))||[],{headers});if(faults.publicAtComments)isPrivate=false;return reply;
    }
    if(commentMatch&&init.method==='POST'){
      if(faults.post403)return json({message:'write denied'},{status:403,headers});
      const request=JSON.parse(init.body);const row={id:posted.length+1,user:{login:MOBILE_INSTALL_GITHUB_OWNER},body:request.body};posted.push(row);
      if(faults.dropPostResponse){const old=comments.get(Number(commentMatch[1]))||[];comments.set(Number(commentMatch[1]),[...old,row]);throw Error('connection dropped after accept');}
      if(faults.postIdentityChanged)return json({id:1,user:{login:'attacker'},body:request.body},{status:201,headers});
      const old=comments.get(Number(commentMatch[1]))||[];comments.set(Number(commentMatch[1]),[...old,row]);return json(row,{status:201,headers});
    }
    return json({message:'not found'},{status:404,headers});
  };
  const outboxPath=testOutboxPath||tempFile(),transport=createGithubMobileInstallTransportForTests({token,workerPublicKey:pair.publicKey,controller:fakeController,planner:{createPlan:async()=>({})},installEnabled,
    testOnlyOutboxPath:outboxPath,fetchImpl,clock:()=>now,timeoutSignal:ms=>AbortSignal.timeout(faults.timeout?5:ms)});
  return {transport,calls,posted,handled,comments,outboxPath,faults,setPrivate(value){isPrivate=value;},setIssues(value){issueRows=value;},get requests(){return requests;}};
}

test('non-mutating token preflight proves read readiness but explicitly leaves issue write unverified',async t=>{
  const good=createHarness();await assert.rejects(good.transport.pollOnce(),/mobile_github_preflight_required/);
  const result=await good.transport.verifyConnection();assert.deepEqual(result,{state:'READ_READY_WRITE_UNVERIFIED',owner:MOBILE_INSTALL_GITHUB_OWNER,repository:MOBILE_INSTALL_REPOSITORY,private:true,contentsRead:true,actionsRead:true,issuesRead:true,issuesWrite:false});
  assert.equal(good.calls.length,5);assert.ok(good.calls.every(c=>c.url.startsWith(MOBILE_INSTALL_GITHUB_API_ORIGIN)));
  await t.test('owner mismatch',async()=>{const h=createHarness({owner:'attacker'});await assert.rejects(h.transport.verifyConnection(),/mobile_github_repository_identity_rejected/);});
  await t.test('public repository',async()=>{const h=createHarness({privateRepo:false});await assert.rejects(h.transport.verifyConnection(),/mobile_github_repository_identity_rejected/);});
  await t.test('fine-grained token without scope header remains read-ready',async()=>{const h=createHarness({scopes:''});const state=await h.transport.verifyConnection();assert.equal(state.issuesWrite,false);});
  await t.test('Actions permission missing',async()=>{const h=createHarness({faults:{actionsFail:true}});await assert.rejects(h.transport.verifyConnection(),/mobile_github_authorization_failed/);});
});

test('posts exactly one signed hash-only receipt and deduplicates repeated issue polling',async()=>{
  const item=issue('PLAN_M574',2010),h=createHarness({issues:[item],installEnabled:true});await h.transport.verifyConnection();
  const first=await h.transport.pollOnce();assert.equal(first.posted,1);assert.equal(h.posted.length,1);assert.equal(h.handled.length,1);
  assert.equal(first.writeState,'VERIFIED');
  const bodyText=h.posted[0].body;assert.ok(bodyText.startsWith(MOBILE_INSTALL_GITHUB_RESULT_MARKER+'\n'));
  assert.equal(bodyText.includes(TOKEN),false);assert.equal(bodyText.includes('synthetic'),false);
  const receipt=JSON.parse(bodyText.slice(MOBILE_INSTALL_GITHUB_RESULT_MARKER.length+1));assert.equal(receipt.protocol,MOBILE_INSTALL_RECEIPT_PROTOCOL);assert.equal(Object.hasOwn(receipt,'archive'),false);
  assert.equal(verifyHistoricalMobileInstallReceipt(receipt,pair.publicKey,{expectedWorkerId:workerId,expectedAction:'PLAN_M574',expectedIssueNumber:2010,expectedRequestId:JSON.parse(item.body).requestId,expectedNonce:JSON.parse(item.body).nonce,now}).state,'PLANNED');
  const again=await h.transport.pollOnce();assert.equal(again.alreadyPosted,1);assert.equal(h.posted.length,1);assert.equal(h.handled.length,1);
  const install=issue('INSTALL_M574',2011,{planId:receipt.planId,archiveSha256:receipt.archiveSha256,manifestSha256:receipt.manifestSha256});h.setIssues([install]);
  const installResult=await h.transport.pollOnce();assert.equal(installResult.posted,1);assert.equal(h.posted.length,2);assert.equal(h.handled.length,2);assert.equal(h.transport.snapshot().writeVerified,true);
  const previous=JSON.parse(install.body),changed={...install,body:JSON.stringify({...previous,issuedAt:previous.issuedAt+1,expiresAt:previous.expiresAt+1})};h.setIssues([changed]);
  const conflict=await h.transport.pollOnce();assert.equal(conflict.conflicts,1);assert.equal(h.handled.length,2);assert.equal(h.posted.length,2);
  const outbox=fs.readFileSync(h.outboxPath,'utf8');assert.equal(outbox.includes(TOKEN),false);
});

test('a dropped comment response is reconciled from a valid signed marker and never reposted',async()=>{
  const item=issue('PLAN_M574',2020),h=createHarness({issues:[item],faults:{dropPostResponse:true}});await h.transport.verifyConnection();
  await assert.rejects(h.transport.pollOnce(),/mobile_github_comment_post_ambiguous/);assert.equal(h.posted.length,1);
  const result=await h.transport.pollOnce();assert.equal(result.posted,1);assert.equal(h.posted.length,1);assert.equal(h.handled.length,1);
});

test('pollOnce is single-flight even when callers overlap',async()=>{
  const h=createHarness({issues:[],faults:{delayIssues:true}});await h.transport.verifyConnection();
  const first=h.transport.pollOnce();await assert.rejects(h.transport.pollOnce(),/mobile_github_poll_already_running/);await first;
});

test('unknown comment POST with no visible marker becomes permanent AMBIGUOUS without blind duplicate',async()=>{
  const item=issue('PLAN_M574',2030),h=createHarness({issues:[item],faults:{dropPostResponse:true}});await h.transport.verifyConnection();
  await assert.rejects(h.transport.pollOnce(),/mobile_github_comment_post_ambiguous/);h.comments.set(2030,[]);
  const second=await h.transport.pollOnce();assert.equal(second.ambiguous,1);assert.equal(h.posted.length,1);
  const third=await h.transport.pollOnce();assert.equal(third.ambiguous,1);assert.equal(h.posted.length,1);assert.equal(h.handled.length,1);
});

test('repo privacy is rechecked before comment; invalid or foreign marked comments are never accepted',async t=>{
  await t.test('privacy changed before POST',async()=>{
    const item=issue('PLAN_M574',2040),h=createHarness({issues:[item],faults:{publicAtComments:true}});await h.transport.verifyConnection();
    await assert.rejects(h.transport.pollOnce(),/mobile_github_repository_identity_rejected/);assert.equal(h.posted.length,0);
    h.faults.publicAtComments=false;h.setPrivate(true);const result=await h.transport.pollOnce();assert.equal(result.posted,1);assert.equal(h.posted.length,1);
  });
  await t.test('foreign marker conflict',async()=>{
    const item=issue('PLAN_M574',2041),h=createHarness({issues:[item],faults:{foreignMarker:true}});await h.transport.verifyConnection();
    const result=await h.transport.pollOnce();assert.equal(result.ambiguous,1);assert.equal(h.posted.length,0);assert.equal(h.handled.length,1);
  });
});

test('redirect, timeout and bounded latest-first pagination fail closed without leaking token',async t=>{
  await t.test('redirect error',async()=>{const h=createHarness({faults:{redirect:true}});await assert.rejects(h.transport.verifyConnection(),/mobile_github_network_failure/);});
  await t.test('timeout',async()=>{const h=createHarness({faults:{timeout:true}});await assert.rejects(h.transport.verifyConnection(),/mobile_github_timeout/);});
  await t.test('more than 90 open issues returns bounded latest-first slice and reports truncation',async()=>{
    const h=createHarness({issues:[issue('PLAN_M574',2049)],faults:{largeIssueSet:true}});await h.transport.verifyConnection();
    const result=await h.transport.pollOnce();assert.equal(result.truncatedIssues,true);assert.equal(result.posted,1);assert.equal(h.handled.length,1);
    const paged=h.calls.filter(x=>x.url.includes('/issues?state=open&sort=created&direction=desc'));assert.equal(paged.length,3);
  });
  await t.test('bounded comment pagination',async()=>{const h=createHarness({issues:[issue('PLAN_M574',2050)],faults:{fullCommentPages:true}});await h.transport.verifyConnection();await assert.rejects(h.transport.pollOnce(),/mobile_github_comment_pagination_limit/);assert.equal(h.posted.length,0);});
});

test('terminal and invalid jobs do not consume the actionable per-poll budget',async()=>{
  const first=[issue('PLAN_M574',2110),issue('PLAN_M574',2111),issue('PLAN_M574',2112),issue('PLAN_M574',2113)];
  const h=createHarness({issues:first});await h.transport.verifyConnection();
  const initial=await h.transport.pollOnce();assert.equal(initial.posted,3);assert.equal(initial.deferred,1);
  const malformed={...issue('PLAN_M574',2114),body:'not-json'};h.setIssues([first[0],first[1],first[2],malformed,first[3]]);
  const next=await h.transport.pollOnce();assert.equal(next.alreadyPosted,3);assert.equal(next.rejected,1);assert.equal(next.posted,1);
  assert.equal(h.handled.length,4);assert.equal(h.posted.length,4);
});

test('expired jobs produce only their signed rejection receipt and API errors contain no token',async()=>{
  const item=issue('PLAN_M574',2060,{stale:true}),h=createHarness({issues:[item]});await h.transport.verifyConnection();
  const result=await h.transport.pollOnce();assert.equal(result.posted,1);const posted=JSON.parse(h.posted[0].body.slice(MOBILE_INSTALL_GITHUB_RESULT_MARKER.length+1));assert.equal(posted.state,'REJECTED');assert.equal(posted.errorCode,'JOB_EXPIRED');
  const bad=createHarness({owner:'intruder'});await assert.rejects(bad.transport.verifyConnection(),error=>!error.message.includes(TOKEN)&&!String(error.stack).includes(TOKEN));
});

test('read-only write denial never invokes INSTALL controller',async()=>{
  const h=createHarness({issues:[issue('PLAN_M574',2070)],faults:{post403:true}});await h.transport.verifyConnection();
  await assert.rejects(h.transport.pollOnce(),/mobile_github_comment_post_ambiguous/);assert.equal(h.transport.snapshot().writeVerified,false);
  const install=issue('INSTALL_M574',2071);h.setIssues([install]);const result=await h.transport.pollOnce();assert.equal(result.deferred,1);assert.equal(h.handled.length,1);assert.equal(h.posted.length,0);
});

test('historical owner comment or restart never grants a new process/token write capability',async t=>{
  await t.test('historical owner comment on a new token',async()=>{
    const planIssue=issue('PLAN_M574',2080),first=createHarness({issues:[planIssue]});await first.transport.verifyConnection();await first.transport.pollOnce();assert.equal(first.transport.snapshot().writeVerified,true);
    const newToken='github_pat_'+('n'.repeat(32)),second=createHarness({issues:[planIssue],comments:first.comments,token:newToken});await second.transport.verifyConnection();
    const replay=await second.transport.pollOnce();assert.equal(replay.posted,1);assert.equal(replay.writeState,'UNVERIFIED');assert.equal(second.transport.snapshot().writeVerified,false);assert.equal(second.posted.length,0);
    second.setIssues([issue('INSTALL_M574',2081)]);const blocked=await second.transport.pollOnce();assert.equal(blocked.deferred,1);assert.equal(second.handled.length,1);assert.equal(second.posted.length,0);
  });
  await t.test('restart with a POSTED plan outbox',async()=>{
    const planIssue=issue('PLAN_M574',2090),first=createHarness({issues:[planIssue]});await first.transport.verifyConnection();await first.transport.pollOnce();
    const restarted=createHarness({issues:[planIssue],comments:first.comments,outboxPath:first.outboxPath});await restarted.transport.verifyConnection();
    const replay=await restarted.transport.pollOnce();assert.equal(replay.alreadyPosted,1);assert.equal(restarted.transport.snapshot().writeVerified,false);
    restarted.setIssues([issue('INSTALL_M574',2091)]);const blocked=await restarted.transport.pollOnce();assert.equal(blocked.deferred,1);assert.equal(restarted.handled.length,0);assert.equal(restarted.posted.length,0);
  });
});

test('INSTALL stays blocked by local default gate even after a verified PLAN receipt',async()=>{
  const plan=issue('PLAN_M574',2990),h=createHarness({issues:[plan]});await h.transport.verifyConnection();const result=await h.transport.pollOnce();assert.equal(result.posted,1);
  const receipt=JSON.parse(h.posted[0].body.slice(MOBILE_INSTALL_GITHUB_RESULT_MARKER.length+1));const install=issue('INSTALL_M574',2991,{planId:receipt.planId,archiveSha256:receipt.archiveSha256,manifestSha256:receipt.manifestSha256});h.setIssues([install]);
  const blocked=await h.transport.pollOnce();assert.equal(blocked.deferred,1);assert.equal(blocked.posted,0);assert.equal(h.handled.length,1);assert.equal(h.posted.length,1);
});
