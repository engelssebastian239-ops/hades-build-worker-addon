import fs from'node:fs';import path from'node:path';import{fileURLToPath}from'node:url';
import{parseTask,receiptFor}from'./task.mjs';import{readLedger,writeLedger,acquireLock}from'./storage.mjs';import{createGithub,loadToken}from'./github.mjs';
export function validateConfig(c){
 if(!c||typeof c!=='object'||!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(c.repository||''))throw Error('invalid_repo_config');
 if(!Array.isArray(c.authorizedAuthors)||c.authorizedAuthors.length!==1||c.authorizedAuthors[0]!==c.repository.split('/')[0])throw Error('unauthorized_author_config');
 if(c.mode!=='intake-only')throw Error('execution_not_permitted');
 if(!Number.isInteger(c.pollSeconds)||c.pollSeconds<60||c.pollSeconds>3600)throw Error('invalid_poll');
 if(!Number.isInteger(c.maxIssuesPerCycle)||c.maxIssuesPerCycle<1||c.maxIssuesPerCycle>5)throw Error('invalid_batch');
 if(typeof c.tokenFile!=='string'||!c.tokenFile.startsWith('/data/hades-dev-workspace/hades-m35-secrets-20261011/'))throw Error('invalid_token_path');
 const stateRoot='/data/hades-dev-workspace/hades-m35-secrets-20261011';
 if(c.stateDirectory!==undefined&&(typeof c.stateDirectory!=='string'||!path.resolve(c.stateDirectory).startsWith(stateRoot+path.sep)))throw Error('invalid_state_directory');
 return c;
}
export function retryDelayMs(error,pollSeconds=120,failureCount=1,now=Date.now()){
 const pollMs=pollSeconds*1000,dayMs=24*60*60*1000;
 const retry=String(error?.retryAfter??'').trim();
 if(retry){
  const seconds=Number(retry),delay=Number.isFinite(seconds)?seconds*1000:Date.parse(retry)-now;
  if(Number.isFinite(delay)&&delay>=0)return Math.min(Math.max(1000,delay),dayMs);
 }
 if(error?.status===403||error?.status===429){
  if(error.rateLimitRemaining==='0'&&Number.isFinite(error.rateLimitReset))
   return Math.min(Math.max(pollMs,error.rateLimitReset*1000-now+5000),dayMs);
  return Math.min(Math.max(pollMs,60000),15*60*1000);
 }
 if(!error?.status||error.status>=500)
  return Math.min(pollMs*2**Math.min(Math.max(0,failureCount-1),4),15*60*1000);
 return pollMs;
}
export async function runCycle(gh, stateDir, config){
 const c=validateConfig(config),ledger=readLedger(stateDir),stats={new:0,already:0,recovered:0,invalid:0,inspected:0,blockedExecution:true};
 const issues=await gh.listIssues();if(!Array.isArray(issues))throw Error('invalid_github_issues_reply');
 for(const issue of issues){
  if(stats.new>=c.maxIssuesPerCycle)break;
  const task=parseTask(issue,c);if(!task){stats.invalid++;continue}
  stats.inspected++;const key=String(issue.number),{marker,body}=receiptFor(task,c.repository);
  if(ledger.issues[key]?.state==='RECEIPT_CONFIRMED'){stats.already++;continue}
  const comments=await gh.listComments(issue.number);if(!Array.isArray(comments))throw Error('invalid_github_comments_reply');
  if(comments.some(comment=>comment.user?.login===c.authorizedAuthors[0]&&typeof comment.body==='string'&&comment.body.includes('<!-- '+marker+' -->'))){
   ledger.issues[key]={state:'RECEIPT_CONFIRMED',taskId:task.taskId,recovered:true,at:new Date().toISOString()};
   writeLedger(stateDir,ledger);stats.recovered++;continue;
  }
  // In this phase HERMES acknowledges receipt ONLY. No model call, no code, no shell.
  await gh.postComment(issue.number,body);
  ledger.issues[key]={state:'RECEIPT_CONFIRMED',taskId:task.taskId,at:new Date().toISOString()};
  writeLedger(stateDir,ledger);stats.new++;
 }
 return stats;
}
export async function runNoWriteAcceptance(gh,config,issueNumber=1){
 const c=validateConfig(config);
 if(issueNumber!==1)throw Error('acceptance_issue_must_be_1');
 const issues=await gh.listIssues();if(!Array.isArray(issues))throw Error('invalid_github_issues_reply');
 const issue=issues.find(x=>x?.number===issueNumber);if(!issue)throw Error('acceptance_issue_not_found');
 const task=parseTask(issue,c);if(!task)throw Error('invalid_acceptance_task');
 const {marker,body}=receiptFor(task,c.repository),comments=await gh.listComments(issueNumber);
 if(!Array.isArray(comments))throw Error('invalid_github_comments_reply');
 if(comments.some(comment=>comment.user?.login===c.authorizedAuthors[0]&&typeof comment.body==='string'&&comment.body.includes('<!-- '+marker+' -->')))
  return {state:'ALREADY_RECEIVED',issue:issueNumber,taskId:task.taskId,blockedExecution:true};
 // Acceptance-only path: remote marker is the idempotency record; no local state, lock or ledger is touched.
 await gh.postComment(issueNumber,body);
 return {state:'RECEIPT_POSTED',issue:issueNumber,taskId:task.taskId,blockedExecution:true};
}
async function main(){
 const arg=process.argv[2];if(!['--once','--loop','--acceptance-no-write'].includes(arg))throw Error('usage:_--once_--loop_or_--acceptance-no-write');
 const root=path.resolve(fileURLToPath(import.meta.url),'../..'),config=validateConfig(JSON.parse(fs.readFileSync(path.join(root,'config.json'),'utf8')));
 const token=loadToken(config.tokenFile),gh=createGithub({repo:config.repository,token}),stateDir=config.stateDirectory||path.join(root,'state');
 // Verify repository is private and the credential belongs to its owner, before processing any issues.
 const repo=await gh.getRepo();if(repo?.private!==true||repo?.full_name!==config.repository)throw Error('private_repository_verification_failed');
 const user=await gh.getUser();if(user?.login!==config.authorizedAuthors[0])throw Error('github_token_owner_mismatch');
 if(arg==='--acceptance-no-write'){
  const stats=await runNoWriteAcceptance(gh,config,1);
  console.log(JSON.stringify({at:new Date().toISOString(),state:'ACCEPTANCE_NO_WRITE_OK',...stats}));
  return;
 }
 const unlock=acquireLock(stateDir);
 let stopping=false,resolveStop;
 const stopSignal=new Promise(resolve=>{resolveStop=resolve});
 const stop=()=>{stopping=true;resolveStop()};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 let failures=0;
 try{
  while(!stopping){
   let waitMs=config.pollSeconds*1000;
   try{
    const stats=await runCycle(gh,stateDir,config);
    failures=0;
    console.log(JSON.stringify({at:new Date().toISOString(),state:'POLL_OK',...stats}));
   }catch(e){
    failures++;
    waitMs=retryDelayMs(e,config.pollSeconds,failures);
    const reason=Number.isInteger(e?.status)?'github_http_'+e.status:/^[a-z0-9_]+$/i.test(e?.message||'')?e.message:'network_or_worker_error';
    console.error(JSON.stringify({at:new Date().toISOString(),state:'POLL_FAILED',error:reason,retryInSeconds:Math.ceil(waitMs/1000)}));
    if(arg==='--once')process.exitCode=1;
   }
   if(arg==='--once'||stopping)break;
   let timer;
   await Promise.race([new Promise(resolve=>{timer=setTimeout(resolve,waitMs)}),stopSignal]);
   if(timer)clearTimeout(timer);
  }
 }finally{
  process.removeListener('SIGTERM',stop);process.removeListener('SIGINT',stop);unlock()
 }
}
if(process.argv[1]&&path.resolve(process.argv[1])===fileURLToPath(import.meta.url))main().catch(e=>{console.error(JSON.stringify({state:'STARTUP_BLOCKED',error:e.message}));process.exitCode=2});