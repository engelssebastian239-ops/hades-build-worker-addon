import fs from'node:fs';
const base='https://api.github.com';
const PAGE_SIZE=100;
const MAX_PAGES=10;
export function loadToken(file){
 const s=fs.lstatSync(file);
 if(!s.isFile()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)throw Error('insecure_github_token_file');
 const token=fs.readFileSync(file,'utf8').trim();
 if(!/^(github_pat_|ghp_)[A-Za-z0-9_]{20,}$/.test(token))throw Error('invalid_github_token_format');
 return token;
}
export function createGithub({repo,token,fetchFn=globalThis.fetch}){
 if(!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repo))throw Error('invalid_repository_name');
 if(!token)throw Error('github_token_required');
 const repoPath='/repos/'+repo;
 async function call(method,path,body){
  if(!path.startsWith(repoPath+'/')&&!['/user',repoPath].includes(path))throw Error('forbidden_github_path');
  const res=await fetchFn(base+path,{method,headers:{'Authorization':'Bearer '+token,'Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28','User-Agent':'HADES-HERMES-M35-bridge','Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(12000),redirect:'error'});
  if(!res.ok){const retry=res.headers.get('retry-after');const reset=res.headers.get('x-ratelimit-reset');const remaining=res.headers.get('x-ratelimit-remaining');const e=Error('github_http_'+res.status);e.status=res.status;e.retryAfter=retry;const resetNumber=Number(reset);e.rateLimitReset=Number.isInteger(resetNumber)&&resetNumber>0?resetNumber:null;e.rateLimitRemaining=remaining;throw e}
  return await res.json();
 }
 async function listAll(path){
  const items=[],separator=path.includes('?')?'&':'?';
  for(let page=1;page<=MAX_PAGES;page++){
   const result=await call('GET',path+separator+'per_page='+PAGE_SIZE+'&page='+page);
   if(!Array.isArray(result))throw Error('invalid_github_pagination_reply');
   items.push(...result);
   if(result.length<PAGE_SIZE)return items;
  }
  throw Error('github_pagination_limit_reached');
 }
 return Object.freeze({
  getRepo:()=>call('GET',repoPath),
  getUser:()=>call('GET','/user'),
  listIssues:()=>listAll(repoPath+'/issues?state=open&sort=created&direction=asc'),
  listComments:(issue)=>listAll(repoPath+'/issues/'+issue+'/comments'),
  postComment:(issue,body)=>call('POST',repoPath+'/issues/'+issue+'/comments',{body}),
 });
}