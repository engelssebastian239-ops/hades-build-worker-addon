import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';

const REPOSITORY='engelssebastian239-ops/hades-build-worker-addon';
const ROOTS=['hades_mobile_build_worker','hades_mobile_installer'];
const MAX_ARCHIVE_BYTES=16*1024*1024,MAX_PACKAGE_BYTES=12*1024*1024,MAX_FILES=512,MAX_TIMEOUT_MS=15_000;
const fail=code=>{throw Object.assign(Error(code),{code});};
function git(args,maxBuffer=16*1024*1024){try{return execFileSync('git',args,{encoding:'buffer',maxBuffer,timeout:MAX_TIMEOUT_MS,stdio:['ignore','pipe','ignore']});}catch{fail('source_git_verification_failed');}}
function boundedResponse(response){return new Promise(async(resolve,reject)=>{if(!response?.ok||response.url!==`https://codeload.github.com/${REPOSITORY}/tar.gz/${commit}`||!response.body?.getReader)return reject(Error('source_archive_response_rejected'));const len=Number(response.headers.get('content-length'));if(Number.isFinite(len)&&len>MAX_ARCHIVE_BYTES)return reject(Error('source_archive_too_large'));const reader=response.body.getReader(),chunks=[];let size=0;try{for(;;){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>MAX_ARCHIVE_BYTES){await reader.cancel();return reject(Error('source_archive_too_large'));}chunks.push(Buffer.from(value));}resolve(Buffer.concat(chunks));}catch{reject(Error('source_archive_read_failed'));}});}
const commit=process.env.M577_SOURCE_COMMIT;
if(!/^[a-f0-9]{40}$/.test(commit||''))fail('source_commit_missing');
const head=git(['rev-parse','HEAD']).toString('ascii').trim();if(head!==commit)fail('source_head_mismatch');
const sourceUrl=`https://codeload.github.com/${REPOSITORY}/tar.gz/${commit}`;
const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),15_000);
let archive;try{const response=await fetch(sourceUrl,{redirect:'error',signal:controller.signal,headers:{accept:'application/vnd.github+json','user-agent':'HADES-M577-source-digest'}});archive=await boundedResponse(response);}catch(error){fail(error?.message==='source_archive_too_large'?'source_archive_too_large':'source_archive_fetch_failed');}finally{clearTimeout(timer);}
const archiveSha256=createHash('sha256').update(archive).digest('hex');
const results=[];
for(const root of ROOTS){
  const raw=git(['ls-tree','-rz','-l','--full-tree',commit,'--',root]);
  const records=raw.toString('utf8').split('\0').filter(Boolean),entries=[];let total=0;
  for(const record of records){const tab=record.indexOf('\t');if(tab<0)fail('source_tree_invalid');const meta=record.slice(0,tab).trim().split(/\s+/),file=record.slice(tab+1);if(meta.length!==4)fail('source_tree_invalid');const [mode,type,blob,sizeText]=meta;const size=Number(sizeText);
    if(!file.startsWith(root+'/')||!['100644','100755'].includes(mode)||type!=='blob'||!/^[a-f0-9]{40}$/.test(blob)||!Number.isSafeInteger(size)||size<0)fail('source_tree_entry_rejected');
    total+=size;if(entries.length>=MAX_FILES||total>MAX_PACKAGE_BYTES)fail('source_package_limit');
    const bytes=git(['cat-file','blob',blob],MAX_PACKAGE_BYTES);if(bytes.length!==size||createHash('sha1').update(Buffer.concat([Buffer.from(`blob ${size}\0`),bytes])).digest('hex')!==blob)fail('source_blob_invalid');
    entries.push({path:file,mode,gitBlob:blob,size,sha256:createHash('sha256').update(bytes).digest('hex')});
  }
  if(entries.length===0)fail('source_package_empty');entries.sort((a,b)=>a.path.localeCompare(b.path));
  const manifest=Buffer.from(JSON.stringify(entries));
  results.push({path:root,commit,fileCount:entries.length,totalBytes:total,manifestSha256:createHash('sha256').update(manifest).digest('hex'),manifest:entries});
}
console.log(JSON.stringify({state:'M577_SOURCE_DIGEST',repository:REPOSITORY,commit,archiveUrl:sourceUrl,archiveBytes:archive.length,archiveSha256,packages:results}));
