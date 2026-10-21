import fs from 'node:fs';import path from 'node:path';
export function safeStateDir(dir){
 fs.mkdirSync(dir,{recursive:true,mode:0o700});const s=fs.lstatSync(dir);
 if(!s.isDirectory()||s.isSymbolicLink()||s.uid!==process.getuid()||(s.mode&0o077)!==0)throw Error('insecure_state_directory');
 return dir;
}
export function ledgerFile(dir){return path.join(safeStateDir(dir),'receipts.json')}
export function readLedger(dir){const f=ledgerFile(dir);if(!fs.existsSync(f))return {version:1,issues:{}};const s=fs.lstatSync(f);if(!s.isFile()||s.isSymbolicLink()||(s.mode&0o077)!==0)throw Error('insecure_ledger');const v=JSON.parse(fs.readFileSync(f,'utf8'));if(v?.version!==1||typeof v.issues!=='object'||!v.issues||Array.isArray(v.issues))throw Error('corrupt_ledger');return v}
export function writeLedger(dir,data){const f=ledgerFile(dir),tmp=f+'.tmp-'+process.pid;try{fs.writeFileSync(tmp,JSON.stringify(data,null,2)+'\n',{mode:0o600,flag:'wx'});fs.renameSync(tmp,f);fs.chmodSync(f,0o600)}finally{if(fs.existsSync(tmp))fs.unlinkSync(tmp)}}
function lockOwnerIsRunning(pid, dir){
 if(!Number.isSafeInteger(pid)||pid<2)return false;
 if(pid===process.pid)return true;
 try{
  const cmd=fs.readFileSync('/proc/'+pid+'/cmdline','utf8').replaceAll('\0',' ');
  return cmd.includes(path.join(path.resolve(dir),'src','worker.mjs'));
 }catch{return false}
}
export function acquireLock(dir){
 const lock=path.join(safeStateDir(dir),'.worker-lock');
 try{fs.mkdirSync(lock,{mode:0o700})}
 catch(e){
  if(e.code!=='EEXIST')throw e;
  let owner=null,recent=false;
  try{owner=Number(fs.readFileSync(path.join(lock,'owner'),'utf8').trim())}catch{}
  try{recent=Date.now()-fs.statSync(lock).mtimeMs<10000}catch{}
  if(lockOwnerIsRunning(owner,dir)||(!owner&&recent))throw Error('worker_already_running');
  const info=fs.lstatSync(lock);
  if(!info.isDirectory()||info.isSymbolicLink())throw Error('insecure_worker_lock');
  fs.rmSync(lock,{recursive:true,force:true});
  fs.mkdirSync(lock,{mode:0o700});
 }
 try{fs.writeFileSync(path.join(lock,'owner'),String(process.pid)+'\n',{mode:0o600})}
 catch(e){fs.rmSync(lock,{recursive:true,force:true});throw e}
 return ()=>fs.rmSync(lock,{recursive:true,force:true})
}