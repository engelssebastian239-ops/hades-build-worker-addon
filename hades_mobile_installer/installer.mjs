import fs from 'node:fs';
import path from 'node:path';
import {createCipheriv,createDecipheriv,createHash,createPrivateKey,createPublicKey,generateKeyPairSync,randomBytes,sign,verify} from 'node:crypto';
import {gunzipSync} from 'node:zlib';

export const INSTALL_PROTOCOL='HADES_MOBILE_M574_INSTALL_V1';
export const INSTALL_REPOSITORY='engelssebastian239-ops/hades-hermes-queue';
export const INSTALL_COMMIT='addf609d98256e989e1fc7b2f833d80f95628ae7';
export const INSTALL_PACKAGE_PATH='hades-m2-local-app/hades_m2_mobile';
export const TARGET_SLUG='local_hades_m2_mobile';
export const TARGET_DIR='/addons/hades_m2_mobile';
export const PACKAGE_MANIFEST='HADES-M574-MANIFEST.json';
export const MAX_ARCHIVE_BYTES=8*1024*1024;
export const MAX_EXPANDED_BYTES=12*1024*1024;
export const MAX_FILES=512;
export const MAX_TTL_MS=300_000;
export const SUPPORTED_SUPERVISOR_VERSIONS=Object.freeze(['2026.10.3']);
export const APPARMOR_PROFILE_SHA256='c994fe31bbd8938c813eede4631bdd1edd9edc85ad64caf593a39d7d3089a905';
export const APPARMOR_PROFILE_NAME='c406e920_hades_m574_installer';

const SHA=/^[a-f0-9]{64}$/;
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const KEY=/^[A-Za-z0-9+/]+={0,2}$/;
const REQUEST_KEYS=['protocol','action','brokerId','adapterId','jobId','nonce','issuedAt','expiresAt','repository','commit','packagePath','archiveSha256','archiveSize','manifestSha256','signature'];
const RESPONSE_KEYS=['protocol','adapterId','jobId','nonce','issuedAt','expiresAt','state','targetSlug','commit','archiveSha256','backupSlug','sourceSha256','errorCode','signature'];
const DOCKERFILE_OLD_SHA256='acba06f11b28daeea6d0f35ce924b7813cca1084d243f84324acda7295c8080b';
const DOCKERFILE_M574_SHA256='5c58e91ffa3465e984969a7438aec8e15607a07d3edb293dda7e016aacfed448';
const ACTIVE_STATES=new Set(['RECEIVED','VALIDATED','BACKUP_PENDING','BACKUP_READY','STAGE_READY','PROMOTION_PREPARED','SOURCE_PROMOTED','BUILDING','BUILD_FAILED','RECONCILING','ROLLBACK_SOURCE_MOVED','ROLLBACK_SOURCE_RESTORED','ROLLBACK_BUILDING','UNKNOWN']);

function exact(v,keys){return !!v&&Object.getPrototypeOf(v)===Object.prototype&&Object.keys(v).sort().join(',')===[...keys].sort().join(',');}
function keyFrom(value){
  if(typeof value!=='string'||value.length<40||value.length>512||!KEY.test(value))throw Error('broker_key_invalid');
  return createPublicKey({key:Buffer.from(value,'base64'),format:'der',type:'spki'});
}
function fingerprint(key){return 'sha256:'+createHash('sha256').update(key.export({type:'spki',format:'der'})).digest('hex');}
function requestBytes(v){return Buffer.from(JSON.stringify([v.protocol,v.action,v.brokerId,v.adapterId,v.jobId,v.nonce,v.issuedAt,v.expiresAt,v.repository,v.commit,v.packagePath,v.archiveSha256,v.archiveSize,v.manifestSha256]));}
function responseBytes(v){return Buffer.from(JSON.stringify([v.protocol,v.adapterId,v.jobId,v.nonce,v.issuedAt,v.expiresAt,v.state,v.targetSlug,v.commit,v.archiveSha256,v.backupSlug,v.sourceSha256,v.errorCode]));}
function controlBytes(v){return Buffer.from(JSON.stringify([v.protocol,v.action,v.brokerId,v.adapterId,v.jobId,v.nonce,v.issuedAt,v.expiresAt,v.decision||'',v.reviewId||'']));}
function sha(bytes){return createHash('sha256').update(bytes).digest('hex');}
function fsyncDir(dir){const fd=fs.openSync(dir,fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
function safeMkdir(dir,mode=0o700){
  try{fs.mkdirSync(dir,{mode});}catch(e){if(e.code!=='EEXIST')throw e;}
  const st=fs.lstatSync(dir);
  if(!st.isDirectory()||st.isSymbolicLink()||(st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid()))throw Error('private_data_permissions');
}
function safeFile(file){
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o077)!==0||(typeof process.getuid==='function'&&st.uid!==process.getuid()))throw Error('private_file_permissions');
  return st;
}
function atomicWrite(file,data){
  const dir=path.dirname(file),temp=`${file}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`;
  safeMkdir(dir);
  const fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,data);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
  fs.renameSync(temp,file);fsyncDir(dir);
}
function verifyRequest(v,{brokerKey,brokerId,adapterId,now}){
  if(!exact(v,REQUEST_KEYS)||v.protocol!==INSTALL_PROTOCOL||v.action!=='INSTALL_MOBILE_M574'||v.brokerId!==brokerId||v.adapterId!==adapterId||
    v.repository!==INSTALL_REPOSITORY||v.commit!==INSTALL_COMMIT||v.packagePath!==INSTALL_PACKAGE_PATH||!UUID.test(v.jobId)||!UUID.test(v.nonce)||
    !SHA.test(v.archiveSha256)||!SHA.test(v.manifestSha256)||!Number.isSafeInteger(v.archiveSize)||v.archiveSize<1||v.archiveSize>MAX_ARCHIVE_BYTES||
    !Number.isSafeInteger(v.issuedAt)||!Number.isSafeInteger(v.expiresAt)||v.issuedAt>now+5_000||v.expiresAt<=now||v.expiresAt<=v.issuedAt||v.expiresAt-v.issuedAt>MAX_TTL_MS||
    typeof v.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(v.signature))throw Error('request_schema_rejected');
  if(!verify(null,requestBytes(v),brokerKey,Buffer.from(v.signature,'base64url')))throw Error('request_signature_rejected');
  return v;
}
export function signInstallRequest(fields,privateKey){
  const value={...fields,signature:''};
  value.signature=sign(null,requestBytes(value),privateKey).toString('base64url');
  return Object.freeze(value);
}
export function signControlRequest(fields,privateKey){const value={...fields,signature:''};value.signature=sign(null,controlBytes(value),privateKey).toString('base64url');return Object.freeze(value);}
function cString(buf){const i=buf.indexOf(0);return buf.subarray(0,i<0?buf.length:i).toString('utf8');}
function octal(buf){const s=buf.toString('ascii').replace(/\0.*$/s,'').trim();if(!s)return 0;if(!/^[0-7]+$/.test(s))throw Error('tar_numeric_invalid');const n=parseInt(s,8);if(!Number.isSafeInteger(n))throw Error('tar_numeric_invalid');return n;}
function safeRel(value){
  if(typeof value!=='string'||!value||value.startsWith('/')||value.includes('\\')||value.includes('\0'))throw Error('tar_path_invalid');
  const parts=value.split('/');
  if(parts.some(p=>!p||p==='.'||p==='..'||!/^[A-Za-z0-9_.@+-]+$/.test(p)))throw Error('tar_path_invalid');
  return parts.join('/');
}
function headerCheck(block){const stored=octal(block.subarray(148,156));const sum=block.reduce((n,b,i)=>n+(i>=148&&i<156?32:b),0);if(sum!==stored)throw Error('tar_checksum_invalid');const magic=block.subarray(257,263).toString('ascii');if(magic!=='ustar\0'&&magic!=='ustar ')throw Error('tar_format_unsupported');}
function parseArchive(archive,request){
  if(!Buffer.isBuffer(archive)||archive.length!==request.archiveSize||archive.length>MAX_ARCHIVE_BYTES||sha(archive)!==request.archiveSha256)throw Error('archive_digest_mismatch');
  let data;try{data=gunzipSync(archive,{maxOutputLength:MAX_EXPANDED_BYTES+512});}catch{throw Error('archive_gzip_invalid');}
  if(data.length>MAX_EXPANDED_BYTES)throw Error('archive_expansion_limit');
  const files=new Map(),directories=new Set();let offset=0,zeroBlocks=0,total=0;
  while(offset+512<=data.length){
    const header=data.subarray(offset,offset+512);offset+=512;
    if(header.every(x=>x===0)){zeroBlocks++;if(zeroBlocks===2)break;continue;}zeroBlocks=0;headerCheck(header);
    const name=cString(header.subarray(0,100)),prefix=cString(header.subarray(345,500));const full=safeRel(prefix?`${prefix}/${name}`:name);
    const type=header[156],size=octal(header.subarray(124,136)),mode=octal(header.subarray(100,108));
    if(offset+size>data.length||size>MAX_EXPANDED_BYTES)throw Error('archive_entry_size_invalid');
    const payload=data.subarray(offset,offset+size);offset+=Math.ceil(size/512)*512;
    if(mode&~0o777||mode&0o022||mode&0o7000)throw Error('archive_permissions_invalid');
    if(type===53)throw Error('archive_directory_entries_rejected');
    if(type!==0&&type!==48)throw Error('archive_link_or_special_file_rejected');
    if(files.has(full)||directories.has(full)||mode!==0o644&&mode!==0o755&&full!==PACKAGE_MANIFEST&&mode!==0o600)throw Error('archive_duplicate_or_mode_invalid');
    total+=size;if(total>MAX_EXPANDED_BYTES||files.size>=MAX_FILES+1)throw Error('archive_limit_exceeded');
    files.set(full,{bytes:Buffer.from(payload),mode,size});
  }
  if(zeroBlocks<2||offset<data.length&&!data.subarray(offset).every(x=>x===0))throw Error('archive_terminator_invalid');
  const manifestEntry=files.get(PACKAGE_MANIFEST);if(!manifestEntry||manifestEntry.mode!==0o600||sha(manifestEntry.bytes)!==request.manifestSha256)throw Error('manifest_digest_mismatch');
  let manifest;try{manifest=JSON.parse(manifestEntry.bytes.toString('utf8'));}catch{throw Error('manifest_json_invalid');}
  if(JSON.stringify(manifest)!==manifestEntry.bytes.toString('utf8')||!exact(manifest,['protocol','repository','commit','packagePath','files'])||manifest.protocol!=='HADES_MOBILE_M574_PACKAGE_V1'||manifest.repository!==INSTALL_REPOSITORY||manifest.commit!==INSTALL_COMMIT||manifest.packagePath!==INSTALL_PACKAGE_PATH||!Array.isArray(manifest.files)||manifest.files.length<1||manifest.files.length>MAX_FILES)throw Error('manifest_schema_rejected');
  const listed=new Map();let last='';
  for(const row of manifest.files){
    if(!exact(row,['path','sha256','size','mode']))throw Error('manifest_entry_invalid');
    const rel=safeRel(row.path);if(rel<=last||listed.has(rel)||!SHA.test(row.sha256)||!Number.isSafeInteger(row.size)||row.size<0||!Number.isInteger(row.mode)||![0o644,0o755].includes(row.mode))throw Error('manifest_entry_invalid');last=rel;listed.set(rel,row);
  }
  const prefix=INSTALL_PACKAGE_PATH+'/';const actual=new Map();
  for(const [name,row] of files){if(name===PACKAGE_MANIFEST)continue;if(!name.startsWith(prefix))throw Error('archive_outside_package_rejected');const rel=safeRel(name.slice(prefix.length));if(!rel)throw Error('archive_path_invalid');actual.set(rel,row);}
  if(actual.size!==listed.size)throw Error('manifest_file_set_mismatch');
  for(const [rel,expected] of listed){const item=actual.get(rel);if(!item||item.size!==expected.size||item.mode!==expected.mode||sha(item.bytes)!==expected.sha256)throw Error('manifest_file_mismatch');}
  return {manifest,files:actual};
}
function hashTree(root,{temporaryPath,temporaryBytes}={}){
  const rows=[];let bytes=0;
  function walk(dir,rel=''){
    const entries=fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name<b.name?-1:a.name>b.name?1:0);
    for(const entry of entries){const name=rel?`${rel}/${entry.name}`:entry.name;safeRel(name);const file=path.join(dir,entry.name),st=fs.lstatSync(file);
      if(file===temporaryPath){if(!temporaryBytes||!st.isFile()||st.isSymbolicLink()||st.nlink!==1||(st.mode&0o777)!==0o644||st.uid!==process.getuid()||st.gid!==process.getgid()||sha(fs.readFileSync(file))!==sha(temporaryBytes))throw Error('promotion_temp_unsafe');continue;}
      if(st.isSymbolicLink()||st.mode&0o022||st.mode&0o7000)throw Error('target_source_unsafe');
      if(st.isDirectory()){walk(file,name);continue;}
      if(st.nlink!==1)throw Error('target_source_unsafe');
      if(!st.isFile()||![0o644,0o755].includes(st.mode&0o777))throw Error('target_source_unsafe');
      bytes+=st.size;if(bytes>MAX_EXPANDED_BYTES||rows.length>=MAX_FILES)throw Error('target_source_limit');
      rows.push({path:name,sha256:sha(fs.readFileSync(file)),size:st.size,mode:st.mode&0o777});
    }
  }
  const rootSt=fs.lstatSync(root);if(!rootSt.isDirectory()||rootSt.isSymbolicLink())throw Error('target_source_missing');walk(root);return rows;
}
function assertAllowedDelta(oldRows,newRows,expected){
  const before=new Map(oldRows.map(r=>[r.path,r])),after=new Map(newRows.map(r=>[r.path,r]));
  const oldDocker=before.get('Dockerfile'),newDocker=after.get('Dockerfile');
  if(!oldDocker||oldDocker.sha256!==expected.old||!newDocker||newDocker.sha256!==expected.candidate||oldDocker.mode!==newDocker.mode)throw Error('baseline_dockerfile_mismatch');
  const paths=new Set([...before.keys(),...after.keys()]);
  for(const rel of paths){
    if(rel==='Dockerfile')continue;
    const a=before.get(rel),b=after.get(rel);
    if(!a||!b||a.sha256!==b.sha256||a.size!==b.size||a.mode!==b.mode)throw Error('non_dockerfile_delta_rejected');
  }
}
function ensureTargetParent(target,allowCustom=false){
  const parent=path.dirname(target);let cur='/';for(const part of parent.split('/').filter(Boolean)){cur=path.join(cur,part);const st=fs.lstatSync(cur);if(!st.isDirectory()||st.isSymbolicLink())throw Error('target_parent_unsafe');}
  if(!allowCustom&&path.resolve(target)!==TARGET_DIR)throw Error('target_path_invalid');
}
function verifyFilesystemProfile(targetDir,profileFile){
  if(sha(fs.readFileSync(profileFile))!==APPARMOR_PROFILE_SHA256)throw Error('apparmor_profile_hash_mismatch');
  fs.readFileSync(path.join(targetDir,'config.yaml'));
  let writable=false;let fd;
  try{fd=fs.openSync(path.join(targetDir,'config.yaml'),fs.constants.O_WRONLY|fs.constants.O_NOFOLLOW);writable=true;}
  catch(e){if(e.code!=='EACCES'&&e.code!=='EPERM')throw Error('apparmor_negative_probe_failed');}
  finally{if(fd!==undefined)fs.closeSync(fd);}
  if(writable)throw Error('apparmor_write_scope_too_broad');
  const probe=path.join(targetDir,`.hades-m574-probe-${randomBytes(8).toString('hex')}.Dockerfile`);
  const probeFd=fs.openSync(probe,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(probeFd,Buffer.from('.'));fs.fsyncSync(probeFd);}finally{fs.closeSync(probeFd);}
  fs.unlinkSync(probe);fsyncDir(targetDir);
}
function writeStage(stage,files){
  fs.mkdirSync(stage,{mode:0o700});
  for(const [rel,item] of [...files.entries()].sort((a,b)=>a[0].localeCompare(b[0],'en'))){
    const out=path.join(stage,...rel.split('/')),parent=path.dirname(out);fs.mkdirSync(parent,{recursive:true,mode:0o755});
    const fd=fs.openSync(out,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,item.mode);
    try{fs.writeFileSync(fd,item.bytes);fs.fsyncSync(fd);fs.fchmodSync(fd,item.mode);}finally{fs.closeSync(fd);}
  }
  const dirs=[];function collect(dir){for(const e of fs.readdirSync(dir,{withFileTypes:true})){if(e.isDirectory())collect(path.join(dir,e.name));}dirs.push(dir);}collect(stage);
  for(const dir of dirs){fs.chmodSync(dir,0o755);fsyncDir(dir);}fsyncDir(path.dirname(stage));
}
function encryptSourceSnapshot(root,file,key){
  const rows=hashTree(root),parts=[];for(const row of rows){const bytes=fs.readFileSync(path.join(root,...row.path.split('/')));parts.push({path:row.path,mode:row.mode,uid:fs.statSync(path.join(root,...row.path.split('/'))).uid,gid:fs.statSync(path.join(root,...row.path.split('/'))).gid,bytes:bytes.toString('base64')});}
  const plain=Buffer.from(JSON.stringify({version:1,rows,files:parts}));const iv=randomBytes(12),cipher=createCipheriv('aes-256-gcm',key,iv);const encrypted=Buffer.concat([cipher.update(plain),cipher.final()]);
  const blob=Buffer.concat([Buffer.from('HADESM575\0'),iv,cipher.getAuthTag(),encrypted]);const fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,blob);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fsyncDir(path.dirname(file));return {rows,sourceSha256:sha(Buffer.from(JSON.stringify(rows)))};
}
function decryptSourceSnapshot(file,key){
  const st=safeFile(file);if(st.size<40||st.size>MAX_EXPANDED_BYTES*3)throw Error('source_snapshot_invalid');const blob=fs.readFileSync(file);
  if(blob.subarray(0,10).toString()!=='HADESM575\0')throw Error('source_snapshot_invalid');const iv=blob.subarray(10,22),tag=blob.subarray(22,38),dec=createDecipheriv('aes-256-gcm',key,iv);dec.setAuthTag(tag);
  let data;try{data=Buffer.concat([dec.update(blob.subarray(38)),dec.final()]);}catch{throw Error('source_snapshot_auth_failed');}
  let snapshot;try{snapshot=JSON.parse(data.toString('utf8'));}catch{throw Error('source_snapshot_invalid');}
  if(snapshot.version!==1||!Array.isArray(snapshot.files)||!Array.isArray(snapshot.rows))throw Error('source_snapshot_invalid');return snapshot;
}
function restoreDockerfileFromSnapshot(targetDir,snapshot){
  const row=snapshot.files.find(x=>x.path==='Dockerfile');if(!row||!snapshot.rows.some(x=>x.path==='Dockerfile'&&x.sha256===sha(Buffer.from(row.bytes,'base64'))&&x.mode===row.mode))throw Error('source_snapshot_dockerfile_invalid');
  const bytes=Buffer.from(row.bytes,'base64'),temp=path.join(targetDir,`.hades-m574-recovery-${randomBytes(8).toString('hex')}.Dockerfile`),dest=path.join(targetDir,'Dockerfile');
  const fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,row.mode);try{fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.fchmodSync(fd,row.mode);}finally{fs.closeSync(fd);}
  fs.renameSync(temp,dest);fsyncDir(targetDir);const rows=hashTree(targetDir);if(JSON.stringify(rows)!==JSON.stringify(snapshot.rows))throw Error('source_snapshot_restore_mismatch');
}
function readState(file){try{safeFile(file);const value=JSON.parse(fs.readFileSync(file,'utf8'));if(value.version!==1||!Array.isArray(value.jobs)||value.jobs.length>64)throw Error();return value;}catch(e){if(e.code==='ENOENT')return {version:1,jobs:[]};throw Error('journal_unavailable');}}
function persistState(file,state){atomicWrite(file,JSON.stringify(state));}
function newResponse(fields,key){const v={protocol:fields.protocol||INSTALL_PROTOCOL,adapterId:fields.adapterId,jobId:fields.jobId,nonce:fields.nonce,issuedAt:fields.now,expiresAt:fields.expiresAt,state:fields.state,targetSlug:TARGET_SLUG,commit:INSTALL_COMMIT,archiveSha256:fields.archiveSha256||'',backupSlug:fields.backupSlug||'',sourceSha256:fields.sourceSha256||'',errorCode:fields.errorCode||'',signature:''};v.signature=sign(null,responseBytes(v),key).toString('base64url');return Object.freeze(v);}

export function createSupervisorClient({token,fetchImpl=fetch,base='http://supervisor',timeoutMs=20*60_000}={}){
  if(typeof token!=='string'||token.length<16)throw Error('supervisor_token_missing');
  async function request(method,urlPath,body){
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeoutMs);let response,text;
    try{
      response=await fetchImpl(base+urlPath,{method,redirect:'error',signal:controller.signal,headers:{authorization:`Bearer ${token}`,'content-type':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
      if(!response.body)text='';else{
        const reader=response.body.getReader(),chunks=[];let size=0;
        while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>1024*1024){await reader.cancel();throw Error('supervisor_response_too_large');}chunks.push(Buffer.from(value));}
        text=Buffer.concat(chunks).toString('utf8');
      }
    }
    catch{throw Object.assign(Error('supervisor_outcome_unknown'),{code:'SUPERVISOR_OUTCOME_UNKNOWN'});}finally{clearTimeout(timer);}
    let envelope={};if(text){try{envelope=JSON.parse(text);}catch{throw Error('supervisor_response_invalid');}}
    if(!response.ok||envelope.result!=='ok'||!Object.hasOwn(envelope,'data'))throw Object.assign(Error('supervisor_request_failed'),{code:`SUPERVISOR_HTTP_${response.status||0}`,status:response.status||0});
    return envelope.data;
  }
  function childJobsSuccessful(job){if(!job||typeof job!=='object'||job.done!==true||Array.isArray(job.errors)&&job.errors.length>0)return false;const children=job.child_jobs??[];return Array.isArray(children)&&children.every(childJobsSuccessful);}
  function hasActiveTargetJob(job,inheritedTarget=false){
    if(!job||typeof job!=='object'||typeof job.done!=='boolean')throw Error('jobs_info_invalid');
    const children=job.child_jobs??[];if(!Array.isArray(children))throw Error('jobs_info_invalid');
    const referencesTarget=inheritedTarget||job.reference===TARGET_SLUG||job.slug===TARGET_SLUG||job.addon===TARGET_SLUG;
    if(!job.done&&referencesTarget)return true;
    return children.some(child=>hasActiveTargetJob(child,referencesTarget));
  }
  return Object.freeze({
    async preflight(){const info=await request('GET','/supervisor/info');const v=info.version;if(!SUPPORTED_SUPERVISOR_VERSIONS.includes(v))throw Object.assign(Error('supervisor_version_unsupported'),{supervisorVersion:typeof v==='string'?v:'unknown'});const apps=await request('GET','/addons');const rows=apps.addons;if(!Array.isArray(rows))throw Error('supervisor_apps_response_invalid');const target=rows.find(x=>x?.slug===TARGET_SLUG);if(!target||target.build!==true||target.version!=='0.5.71-dev.m5.71'||target.version_latest!=='0.5.71-dev.m5.71'||target.installed===false)throw Error('target_app_preflight_rejected');return Object.freeze({supervisorVersion:v,appVersion:target.version});},
    async createBackup(password,onStarted=()=>{}){const result=await request('POST','/backups/new/partial',{name:'HADES M575 Mobile source hotfix',password,homeassistant:false,addons:[TARGET_SLUG],folders:[],compressed:true,location:null,background:true});if(typeof result.job_id!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(result.job_id))throw Error('backup_job_missing');onStarted({jobId:result.job_id});let doneJob;const deadline=Date.now()+timeoutMs;while(Date.now()<deadline){const job=await request('GET',`/jobs/${encodeURIComponent(result.job_id)}`);if(job.done===true){if(!childJobsSuccessful(job))throw Error('backup_job_failed');doneJob=job;break;}await new Promise(r=>setTimeout(r,1000));}if(!doneJob)throw Object.assign(Error('backup_outcome_unknown'),{code:'BACKUP_OUTCOME_UNKNOWN'});const backupSlug=doneJob.reference;if(typeof backupSlug!=='string'||!/^[A-Za-z0-9_-]{1,128}$/.test(backupSlug))throw Error('backup_job_reference_invalid');const info=await request('GET',`/backups/${encodeURIComponent(backupSlug)}/info`);const appRows=info.addons;if(info.protected!==true||info.type!=='partial'||info.homeassistant!==undefined&&info.homeassistant!==null&&info.homeassistant!==false||!Array.isArray(appRows)||appRows.length!==1||appRows[0]?.slug!==TARGET_SLUG||!Array.isArray(info.folders)||info.folders.length!==0)throw Error('backup_scope_unverified');return backupSlug;},
    async rebuild(){return request('POST',`/addons/${TARGET_SLUG}/rebuild`,{force:false});},
    async targetBuildRunning(){const info=await request('GET','/jobs/info');if(!info||!Array.isArray(info.jobs))throw Error('jobs_info_invalid');return info.jobs.some(job=>hasActiveTargetJob(job));}
  });
}

export function createMobileInstaller({enabled=false,brokerId,trustedBrokerPublicKey,privateDir='/data/hades-m574-installer',targetDir=TARGET_DIR,supervisor,clock=Date.now,buildTimeoutMs=20*60_000,profileFile='/opt/hades-m574-installer/apparmor.txt',profileReader=()=>fs.readFileSync('/proc/self/attr/current','utf8').trim(),filesystemProfileProbe=verifyFilesystemProfile,testOnlyAllowTargetOverride=false,testOnlyExpectedDockerfileHashes}={}){
  if(enabled!==true)throw Error('installer_disabled');if(targetDir!==TARGET_DIR&&testOnlyAllowTargetOverride!==true)throw Error('target_path_not_fixed');
  const expectedDockerfiles=testOnlyAllowTargetOverride&&testOnlyExpectedDockerfileHashes?testOnlyExpectedDockerfileHashes:{old:DOCKERFILE_OLD_SHA256,candidate:DOCKERFILE_M574_SHA256};
  if(!SHA.test(expectedDockerfiles.old)||!SHA.test(expectedDockerfiles.candidate))throw Error('test_fixture_hashes_invalid');
  let profile;try{profile=profileReader();}catch{throw Error('apparmor_enforcement_unavailable');}
  if(profile!==APPARMOR_PROFILE_NAME+' (enforce)')throw Error('apparmor_profile_not_enforcing');
  const brokerKey=keyFrom(trustedBrokerPublicKey);if(fingerprint(brokerKey)!==brokerId)throw Error('broker_identity_mismatch');
  safeMkdir(privateDir);const keyFile=path.join(privateDir,'adapter-ed25519.pem'),backupKeyFile=path.join(privateDir,'mobile-backup-key.bin');
  let privateKey;
  try{safeFile(keyFile);privateKey=createPrivateKey(fs.readFileSync(keyFile));}catch(e){if(e.code!=='ENOENT')throw e;const pair=generateKeyPairSync('ed25519');const pem=pair.privateKey.export({type:'pkcs8',format:'pem'});const fd=fs.openSync(keyFile,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,pem);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fsyncDir(privateDir);privateKey=pair.privateKey;}
  let backupKey;
  try{safeFile(backupKeyFile);backupKey=fs.readFileSync(backupKeyFile);if(backupKey.length!==32)throw Error('backup_key_invalid');}catch(e){if(e.code!=='ENOENT')throw e;backupKey=randomBytes(32);const fd=fs.openSync(backupKeyFile,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,backupKey);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fsyncDir(privateDir);}
  const adapterId=fingerprint(createPublicKey(privateKey)),journalFile=path.join(privateDir,'journal.json'),sourceBackupDir=path.join(privateDir,'source-backups');safeMkdir(sourceBackupDir);const state=readState(journalFile);
  let interrupted=false;for(const job of state.jobs){if(ACTIVE_STATES.has(job.state)&&job.state!=='UNKNOWN'){job.interruptedState=job.state;job.state='UNKNOWN';job.errorCode='INTERRUPTED_STATE';interrupted=true;}}
  if(interrupted)persistState(journalFile,state);
  let locked=false;const waiters=[];async function acquire(){if(locked)await new Promise(resolve=>waiters.push(resolve));locked=true;}function release(){locked=false;waiters.shift()?.();}
  function signState(job,fields={}){const now=clock();return newResponse({adapterId,jobId:job.jobId,nonce:job.nonce,now,expiresAt:now+MAX_TTL_MS,state:job.state,archiveSha256:job.archiveSha256,backupSlug:job.backupSlug,sourceSha256:job.sourceSha256,errorCode:job.errorCode,...fields},privateKey);}
  function persist(){persistState(journalFile,state);}
  function ensureNoOutstanding(except){if(state.jobs.some(j=>j!==except&&ACTIVE_STATES.has(j.state)))throw Error('reconciliation_required');}
  async function install(envelope,archive){await acquire();let authorizedJob;try{
    const request=verifyRequest(envelope,{brokerKey,brokerId,adapterId,now:clock()});const existing=state.jobs.find(j=>j.jobId===request.jobId);
    if(existing){if(existing.requestDigest!==sha(requestBytes(request)))throw Error('replay_conflict');return existing.response||signState(existing);}
    if(state.jobs.some(j=>j.nonce===request.nonce))throw Error('replay_conflict');if(state.jobs.length>=64)throw Error('journal_full');
    const now=clock(),job={jobId:request.jobId,nonce:request.nonce,expiresAt:request.expiresAt,requestDigest:sha(requestBytes(request)),archiveSha256:request.archiveSha256,state:'RECEIVED',backupSlug:'',sourceSha256:'',errorCode:'',createdAt:now,response:null,reconciliations:[]};
    state.jobs.push(job);authorizedJob=job;persist();ensureNoOutstanding(job);
    const parsed=parseArchive(archive,request);ensureTargetParent(targetDir,testOnlyAllowTargetOverride);filesystemProfileProbe(targetDir,profileFile);const before=hashTree(targetDir);const candidate=[...parsed.files].map(([rel,x])=>({path:rel,sha256:sha(x.bytes),size:x.size,mode:x.mode})).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);assertAllowedDelta(before,candidate,expectedDockerfiles);job.state='VALIDATED';job.sourceSha256=sha(Buffer.from(JSON.stringify(before)));persist();
    const preflight=await supervisor.preflight();job.supervisorVersion=preflight.supervisorVersion;persist();if(preflight.appVersion!=='0.5.71-dev.m5.71')throw Error('target_version_unexpected');
    if(await supervisor.targetBuildRunning())throw Error('target_build_already_running');
    job.state='BACKUP_PENDING';persist();const backupPassword=backupKey.toString('base64url');job.backupSlug=await supervisor.createBackup(backupPassword,started=>{job.backupJobId=started.jobId;if(typeof started.slug==='string')job.backupSlug=started.slug;persist();});job.state='BACKUP_READY';persist();
    const sourceSnapshot=path.join(sourceBackupDir,`${request.jobId}.source.enc`);const saved=encryptSourceSnapshot(targetDir,sourceSnapshot,backupKey);job.sourceBackupFile=sourceSnapshot;persist();
    if(saved.sourceSha256!==job.sourceSha256)throw Error('source_changed_during_backup');
    const stageRoot=path.join(privateDir,'staging');safeMkdir(stageRoot);const stage=path.join(stageRoot,request.jobId);
    if(fs.existsSync(stage))throw Error('transaction_path_collision');writeStage(stage,parsed.files);job.state='STAGE_READY';persist();
    const afterBackup=hashTree(targetDir);if(JSON.stringify(afterBackup)!==JSON.stringify(before))throw Error('target_source_changed');
    if(await supervisor.targetBuildRunning())throw Error('target_build_already_running');
    const candidateDockerfile=fs.readFileSync(path.join(stage,'Dockerfile'));
    const targetDockerfile=path.join(targetDir,'Dockerfile'),tempDockerfile=path.join(targetDir,`.hades-m574-${request.jobId}.Dockerfile`);
    const oldStat=fs.lstatSync(targetDockerfile);if(sha(fs.readFileSync(targetDockerfile))!==expectedDockerfiles.old||oldStat.uid!==process.getuid()||oldStat.gid!==process.getgid()||fs.existsSync(tempDockerfile))throw Error('target_dockerfile_changed');
    const tempFd=fs.openSync(tempDockerfile,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o644);
    try{fs.writeFileSync(tempFd,candidateDockerfile);fs.fsyncSync(tempFd);fs.fchmodSync(tempFd,0o644);}finally{fs.closeSync(tempFd);}
    fsyncDir(targetDir);job.state='PROMOTION_PREPARED';persist();
    if(JSON.stringify(hashTree(targetDir,{temporaryPath:tempDockerfile,temporaryBytes:candidateDockerfile}))!==JSON.stringify(before)){job.state='UNKNOWN';job.errorCode='TARGET_CHANGED_AT_PROMOTION';persist();throw Error('target_source_changed');}
    try{fs.renameSync(tempDockerfile,targetDockerfile);fsyncDir(targetDir);job.state='SOURCE_PROMOTED';persist();}
    catch(e){job.state='UNKNOWN';job.errorCode='PROMOTION_UNKNOWN';persist();throw e;}
    job.state='BUILDING';persist();
    let buildTimer;try{await Promise.race([supervisor.rebuild(),new Promise((_,reject)=>{buildTimer=setTimeout(()=>reject(Object.assign(Error('rebuild_timeout'),{code:'BUILD_OUTCOME_UNKNOWN'})),buildTimeoutMs);})]);}
    catch(error){if(error.code==='BUILD_OUTCOME_UNKNOWN'||error.code==='SUPERVISOR_OUTCOME_UNKNOWN'){job.state='UNKNOWN';job.errorCode='BUILD_OUTCOME_UNKNOWN';persist();job.response=signState(job);return job.response;}
      let running=true;try{running=await supervisor.targetBuildRunning();}catch{running=true;}
      if(running){job.state='UNKNOWN';job.errorCode='BUILD_OUTCOME_UNKNOWN';persist();job.response=signState(job);return job.response;}
      job.state='BUILD_FAILED';job.errorCode='BUILD_FAILED_CONFIRMED';persist();
      const snap=decryptSourceSnapshot(sourceSnapshot,backupKey);restoreDockerfileFromSnapshot(targetDir,snap);job.state='ROLLBACK_SOURCE_RESTORED';persist();
      try{await supervisor.rebuild();job.state='ROLLED_BACK';job.errorCode='BUILD_FAILED_ROLLED_BACK';}catch(rollbackError){job.state='UNKNOWN';job.errorCode=rollbackError.code==='SUPERVISOR_OUTCOME_UNKNOWN'?'ROLLBACK_BUILD_OUTCOME_UNKNOWN':'ROLLBACK_BUILD_FAILED';}
      persist();job.response=signState(job);return job.response;
    }finally{clearTimeout(buildTimer);}
    job.state='COMPLETED';job.errorCode='';persist();job.response=signState(job);persist();
    try{fs.rmSync(stage,{recursive:true,force:false});fsyncDir(stageRoot);}catch{job.state='COMPLETED_WITH_STAGE_RETAINED';persist();job.response=signState(job);persist();}
    return job.response;
  }catch(error){
    // Never expose Supervisor response bodies, paths, or exception messages.
    const code=/^[A-Z0-9_]+$/.test(error.code||'')?error.code:({backup_job_failed:'BACKUP_FAILED',backup_scope_unverified:'BACKUP_SCOPE_INVALID',supervisor_version_unsupported:'SUPERVISOR_VERSION_UNSUPPORTED',target_app_preflight_rejected:'TARGET_PREFLIGHT_FAILED',non_dockerfile_delta_rejected:'SOURCE_DELTA_REJECTED',baseline_dockerfile_mismatch:'BASELINE_MISMATCH',source_changed_during_backup:'SOURCE_CHANGED',target_source_changed:'TARGET_SOURCE_CHANGED'}[error.message]||'INSTALL_REJECTED');
    const job=authorizedJob;if(job&&typeof error.supervisorVersion==='string'){job.supervisorVersion=error.supervisorVersion;persist();}
    if(job){if(['UNKNOWN','BACKUP_PENDING','BUILDING','BUILD_FAILED','SOURCE_PROMOTED','PROMOTION_PREPARED','ROLLBACK_SOURCE_RESTORED','RECONCILING','ROLLBACK_BUILDING'].includes(job.state)){job.state='UNKNOWN';job.errorCode=job.errorCode||code;}else{job.state='REJECTED';job.errorCode=code;}persist();job.response=signState(job);persist();return job.response;}
    throw Error(code);
  }finally{release();}}
  function verifyControl(v,action,needsDecision=false){
    const expected=['protocol','action','brokerId','adapterId','jobId','nonce','issuedAt','expiresAt',...(needsDecision?['decision','reviewId']:[]),'signature'];
    if(!exact(v,expected)||v.protocol!==INSTALL_PROTOCOL||v.action!==action||v.brokerId!==brokerId||v.adapterId!==adapterId||!UUID.test(v.jobId)||!UUID.test(v.nonce)||
      !Number.isSafeInteger(v.issuedAt)||!Number.isSafeInteger(v.expiresAt)||v.issuedAt>clock()+5_000||v.expiresAt<=clock()||v.expiresAt<=v.issuedAt||v.expiresAt-v.issuedAt>MAX_TTL_MS||
      needsDecision&&(!['KEEP_CANDIDATE','ROLLBACK_SOURCE','ABORT_NO_SOURCE_CHANGE'].includes(v.decision)||!UUID.test(v.reviewId))||typeof v.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(v.signature)||
      !verify(null,controlBytes(v),brokerKey,Buffer.from(v.signature,'base64url')))throw Error('control_request_rejected');return v;
  }
  function statusSigned(envelope){const request=verifyControl(envelope,'STATUS_MOBILE_INSTALL');const job=state.jobs.find(j=>j.jobId===request.jobId);return newResponse({adapterId,jobId:request.jobId,nonce:request.nonce,now:clock(),expiresAt:request.expiresAt,state:job?.state||'NOT_FOUND',archiveSha256:job?.archiveSha256||'',backupSlug:job?.backupSlug||'',sourceSha256:job?.sourceSha256||'',errorCode:job?.errorCode||''},privateKey);}
  async function reconcile(envelope){await acquire();let request,job;try{
    request=verifyControl(envelope,'RECONCILE_MOBILE_INSTALL',true);job=state.jobs.find(j=>j.jobId===request.jobId);
    const reply=(stateValue,errorCode='')=>newResponse({adapterId,jobId:request.jobId,nonce:request.nonce,now:clock(),expiresAt:request.expiresAt,state:stateValue,targetSlug:TARGET_SLUG,commit:INSTALL_COMMIT,archiveSha256:job?.archiveSha256||'',backupSlug:job?.backupSlug||'',sourceSha256:job?.sourceSha256||'',errorCode},privateKey);
    if(!job||job.state!=='UNKNOWN')return reply(job?.state||'NOT_FOUND','RECONCILIATION_NOT_AVAILABLE');
    const digest=sha(controlBytes(request));const prior=job.reconciliations.find(x=>x.nonce===request.nonce);if(prior){if(prior.digest!==digest)return reply(job.state,'REPLAY_CONFLICT');return prior.response||reply(job.state,'RECONCILIATION_PENDING');}
    if(job.reconciliations.length>=8||state.jobs.some(other=>other!==job&&other.nonce===request.nonce))return reply(job.state,'REPLAY_CONFLICT');
    let running;try{running=await supervisor.targetBuildRunning();}catch{return reply(job.state,'SUPERVISOR_STATUS_UNKNOWN');}
    if(running)return reply(job.state,'BUILD_STILL_RUNNING');
    const rec={nonce:request.nonce,digest,decision:request.decision,reviewId:request.reviewId,response:null};job.reconciliations.push(rec);job.state='RECONCILING';persist();
    try{
      if(request.decision==='ABORT_NO_SOURCE_CHANGE'){
        if(!job.sourceSha256||sha(Buffer.from(JSON.stringify(hashTree(targetDir))))!==job.sourceSha256)throw Error('reconciliation_target_changed');
        job.state='ABORTED_RECONCILED';job.errorCode='';
      }else if(request.decision==='KEEP_CANDIDATE'){
        if(!job.sourceBackupFile)throw Error('reconciliation_source_backup_missing');
        const snapshot=decryptSourceSnapshot(job.sourceBackupFile,backupKey),current=hashTree(targetDir);assertAllowedDelta(snapshot.rows,current,expectedDockerfiles);
        if(current.find(x=>x.path==='Dockerfile')?.sha256!==expectedDockerfiles.candidate)throw Error('reconciliation_target_changed');job.state='COMPLETED_RECONCILED';job.errorCode='';
      }else{
        if(!job.sourceBackupFile)throw Error('reconciliation_source_backup_missing');
        const snapshot=decryptSourceSnapshot(job.sourceBackupFile,backupKey),current=hashTree(targetDir),docker=current.find(x=>x.path==='Dockerfile');
        if(!docker||docker.sha256!==expectedDockerfiles.candidate)throw Error('reconciliation_target_changed');
        restoreDockerfileFromSnapshot(targetDir,snapshot);job.state='ROLLBACK_BUILDING';persist();
        let rollbackTimer;try{await Promise.race([supervisor.rebuild(),new Promise((_,reject)=>{rollbackTimer=setTimeout(()=>reject(Object.assign(Error('rollback_timeout'),{code:'BUILD_OUTCOME_UNKNOWN'})),buildTimeoutMs);})]);}finally{clearTimeout(rollbackTimer);}
        job.state='ROLLED_BACK_RECONCILED';job.errorCode='';
      }
    }catch(error){job.state='UNKNOWN';job.errorCode=error.code==='SUPERVISOR_OUTCOME_UNKNOWN'||error.code==='BUILD_OUTCOME_UNKNOWN'?'ROLLBACK_BUILD_OUTCOME_UNKNOWN':'RECONCILIATION_FAILED';}
    const completedAt=clock();rec.response=newResponse({adapterId,jobId:job.jobId,nonce:request.nonce,now:completedAt,expiresAt:completedAt+MAX_TTL_MS,state:job.state,targetSlug:TARGET_SLUG,commit:INSTALL_COMMIT,archiveSha256:job.archiveSha256,backupSlug:job.backupSlug,sourceSha256:job.sourceSha256,errorCode:job.errorCode||''},privateKey);job.response=signState(job);persist();return rec.response;
  }catch(error){
    if(request){if(job?.state==='RECONCILING'){job.state='UNKNOWN';job.errorCode='RECONCILIATION_FAILED';job.response=signState(job);persist();}return newResponse({adapterId,jobId:request.jobId,nonce:request.nonce,now:clock(),expiresAt:request.expiresAt,state:job?.state||'NOT_FOUND',targetSlug:TARGET_SLUG,commit:INSTALL_COMMIT,archiveSha256:job?.archiveSha256||'',backupSlug:job?.backupSlug||'',sourceSha256:job?.sourceSha256||'',errorCode:'RECONCILIATION_FAILED'},privateKey);}
    throw Error('control_request_rejected');
  }finally{release();}}
  return Object.freeze({adapterId,publicKey:createPublicKey(privateKey).export({type:'spki',format:'der'}).toString('base64'),install,statusSigned,reconcile,snapshot:()=>Object.freeze({jobs:state.jobs.map(j=>({jobId:j.jobId,state:j.state,errorCode:j.errorCode||''})),reconciliationRequired:state.jobs.some(j=>ACTIVE_STATES.has(j.state))})});
}
