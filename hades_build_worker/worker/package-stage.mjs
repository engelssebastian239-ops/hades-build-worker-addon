import fs from 'node:fs';
import path from 'node:path';
import {createHash, createPublicKey, sign, verify} from 'node:crypto';
import {gunzipSync} from 'node:zlib';

export const PACKAGE_STAGE_VERSION = 'HADES_PACKAGE_STAGE_V1';
export const PACKAGE_STAGE_ACTION = 'PACKAGE_STAGE';
export const PACKAGE_STAGE_TTL_MS = 900_000;
export const MAX_ARCHIVE_BYTES = 8 * 1024 * 1024;
export const MAX_EXPANDED_BYTES = 16 * 1024 * 1024;
export const MAX_FILES = 256;
export const ALLOWED_PACKAGES = Object.freeze({
  'engelssebastian239-ops/hades-hermes-queue': Object.freeze([
    'hades-m2-local-app/hades_m2_mobile'
  ])
});

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256 = /^[a-f0-9]{64}$/;
const COMMIT = /^[a-f0-9]{40}$/;
const FINGERPRINT = /^sha256:[a-f0-9]{64}$/;
const REQUEST_KEYS = ['version','action','brokerId','workerId','taskId','jobId','nonce','issuedAt','expiresAt','repository','commit','packagePath','archiveSha256','archiveSize','signature'];
const RESPONSE_KEYS = ['version','brokerId','workerId','taskId','jobId','nonce','issuedAt','expiresAt','state','packageSha256','fileCount','byteCount','stageId','signature'];

function exact(value, keys) {
  return !!value && Object.getPrototypeOf(value) === Object.prototype &&
    Object.keys(value).sort().join(',') === [...keys].sort().join(',');
}
function publicKeyOf(key) { return key?.type === 'public' ? key : createPublicKey(key); }
export function packageStageIdentity(publicKey) {
  return 'sha256:' + createHash('sha256').update(publicKeyOf(publicKey).export({type:'spki',format:'der'})).digest('hex');
}
function requestBytes(v) {
  return Buffer.from(JSON.stringify([v.version,v.action,v.brokerId,v.workerId,v.taskId,v.jobId,v.nonce,
    v.issuedAt,v.expiresAt,v.repository,v.commit,v.packagePath,v.archiveSha256,v.archiveSize]));
}
function responseBytes(v) {
  return Buffer.from(JSON.stringify([v.version,v.brokerId,v.workerId,v.taskId,v.jobId,v.nonce,
    v.issuedAt,v.expiresAt,v.state,v.packageSha256,v.fileCount,v.byteCount,v.stageId]));
}
function checkRequest(v, now) {
  if (!exact(v, REQUEST_KEYS) || v.version !== PACKAGE_STAGE_VERSION || v.action !== PACKAGE_STAGE_ACTION ||
      !FINGERPRINT.test(v.brokerId) || !FINGERPRINT.test(v.workerId) || !UUID.test(v.taskId) ||
      !UUID.test(v.jobId) || !UUID.test(v.nonce) || !COMMIT.test(v.commit) || !SHA256.test(v.archiveSha256) ||
      !Number.isSafeInteger(v.archiveSize) || v.archiveSize < 1 || v.archiveSize > MAX_ARCHIVE_BYTES ||
      typeof v.repository !== 'string' || !Object.hasOwn(ALLOWED_PACKAGES, v.repository) ||
      !ALLOWED_PACKAGES[v.repository].includes(v.packagePath)) throw Error('package_stage_schema_rejected');
  if (!Number.isSafeInteger(v.issuedAt) || !Number.isSafeInteger(v.expiresAt) || v.issuedAt > now + 5000 ||
      v.expiresAt <= now || v.expiresAt <= v.issuedAt || v.expiresAt - v.issuedAt > PACKAGE_STAGE_TTL_MS)
    throw Error('package_stage_expired');
  if (typeof v.signature !== 'string' || !/^[A-Za-z0-9_-]{86}$/.test(v.signature)) throw Error('package_stage_signature_invalid');
  return v;
}
export function signPackageStageRequest(fields, privateKey) {
  const value = {...fields, signature:''};
  value.signature = sign(null, requestBytes(value), privateKey).toString('base64url');
  checkRequest(value, fields.issuedAt);
  return Object.freeze(value);
}

function octal(field) {
  const s = field.toString('ascii').replace(/\0.*$/s, '').trim();
  if (!s) return 0;
  if (!/^[0-7]+$/.test(s)) throw Error('tar_numeric_field_invalid');
  const n = Number.parseInt(s, 8);
  if (!Number.isSafeInteger(n)) throw Error('tar_numeric_field_invalid');
  return n;
}
function cString(field) { const i = field.indexOf(0); return field.subarray(0, i < 0 ? field.length : i).toString('utf8'); }
function assertSafeRelPath(value) {
  if (!value || value.startsWith('/') || value.includes('\\') || value.includes('\0')) throw Error('tar_path_invalid');
  const parts = value.split('/');
  if (parts.some(p => !p || p === '.' || p === '..') || !/^[A-Za-z0-9_.@+-]+$/.test(parts.join('/').replaceAll('/','')) && parts.some(p=>! /^[A-Za-z0-9_.@+-]+$/.test(p)))
    throw Error('tar_path_invalid');
  return parts.join('/');
}
function verifyTarHeader(block) {
  const stored = octal(block.subarray(148,156));
  const sum = block.reduce((n,b,i)=>n+(i>=148&&i<156?32:b),0);
  if (stored !== sum) throw Error('tar_checksum_invalid');
  const magic = block.subarray(257,263).toString('ascii');
  if (magic !== 'ustar\0' && magic !== 'ustar ') throw Error('tar_format_unsupported');
}
function ensureDir(root, rel) {
  let current = root;
  for (const part of rel.split('/').filter(Boolean)) {
    current = path.join(current, part);
    try { fs.mkdirSync(current, {mode:0o700}); }
    catch (e) { if (e.code !== 'EEXIST') throw e; }
    const st = fs.lstatSync(current);
    if (!st.isDirectory() || st.isSymbolicLink() || st.uid !== process.getuid()) throw Error('stage_path_unsafe');
  }
}
function safeWrite(root, rel, bytes) {
  const parent = path.posix.dirname(rel);
  if (parent !== '.') ensureDir(root, parent);
  const out = path.join(root, ...rel.split('/'));
  const fd = fs.openSync(out, fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}

export function extractPackageTarGz(archive, {packagePath, destination, maxExpandedBytes=MAX_EXPANDED_BYTES, maxFiles=MAX_FILES}={}) {
  if (!Buffer.isBuffer(archive) || archive.length < 20 || archive.length > MAX_ARCHIVE_BYTES) throw Error('archive_size_rejected');
  const expanded = gunzipSync(archive, {maxOutputLength:maxExpandedBytes + 512});
  if (expanded.length > maxExpandedBytes) throw Error('archive_expansion_limit');
  const root = path.resolve(destination);
  const rootStat = fs.lstatSync(root);
  if (!rootStat.isDirectory() || rootStat.isSymbolicLink() || rootStat.uid !== process.getuid() || (rootStat.mode&0o077)!==0)
    throw Error('stage_root_unsafe');
  let offset=0, count=0, bytes=0, zeros=0;
  const seen=new Set(), files=[];
  while (offset + 512 <= expanded.length) {
    const header=expanded.subarray(offset,offset+512); offset+=512;
    if (header.every(b=>b===0)) { zeros++; if(zeros===2) break; continue; }
    zeros=0; verifyTarHeader(header);
    const name=cString(header.subarray(0,100)), prefix=cString(header.subarray(345,500));
    const full=assertSafeRelPath(prefix ? `${prefix}/${name}` : name);
    const type=header[156];
    if (type!==0 && type!==48 && type!==53) throw Error('tar_link_or_special_file_rejected');
    const size=octal(header.subarray(124,136));
    if (size > maxExpandedBytes || offset+size > expanded.length) throw Error('tar_entry_size_rejected');
    const data=expanded.subarray(offset,offset+size);
    offset += Math.ceil(size/512)*512;
    if (full.split('/').some(p=>p==='..')) throw Error('tar_path_invalid');
    const parts=full.split('/'), packageParts=packagePath.split('/');
    if(parts.length<packageParts.length+1||!packageParts.every((part,i)=>parts[i+1]===part)) continue;
    const rel=parts.slice(packageParts.length+1).join('/');
    if(!rel) continue;
    if(type===53) { assertSafeRelPath(rel); ensureDir(root,rel); continue; }
    assertSafeRelPath(rel);
    if(seen.has(rel)) throw Error('tar_duplicate_path');
    seen.add(rel); count++; bytes+=size;
    if(count>maxFiles||bytes>maxExpandedBytes) throw Error('package_limits_exceeded');
    safeWrite(root,rel,data);
    files.push({path:rel,size,sha256:createHash('sha256').update(data).digest('hex')});
  }
  if(offset<expanded.length&&!expanded.subarray(offset).every(b=>b===0)) throw Error('tar_trailing_data_rejected');
  if (!zeros || count===0) throw Error('package_contents_missing');
  return Object.freeze({fileCount:count,byteCount:bytes,files:Object.freeze(files)});
}

function readLedger(file) {
  try {
    const st=fs.lstatSync(file);
    if(!st.isFile()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)!==0) throw Error('ledger_permissions');
    const v=JSON.parse(fs.readFileSync(file,'utf8'));
    if(v?.version!==1||!Array.isArray(v.entries)||v.entries.length>2048) throw Error('ledger_invalid');
    return new Map(v.entries);
  } catch(e) { if(e.code==='ENOENT') return new Map(); throw Error('package_stage_ledger_unavailable'); }
}
function persistLedger(file, ledger) {
  const dir=path.dirname(file); const st=fs.lstatSync(dir);
  if(!st.isDirectory()||st.isSymbolicLink()||st.uid!==process.getuid()||(st.mode&0o077)!==0) throw Error('ledger_directory_unsafe');
  const temp=file+'.tmp-'+process.pid;
  fs.writeFileSync(temp,JSON.stringify({version:1,entries:[...ledger]}),{flag:'wx',mode:0o600});
  fs.renameSync(temp,file);
}

export function createPackageStageReceiver({enabled=false,brokerId,trustedBrokerPublicKey,workerPrivateKey,stageRoot,ledgerPath,clock=Date.now}={}) {
  if(enabled!==true) throw Error('package_stage_disabled');
  const brokerKey=publicKeyOf(trustedBrokerPublicKey);
  const workerId=packageStageIdentity(createPublicKey(workerPrivateKey));
  if(packageStageIdentity(brokerKey)!==brokerId) throw Error('package_stage_broker_identity_mismatch');
  const root=path.resolve(stageRoot), rootStat=fs.lstatSync(root);
  if(!rootStat.isDirectory()||rootStat.isSymbolicLink()||rootStat.uid!==process.getuid()||(rootStat.mode&0o077)!==0) throw Error('stage_root_unsafe');
  const ledger=readLedger(ledgerPath);
  const ownedDirectory=dir=>{try{const st=fs.lstatSync(dir);return st.isDirectory()&&!st.isSymbolicLink()&&st.uid===process.getuid()&&(st.mode&0o077)===0;}catch{return false;}};
  return Object.freeze({
    workerId,
    stage(request, archive) {
      const now=clock(), v=checkRequest(request,now);
      if(v.brokerId!==brokerId||v.workerId!==workerId||!verify(null,requestBytes(v),brokerKey,Buffer.from(v.signature,'base64url'))) throw Error('package_stage_signature_rejected');
      if(!Buffer.isBuffer(archive)||archive.length!==v.archiveSize||createHash('sha256').update(archive).digest('hex')!==v.archiveSha256) throw Error('package_stage_digest_mismatch');
      const id=`${v.commit}-${v.taskId}`;
      const key=[v.brokerId,v.taskId,v.jobId,v.nonce].join(':');
      const digest=createHash('sha256').update(requestBytes(v)).digest('hex');
      const prior=ledger.get(key);
      const target=path.join(root,id),pending=path.join(root,'.'+id+'.pending');
      if(prior) {
        if(prior.digest!==digest) throw Error('package_stage_replay_conflict');
        if(prior.state==='PREPARED'){
          if(ownedDirectory(target)){}
          else if(ownedDirectory(pending))fs.renameSync(pending,target);
          else throw Error('package_stage_recovery_missing');
          prior.state='STAGED';persistLedger(ledgerPath,ledger);
        }
        if(prior.state==='STAGED'&&!ownedDirectory(target))throw Error('package_stage_recovery_missing');
        return prior.response;
      }
      for(const row of ledger.values()) if(row.taskId===v.taskId||row.jobId===v.jobId||row.nonce===v.nonce) throw Error('package_stage_replay_conflict');
      if(ledger.size>=2048) throw Error('package_stage_ledger_full');
      if(fs.existsSync(target))throw Error('package_stage_target_collision');
      if(fs.existsSync(pending)){
        if(!ownedDirectory(pending))throw Error('package_stage_pending_unsafe');
        fs.rmSync(pending,{recursive:true,force:true});
      }
      fs.mkdirSync(pending,{mode:0o700});
      let summary;
      try { summary=extractPackageTarGz(archive,{packagePath:v.packagePath,destination:pending}); }
      catch(e) { fs.rmSync(pending,{recursive:true,force:true}); throw e; }
      const packageSha256=createHash('sha256').update(JSON.stringify(summary.files)).digest('hex');
      const fields={version:PACKAGE_STAGE_VERSION,brokerId,workerId,taskId:v.taskId,jobId:v.jobId,nonce:v.nonce,
        issuedAt:now,expiresAt:v.expiresAt,state:'STAGED',packageSha256,fileCount:summary.fileCount,
        byteCount:summary.byteCount,stageId:id,signature:''};
      fields.signature=sign(null,responseBytes(fields),workerPrivateKey).toString('base64url');
      const record={taskId:v.taskId,jobId:v.jobId,nonce:v.nonce,digest,state:'PREPARED',response:Object.freeze(fields)};
      ledger.set(key,record);
      persistLedger(ledgerPath,ledger);
      fs.renameSync(pending,target);
      record.state='STAGED';persistLedger(ledgerPath,ledger);
      return Object.freeze(fields);
    }
  });
}

export function verifyPackageStageResponse(response, workerPublicKey, expected, now=Date.now()) {
  if(!exact(response,RESPONSE_KEYS)||response.version!==PACKAGE_STAGE_VERSION||response.state!=='STAGED'||
    !FINGERPRINT.test(response.brokerId)||!FINGERPRINT.test(response.workerId)||!UUID.test(response.taskId)||
    !UUID.test(response.jobId)||!UUID.test(response.nonce)||!SHA256.test(response.packageSha256)||
    !Number.isSafeInteger(response.fileCount)||response.fileCount<1||response.fileCount>MAX_FILES||
    !Number.isSafeInteger(response.byteCount)||response.byteCount<1||response.byteCount>MAX_EXPANDED_BYTES||
    typeof response.stageId!=='string'||!/^([a-f0-9]{40})-([0-9a-f-]{36})$/.test(response.stageId)||
    !Number.isSafeInteger(response.issuedAt)||!Number.isSafeInteger(response.expiresAt)||response.issuedAt>now+5000||
    response.expiresAt<=now||response.expiresAt<=response.issuedAt||response.expiresAt-response.issuedAt>PACKAGE_STAGE_TTL_MS||
    typeof response.signature!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(response.signature)) throw Error('package_stage_response_invalid');
  const worker=publicKeyOf(workerPublicKey);
  if(packageStageIdentity(worker)!==response.workerId||response.brokerId!==expected.brokerId||response.workerId!==expected.workerId||
    response.taskId!==expected.taskId||response.jobId!==expected.jobId||response.nonce!==expected.nonce||response.expiresAt!==expected.expiresAt)
    throw Error('package_stage_response_correlation_failed');
  if(!verify(null,responseBytes(response),worker,Buffer.from(response.signature,'base64url'))) throw Error('package_stage_response_signature_invalid');
  return Object.freeze({...response});
}
