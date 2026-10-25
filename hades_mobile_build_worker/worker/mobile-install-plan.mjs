import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';

export const MOBILE_INSTALL_REPOSITORY='engelssebastian239-ops/hades-hermes-queue';
export const MOBILE_INSTALL_COMMIT='addf609d98256e989e1fc7b2f833d80f95628ae7';
export const MOBILE_INSTALL_PACKAGE_PATH='hades-m2-local-app/hades_m2_mobile';
export const MOBILE_INSTALL_CI_RUN=40190750157;
export const MOBILE_INSTALL_CI_WORKFLOW='.github/workflows/m574-mobile-module-assets.yml';
export const MOBILE_INSTALL_REQUIRED_ASSET='server-first/mobile-pwa/studio-night.png';
export const MOBILE_INSTALL_REGRESSION_RELATIVE_PATH='tests/m574-docker-module-assets.test.mjs';
export const MOBILE_INSTALL_REGRESSION_PATH=`${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REGRESSION_RELATIVE_PATH}`;
export const MOBILE_INSTALL_REGRESSION_SHA256='57195d6152d96df254a2521467a4797e82c923dcd826c6a9b9451b3afb6e0c92';
export const MOBILE_INSTALL_DOCKERFILE_SHA256='5c58e91ffa3465e984969a7438aec8e15607a07d3edb293dda7e016aacfed448';
export const MOBILE_INSTALL_MAX_FILES=512;
export const MOBILE_INSTALL_MAX_EXPANDED_BYTES=12*1024*1024;
export const MOBILE_INSTALL_MAX_ARCHIVE_BYTES=8*1024*1024;
export const MOBILE_INSTALL_MANIFEST='HADES-M574-MANIFEST.json';
export const MOBILE_INSTALL_MANIFEST_PROTOCOL='HADES_MOBILE_M574_PACKAGE_V1';

const API_ORIGIN='https://api.github.com';
const REQUEST_TIMEOUT_MS=15_000;
const PLAN_TIMEOUT_MS=120_000;
const MAX_JSON_BYTES=5*1024*1024;
const MAX_BLOB_JSON_BYTES=17*1024*1024;
const SAFE_PATH=/^[A-Za-z0-9_.@+-]+(?:\/[A-Za-z0-9_.@+-]+)*$/;
const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const gitBlobSha=bytes=>createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');

function fail(code){throw new Error(code);}
function safePath(value){if(typeof value!=='string'||!SAFE_PATH.test(value)||value.split('/').some(part=>part==='.'||part==='..'))fail('github_tree_path_invalid');return value;}
function tarNumber(value,width){const s=value.toString(8).padStart(width-1,'0')+'\0';if(s.length>width)fail('tar_field_overflow');return Buffer.from(s,'ascii');}
function tarHeader(name,size,mode){
  let filename=name,prefix='';if(Buffer.byteLength(filename)>100){const ix=filename.lastIndexOf('/');if(ix<1||Buffer.byteLength(filename.slice(0,ix))>155||Buffer.byteLength(filename.slice(ix+1))>100)fail('tar_path_too_long');prefix=filename.slice(0,ix);filename=filename.slice(ix+1);}
  const h=Buffer.alloc(512);Buffer.from(filename).copy(h);tarNumber(mode,8).copy(h,100);tarNumber(0,8).copy(h,108);tarNumber(0,8).copy(h,116);tarNumber(size,12).copy(h,124);tarNumber(0,12).copy(h,136);h.fill(32,148,156);h[156]=48;Buffer.from('ustar\0','ascii').copy(h,257);Buffer.from('00','ascii').copy(h,263);Buffer.from('root','ascii').copy(h,265);Buffer.from('root','ascii').copy(h,297);Buffer.from(prefix).copy(h,345);let sum=0;for(const b of h)sum+=b;Buffer.from(sum.toString(8).padStart(6,'0')+'\0 ','ascii').copy(h,148);return h;
}
function tarEntry(name,bytes,mode){const padding=(512-bytes.length%512)%512;return Buffer.concat([tarHeader(name,bytes.length,mode),bytes,Buffer.alloc(padding)]);}
function buildMobileInstallPackagePinned(files,dockerfileSha256){
  if(!Array.isArray(files)||files.length<1||files.length>MOBILE_INSTALL_MAX_FILES)fail('package_file_count_invalid');
  const rows=files.map(file=>{
    const rel=safePath(file.path);if(!Buffer.isBuffer(file.bytes)||![0o644,0o755].includes(file.mode))fail('package_file_invalid');
    return {path:rel,bytes:Buffer.from(file.bytes),size:file.bytes.length,mode:file.mode,sha256:sha256(file.bytes)};
  }).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  const paths=new Set();for(const row of rows){if(paths.has(row.path))fail('package_path_collision');paths.add(row.path);}
  for(const row of rows){const segments=row.path.split('/');for(let i=1;i<segments.length;i++)if(paths.has(segments.slice(0,i).join('/')))fail('package_path_collision');}
  if(!rows.some(row=>row.path===MOBILE_INSTALL_REQUIRED_ASSET))fail('pinned_asset_missing');
  const dockerfile=rows.find(row=>row.path==='Dockerfile');if(!dockerfile||dockerfile.sha256!==dockerfileSha256)fail('m574_dockerfile_mismatch');
  const manifest={protocol:MOBILE_INSTALL_MANIFEST_PROTOCOL,repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,packagePath:MOBILE_INSTALL_PACKAGE_PATH,
    files:rows.map(({path,sha256,size,mode})=>({path,sha256,size,mode}))};
  const manifestBytes=Buffer.from(JSON.stringify(manifest));
  const raw=Buffer.concat([tarEntry(MOBILE_INSTALL_MANIFEST,manifestBytes,0o600),...rows.map(row=>tarEntry(`${MOBILE_INSTALL_PACKAGE_PATH}/${row.path}`,row.bytes,row.mode)),Buffer.alloc(1024)]);
  if(raw.length>MOBILE_INSTALL_MAX_EXPANDED_BYTES)fail('package_expansion_limit');
  const archive=gzipSync(raw,{level:9,mtime:0});if(archive.length>MOBILE_INSTALL_MAX_ARCHIVE_BYTES)fail('package_archive_limit');
  return Object.freeze({manifest:Object.freeze(manifest),manifestSha256:sha256(manifestBytes),archive,archiveSha256:sha256(archive),archiveSize:archive.length,fileCount:rows.length,expandedBytes:raw.length});
}

export function buildMobileInstallPackage(files){return buildMobileInstallPackagePinned(files,MOBILE_INSTALL_DOCKERFILE_SHA256);}
export function buildMobileInstallPackageForTests(files,{testOnlyDockerfileSha256}={}){
  if(typeof testOnlyDockerfileSha256!=='string'||!/^[a-f0-9]{64}$/.test(testOnlyDockerfileSha256))fail('planner_test_pin_invalid');
  return buildMobileInstallPackagePinned(files,testOnlyDockerfileSha256);
}

function createMobileInstallPlannerImpl({token,fetchImpl=fetch,timeoutMs=REQUEST_TIMEOUT_MS,regressionSha256=MOBILE_INSTALL_REGRESSION_SHA256,dockerfileSha256=MOBILE_INSTALL_DOCKERFILE_SHA256}={}){
  if(typeof token!=='string'||token.length<16||token.length>512)fail('github_token_invalid');
  if(!/^[a-f0-9]{64}$/.test(regressionSha256)||!/^[a-f0-9]{64}$/.test(dockerfileSha256)||!Number.isSafeInteger(timeoutMs)||timeoutMs<100||timeoutMs>60_000)fail('planner_options_invalid');
  async function get(path,maxBytes=MAX_JSON_BYTES,deadline){
    if(typeof path!=='string'||!path.startsWith('/repos/'+MOBILE_INSTALL_REPOSITORY+'/')||path.includes('..'))fail('github_path_rejected');
    const remaining=deadline-Date.now();if(remaining<=0)fail('github_timeout');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),Math.min(timeoutMs,remaining));let response,bytes;
    try{
      response=await fetchImpl(API_ORIGIN+path,{method:'GET',redirect:'error',signal:controller.signal,headers:{authorization:`Bearer ${token}`,accept:'application/vnd.github+json','x-github-api-version':'2022-11-28','user-agent':'hades-mobile-install-planner'}});
      if(!response||!response.ok)fail('github_api_unavailable');
      if(!response.body)fail('github_response_invalid');
      const reader=response.body.getReader(),chunks=[];let size=0;
      while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>maxBytes){await reader.cancel();fail('github_response_too_large');}chunks.push(Buffer.from(value));}
      bytes=Buffer.concat(chunks);
    }catch(error){if(error?.message?.startsWith('github_'))throw error;fail(error?.name==='AbortError'?'github_timeout':'github_api_unavailable');}
    finally{clearTimeout(timer);}
    try{return JSON.parse(bytes.toString('utf8'));}catch{fail('github_json_invalid');}
  }
  async function readBlob(entry,deadline){
    if(!entry||entry.type!=='blob'||!['100644','100755'].includes(entry.mode)||!/^[a-f0-9]{40}$/.test(entry.sha))fail('github_blob_mode_rejected');
    const result=await get(`/repos/${MOBILE_INSTALL_REPOSITORY}/git/blobs/${entry.sha}`,MAX_BLOB_JSON_BYTES,deadline);
    if(result.sha!==entry.sha||result.encoding!=='base64'||typeof result.content!=='string'||!Number.isSafeInteger(result.size)||result.size<0)fail('github_blob_invalid');
    const encoded=result.content.replace(/[\r\n]/g,'');if(!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded))fail('github_blob_base64_invalid');
    const bytes=Buffer.from(encoded,'base64');if(bytes.toString('base64')!==encoded||bytes.length!==result.size||gitBlobSha(bytes)!==entry.sha)fail('github_blob_hash_mismatch');
    return bytes;
  }
  return Object.freeze({async createPlan(){
    const deadline=Date.now()+PLAN_TIMEOUT_MS;
    const run=await get(`/repos/${MOBILE_INSTALL_REPOSITORY}/actions/runs/${MOBILE_INSTALL_CI_RUN}`,MAX_JSON_BYTES,deadline);
    if(run.id!==MOBILE_INSTALL_CI_RUN||run.status!=='completed'||run.conclusion!=='success'||run.head_sha!==MOBILE_INSTALL_COMMIT||run.path!==MOBILE_INSTALL_CI_WORKFLOW)fail('ci_run_not_verified');
    const commit=await get(`/repos/${MOBILE_INSTALL_REPOSITORY}/git/commits/${MOBILE_INSTALL_COMMIT}`,MAX_JSON_BYTES,deadline);if(commit.sha!==MOBILE_INSTALL_COMMIT||!/^[a-f0-9]{40}$/.test(commit.tree?.sha||''))fail('commit_not_verified');
    const tree=await get(`/repos/${MOBILE_INSTALL_REPOSITORY}/git/trees/${commit.tree.sha}?recursive=1`,MAX_JSON_BYTES,deadline);if(tree.sha!==commit.tree.sha||tree.truncated!==false||!Array.isArray(tree.tree))fail('git_tree_truncated_or_invalid');
    const packagePrefix=MOBILE_INSTALL_PACKAGE_PATH+'/',packageEntries=[],seenPaths=new Set();let regressionEntry;
    for(const entry of tree.tree){
      const rel=safePath(entry.path);
      if(seenPaths.has(rel))fail('github_tree_duplicate_path');seenPaths.add(rel);
      if(rel===MOBILE_INSTALL_REGRESSION_PATH){regressionEntry=entry;continue;}
      if(rel.startsWith(packagePrefix)){if(entry.type==='tree')continue;packageEntries.push({entry,relative:rel.slice(packagePrefix.length)});}
    }
    if(packageEntries.length<1||packageEntries.length>MOBILE_INSTALL_MAX_FILES)fail('package_file_count_invalid');
    if(!regressionEntry||regressionEntry.type!=='blob'||regressionEntry.mode!=='100644')fail('regression_test_missing');
    const regressionBytes=await readBlob(regressionEntry,deadline);if(sha256(regressionBytes)!==regressionSha256)fail('regression_test_hash_mismatch');
    let total=regressionBytes.length;const files=await mapLimit(packageEntries,4,async item=>{
      const bytes=await readBlob(item.entry,deadline);total+=bytes.length;if(total>MOBILE_INSTALL_MAX_EXPANDED_BYTES)fail('package_expansion_limit');
      return {path:item.relative,bytes,mode:item.entry.mode==='100755'?0o755:0o644};
    });
    if(files.some(file=>file.path===MOBILE_INSTALL_REGRESSION_PATH))fail('regression_test_must_not_be_packaged');
    const pack=buildMobileInstallPackagePinned(files,dockerfileSha256);
    return Object.freeze({repository:MOBILE_INSTALL_REPOSITORY,commit:MOBILE_INSTALL_COMMIT,ciRun:MOBILE_INSTALL_CI_RUN,workflow:MOBILE_INSTALL_CI_WORKFLOW,packagePath:MOBILE_INSTALL_PACKAGE_PATH,
      archive:pack.archive,archiveSha256:pack.archiveSha256,archiveSize:pack.archiveSize,manifestSha256:pack.manifestSha256,fileCount:pack.fileCount,expandedBytes:pack.expandedBytes});
  }});
}

export function createMobileInstallPlanner(options={}){
  return createMobileInstallPlannerImpl({token:options.token,fetchImpl:options.fetchImpl,timeoutMs:options.timeoutMs,
    regressionSha256:MOBILE_INSTALL_REGRESSION_SHA256,dockerfileSha256:MOBILE_INSTALL_DOCKERFILE_SHA256});
}
export function createMobileInstallPlannerForTests({token,fetchImpl=fetch,timeoutMs=REQUEST_TIMEOUT_MS,testOnlyRegressionSha256,testOnlyDockerfileSha256}={}){
  if(typeof testOnlyRegressionSha256!=='string'||typeof testOnlyDockerfileSha256!=='string')fail('planner_test_pin_invalid');
  return createMobileInstallPlannerImpl({token,fetchImpl,timeoutMs,regressionSha256:testOnlyRegressionSha256,dockerfileSha256:testOnlyDockerfileSha256});
}

async function mapLimit(items,limit,fn){const out=new Array(items.length);let next=0;async function worker(){while(true){const index=next++;if(index>=items.length)return;out[index]=await fn(items[index],index);}}await Promise.all(Array.from({length:Math.min(limit,items.length)},worker));return out;}
