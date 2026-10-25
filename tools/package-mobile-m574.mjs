import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {createHash} from 'node:crypto';
import {gzipSync} from 'node:zlib';
import {INSTALL_COMMIT,INSTALL_PACKAGE_PATH,INSTALL_PROTOCOL,INSTALL_REPOSITORY,MAX_ARCHIVE_BYTES,MAX_EXPANDED_BYTES} from '../hades_mobile_installer/installer.mjs';

const TOOL_DIR=path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT=path.resolve(TOOL_DIR,'..');
const CHECKOUT=path.resolve(REPO_ROOT,'../hades-hermes-queue');
const SOURCE=path.join(CHECKOUT,...INSTALL_PACKAGE_PATH.split('/'));
const OUTPUT=path.join(REPO_ROOT,'dist','hades-mobile-m574-install.tar.gz');
const REQUIRED_ASSET='server-first/mobile-pwa/studio-night.png';
const DOCKERFILE_SHA='5c58e91ffa3465e984969a7438aec8e15607a07d3edb293dda7e016aacfed448';
const REGRESSION_TEST='tests/m574-docker-module-assets.test.mjs';
const REGRESSION_TEST_SHA='57195d6152d96df254a2521467a4797e82c923dcd826c6a9b9451b3afb6e0c92';
const hash=data=>createHash('sha256').update(data).digest('hex');

function gitDirFor(checkout){
  const dot=path.join(checkout,'.git'),st=fs.lstatSync(dot);
  if(st.isDirectory())return dot;
  if(!st.isFile())throw Error('git_metadata_unavailable');
  const match=/^gitdir: (.+)\r?\n?$/.exec(fs.readFileSync(dot,'utf8'));
  if(!match)throw Error('git_metadata_unavailable');
  return path.resolve(checkout,match[1]);
}
function gitHead(checkout){
  const gitDir=gitDirFor(checkout),head=fs.readFileSync(path.join(gitDir,'HEAD'),'utf8').trim();
  if(/^[a-f0-9]{40}$/.test(head))return head;
  if(!head.startsWith('ref: '))throw Error('git_head_invalid');
  const ref=head.slice(5),loose=path.join(gitDir,...ref.split('/'));
  try{return fs.readFileSync(loose,'utf8').trim();}catch(e){if(e.code!=='ENOENT')throw e;}
  const packed=fs.readFileSync(path.join(gitDir,'packed-refs'),'utf8');
  for(const line of packed.split('\n')){const m=/^([a-f0-9]{40}) (.+)$/.exec(line);if(m&&m[2]===ref)return m[1];}
  throw Error('git_head_unresolved');
}
function safePath(rel){
  if(!rel||rel.startsWith('/')||rel.includes('\\')||rel.split('/').some(p=>!p||p==='.'||p==='..'||!/^[A-Za-z0-9_.@+-]+$/.test(p)))throw Error('source_path_unsafe');
  return rel;
}
function walk(dir,rel='',rows=[]){
  for(const entry of fs.readdirSync(dir,{withFileTypes:true}).sort((a,b)=>a.name.localeCompare(b.name,'en'))){
    const childRel=safePath(rel?`${rel}/${entry.name}`:entry.name),absolute=path.join(dir,entry.name),st=fs.lstatSync(absolute);
    if(st.isSymbolicLink())throw Error('source_symlink_rejected');
    if(st.isDirectory()){walk(absolute,childRel,rows);continue;}
    if(!st.isFile()||st.nlink!==1||(st.mode&0o022)||(st.mode&0o7000)||![0o644,0o755].includes(st.mode&0o777))throw Error('source_file_mode_rejected');
    if(rows.length>=512)throw Error('package_file_count_limit');
    const bytes=fs.readFileSync(absolute);rows.push({path:childRel,bytes,mode:st.mode&0o777,size:st.size,sha256:hash(bytes)});
  }
  return rows;
}
function tarNumber(value,width){const s=value.toString(8).padStart(width-1,'0')+'\0';if(s.length>width)throw Error('tar_field_overflow');return Buffer.from(s,'ascii');}
function tarHeader(name,size,mode){
  let filename=name,prefix='';if(Buffer.byteLength(filename)>100){const ix=filename.lastIndexOf('/');if(ix<1||Buffer.byteLength(filename.slice(0,ix))>155||Buffer.byteLength(filename.slice(ix+1))>100)throw Error('tar_path_too_long');prefix=filename.slice(0,ix);filename=filename.slice(ix+1);}
  const h=Buffer.alloc(512);Buffer.from(filename).copy(h,0);tarNumber(mode,8).copy(h,100);tarNumber(0,8).copy(h,108);tarNumber(0,8).copy(h,116);tarNumber(size,12).copy(h,124);tarNumber(0,12).copy(h,136);h.fill(32,148,156);h[156]=48;Buffer.from('ustar\0','ascii').copy(h,257);Buffer.from('00','ascii').copy(h,263);Buffer.from('root').copy(h,265);Buffer.from('root').copy(h,297);Buffer.from(prefix).copy(h,345);let sum=0;for(const b of h)sum+=b;Buffer.from(sum.toString(8).padStart(6,'0')+'\0 ','ascii').copy(h,148);return h;
}
function tarEntry(name,bytes,mode){const header=tarHeader(name,bytes.length,mode),padding=(512-bytes.length%512)%512;return Buffer.concat([header,bytes,Buffer.alloc(padding)]);}
function main(){
  if(gitHead(CHECKOUT)!==INSTALL_COMMIT)throw Error('pinned_checkout_commit_required');
  const sourceStat=fs.lstatSync(SOURCE);if(!sourceStat.isDirectory()||sourceStat.isSymbolicLink())throw Error('source_directory_invalid');
  const rows=walk(SOURCE).sort((a,b)=>a.path<b.path?-1:a.path>b.path?1:0);
  if(!rows.some(x=>x.path===REQUIRED_ASSET))throw Error('pinned_asset_missing');
  const dockerfile=rows.find(x=>x.path==='Dockerfile');if(!dockerfile||dockerfile.sha256!==DOCKERFILE_SHA)throw Error('m574_dockerfile_mismatch');
  const regressionPath=path.join(CHECKOUT,...REGRESSION_TEST.split('/')),regressionStat=fs.lstatSync(regressionPath);
  if(!regressionStat.isFile()||regressionStat.isSymbolicLink()||regressionStat.nlink!==1||hash(fs.readFileSync(regressionPath))!==REGRESSION_TEST_SHA)throw Error('m574_regression_test_mismatch');
  if(rows.some(x=>x.path===REGRESSION_TEST))throw Error('regression_test_must_not_be_packaged');
  const manifest={protocol:'HADES_MOBILE_M574_PACKAGE_V1',repository:INSTALL_REPOSITORY,commit:INSTALL_COMMIT,packagePath:INSTALL_PACKAGE_PATH,
    files:rows.map(({path:p,sha256,size,mode})=>({path:p,sha256,size,mode}))};
  const manifestBytes=Buffer.from(JSON.stringify(manifest));
  const entries=[tarEntry('HADES-M574-MANIFEST.json',manifestBytes,0o600),...rows.map(row=>tarEntry(`${INSTALL_PACKAGE_PATH}/${row.path}`,row.bytes,row.mode)),Buffer.alloc(1024)];
  const raw=Buffer.concat(entries);if(raw.length>MAX_EXPANDED_BYTES)throw Error('package_expansion_limit');
  const archive=gzipSync(raw,{level:9,mtime:0});if(archive.length>MAX_ARCHIVE_BYTES)throw Error('package_archive_limit');
  fs.mkdirSync(path.dirname(OUTPUT),{recursive:true,mode:0o700});const temp=OUTPUT+'.tmp';const fd=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  try{fs.writeFileSync(fd,archive);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}fs.renameSync(temp,OUTPUT);
  console.log(JSON.stringify({state:'PACKAGE_READY',repository:INSTALL_REPOSITORY,commit:INSTALL_COMMIT,packagePath:INSTALL_PACKAGE_PATH,fileCount:rows.length,byteCount:rows.reduce((n,r)=>n+r.size,0),archiveSha256:hash(archive),archiveSize:archive.length,manifestSha256:hash(manifestBytes),output:'dist/hades-mobile-m574-install.tar.gz'}));
}
try{main();}catch(error){const code=/^[a-z0-9_]+$/.test(error.message||'')?error.message:'package_rejected';console.error(JSON.stringify({state:'PACKAGE_BLOCKED',code}));process.exitCode=1;}
