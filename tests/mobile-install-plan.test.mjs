import test from 'node:test';
import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {gunzipSync} from 'node:zlib';
import {
  MOBILE_INSTALL_CI_RUN,MOBILE_INSTALL_CI_WORKFLOW,MOBILE_INSTALL_COMMIT,MOBILE_INSTALL_PACKAGE_PATH,
  MOBILE_INSTALL_REGRESSION_PATH,MOBILE_INSTALL_REGRESSION_RELATIVE_PATH,MOBILE_INSTALL_REPOSITORY,
  buildMobileInstallPackageForTests,createMobileInstallPlanner,createMobileInstallPlannerForTests
} from '../hades_build_worker/worker/mobile-install-plan.mjs';

const sha256=bytes=>createHash('sha256').update(bytes).digest('hex');
const gitSha=bytes=>createHash('sha1').update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
const token='github_pat_'+'X'.repeat(30);
const docker=Buffer.from('FROM scratch\n# synthetic CI test Dockerfile\n');
const png=Buffer.from([137,80,78,71,13,10,26,10,0,0,0,0]);
const config=Buffer.from('name: synthetic\n');
const regression=Buffer.from('synthetic pinned regression test fixture\n');
const dockerPin=sha256(docker),regressionPin=sha256(regression),treeSha='a'.repeat(40),run={id:MOBILE_INSTALL_CI_RUN,status:'completed',conclusion:'success',head_sha:MOBILE_INSTALL_COMMIT,path:MOBILE_INSTALL_CI_WORKFLOW};

function fixture({ci=run,treeEntries,alterBlobSha='',oversized=false,redirect=false,returnedTreeSha=treeSha}={}){
  const sourceFiles=[['Dockerfile',docker,'100644'],['config.yaml',config,'100644'],['server-first/mobile-pwa/studio-night.png',png,'100644']];
  const all=sourceFiles.map(([path,bytes,mode])=>({path:`${MOBILE_INSTALL_PACKAGE_PATH}/${path}`,type:'blob',mode,sha:gitSha(bytes)}));
  const regressionEntry={path:MOBILE_INSTALL_REGRESSION_PATH,type:'blob',mode:'100644',sha:gitSha(regression)};
  const defaultEntries=[...all,regressionEntry];
  const bodies=new Map([...sourceFiles.map(([,bytes])=>[gitSha(bytes),bytes]),[gitSha(regression),regression]]);
  const calls=[];
  const fetchImpl=async(url,init)=>{
    const parsed=new URL(url);calls.push({url:parsed,init});
    if(redirect)return new Response('',{status:302,headers:{location:'https://example.invalid/'} });
    let data;
    if(parsed.pathname.endsWith(`/actions/runs/${MOBILE_INSTALL_CI_RUN}`))data=ci;
    else if(parsed.pathname.endsWith(`/git/commits/${MOBILE_INSTALL_COMMIT}`))data={sha:MOBILE_INSTALL_COMMIT,tree:{sha:treeSha}};
    else if(parsed.pathname.endsWith(`/git/trees/${treeSha}`))data={sha:returnedTreeSha,truncated:false,tree:treeEntries||defaultEntries};
    else if(parsed.pathname.includes('/git/blobs/')){
      const requested=parsed.pathname.split('/').at(-1);let bytes=bodies.get(requested);
      if(oversized)bytes=Buffer.alloc(17*1024*1024+1,65);
      if(!bytes)return new Response(JSON.stringify({message:'not found'}),{status:404});
      data={sha:alterBlobSha||requested,size:bytes.length,encoding:'base64',content:bytes.toString('base64')};
    }else return new Response('',{status:404});
    return new Response(JSON.stringify(data),{status:200,headers:{'content-type':'application/json'}});
  };
  return {fetchImpl,calls,entries:defaultEntries};
}
function planner(f,{timeoutMs=1000}={}){return createMobileInstallPlannerForTests({token,fetchImpl:f.fetchImpl,timeoutMs,testOnlyRegressionSha256:regressionPin,testOnlyDockerfileSha256:dockerPin});}
function getManifest(archive){
  const bytes=gunzipSync(archive);const header=bytes.subarray(0,512),size=parseInt(header.subarray(124,136).toString('ascii').replace(/\0.*$/s,'').trim(),8);return JSON.parse(bytes.subarray(512,512+size).toString('utf8'));
}

test('builds a canonical pinned package from successful CI and verified Git blob bytes',async()=>{
  const f=fixture(),result=await planner(f).createPlan();
  assert.equal(result.repository,MOBILE_INSTALL_REPOSITORY);assert.equal(result.commit,MOBILE_INSTALL_COMMIT);assert.equal(result.ciRun,MOBILE_INSTALL_CI_RUN);
  assert.equal(result.workflow,MOBILE_INSTALL_CI_WORKFLOW);assert.equal(result.packagePath,MOBILE_INSTALL_PACKAGE_PATH);assert.equal(result.fileCount,3);
  const manifest=getManifest(result.archive);assert.deepEqual(manifest.files.map(row=>row.path),['Dockerfile','config.yaml','server-first/mobile-pwa/studio-night.png']);
  assert.ok(!manifest.files.some(row=>row.path===MOBILE_INSTALL_REGRESSION_PATH));assert.equal(result.archiveSha256,sha256(result.archive));
  assert.equal(f.calls.every(call=>call.url.origin==='https://api.github.com'&&call.init.redirect==='error'),true);
  assert.ok(f.calls.some(call=>call.url.pathname.endsWith(`/git/blobs/${gitSha(png)}`)));
});

test('rejects CI that is failed, incomplete, wrong-head, wrong-run, or wrong-workflow',async t=>{
  const cases=[
    ['failure',{...run,conclusion:'failure'}],['not complete',{...run,status:'in_progress'}],['wrong head',{...run,head_sha:'b'.repeat(40)}],
    ['wrong workflow',{...run,path:'.github/workflows/other.yml'}],['wrong run id',{...run,id:MOBILE_INSTALL_CI_RUN+1}]
  ];
  for(const [name,ci] of cases)await t.test(name,async()=>{const f=fixture({ci});await assert.rejects(planner(f).createPlan(),/ci_run_not_verified/);});
});

test('rejects redirects, oversized API responses, and a truncated Git tree',async t=>{
  await t.test('redirect',async()=>{const f=fixture({redirect:true});await assert.rejects(planner(f).createPlan(),/github_api_unavailable/);assert.equal(f.calls[0].init.redirect,'error');});
  await t.test('oversized blob',async()=>{const f=fixture({oversized:true});await assert.rejects(planner(f).createPlan(),/github_response_too_large/);});
  await t.test('request timeout',async()=>{const f=fixture();const timeoutPlanner=createMobileInstallPlanner({token,regressionSha256:regressionPin,dockerfileSha256:dockerPin,timeoutMs:100,fetchImpl:async(_url,init)=>new Promise((_resolve,reject)=>init.signal.addEventListener('abort',()=>reject(Object.assign(Error('aborted'),{name:'AbortError'}))))});await assert.rejects(timeoutPlanner.createPlan(),/github_timeout/);});
  await t.test('truncated',async()=>{const f=fixture({treeEntries:[]});f.fetchImpl=async url=>{const parsed=new URL(url);if(parsed.pathname.endsWith(`/actions/runs/${MOBILE_INSTALL_CI_RUN}`))return new Response(JSON.stringify(run));if(parsed.pathname.endsWith(`/git/commits/${MOBILE_INSTALL_COMMIT}`))return new Response(JSON.stringify({sha:MOBILE_INSTALL_COMMIT,tree:{sha:treeSha}}));return new Response(JSON.stringify({sha:treeSha,truncated:true,tree:[]}));};await assert.rejects(planner(f).createPlan(),/git_tree_truncated_or_invalid/);});
  await t.test('tree sha mismatch',async()=>{const f=fixture({returnedTreeSha:'b'.repeat(40)});await assert.rejects(planner(f).createPlan(),/git_tree_truncated_or_invalid/);});
});

test('rejects Git path traversal, symlink modes, and altered blob bytes',async t=>{
  const normal=fixture();
  for(const [name,entry] of [
    ['traversal',{path:`${MOBILE_INSTALL_PACKAGE_PATH}/../evil`,type:'blob',mode:'100644',sha:gitSha(config)}],
    ['symlink',{path:`${MOBILE_INSTALL_PACKAGE_PATH}/bad-link`,type:'blob',mode:'120000',sha:gitSha(config)}]
  ])await t.test(name,async()=>{const f=fixture({treeEntries:[...normal.entries,entry]});await assert.rejects(planner(f).createPlan(),name==='traversal'?/github_tree_path_invalid/:/github_blob_mode_rejected/);});
  await t.test('blob hash mismatch',async()=>{const f=fixture({alterBlobSha:'f'.repeat(40)});await assert.rejects(planner(f).createPlan(),/github_blob_invalid|github_blob_hash_mismatch/);});
  await t.test('duplicate tree paths',async()=>{const f=fixture();f.fetchImpl=async url=>{const parsed=new URL(url);if(parsed.pathname.endsWith(`/actions/runs/${MOBILE_INSTALL_CI_RUN}`))return new Response(JSON.stringify(run));if(parsed.pathname.endsWith(`/git/commits/${MOBILE_INSTALL_COMMIT}`))return new Response(JSON.stringify({sha:MOBILE_INSTALL_COMMIT,tree:{sha:treeSha}}));return new Response(JSON.stringify({sha:treeSha,truncated:false,tree:[...f.entries,...f.entries.slice(0,1)]}));};await assert.rejects(planner(f).createPlan(),/github_tree_duplicate_path/);});
});

test('rejects an incorrect pinned regression hash and package file overflow',async()=>{
  const f=fixture(),bad=createMobileInstallPlannerForTests({token,fetchImpl:f.fetchImpl,testOnlyRegressionSha256:'0'.repeat(64),testOnlyDockerfileSha256:dockerPin});
  await assert.rejects(bad.createPlan(),/regression_test_hash_mismatch/);
  const many=Array.from({length:513},(_,i)=>({path:`x${i}`,bytes:Buffer.from('x'),mode:0o644}));
  assert.throws(()=>buildMobileInstallPackageForTests(many,{testOnlyDockerfileSha256:dockerPin}),/package_file_count_invalid/);
  const large=[{path:'Dockerfile',bytes:docker,mode:0o644},{path:'config.yaml',bytes:config,mode:0o644},{path:'server-first/mobile-pwa/studio-night.png',bytes:png,mode:0o644},{path:'large.bin',bytes:Buffer.alloc(12*1024*1024),mode:0o644}];
  assert.throws(()=>buildMobileInstallPackageForTests(large,{testOnlyDockerfileSha256:dockerPin}),/package_expansion_limit/);
  const noisy=[{path:'Dockerfile',bytes:docker,mode:0o644},{path:'config.yaml',bytes:config,mode:0o644},{path:'server-first/mobile-pwa/studio-night.png',bytes:png,mode:0o644},{path:'large.bin',bytes:randomBytes(8*1024*1024),mode:0o644}];
  assert.throws(()=>buildMobileInstallPackageForTests(noisy,{testOnlyDockerfileSha256:dockerPin}),/package_archive_limit/);
});

test('full regression path is validated by Git tree but excluded from package',async()=>{
  const f=fixture(),result=await planner(f).createPlan();assert.ok(f.entries.some(entry=>entry.path===`${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REGRESSION_RELATIVE_PATH}`));
  assert.equal(MOBILE_INSTALL_REGRESSION_PATH,`${MOBILE_INSTALL_PACKAGE_PATH}/${MOBILE_INSTALL_REGRESSION_RELATIVE_PATH}`);
  assert.ok(!getManifest(result.archive).files.some(row=>row.path===MOBILE_INSTALL_REGRESSION_RELATIVE_PATH));
  const production=createMobileInstallPlanner({token,fetchImpl:f.fetchImpl,regressionSha256:regressionPin,dockerfileSha256:dockerPin});
  await assert.rejects(production.createPlan(),/regression_test_hash_mismatch/);
});

test('package path collisions detect every ancestor, including non-adjacent lexical entries',()=>{
  const files=[
    {path:'Dockerfile',bytes:docker,mode:0o644},{path:'server-first/mobile-pwa/studio-night.png',bytes:png,mode:0o644},
    {path:'a',bytes:Buffer.from('file'),mode:0o644},{path:'a-b',bytes:Buffer.from('file'),mode:0o644},{path:'a/c',bytes:Buffer.from('child'),mode:0o644}
  ];
  assert.throws(()=>buildMobileInstallPackageForTests(files,{testOnlyDockerfileSha256:dockerPin}),/package_path_collision/);
});
