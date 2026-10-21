import fs from 'node:fs';
import path from 'node:path';
import { assertTrustedPublicKeyFingerprint, decryptTokenCiphertext } from '../src/rsa-oaep.mjs';
import { writeProvisionedCredential } from '../src/credential-file.mjs';
const privateDir='/data/hades-dev-workspace/hades-m35-secrets-20261011';
const repository='engelssebastian239-ops/hades-hermes-queue';
const tokenFile=path.join(privateDir,'github-token');
const keyFile=path.join(privateDir,'provision-private.pem');
const publicKeyJsonFile=path.join(privateDir,'public-for-windows.json');
const cipherFile=path.join(privateDir,'github-token.enc');
async function main(){
 if(process.getuid()===0)throw Error('wrong_execution_identity');
 const cipherStat=fs.lstatSync(cipherFile);
 if(!cipherStat.isFile()||cipherStat.isSymbolicLink()||cipherStat.uid!==process.getuid()||(cipherStat.mode&0o077)!==0)throw Error('insecure_encrypted_file');
 const b64=fs.readFileSync(cipherFile,'utf8').trim();
 if(fs.existsSync(tokenFile))throw Error('credential_already_exists_no_overwrite');
 const keyStat=fs.lstatSync(keyFile);
 if(!keyStat.isFile()||keyStat.isSymbolicLink()||keyStat.uid!==process.getuid()||(keyStat.mode&0o077)!==0)throw Error('insecure_provision_key');
 const publicStat=fs.lstatSync(publicKeyJsonFile);
 if(!publicStat.isFile()||publicStat.isSymbolicLink())throw Error('invalid_public_key_file');
 const publicKeyDocument=fs.readFileSync(publicKeyJsonFile,'utf8');
 const trustedFingerprint=process.env.HADES_M35_TRUSTED_PUBLIC_KEY_SHA256;
 assertTrustedPublicKeyFingerprint(publicKeyDocument,trustedFingerprint);
 const privateKey=fs.readFileSync(keyFile,'utf8');
 const plaintext=decryptTokenCiphertext(b64,privateKey,publicKeyDocument);
 const headers={'Authorization':'Bearer '+plaintext,'User-Agent':'HADES-HERMES-M35','Accept':'application/vnd.github+json','X-GitHub-Api-Version':'2022-11-28'};
 async function check(url){let res;
  try{res=await fetch('https://api.github.com'+url,{headers,signal:AbortSignal.timeout(12000),redirect:'error'})}
  catch{throw Error('github_transport_failure')}
  if(!res.ok)throw Error('github_authorization_failed_status_'+res.status);
  return await res.json();
 }
 const user=await check('/user');
 if(user.login!=='engelssebastian239-ops')throw Error('wrong_github_account');
 const repo=await check('/repos/'+repository);
 if(repo.full_name!==repository||repo.private!==true)throw Error('wrong_or_nonprivate_repository');
 const issue=await check('/repos/'+repository+'/issues/1');
 if(issue.number!==1)throw Error('test_issue_not_found');
 writeProvisionedCredential(tokenFile,plaintext);
 for(const f of ['provision-public.pem','public-for-windows.json','github-token.enc']){try{fs.unlinkSync(path.join(privateDir,f))}catch{}}
 console.log(JSON.stringify({result:'PROVISIONED',account:user.login,repository:repo.full_name,privateRepo:true,issue1Readable:true,tokenPermissions:'0600',tokenLogged:false,canary:false}));
}
main().catch(e=>{console.error(JSON.stringify({result:'BLOCKED',reason:e.message}));process.exitCode=1});