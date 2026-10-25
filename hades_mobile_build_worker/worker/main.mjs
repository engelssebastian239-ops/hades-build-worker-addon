import fs from 'node:fs';
import path from 'node:path';
import {createPrivateKey,createPublicKey,generateKeyPairSync} from 'node:crypto';
import {identityId} from '../shared/identity.mjs';
import {createMobileInstallRuntime} from './mobile-install-runtime.mjs';
import {createGithubPullProvisioner,loadGithubPullToken} from './mobile-credential-provisioner.mjs';

const ROOT='/data/hades-mobile-plan-worker',TOKEN_FILE=ROOT+'/github-token',KEY_FILE=ROOT+'/worker-ed25519.pem',INGRESS_PORT=8766;
const fail=code=>{throw Object.assign(Error(code),{code});};
function readOptions(){const x=JSON.parse(process.env.HADES_OPTIONS_JSON||fs.readFileSync('/data/options.json','utf8'));if(!x||Object.getPrototypeOf(x)!==Object.prototype||typeof x.mobile_plan_enabled!=='boolean'||typeof x.mobile_install_enabled!=='boolean'||typeof x.installer_adapter_id!=='string'||typeof x.installer_adapter_public_key!=='string')fail('options_invalid');return x;}
function assertWorkerKey(key){if(key.asymmetricKeyType!=='ed25519')fail('worker_key_type_invalid');return key;}
function syncParent(file){const fd=fs.openSync(path.dirname(file),fs.constants.O_RDONLY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
export function loadKey(file=KEY_FILE){try{const st=fs.lstatSync(file);if(!st.isFile()||st.isSymbolicLink()||st.nlink!==1||st.uid!==process.getuid()||(st.mode&0o777)!==0o600)fail('worker_key_permissions');return {key:assertWorkerKey(createPrivateKey(fs.readFileSync(file))),created:false};}catch(e){if(e.code!=='ENOENT')throw e;const pair=generateKeyPairSync('ed25519'),pem=pair.privateKey.export({type:'pkcs8',format:'pem'}),fd=fs.openSync(file,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);try{fs.writeFileSync(fd,pem);fs.fsyncSync(fd);}finally{fs.closeSync(fd);}syncParent(file);return {key:assertWorkerKey(pair.privateKey),created:true};}}
function validAdapter(options){try{if(!/^sha256:[a-f0-9]{64}$/.test(options.installer_adapter_id)||options.installer_adapter_public_key.length>512)return false;const key=createPublicKey({key:Buffer.from(options.installer_adapter_public_key,'base64'),format:'der',type:'spki'});return key.asymmetricKeyType==='ed25519'&&identityId(key)===options.installer_adapter_id;}catch{return false;}}
export async function main(){const options=readOptions(),keyInfo=loadKey(),workerPublic=createPublicKey(keyInfo.key),workerId=identityId(workerPublic),workerPublicKey=workerPublic.export({type:'spki',format:'der'}).toString('base64');
 console.log(JSON.stringify({state:'MOBILE_PLAN_WORKER_IDENTITY',workerId,workerPublicKeyBase64:workerPublicKey,identityCreatedThisStart:keyInfo.created,planEnabled:options.mobile_plan_enabled,installEnabled:options.mobile_install_enabled}));
 if(options.mobile_plan_enabled!==true){console.log(JSON.stringify({state:'MOBILE_PLAN_ONLY_DISABLED'}));setInterval(()=>{},120_000).ref();return;}
 if(!validAdapter(options)){console.error(JSON.stringify({state:'MOBILE_PLAN_BLOCKED',code:'installer_pin_invalid'}));setInterval(()=>{},120_000).ref();return;}
 let runtime=null,loop=null;
 const runtimeFor=token=>createMobileInstallRuntime({enabled:true,installEnabled:options.mobile_install_enabled,token,workerPrivateKey:keyInfo.key,adapterId:options.installer_adapter_id,adapterPublicKey:options.installer_adapter_public_key,log:event=>console.log(JSON.stringify(event))});
 const activate=async token=>{if(loop)return;const candidate=runtimeFor(token);await candidate.verifyConnection();candidate.start();runtime=candidate;loop=true;console.log(JSON.stringify({state:'MOBILE_PLAN_PULL_READY',pollSeconds:120,installEnabled:options.mobile_install_enabled,writeState:'UNVERIFIED'}));};
 let server;
 try{server=createGithubPullProvisioner({tokenFile:TOKEN_FILE,mobileInstallEnabled:true,validateToken:async token=>{const candidate=runtimeFor(token);await candidate.verifyConnection();},onProvisioned:activate});server.on('error',()=>console.error(JSON.stringify({state:'MOBILE_INGRESS_BLOCKED'})));server.listen(INGRESS_PORT,'0.0.0.0');await new Promise((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});console.log(JSON.stringify({state:'MOBILE_INGRESS_READY',port:INGRESS_PORT,credentialStored:false}));}
 catch(error){console.error(JSON.stringify({state:'MOBILE_INGRESS_BLOCKED',code:/^[a-z0-9_]+$/i.test(error?.code||'')?error.code:'listener_failed'}));}
 try{const token=loadGithubPullToken(TOKEN_FILE);await activate(token);}catch(error){if(error.code==='ENOENT')console.log(JSON.stringify({state:'MOBILE_GITHUB_SETUP_REQUIRED'}));else console.error(JSON.stringify({state:'MOBILE_GITHUB_BLOCKED',code:/^[a-z0-9_]+$/i.test(error?.code||'')?error.code:'preflight_failed'}));}
 const stop=()=>{runtime?.stop();server?.close();process.exit(0);};process.once('SIGTERM',stop);process.once('SIGINT',stop);
}
