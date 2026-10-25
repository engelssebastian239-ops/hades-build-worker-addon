import {createPublicKey} from 'node:crypto';
import {identityId} from '../shared/identity.mjs';
import {createMobileInstallPlanner} from './mobile-install-plan.mjs';
import {createMobileInstallStore} from './mobile-install-store.mjs';
import {createMobileInstallController} from './mobile-install-controller.mjs';
import {createGithubMobileInstallTransport,startGithubMobileInstallLoop} from './mobile-install-github.mjs';

const fail=code=>{throw Object.assign(new Error(code),{code});};

function makeRuntime({enabled=false,installEnabled=false,token,workerPrivateKey,adapterId,adapterPublicKey,log=()=>{},dependencies={}}={}){
  if(enabled!==true)return Object.freeze({enabled:false,async verifyConnection(){return false;},start(){return false;},stop(){},snapshot:()=>Object.freeze({enabled:false,running:false,ready:false})});
  if(typeof token!=='string'||!workerPrivateKey||typeof adapterId!=='string'||typeof adapterPublicKey!=='string')fail('mobile_install_runtime_configuration_invalid');
  if(adapterPublicKey.length<40||adapterPublicKey.length>512||!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(adapterPublicKey))fail('mobile_install_adapter_key_invalid');
  let pinnedKey;try{const der=Buffer.from(adapterPublicKey,'base64');if(der.toString('base64')!==adapterPublicKey)fail('mobile_install_adapter_key_invalid');pinnedKey=createPublicKey({key:der,format:'der',type:'spki'});}catch{fail('mobile_install_adapter_key_invalid');}
  if(pinnedKey.asymmetricKeyType!=='ed25519'||identityId(pinnedKey)!==adapterId)fail('mobile_install_adapter_pin_mismatch');
  const planner=(dependencies.createPlanner||createMobileInstallPlanner)({token});
  const store=(dependencies.createStore||createMobileInstallStore)();
  const controller=(dependencies.createController||createMobileInstallController)({planner,store,workerPrivateKey,trustedAdapterId:adapterId,trustedAdapterPublicKey:pinnedKey});
  const transport=(dependencies.createTransport||createGithubMobileInstallTransport)({token,workerPublicKey:workerPrivateKey,controller,planner,installEnabled});
  const startLoop=dependencies.startLoop||((value,options)=>startGithubMobileInstallLoop(value,{...options,...(dependencies.timers?{timers:dependencies.timers}:{})}));
  let ready=false,stopLoop=null;
  return Object.freeze({
    enabled:true,
    async verifyConnection(){ready=false;await transport.verifyConnection();ready=true;return true;},
    start(){if(!ready)fail('mobile_install_preflight_required');if(stopLoop)return false;const handle=startLoop(transport,{pollSeconds:120,log});if(!handle||typeof handle.stop!=='function')fail('mobile_install_loop_handle_invalid');stopLoop=handle;return true;},
    stop(){if(stopLoop){const handle=stopLoop;stopLoop=null;handle.stop();}},
    snapshot(){return Object.freeze({enabled:true,running:!!stopLoop,ready});}
  });
}

export function createMobileInstallRuntime({enabled=false,installEnabled=false,token,workerPrivateKey,adapterId,adapterPublicKey,log=()=>{}}={}){
  return makeRuntime({enabled,installEnabled,token,workerPrivateKey,adapterId,adapterPublicKey,log});
}
export function createMobileInstallRuntimeForTests({testOnlyDependencies,...options}={}){
  if(!testOnlyDependencies||Object.getPrototypeOf(testOnlyDependencies)!==Object.prototype)fail('mobile_install_runtime_test_dependencies_missing');
  return makeRuntime({...options,dependencies:testOnlyDependencies});
}
