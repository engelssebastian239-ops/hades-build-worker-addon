import fs from 'node:fs';
import http from 'node:http';
import {createMobileInstaller,createSupervisorClient,MAX_ARCHIVE_BYTES} from './installer.mjs';

const INSTALL_PATH='/v1/mobile/install';
const STATUS_PATH='/v1/mobile/status';
const RECONCILE_PATH='/v1/mobile/reconcile';
const PORT=8767;

function options(){
  const value=JSON.parse(fs.readFileSync('/data/options.json','utf8'));
  if(!value||Object.getPrototypeOf(value)!==Object.prototype||typeof value.enabled!=='boolean'||typeof value.trusted_broker_id!=='string'||typeof value.trusted_broker_public_key!=='string')throw Error('options_invalid');
  return value;
}
function writeJson(res,status,value){res.writeHead(status,{'content-type':'application/json','cache-control':'no-store','x-content-type-options':'nosniff'});res.end(JSON.stringify(value));}
export function readBody(req,maxBytes){return new Promise((resolve,reject)=>{let length=0,settled=false;const cleanup=()=>{req.setTimeout(0);req.removeListener('data',onData);req.removeListener('end',onEnd);req.removeListener('error',onError);};const finish=(error,value)=>{if(settled)return;settled=true;cleanup();if(error)reject(error);else resolve(value);};const onData=chunk=>{length+=chunk.length;if(length>maxBytes){req.destroy();finish(Error('request_too_large'));return;}chunks.push(chunk);};const onEnd=()=>finish(null,Buffer.concat(chunks));const onError=()=>finish(Error('request_read_failed'));const chunks=[];req.setTimeout(30_000,()=>{req.destroy();finish(Error('request_timeout'));});req.on('data',onData);req.on('end',onEnd);req.on('error',onError);});}
function createHttpServer(installer){
  let windowStart=Date.now(),count=0,active=0;
  return http.createServer(async(req,res)=>{
    const now=Date.now();if(now-windowStart>=60_000){windowStart=now;count=0;}if(++count>20||active>=4){writeJson(res,429,{error:'rate_limited'});return;}active++;
    try{
      if(req.method!=='POST'){writeJson(res,404,{error:'not_found'});return;}
      if(req.url===INSTALL_PATH){
        if(req.headers['content-type']?.split(';')[0].trim().toLowerCase()!=='application/gzip'){writeJson(res,415,{error:'content_type_rejected'});return;}
        const header=req.headers['x-hades-install-request'];if(typeof header!=='string'||header.length>8192||!/^[A-Za-z0-9_-]+$/.test(header)){writeJson(res,400,{error:'request_rejected'});return;}
        let envelope;try{envelope=JSON.parse(Buffer.from(header,'base64url').toString('utf8'));}catch{writeJson(res,400,{error:'request_rejected'});return;}
        const archive=await readBody(req,MAX_ARCHIVE_BYTES);const result=await installer.install(envelope,archive);writeJson(res,200,result);return;
      }
      if(req.url===STATUS_PATH||req.url===RECONCILE_PATH){
        if(req.headers['content-type']?.split(';')[0].trim().toLowerCase()!=='application/json'){writeJson(res,415,{error:'content_type_rejected'});return;}
        const body=await readBody(req,16*1024);let envelope;try{envelope=JSON.parse(body.toString('utf8'));}catch{writeJson(res,400,{error:'request_rejected'});return;}
        if(req.url===STATUS_PATH){writeJson(res,200,installer.statusSigned(envelope));return;}
        writeJson(res,200,await installer.reconcile(envelope));return;
      }
      writeJson(res,404,{error:'not_found'});
    }catch{if(!res.headersSent)writeJson(res,400,{error:'signed_request_rejected'});else res.destroy();}
    finally{active--;}
  });
}

export function main(){
  const config=options();
  if(config.enabled!==true){console.log(JSON.stringify({state:'INSTALLER_DISABLED',executionEnabled:false}));setInterval(()=>{},120_000).ref();return;}
  const token=process.env.SUPERVISOR_TOKEN;if(typeof token!=='string'||token.length<16)throw Error('supervisor_token_missing');
  const supervisor=createSupervisorClient({token});
  const installer=createMobileInstaller({enabled:true,brokerId:config.trusted_broker_id,trustedBrokerPublicKey:config.trusted_broker_public_key,supervisor});
  const server=createHttpServer(installer);server.on('error',()=>console.error(JSON.stringify({state:'INSTALLER_BLOCKED',code:'INGRESS_BIND_FAILED'})));
  server.listen(PORT,'0.0.0.0',()=>console.log(JSON.stringify({state:'INSTALLER_READY',target:'local_hades_m2_mobile',enabled:true,port:PORT,publicKey:installer.publicKey,reconciliationRequired:installer.snapshot().reconciliationRequired})));
}

if(import.meta.url===`file://${process.argv[1]}`)main();
