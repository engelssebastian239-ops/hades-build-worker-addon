import fs from 'node:fs';

const DATA_DIR='/data/hades-m42.5';
const SERVICE_UID=1000;
const SERVICE_GID=1000;

function readOptions() {
  const file='/data/options.json';
  const st=fs.lstatSync(file);
  if(!st.isFile()||st.isSymbolicLink()) throw Error('options_file_invalid');
  const options=JSON.parse(fs.readFileSync(file,'utf8'));
  if(!options||typeof options!=='object'||Array.isArray(options)||
      typeof options.enabled!=='boolean'||!Number.isInteger(options.listen_port)||
      options.listen_port<1024||options.listen_port>65535||
      typeof options.trusted_broker_id!=='string'||
      typeof options.trusted_broker_public_key!=='string') throw Error('options_invalid');
  return options;
}

function prepareDataDirectory() {
  try {
    const st=fs.lstatSync(DATA_DIR);
    if(!st.isDirectory()||st.isSymbolicLink()) throw Error('data_directory_invalid');
  } catch(error) {
    if(error.code!=='ENOENT') throw error;
    fs.mkdirSync(DATA_DIR,{mode:0o700});
  }
  fs.chownSync(DATA_DIR,SERVICE_UID,SERVICE_GID);
  fs.chmodSync(DATA_DIR,0o700);
  const st=fs.statSync(DATA_DIR);
  if(st.uid!==SERVICE_UID||st.gid!==SERVICE_GID||(st.mode&0o077)!==0)
    throw Error('data_directory_permissions');
}

function dropPrivileges() {
  if(typeof process.getuid!=='function'||process.getuid()!==0||
      typeof process.setgroups!=='function'||typeof process.setgid!=='function'||
      typeof process.setuid!=='function') throw Error('privilege_drop_unavailable');
  process.setgroups([SERVICE_GID]);
  process.setgid(SERVICE_GID);
  process.setuid(SERVICE_UID);
  if(process.getuid()!==SERVICE_UID||process.getgid()!==SERVICE_GID)
    throw Error('privilege_drop_failed');
}

async function main() {
  const options=readOptions();
  prepareDataDirectory();
  process.env.HADES_OPTIONS_JSON=JSON.stringify(options);
  process.env.HADES_PRIVATE_KEY_PATH=DATA_DIR+'/worker-ed25519.pem';
  process.env.HADES_LEDGER_PATH=DATA_DIR+'/diagnostic-ledger.json';
  dropPrivileges();
  const {main:runWorker}=await import('./main.mjs');
  await runWorker();
}

main().catch(error=>{
  const code=/^[a-z0-9_]+$/i.test(error?.message||'')?error.message:'launcher_startup_error';
  console.error(JSON.stringify({state:'STARTUP_BLOCKED',error:code}));
  process.exitCode=2;
});