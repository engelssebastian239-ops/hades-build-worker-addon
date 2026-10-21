export const PREFIX='[HADES] ';
export const VERSION='HADES_TASK_V1';
const validPath=p=>typeof p==='string'&&p.length<=140&&/^[a-zA-Z0-9_.\/-]+$/.test(p)&&!p.startsWith('/')&&!p.split('/').includes('..');
export function parseTask(issue,{authorizedAuthors=[]}={}){
  if(!issue||typeof issue!=='object'||issue.pull_request)return null;
  if(!Number.isSafeInteger(issue.number)||issue.number<1)return null;
  if(!authorizedAuthors.includes(issue.user?.login))return null;
  if(typeof issue.title!=='string'||!issue.title.startsWith(PREFIX)||issue.title.length>140)return null;
  if(typeof issue.body!=='string'||issue.body.length>6000)return null;
  let t;try{t=JSON.parse(issue.body)}catch{return null}
  if(!t||typeof t!=='object'||Array.isArray(t))return null;
  if(t.version!==VERSION||t.action!=='proposal-only')return null;
  if(typeof t.taskId!=='string'||!/^[A-Z0-9-]{6,60}$/.test(t.taskId))return null;
  if(typeof t.goal!=='string'||t.goal.trim().length<10||t.goal.length>1800)return null;
  if(!Array.isArray(t.acceptance)||t.acceptance.length<1||t.acceptance.length>8||!t.acceptance.every(x=>typeof x==='string'&&x.length>=3&&x.length<=260))return null;
  if(!Array.isArray(t.files)||t.files.length>20||!t.files.every(validPath))return null;
  const keys=Object.keys(t).sort().join(',');
  if(keys!==['version','action','taskId','goal','acceptance','files'].sort().join(','))return null;
  return Object.freeze({issue:issue.number, taskId:t.taskId, title:issue.title.slice(PREFIX.length),goal:t.goal,acceptance:[...t.acceptance],files:[...t.files],author:issue.user.login});
}
export function receiptFor(task,repo){
 const marker='HADES-M35-RECEIPT:'+repo+'#'+task.issue;
 return {marker,body:['<!-- '+marker+' -->','**H.A.D.E.S. / HERMES – Auftrag empfangen**','','- Task-ID: '+task.taskId,'- Status: `RECEIVED_EXECUTION_BLOCKED`','- Übermittlungsweg: GitHub Issues → FinestraMiner','- Ausführung: **Keine** Dateiänderungen, Shell-Befehle oder KI-Ausführung','- Nächster Schritt: Sandbox- und Freigabeprüfung vor echter Programmierung','','Dieser Empfangsbeleg bestätigt nur die GitHub-Kommunikation; er ist **kein** Fertigstellungsbericht.'].join('\n')};
}